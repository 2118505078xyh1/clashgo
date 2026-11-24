// Package backup handles local configuration backups.
package backup

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"clashgo/internal/paths"
)

// Info describes one backup file.
type Info struct {
	Name string
	Size int64
	Time time.Time
}

// Create copies the current config files into a timestamped backup dir.
// The name is made unique even when several backups are created within the
// same second — SafeRestore relies on this so it can never overwrite the very
// backup it is about to restore from.
func Create() (string, error) {
	base := time.Now().Format("20060102-150405")
	name := base
	for i := 1; ; i++ {
		if _, err := os.Stat(filepath.Join(paths.Backup, name)); os.IsNotExist(err) {
			break
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
	dir := filepath.Join(paths.Backup, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	files := []string{paths.Settings, paths.ProfilesDB}
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			continue
		}
		if err := copyFile(f, filepath.Join(dir, filepath.Base(f))); err != nil {
			return "", err
		}
	}
	// Copy profiles directory.
	src := paths.Profiles
	dst := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		if !e.IsDir() {
			_ = copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()))
		}
	}
	return name, nil
}

// List returns all backups, newest first.
func List() ([]Info, error) {
	entries, err := os.ReadDir(paths.Backup)
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() {
			info, _ := e.Info()
			if info != nil {
				out = append(out, Info{Name: e.Name(), Time: info.ModTime()})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Restore replaces current config files with a backup.
func Restore(name string) error {
	dir := filepath.Join(paths.Backup, name)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("backup %s not found", name)
	}
	for _, f := range []string{"settings.yaml", "profiles.yaml"} {
		src := filepath.Join(dir, f)
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(paths.Home, f)
			if err := copyFile(src, dst); err != nil {
				return err
			}
		}
	}
	// Restore profiles dir.
	srcDir := filepath.Join(dir, "profiles")
	entries, _ := os.ReadDir(srcDir)
	for _, e := range entries {
		_ = copyFile(filepath.Join(srcDir, e.Name()), filepath.Join(paths.Profiles, e.Name()))
	}
	return nil
}

// Delete removes a backup.
func Delete(name string) error {
	return os.RemoveAll(filepath.Join(paths.Backup, name))
}

// CreateZip makes a fresh directory backup and packs it into
// paths.Backup/<name>.zip, returning the zip path. An empty name falls back
// to the generated backup directory name.
func CreateZip(name string) (string, error) {
	dirName, err := Create()
	if err != nil {
		return "", err
	}
	name = strings.TrimSuffix(filepath.Base(name), ".zip")
	if name == "" || name == "." {
		name = dirName
	}
	zipPath := filepath.Join(paths.Backup, name+".zip")
	if err := zipDir(filepath.Join(paths.Backup, dirName), zipPath); err != nil {
		return "", err
	}
	return zipPath, nil
}

// SafeRestore backs up the current configuration before restoring name.
// The fresh backup is deliberately kept so a failed restore can be rolled
// back by restoring that new backup.
func SafeRestore(name string) error {
	if _, err := Create(); err != nil {
		return fmt.Errorf("pre-restore backup failed: %w", err)
	}
	return Restore(name)
}

// RestoreZip extracts a zip backup into a temporary directory under
// paths.Backup and restores from it. Entry paths are validated so a crafted
// archive cannot write outside the extraction directory (zip-slip).
func RestoreZip(zipPath string) error {
	if err := os.MkdirAll(paths.Backup, 0o755); err != nil {
		return err
	}
	name := fmt.Sprintf("restore-%d", time.Now().UnixNano())
	tmpDir := filepath.Join(paths.Backup, name)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := unzip(zipPath, tmpDir); err != nil {
		return err
	}
	return Restore(name)
}

// zipDir writes srcDir (excluding the root entry itself) into a zip file.
func zipDir(srcDir, zipPath string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			h.Name += "/"
		} else {
			h.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, in)
		closeErr := in.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		_ = zw.Close()
		return err
	}
	return zw.Close()
}

// unzip extracts a zip archive into dstDir, rejecting unsafe entry paths.
func unzip(zipPath, dstDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		name := filepath.Clean(filepath.FromSlash(f.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." ||
			strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe zip entry: %q", f.Name)
		}
		target := filepath.Join(dstDir, name)
		rel, err := filepath.Rel(dstDir, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe zip entry: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		mode := f.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			_ = rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		closeErr := out.Close()
		_ = rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
