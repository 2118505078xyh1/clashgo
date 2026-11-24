// Package webdav provides config backup/restore over WebDAV.
package webdav

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"clashgo/internal/paths"
	"clashgo/internal/webdavclient"
)

// Config holds WebDAV connection settings.
type Config struct {
	URL      string `yaml:"url" json:"url"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// Client wraps a WebDAV connection.
type Client struct {
	cfg Config
	c   *webdavclient.Client
}

// New creates a WebDAV client (does not connect until an operation).
func New(cfg Config) *Client {
	return &Client{cfg: cfg, c: webdavclient.NewClient(cfg.URL, cfg.Username, cfg.Password)}
}

// File describes a remote backup.
type File struct {
	Name         string
	Href         string
	LastModified time.Time
	Size         int64
}

// TestConnection verifies the WebDAV endpoint is reachable.
func (w *Client) TestConnection() error {
	if w.cfg.URL == "" {
		return fmt.Errorf("WebDAV URL is empty")
	}
	if err := w.c.Connect(); err != nil {
		return err
	}
	return nil
}

// Create uploads a local backup directory to WebDAV.
func (w *Client) Create(name string) error {
	srcDir := filepath.Join(paths.Backup, name)
	entries, err := listFiles(srcDir)
	if err != nil {
		return err
	}
	remoteDir := "/clashgo-backup/" + name
	if err := w.c.MkdirAll(remoteDir, 0o755); err != nil {
		return err
	}
	for _, rel := range entries {
		data, err := readFile(filepath.Join(srcDir, rel))
		if err != nil {
			continue
		}
		if err := w.c.Write(remoteDir+"/"+rel, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// List returns remote backups sorted newest first.
func (w *Client) List() ([]File, error) {
	files, err := w.c.ReadDir("/clashgo-backup")
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not found") {
			return []File{}, nil
		}
		return nil, err
	}
	var out []File
	for _, f := range files {
		if f.IsDir {
			out = append(out, File{Name: f.Name, Href: "/clashgo-backup/" + f.Name, LastModified: f.LastModified, Size: f.Size})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Restore downloads a remote backup into a local backup dir, then returns
// its name so the caller can use backup.Restore.
func (w *Client) Restore(name string) error {
	remoteDir := "/clashgo-backup/" + name
	localDir := filepath.Join(paths.Backup, name+"-webdav")
	files, err := w.c.ReadDir(remoteDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir {
			continue
		}
		data, err := w.c.Read(remoteDir + "/" + f.Name)
		if err != nil {
			return err
		}
		// Handle profiles subdirectory files.
		target := filepath.Join(localDir, f.Name)
		if err := writeFile(target, data); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes a remote backup.
func (w *Client) Delete(name string) error {
	return w.c.RemoveAll("/clashgo-backup/" + name)
}
