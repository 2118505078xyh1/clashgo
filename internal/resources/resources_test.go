package resources

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadListDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("resource-payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := Download(dir, "GeoIP.dat", srv.URL+"/geoip.dat"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "GeoIP.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "resource-payload" {
		t.Fatalf("downloaded content = %q", got)
	}

	list := List(dir)
	var found ResourceInfo
	for _, r := range list {
		if r.File == "GeoIP.dat" {
			found = r
		}
	}
	if !found.Installed || found.Size != int64(len("resource-payload")) {
		t.Fatalf("GeoIP.dat not reported as installed: %+v", found)
	}

	// Re-download over an existing file must succeed.
	if err := Download(dir, "GeoIP.dat", srv.URL+"/geoip.dat"); err != nil {
		t.Fatal(err)
	}
	if err := Delete(dir, "GeoIP.dat"); err != nil {
		t.Fatal(err)
	}
	if List(dir)[0].Installed {
		t.Fatal("resource still reported installed after delete")
	}
}

func TestDownloadRejectsBadResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := Download(dir, "GeoIP.dat", srv.URL+"/missing"); err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if _, err := os.Stat(filepath.Join(dir, "GeoIP.dat")); !os.IsNotExist(err) {
		t.Fatal("target should not exist after a failed download")
	}
}
