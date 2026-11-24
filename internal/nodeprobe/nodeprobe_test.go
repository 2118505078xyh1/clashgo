package nodeprobe

import (
	"testing"
	"time"
)

func TestStoreCache(t *testing.T) {
	s := NewStore(t.TempDir())
	r := Result{Node: "n1", IP: "1.2.3.4", CountryCode: "US", OK: true}
	if _, ok := s.Get("n1", 24*time.Hour); ok {
		t.Error("empty cache should miss")
	}
	s.Put("n1", r)
	got, ok := s.Get("n1", 24*time.Hour)
	if !ok || got.IP != "1.2.3.4" || got.CountryCode != "US" {
		t.Errorf("cache hit wrong: %+v ok=%v", got, ok)
	}
}
