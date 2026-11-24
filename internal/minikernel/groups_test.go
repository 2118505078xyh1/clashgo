package minikernel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type recordingProxy struct {
	name string
	used *string
}

func (p *recordingProxy) Name() string { return p.name }
func (p *recordingProxy) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	*p.used = p.name
	return nil, fmt.Errorf("called")
}

func TestSelector(t *testing.T) {
	k := NewKernel()
	var used string
	k.Proxies["A"] = &recordingProxy{name: "A", used: &used}
	k.Proxies["B"] = &recordingProxy{name: "B", used: &used}
	s := NewSelector(k, "PROXY", []string{"A", "B"})
	k.Proxies["PROXY"] = s

	if s.Selected() != "A" {
		t.Fatalf("default selected = %q, want A", s.Selected())
	}
	if !s.Set("B") || s.Selected() != "B" {
		t.Fatal("Set(B) failed")
	}
	if s.Set("C") {
		t.Fatal("Set(C) should fail (not a member)")
	}
	_, _ = k.Proxies["PROXY"].DialContext(context.Background(), &Metadata{Host: "x.com"})
	if used != "B" {
		t.Fatalf("dial used %q, want B", used)
	}
	if len(s.Members()) != 2 {
		t.Fatal("Members() wrong length")
	}
}

func TestURLTestBest(t *testing.T) {
	k := NewKernel()
	var used string
	k.Proxies["A"] = &recordingProxy{name: "A", used: &used}
	k.Proxies["B"] = &recordingProxy{name: "B", used: &used}
	ut := NewURLTest(k, "AUTO", []string{"A", "B"})

	// 未测时回退第一个成员。
	if ut.best() != "A" {
		t.Fatalf("best before test = %q, want A", ut.best())
	}
	ut.SetDelay("A", 100)
	ut.SetDelay("B", 50)
	if ut.best() != "B" {
		t.Fatalf("best = %q, want B", ut.best())
	}
	_, _ = ut.DialContext(context.Background(), &Metadata{Host: "x.com"})
	if used != "B" {
		t.Fatalf("dial used %q, want B", used)
	}
}

func TestTestDelay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond) // 保证延迟可测量（>0ms）
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := TestDelay(context.Background(), &Direct{}, srv.URL)
	if r.Error != "" {
		t.Fatalf("delay error: %s", r.Error)
	}
	if r.Delay == 0 {
		t.Fatal("delay is 0, expected measurable latency")
	}
}
