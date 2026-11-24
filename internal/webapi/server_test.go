package webapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func authGet(t *testing.T, url, secret string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestAuthMiddleware(t *testing.T) {
	s := New("127.0.0.1:0", "s3cr3t")
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	// No token -> 401 and a WWW-Authenticate challenge.
	resp := authGet(t, ts.URL+"/api/version", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("missing WWW-Authenticate challenge")
	}

	// Wrong token -> 401.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/version", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", resp2.StatusCode)
	}

	// Correct token -> 200 with the version payload.
	resp3 := authGet(t, ts.URL+"/api/version", "s3cr3t")
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("correct token: got %d, want 200", resp3.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp3.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["version"] != Version {
		t.Errorf("version = %q, want %q", body["version"], Version)
	}

	// Empty secret -> open endpoint.
	open := New("127.0.0.1:0", "")
	ots := httptest.NewServer(open.handler())
	defer ots.Close()
	resp4 := authGet(t, ots.URL+"/api/version", "")
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("open endpoint: got %d, want 200", resp4.StatusCode)
	}
}

func TestStatusSnapshot(t *testing.T) {
	s := New("127.0.0.1:0", "tok")
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	want := Snapshot{
		Version:     "0.1.0",
		Mode:        "rule",
		Up:          1234,
		Down:        5678,
		Connections: 3,
		Proxies:     map[string]any{"PROXY": "ss1"},
		Rules:       []any{"MATCH,DIRECT"},
		UpdatedAt:   time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC),
	}
	s.SetSnapshot(want)

	resp := authGet(t, ts.URL+"/api/status", "tok")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var got Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.Mode != want.Mode || got.Up != want.Up ||
		got.Down != want.Down || got.Connections != want.Connections {
		t.Fatalf("snapshot mismatch: got %+v, want %+v", got, want)
	}
	if got.Proxies["PROXY"] != "ss1" {
		t.Errorf("proxies = %v", got.Proxies)
	}
	if len(got.Rules) != 1 || got.Rules[0] != "MATCH,DIRECT" {
		t.Errorf("rules = %v", got.Rules)
	}
	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("updated_at = %v, want %v", got.UpdatedAt, want.UpdatedAt)
	}
}

func TestSSEPublish(t *testing.T) {
	s := New("127.0.0.1:0", "tok")
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	// A deadline guarantees the stream test cannot hang forever.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer tok")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("open SSE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}

	// client.Do returns only after the handler subscribed and flushed headers,
	// so the event below is guaranteed to be delivered into its buffer.
	s.Publish(Event{Type: "node.changed", Data: map[string]any{"name": "hk01", "delay": 42}})

	reader := bufio.NewReader(resp.Body)
	var eventType, dataLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			dataLine = strings.TrimPrefix(line, "data: ")
		}
		if eventType != "" && dataLine != "" {
			break
		}
	}

	if eventType != "node.changed" {
		t.Errorf("event = %q, want %q", eventType, "node.changed")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(dataLine), &payload); err != nil {
		t.Fatalf("decode data %q: %v", dataLine, err)
	}
	if payload["name"] != "hk01" || payload["delay"] != float64(42) {
		t.Errorf("payload = %v", payload)
	}
}

func TestCommandHandler(t *testing.T) {
	s := New("127.0.0.1:0", "tok")
	var mu sync.Mutex
	type call struct{ action, value string }
	var calls []call
	s.SetCommandHandler(func(action, value string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call{action, value})
		return nil
	})
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	post := func(body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/command", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post(`{"action":"set-mode","value":"rule"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid command: got %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Errorf("response = %v", out)
	}

	resp2 := post(`{"action":"toggle-system-proxy","value":""}`)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("toggle command: got %d, want 200", resp2.StatusCode)
	}

	resp3 := post(`{"action":"bogus"}`)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown action: got %d, want 400", resp3.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("handler called %d times, want 2: %v", len(calls), calls)
	}
	if calls[0] != (call{"set-mode", "rule"}) || calls[1] != (call{"toggle-system-proxy", ""}) {
		t.Errorf("calls = %v", calls)
	}
}

func TestSubscriberLifecycleAndDrop(t *testing.T) {
	s := New("127.0.0.1:0", "")
	sub := s.subscribe()
	if sub == nil {
		t.Fatal("subscribe failed")
	}
	if got := len(s.subs); got != 1 {
		t.Fatalf("subscriber count = %d, want 1", got)
	}

	s.Publish(Event{Type: "tick"})
	select {
	case e := <-sub.ch:
		if e.Type != "tick" {
			t.Errorf("event type = %q", e.Type)
		}
		if e.Time.IsZero() {
			t.Error("publish did not stamp event time")
		}
	default:
		t.Fatal("published event was not delivered")
	}

	// Fill the buffer past capacity: extra events are dropped, never blocking.
	for i := 0; i < subscriberBuffer+10; i++ {
		s.Publish(Event{Type: fmt.Sprintf("flood-%d", i)})
	}
	if got := len(sub.ch); got != subscriberBuffer {
		t.Errorf("buffered events = %d, want %d (slow clients drop)", got, subscriberBuffer)
	}

	s.unsubscribe(sub)
	if got := len(s.subs); got != 0 {
		t.Errorf("subscriber count after unsubscribe = %d, want 0", got)
	}
	// A closed channel still yields buffered items; drain them before checking
	// that the channel is actually closed.
	drained := 0
	for range sub.ch {
		drained++
	}
	if drained != subscriberBuffer {
		t.Errorf("drained %d events, want %d", drained, subscriberBuffer)
	}
	if _, ok := <-sub.ch; ok {
		t.Error("subscriber channel was not closed on unsubscribe")
	}
}
