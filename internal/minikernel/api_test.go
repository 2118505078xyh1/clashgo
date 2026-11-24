package minikernel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"clashgo/internal/ws"
)

func startTestAPI(t *testing.T) (*APIServer, string) {
	t.Helper()
	k := NewKernel()
	var used string
	k.Proxies["A"] = &recordingProxy{name: "A", used: &used}
	k.Proxies["B"] = &recordingProxy{name: "B", used: &used}
	k.Proxies["PROXY"] = NewSelector(k, "PROXY", []string{"A", "B"})
	api := NewAPIServer(k, "secret")
	if err := api.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close() })
	return api, "http://" + api.Addr()
}

func apiRequest(t *testing.T, base, method, path, body string, withAuth bool) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if withAuth {
		req.Header.Set("Authorization", "Bearer secret")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func TestAPIAuth(t *testing.T) {
	_, base := startTestAPI(t)
	resp, _ := apiRequest(t, base, "GET", "/version", "", false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-auth status = %d, want 401", resp.StatusCode)
	}
	resp, data := apiRequest(t, base, "GET", "/version", "", true)
	if resp.StatusCode != 200 {
		t.Fatalf("auth status = %d, body=%s", resp.StatusCode, data)
	}
	var v map[string]any
	json.Unmarshal(data, &v)
	if v["version"] != "0.1.0" {
		t.Fatalf("version = %v, want 0.1.0 (unified)", v["version"])
	}
}

func TestAPISetModeAndSelect(t *testing.T) {
	_, base := startTestAPI(t)
	resp, _ := apiRequest(t, base, "PATCH", "/configs", `{"mode":"global"}`, true)
	if resp.StatusCode != 204 {
		t.Fatalf("PATCH status = %d", resp.StatusCode)
	}
	_, data := apiRequest(t, base, "GET", "/configs", "", true)
	var cfg map[string]any
	json.Unmarshal(data, &cfg)
	if cfg["mode"] != "global" {
		t.Fatalf("mode = %v", cfg["mode"])
	}

	resp, _ = apiRequest(t, base, "PUT", "/proxies/PROXY", `{"name":"B"}`, true)
	if resp.StatusCode != 204 {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}
	_, data = apiRequest(t, base, "GET", "/proxies", "", true)
	var out struct {
		Proxies map[string]struct {
			Now string `json:"now"`
		} `json:"proxies"`
	}
	json.Unmarshal(data, &out)
	if out.Proxies["PROXY"].Now != "B" {
		t.Fatalf("selected = %q, want B", out.Proxies["PROXY"].Now)
	}
}

func TestAPIConnectionsAndRules(t *testing.T) {
	_, base := startTestAPI(t)
	_, data := apiRequest(t, base, "GET", "/connections", "", true)
	var conn struct {
		Connections []any `json:"connections"`
	}
	json.Unmarshal(data, &conn)
	if len(conn.Connections) != 0 {
		t.Fatalf("connections = %d, want 0", len(conn.Connections))
	}
	_, data = apiRequest(t, base, "GET", "/rules", "", true)
	var rules struct {
		Rules []any `json:"rules"`
	}
	if json.Unmarshal(data, &rules) != nil {
		t.Fatalf("bad rules JSON: %s", data)
	}
}

func TestAPIDNSQuery(t *testing.T) {
	_, base := startTestAPI(t)
	_, data := apiRequest(t, base, "GET", "/dns/query?name=localhost&type=A", "", true)
	var out struct {
		Status   int `json:"Status"`
		Question []struct {
			Name string `json:"name"`
		} `json:"Question"`
	}
	if json.Unmarshal(data, &out) != nil {
		t.Fatalf("bad DNS JSON: %s", data)
	}
	if out.Status != 0 || len(out.Question) == 0 || out.Question[0].Name != "localhost" {
		t.Fatalf("DNS response = %+v", out)
	}
}

func TestAPITrafficWS(t *testing.T) {
	api, _ := startTestAPI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer secret")
	c, _, err := ws.Dial(ctx, "ws://"+api.Addr()+"/traffic", &ws.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ws.StatusNormalClosure, "")
	_, msg, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(msg, []byte("up")) || !bytes.Contains(msg, []byte("down")) {
		t.Fatalf("traffic frame = %s", msg)
	}
}
