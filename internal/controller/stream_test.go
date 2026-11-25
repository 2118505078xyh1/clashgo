package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clashgo/internal/ws"
)

// TestStreamTrafficReceivesFrames 验证 traffic 流能收到帧。
//
// 用 httptest 起一个最小 WebSocket 服务端，避免依赖本机 9097 端口上
// 是否真的跑着内核（之前的版本在无内核时必然失败）。
func TestStreamTrafficReceivesFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/traffic" {
			http.NotFound(w, r)
			return
		}
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Logf("ws accept: %v", err)
			return
		}
		defer conn.Close(ws.StatusNormalClosure, "")
		if err := conn.Write(context.Background(), ws.MessageText, []byte(`{"up":12,"down":34}`)); err != nil {
			t.Logf("ws write: %v", err)
		}
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"), "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var got TrafficSample
	n := 0
	err := c.StreamTraffic(ctx, func(s TrafficSample) {
		n++
		got = s
		if n == 1 {
			cancel()
		}
	})
	// ctx 取消后 StreamTraffic 会返回读取错误，这是预期路径。
	if n == 0 {
		t.Fatalf("没有收到任何 traffic 帧, err=%v", err)
	}
	if got.Up != 12 || got.Down != 34 {
		t.Fatalf("帧内容不对: up=%d down=%d", got.Up, got.Down)
	}
}
