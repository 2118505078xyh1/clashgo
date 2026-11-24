package quicproto

import (
	"context"
	"testing"
	"time"

	"clashgo/internal/http3proto"
)

type h3Adapter struct{ c Connection }

func (a h3Adapter) OpenStream() (http3proto.Stream, error) {
	return a.c.OpenStream()
}
func (a h3Adapter) OpenUniStream() (http3proto.Stream, error) {
	return a.c.OpenUniStream()
}

// TestHTTP3OverRealQUIC 用真 QUIC 栈（连本地 tls.QUICServer feature server）
// 跑一次 HTTP/3 请求，验证 QUIC 流层能让 H3 帧双向到达。
// feature server 在请求流上回一个真实的 HEADERS(:status=200) 帧。
func TestHTTP3OverRealQUIC(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{ackApp: true, h3Response: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http3proto.Do(ctx, h3Adapter{c}, http3proto.Request{
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
	})
	if err != nil {
		t.Fatalf("HTTP/3 over real QUIC: %v", err)
	}
	t.Logf("got response status=%d headers=%v", resp.Status, resp.Headers)
}
