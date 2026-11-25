package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"clashgo/internal/ws"
)

func (c *Client) wsURL(path string) string {
	base := c.Base
	base = strings.TrimPrefix(base, "http://")
	base = strings.TrimPrefix(base, "https://")
	scheme := "ws"
	if strings.HasPrefix(c.Base, "https://") {
		scheme = "wss"
	}
	return scheme + "://" + base + path
}

func (c *Client) dial(path string) (*ws.Conn, error) {
	header := http.Header{}
	if c.Secret != "" {
		header.Set("Authorization", "Bearer "+c.Secret)
	}
	conn, resp, err := ws.Dial(context.Background(), c.wsURL(path),
		&ws.DialOptions{HTTPHeader: header})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws dial %s: %w (HTTP %d)", path, err, resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

// StreamTraffic calls onSample for each traffic frame until ctx is done.
func (c *Client) StreamTraffic(ctx context.Context, onSample func(TrafficSample)) error {
	conn, err := c.dial("/traffic")
	if err != nil {
		return err
	}
	defer conn.Close(ws.StatusNormalClosure, "")
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var sample TrafficSample
		if json.Unmarshal(data, &sample) == nil {
			onSample(sample)
		}
	}
}

// StreamLogs calls onLog for each log frame until ctx is done.
func (c *Client) StreamLogs(ctx context.Context, onLog func(LogFrame)) error {
	conn, err := c.dial("/logs")
	if err != nil {
		return err
	}
	defer conn.Close(ws.StatusNormalClosure, "")
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var frame LogFrame
		if json.Unmarshal(data, &frame) == nil {
			onLog(frame)
		}
	}
}

// StreamConnections calls onFrame for each connections snapshot.
func (c *Client) StreamConnections(ctx context.Context, onFrame func(ConnectionFrame)) error {
	conn, err := c.dial("/connections")
	if err != nil {
		return err
	}
	defer conn.Close(ws.StatusNormalClosure, "")
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var frame ConnectionFrame
		if json.Unmarshal(data, &frame) == nil {
			onFrame(frame)
		}
	}
}

// ReconnectStream runs a stream and reconnects with backoff until ctx is done.
func ReconnectStream(ctx context.Context, name string, start func(context.Context) error) {
	delay := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := start(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logfStream(name, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 10*time.Second {
			delay *= 2
		}
	}
}

func logfStream(name string, err error) {
	fmt.Printf("[clashgo] stream %s: %v\n", name, err)
}

// DialTraffic 建立 traffic WebSocket 连接（诊断用：返回连接状态）。
func (c *Client) DialTraffic(ctx context.Context) error {
	conn, err := c.dial("/traffic")
	if err != nil {
		return err
	}
	go func() {
		for {
			_, _, err := conn.Read(ctx)
			if err != nil {
				return
			}
		}
	}()
	return nil
}
