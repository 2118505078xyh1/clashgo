package minikernel

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnInfo 是一条连接的快照信息（字段兼容 Clash API 的 /connections）。
type ConnInfo struct {
	ID            string    `json:"id"`
	Start         time.Time `json:"start"`
	Host          string    `json:"host"`
	Full          string    `json:"full"`
	Network       string    `json:"network"`
	Type          string    `json:"type"`
	Rule          string    `json:"rule"`
	RulePayload   string    `json:"rulePayload"`
	Chain         []string  `json:"chain"`
	Upload        int64     `json:"upload"`
	Download      int64     `json:"download"`
	SourceIP      string    `json:"sourceIP"`
	DestinationIP string    `json:"destinationIP"`
	Process       string    `json:"process"`

	conn net.Conn
	mgr  *ConnManager
	once *sync.Once // 指针，避免快照拷贝锁值
}

// ConnManager 管理活跃连接表。
type ConnManager struct {
	mu    sync.RWMutex
	conns map[string]*ConnInfo
	seq   atomic.Uint64
}

func NewConnManager() *ConnManager {
	return &ConnManager{conns: map[string]*ConnInfo{}}
}

func (m *ConnManager) join(info *ConnInfo) string {
	id := fmt.Sprintf("%016x", m.seq.Add(1))
	info.ID = id
	info.mgr = m
	info.once = &sync.Once{}
	m.mu.Lock()
	m.conns[id] = info
	m.mu.Unlock()
	return id
}

func (m *ConnManager) leave(id string) {
	m.mu.Lock()
	delete(m.conns, id)
	m.mu.Unlock()
}

// Snapshot 返回所有活跃连接的快照（按开始时间排序）。
func (m *ConnManager) Snapshot() []*ConnInfo {
	m.mu.RLock()
	out := make([]*ConnInfo, 0, len(m.conns))
	for _, c := range m.conns {
		cp := *c
		cp.Chain = append([]string(nil), c.Chain...)
		out = append(out, &cp)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

func (m *ConnManager) Close(id string) bool {
	m.mu.RLock()
	info := m.conns[id]
	m.mu.RUnlock()
	if info == nil {
		return false
	}
	info.CloseConn()
	return true
}

func (m *ConnManager) CloseAll() {
	for _, info := range m.Snapshot() {
		m.Close(info.ID)
	}
}

// CloseConn 关闭底层连接并从表中移除（幂等）。
func (c *ConnInfo) CloseConn() {
	c.once.Do(func() {
		if c.mgr != nil {
			c.mgr.leave(c.ID)
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

// trackedConn 包装远端连接，统计字节数并在关闭时从表中移除。
type trackedConn struct {
	net.Conn
	info *ConnInfo
	k    *Kernel
}

func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.info.Download += int64(n)
	c.k.downloadTotal.Add(int64(n))
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.info.Upload += int64(n)
	c.k.uploadTotal.Add(int64(n))
	return n, err
}

func (c *trackedConn) Close() error {
	c.info.CloseConn()
	return nil
}
