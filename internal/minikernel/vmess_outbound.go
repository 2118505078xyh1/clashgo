package minikernel

import (
	"context"
	"net"

	"clashgo/internal/vproto"
)

// VMess 出站（纯标准库自研协议实现，支持 tcp/tls/ws/wss 传输）。
type VMess struct {
	name   string
	client *vproto.VMessClient
	spec   transportSpec
}

// NewVMess 创建 VMess 出站。
func NewVMess(name, server, uuid, cipher string, alterID int, network string, useTLS bool, serverName, path, host string, skipVerify bool) (*VMess, error) {
	client, err := vproto.NewVMessClientWithAlterId(uuid, cipher, alterID)
	if err != nil {
		return nil, err
	}
	return &VMess{
		name:   name,
		client: client,
		spec: transportSpec{
			Server: server, Network: network, TLS: useTLS,
			ServerName: serverName, Path: path, Host: host, SkipVerify: skipVerify,
		},
	}, nil
}

func (v *VMess) Name() string { return v.name }

// ListenPacket 建立 VMess UDP 通道。
func (v *VMess) ListenPacket(ctx context.Context, m *Metadata) (net.PacketConn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"VMess UDP: empty destination"}
	}
	transport, err := dialTransport(ctx, v.spec)
	if err != nil {
		return nil, err
	}
	pc, err := v.client.DialPacketConn(transport, host, m.DstPort)
	if err != nil {
		transport.Close()
		return nil, err
	}
	return pc, nil
}

func (v *VMess) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"VMess: empty destination"}
	}
	transport, err := dialTransport(ctx, v.spec)
	if err != nil {
		return nil, err
	}
	conn, err := v.client.DialConn(transport, host, m.DstPort)
	if err != nil {
		transport.Close()
		return nil, err
	}
	return conn, nil
}
