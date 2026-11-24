package minikernel

import (
	"context"
	"net"

	"clashgo/internal/reality"
	"clashgo/internal/vision"
	"clashgo/internal/vproto"
)

// appendTargetAddr 把目标地址编码成 SOCKS ATYP+ADDR+PORT（Trojan 头用）。
func appendTargetAddr(buf []byte, host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// VLESS 出站（纯标准库自研协议，支持 tcp/tls/ws/wss）。
type VLESS struct {
	name   string
	client *vproto.VLESSClient
	spec   transportSpec
}

func NewVLESS(name, server, uuid, flow, network string, useTLS bool, serverName, path, host string, skipVerify bool, realityCfg *reality.Config) (*VLESS, error) {
	client, err := vproto.NewVLESSClient(uuid, flow)
	if err != nil {
		return nil, err
	}
	return &VLESS{
		name:   name,
		client: client,
		spec: transportSpec{
			Server: server, Network: network, TLS: useTLS,
			ServerName: serverName, Path: path, Host: host, SkipVerify: skipVerify,
			Reality: realityCfg,
		},
	}, nil
}

func (v *VLESS) Name() string { return v.name }

func (v *VLESS) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"VLESS: empty destination"}
	}
	transport, err := dialTransport(ctx, v.spec)
	if err != nil {
		return nil, err
	}
	// XTLS Vision：VLESS header 直写底层明文 conn，后续应用数据走 Vision 帧。
	// 服务端下行：先读 VLESS 响应头（底层），再读 Vision 帧（包装层）。
	var conn net.Conn
	if v.client.Flow == "xtls-rprx-vision" {
		var uid [16]byte
		copy(uid[:], v.client.UUID[:])
		var raw net.Conn
		if tkc, ok := transport.(interface{ RawConn() net.Conn }); ok {
			raw = tkc.RawConn()
		}
		vconn := vision.Wrap(transport, raw, uid, 2)
		// Vision 握手：VLESS header 写完后立刻发一个空帧（首帧带 UUID +
		// 长 padding），否则服务端等不到 Vision 帧就关闭连接。
		conn, err = v.client.DialConnWithHeaderWriterEx(transport, vconn, host,
			m.DstPort, false, func() error {
				_, werr := vconn.Write(nil)
				return werr
			})
	} else {
		conn, err = v.client.DialConn(transport, host, m.DstPort, false)
	}
	if err != nil {
		transport.Close()
		return nil, err
	}
	return conn, nil
}

// Trojan 出站（TLS + 密码头）。
type Trojan struct {
	name     string
	password string
	spec     transportSpec
}

func NewTrojan(name, server, password string, useTLS bool, serverName string, skipVerify bool) *Trojan {
	return &Trojan{
		name: name, password: password,
		spec: transportSpec{Server: server, TLS: useTLS, ServerName: serverName, SkipVerify: skipVerify},
	}
}

func (t *Trojan) Name() string { return t.name }

func (t *Trojan) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"Trojan: empty destination"}
	}
	transport, err := dialTransport(ctx, t.spec)
	if err != nil {
		return nil, err
	}
	header := []byte(t.password + "\r\n\x01")
	header = appendTargetAddr(header, host, m.DstPort)
	header = append(header, '\r', '\n')
	if _, err := transport.Write(header); err != nil {
		transport.Close()
		return nil, err
	}
	return transport, nil
}
