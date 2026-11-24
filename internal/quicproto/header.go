package quicproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// 地址类型常量（Hysteria2 / TUIC 简化协议头共用）。
const (
	addrIPv4   byte = 0x01
	addrDomain byte = 0x02
	addrIPv6   byte = 0x03
)

// targetAddr 是协议头中的目标地址（即要通过代理访问的地址）。
type targetAddr struct {
	host string
	port uint16
}

// appendTargetAddr 按 type(1) + [len(1) +] addr + port(2 BE) 编码目标地址。
func appendTargetAddr(dst []byte, host string, port uint16) ([]byte, error) {
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		dst = append(dst, addrIPv4)
		dst = append(dst, ip.To4()...)
	case ip != nil:
		dst = append(dst, addrIPv6)
		dst = append(dst, ip.To16()...)
	default:
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("quicproto: invalid host name %q", host)
		}
		dst = append(dst, addrDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	dst = append(dst, byte(port>>8), byte(port))
	return dst, nil
}

// readTargetAddr 是 appendTargetAddr 的逆操作，返回解析后的地址和剩余字节。
func readTargetAddr(b []byte) (targetAddr, []byte, error) {
	var out targetAddr
	if len(b) < 1 {
		return out, nil, errors.New("quicproto: missing address type")
	}
	typ := b[0]
	b = b[1:]
	switch typ {
	case addrIPv4:
		if len(b) < net.IPv4len+2 {
			return out, nil, errors.New("quicproto: truncated IPv4 address")
		}
		out.host = net.IP(b[:net.IPv4len]).String()
		b = b[net.IPv4len:]
	case addrIPv6:
		if len(b) < net.IPv6len+2 {
			return out, nil, errors.New("quicproto: truncated IPv6 address")
		}
		out.host = net.IP(b[:net.IPv6len]).String()
		b = b[net.IPv6len:]
	case addrDomain:
		if len(b) < 1 {
			return out, nil, errors.New("quicproto: missing domain length")
		}
		n := int(b[0])
		b = b[1:]
		if len(b) < n+2 {
			return out, nil, errors.New("quicproto: truncated domain name")
		}
		out.host = string(b[:n])
		b = b[n:]
	default:
		return out, nil, fmt.Errorf("quicproto: unknown address type 0x%02x", typ)
	}
	out.port = binary.BigEndian.Uint16(b[:2])
	return out, b[2:], nil
}
