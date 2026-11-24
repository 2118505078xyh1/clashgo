package wgproto

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Config 描述一个 WireGuard 对等体（只支持发起方/客户端角色）。
type Config struct {
	// PrivateKey 是本端 Curve25519 私钥的 base64 编码（32 字节）。
	PrivateKey string
	// PeerPublicKey 是对端静态公钥的 base64 编码（32 字节）。
	PeerPublicKey string
	// Endpoint 是对端 UDP 地址，形如 "1.2.3.4:51820" 或 "example.com:51820"。
	Endpoint string
	// AllowedIPs 是允许经由该隧道的 IP 段（CIDR 或单个 IP）。
	// 本包不实现路由，仅解析并保存，供上层使用。
	AllowedIPs []string
	// Keepalive 是持久保活间隔（秒）。0 表示不发送保活包。
	Keepalive int
}

var (
	errKeySize    = errors.New("wgproto: key must be 32 bytes")
	errNoEndpoint = errors.New("wgproto: endpoint is required")
)

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errKeySize
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("wgproto: invalid base64 key: %w", err)
		}
	}
	if len(raw) != 32 {
		return nil, errKeySize
	}
	return raw, nil
}

// parseAllowedIPs 解析 CIDR 或单个 IP。
func parseAllowedIPs(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("wgproto: invalid allowed IP %q", s)
			}
			bits := 128
			if v4 := ip.To4(); v4 != nil {
				bits = 32
				ip = v4
			}
			s = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("wgproto: invalid allowed IP %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// parsedConfig 保存 New 解析后的配置。
type parsedConfig struct {
	privateKey    *ecdh.PrivateKey
	publicKey     [32]byte
	peerPublicKey [32]byte
	endpoint      *net.UDPAddr
	allowedIPs    []*net.IPNet
	keepalive     int
}

func parseConfig(cfg Config) (*parsedConfig, error) {
	privRaw, err := decodeKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wgproto: private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(privRaw)
	if err != nil {
		return nil, fmt.Errorf("wgproto: private key: %w", err)
	}
	pubRaw := priv.PublicKey().Bytes()

	peerRaw, err := decodeKey(cfg.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("wgproto: peer public key: %w", err)
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errNoEndpoint
	}
	endpoint, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("wgproto: endpoint: %w", err)
	}
	allowed, err := parseAllowedIPs(cfg.AllowedIPs)
	if err != nil {
		return nil, err
	}
	if cfg.Keepalive < 0 {
		return nil, errors.New("wgproto: keepalive must be >= 0")
	}

	p := &parsedConfig{
		privateKey: priv,
		endpoint:   endpoint,
		allowedIPs: allowed,
		keepalive:  cfg.Keepalive,
	}
	copy(p.publicKey[:], pubRaw)
	copy(p.peerPublicKey[:], peerRaw)
	return p, nil
}
