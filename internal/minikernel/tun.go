package minikernel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"clashgo/internal/ipstack"
	"clashgo/internal/procinfo"
)

// TUNConfig 是虚拟网卡配置（纯标准库 TUN 实现）。
type TUNConfig struct {
	Enable    bool     `yaml:"enable"`
	Stack     string   `yaml:"stack"`
	AutoRoute bool     `yaml:"auto-route"`
	Device    string   `yaml:"device"`
	MTU       int      `yaml:"mtu"`
	Gateway   string   `yaml:"gateway"`
	Exclude   []string `yaml:"route-exclude-address"`
}

// TUNServer 管理纯标准库 TUN 虚拟网卡的生命周期。
type TUNServer struct {
	device *tapDevice
	stack  *ipstack.Stack
	routes []string // 已添加的路由，关闭时删除
}

// startTUN 打开 TAP 适配器 → 启动用户态协议栈 → 配置路由。
func startTUN(k *Kernel, cfg TUNConfig) (*TUNServer, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("TUN 当前仅支持 Windows")
	}
	gateway := netip.MustParseAddr("198.18.0.1")
	if cfg.Gateway != "" {
		if g, err := netip.ParseAddr(cfg.Gateway); err == nil {
			gateway = g
		}
	}
	device, err := openTAP(cfg.Device)
	if err != nil {
		return nil, err
	}
	ip4 := gateway.As4()
	mask := [4]byte{255, 255, 0, 0} // /16
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if err := device.configure(ip4, mask, ip4, mtu); err != nil {
		device.Close()
		return nil, err
	}

	s := &TUNServer{device: device}
	handler := &tunHandler{k: k, s: s}
	s.stack = ipstack.New(ipstack.Config{Gateway: ip4, MTU: mtu}, handler)

	// 配置系统路由（auto-route）：把默认流量导向 TAP 网关。
	if cfg.AutoRoute {
		if err := s.setupRoutes(gateway, cfg.Exclude); err != nil {
			// 路由失败不致命（可能无管理员权限），记录但不中断。
			_ = err
		}
	}

	go s.stack.Start(device)
	return s, nil
}

// setupRoutes 添加默认路由指向 TUN 网关，并排除节点服务器与本地网段。
func (s *TUNServer) setupRoutes(gateway netip.Addr, excludes []string) error {
	// 排除项：本地网段、组播、节点服务器 IP。
	builtin := []string{
		"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
	}
	// 加直连路由到网关本身（否则连网关都不通）。
	if err := routeAdd(gateway.String()+"/32", "0.0.0.0"); err != nil {
		return err
	}
	for _, cidr := range append(builtin, excludes...) {
		if err := routeAdd(cidr, "0.0.0.0"); err != nil {
			continue
		}
	}
	// 默认路由走 TUN 网关。
	if err := routeAdd("0.0.0.0/0", gateway.String()); err != nil {
		return err
	}
	return nil
}

func routeAdd(cidr, gateway string) error {
	cmd := exec.Command("route", "add", strings.Split(cidr, "/")[0],
		"mask", cidrMask(cidr), gateway, "METRIC", "5")
	_, err := cmd.CombinedOutput()
	return err
}

func routeDelete(cidr, gateway string) error {
	cmd := exec.Command("route", "delete", strings.Split(cidr, "/")[0], gateway)
	_, err := cmd.CombinedOutput()
	return err
}

// cidrMask 把 CIDR 前缀转成点分掩码。
func cidrMask(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "255.255.255.255"
	}
	var bits int
	fmt.Sscanf(parts[1], "%d", &bits)
	if bits < 0 || bits > 32 {
		bits = 32
	}
	var m uint32
	if bits == 0 {
		m = 0
	} else {
		m = ^uint32(0) << (32 - bits)
	}
	return net.IPv4(byte(m>>24), byte(m>>16), byte(m>>8), byte(m)).String()
}

func (s *TUNServer) Close() error {
	if s.stack != nil {
		s.stack.Close()
	}
	if s.device != nil {
		return s.device.Close()
	}
	return nil
}

// tunHandler 把协议栈的连接交给自研内核。
type tunHandler struct {
	k *Kernel
	s *TUNServer
}

func (h *tunHandler) NewTCP(ctx context.Context, srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, conn net.Conn) {
	m := &Metadata{
		Network: "tcp", Type: "tun",
		DstIP:   netip.AddrFrom4(dstIP),
		SrcIP:   netip.AddrFrom4(srcIP),
		DstPort: dstPort, SrcPort: srcPort,
	}
	// 进程名探测：TUN 连接来自各应用，按源地址反查进程供 PROCESS-NAME 规则用。
	if srcIP[0] != 0 {
		m.Process = procinfo.Lookup("tcp", netip.AddrFrom4(srcIP).String(), srcPort)
	}
	_ = h.k.Dispatch(ctx, conn, m)
}

func (h *tunHandler) NewUDP(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, payload []byte) {
	m := &Metadata{
		Network: "udp", Type: "tun",
		DstIP: netip.AddrFrom4(dstIP), SrcIP: netip.AddrFrom4(srcIP),
		DstPort: dstPort, SrcPort: srcPort,
	}
	// fake-ip 反查域名供规则匹配。
	h.k.preHandleMetadata(m)
	proxy := h.k.selectProxy(m)
	up, ok := proxy.(UDPProxyAdapter)
	if !ok {
		return
	}
	pc, err := up.ListenPacket(context.Background(), m)
	if err != nil {
		return
	}
	addr, err := resolveUDPAddr(m)
	if err != nil {
		pc.Close()
		return
	}
	if _, err := pc.WriteTo(payload, addr); err != nil {
		pc.Close()
		return
	}
	// 把出站响应写回 TUN 协议栈（源=目标，目的=客户端）。
	go func() {
		defer pc.Close()
		buf := make([]byte, 64*1024)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// 回包：源是原目标，目的是原客户端。
			respSrcIP, respSrcPort := dstIP, dstPort
			_ = h.s.stack.SendUDP(respSrcIP, respSrcPort, srcIP, srcPort, buf[:n], false)
		}
	}()
}

var _ = sync.Mutex{}
