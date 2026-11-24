package minikernel

// 这两个导出构造器只供 cmd/verify 做端到端验证使用。
// 它们复用内核的真实出站实现，不引入任何测试专用逻辑。

// NewHysteria2Verifier 创建一个 Hysteria2 出站，供 verify hy2 使用。
func NewHysteria2Verifier(addr, serverName, password string, skipVerify bool) ProxyAdapter {
	return newHysteria2Real("verify-hy2", addr, serverName, password, skipVerify, 0)
}

// NewTUICVerifier 创建一个 TUIC v5 出站，供 verify tuic 使用。
func NewTUICVerifier(addr, uuid, password, serverName string, skipVerify bool) ProxyAdapter {
	return newTUICReal("verify-tuic", addr, uuid, password, serverName, skipVerify)
}
