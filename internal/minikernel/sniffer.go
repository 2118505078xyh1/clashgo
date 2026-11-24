package minikernel

import (
	"bufio"
	"strings"
)

// sniffHost 从连接的前几个字节（不消耗）嗅探目标域名：
//   - TLS ClientHello → SNI
//   - 明文 HTTP → Host 头
//
// 仅用于入站未携带域名（如纯 IP 的 SOCKS5 CONNECT、TUN 流）的场景，
// 把结果写回 Metadata.Host 供 DOMAIN 规则匹配。Peek 不消耗数据，
// 后续的双向转发仍会发送完整字节。
func sniffHost(r *bufio.Reader) string {
	head, err := r.Peek(1)
	if err != nil {
		return ""
	}
	if head[0] == 0x16 { // TLS handshake record
		return sniffTLS(r)
	}
	return sniffHTTP(r)
}

// sniffTLS 解析 TLS ClientHello 的 SNI 扩展（server_name）。
func sniffTLS(r *bufio.Reader) string {
	rec, err := r.Peek(5)
	if err != nil || rec[0] != 0x16 {
		return ""
	}
	recLen := int(rec[3])<<8 | int(rec[4])
	if recLen < 4 || recLen > 0x4000 {
		return ""
	}
	total := 5 + recLen
	b, err := r.Peek(total)
	if err != nil {
		return ""
	}
	if b[5] != 0x01 { // ClientHello
		return ""
	}
	p := 9 + 2 + 32 // handshake 头 + client_version + random
	if p >= len(b) {
		return ""
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return ""
	}
	csLen := int(b[p])<<8 | int(b[p+1])
	p += 2 + csLen
	if p >= len(b) {
		return ""
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return ""
	}
	extLen := int(b[p])<<8 | int(b[p+1])
	p += 2
	end := p + extLen
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		et := int(b[p])<<8 | int(b[p+1])
		el := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if et == 0x0000 && el >= 5 { // SNI 扩展
			q := p + 2 // 跳过 list length
			qEnd := p + el
			if qEnd > len(b) {
				qEnd = len(b)
			}
			for q+3 <= qEnd {
				nameType := b[q]
				nameLen := int(b[q+1])<<8 | int(b[q+2])
				q += 3
				if nameType == 0 && nameLen > 0 && q+nameLen <= qEnd {
					return string(b[q : q+nameLen])
				}
				q += nameLen
			}
		}
		p += el
	}
	return ""
}

// sniffHTTP 从明文 HTTP 请求里解析 Host 头。
func sniffHTTP(r *bufio.Reader) string {
	// 只 peek 当前已缓冲的字节，避免等待凑满固定长度而阻塞。
	first, err := r.Peek(1)
	if err != nil && len(first) == 0 {
		return ""
	}
	n := r.Buffered()
	if n < len(first) {
		n = len(first)
	}
	if n > 8192 {
		n = 8192
	}
	b, _ := r.Peek(n)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 5 && strings.EqualFold(line[:5], "Host:") {
			h := strings.TrimSpace(line[5:])
			if i := strings.IndexAny(h, " \t\r\n/"); i >= 0 {
				h = h[:i]
			}
			if j := strings.LastIndex(h, ":"); j > 0 && !strings.Contains(h[j+1:], "]") {
				h = h[:j]
			}
			return h
		}
	}
	return ""
}
