// Package quicproto 提供仅依赖 Go 标准库的 Hysteria2 / TUIC 出站实现框架。
//
// # 重要兼容性声明（务必先读）
//
// 真实的 Hysteria2 与 TUIC 都是构建在 QUIC 之上的代理协议：QUIC = UDP +
// TLS 1.3（含 QUIC 专用的握手改造、0-RTT、传输参数扩展）+ 拥塞控制 + 多流复用
// + 连接迁移。Go 标准库的 net/http 的 HTTP/3 支持依赖 x/net/http3（外部依赖），
// crypto/tls 也没有暴露 QUIC 模式（TLS 的 QUIC 封装需要改造记录层，标准库不提供）。
// 因此，不用 golang.org/x/*（尤其不用 quic-go）在纯标准库里复刻完整 QUIC 是不现实的。
//
// 本包采取务实方案：实现一个「QUIC-like」的最小可靠 UDP 传输层（序列号、ACK、
// 重传、滑动窗口），在其上用标准库 crypto/aes + crypto/cipher 做简单的 AEAD
// 加密握手，并实现 Hysteria2 / TUIC 的协议头与认证格式。
//
// 本包【不能】与真实的 Hysteria2 / TUIC 服务端互通（它们要求真正的 QUIC + TLS 1.3）。
// 它面向的是使用本包相同线格式的「简化版」服务端，或作为未来接入真正 QUIC
// 实现（例如 quic-go）时替换传输层的可测试框架：上层协议头/认证代码保持不变，
// 只需把 dialReliable 换成真正的 QUIC 拨号即可。
//
// 不导入任何第三方包，特别是不导入 golang.org/x/* 与 quic-go。
package quicproto
