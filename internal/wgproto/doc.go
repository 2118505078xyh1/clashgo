// Package wgproto 是纯 Go 标准库实现的 WireGuard 出站（initiator）协议栈。
//
// 零外部依赖：不引用 golang.org/x/*，也不引用任何第三方模块。
//
// 已实现
//
//   - X25519：使用 Go 1.20+ 标准库 crypto/ecdh（无需自己写 Montgomery ladder /
//     math/big 大数运算）。Curve25519 私钥、公钥、ECDH 全部由标准库完成。
//   - BLAKE2s-256 / BLAKE2s-128（RFC 7693）：本包内实现，含 keyed MAC 模式；
//     用于 Noise 的 HASH、MAC1 以及 HKDF 底层哈希。
//   - HKDF-HMAC-BLAKE2s：按白皮书 KDF1/KDF2/KDF3 定义实现（crypto/hmac +
//     本包 BLAKE2s），与 wireguard-go 的 KDF 完全一致。
//   - ChaCha20 / Poly1305 / ChaCha20Poly1305 AEAD（RFC 8439）：本包内实现，
//     12 字节 nonce；WireGuard 的 Aead(key, counter, ...) 映射为 nonce =
//     4 个零字节 || counter(8 字节小端)。
//   - Noise_IKpsk2 握手：发起消息(type=1, 148 字节)、响应消息(type=2,
//     92 字节) 的完整密钥派生与认证；含 mac1、TAI64N 时间戳、全零 PSK。
//   - 数据传输(type=4)：16 字节头(type+receiver+counter) + AEAD 密文/标签；
//     带 64 包滑动窗口重放过滤。
//   - 持久保活(空 transport 包)与定期重协商（2 分钟）。
//   - net.PacketConn 接口：ReadFrom/WriteTo 读写解密后的内层 IP 包。
//
// 简化与未实现
//
//   - 不创建 TUN/TAP 设备，也不实现 IP/TCP 栈；上层负责构造/解析 IP 包。
//     因此没有 DialContext（IP 包内嵌 TCP 的 SYN/ACK/序号/重传需要完整 TCP 栈）。
//   - 只实现发起方（客户端）角色，不实现响应方（服务端）；不处理 cookie
//     消息(type=3)与 mac2（mac2 恒为 0，正常未受攻击时服务端接受）。
//   - PSK 固定为全零（WireGuard 默认）。
//   - Poly1305 用 math/big 实现，正确但非恒定时间、性能低于专用实现。
//   - AllowedIPs 仅解析保存，不参与本包的路由决策。
//   - 重放窗口为简化实现：丢包乱序超过 64 个包会被拒绝。
//
// 正确性验证
//
// 包内测试覆盖了 RFC 7693（BLAKE2s 带密钥/不带密钥 KAT）、RFC 8439
// （ChaCha20 block / Poly1305 / AEAD 完整测试向量）、RFC 7748（X25519）、
// 握手双向密钥派生一致性，以及本地 UDP 端到端握手 + 加密数据传输。
package wgproto
