// Package http3proto 用纯 Go 标准库实现最小的 HTTP/3 客户端，用于 Hysteria2
// 的认证请求（POST https://hysteria/auth）。它只实现完成这一个请求所需的
// HTTP/3 帧与 QPACK 子集，不提供通用 HTTP/3 / net/http.RoundTripper 能力。
//
// # 范围与接口
//
// QUIC 底层由调用方提供（例如另一个子代理实现的 internal/quicproto）。本包
// 只定义最小的 Stream / Connection 接口（见 client.go），不导入也不依赖任何
// 具体的 QUIC 实现，更不导入 golang.org/x/* 或 quic-go。
//
// # RFC 遵循情况与两处常见误解的澄清
//
//  1. RFC 9114 最终版的 HTTP/3 帧格式是 Type(varint) + Length(varint) +
//     Payload，**没有** HTTP/2 的 Flags 字节，也没有 END_HEADERS / END_STREAM
//     标志。HEADERS 的载荷就是一个完整的 QPACK encoded field section；请求
//     结束由 QUIC FIN（本包中的 Stream.Close()/CloseWrite()）表达。
//  2. QPACK 的「Set Dynamic Table Capacity」指令前缀是 '001'（3 bit），容量 0
//     编码为单字节 0x20，**不是** 0x3f 0x00。而且 RFC 9204 Section 3.2.3 规定：
//     当 SETTINGS_QPACK_MAX_TABLE_CAPACITY 为 0 时，encoder MUST NOT 在 encoder
//     stream 上发送任何指令；Section 4.2 还允许在不使用动态表时不创建该流。
//     本包声明的动态表容量为 0，且所有 field line 只用静态表和 literal，
//     因此**不打开** QPACK encoder/decoder stream，也**不发送**任何 encoder
//     stream 指令。这既符合 RFC，也与 quic-go 的 HTTP/3 实现互通。
//
// 关键静态表索引（RFC 9204 Appendix A，从 0 开始）：:method POST = 20，
// :scheme https = 23，:path "/" = 1，:authority（空值）= 0，:status 200 = 25。
//
// # 与真实 HTTP/3 服务端互通的诚实评估
//
// 本包生成的 HTTP/3 字节流（控制流 + SETTINGS、HEADERS 帧、QPACK 静态表与
// Huffman 编码、响应解码）在协议层面遵循 RFC 9114 / RFC 9204，设计与
// quic-go 的 HTTP/3 实现兼容：Hysteria2 服务端（基于 quic-go）应当能解码本包
// 发出的认证请求，并以 :status 233 回复。
//
// 但本包**不是**一个完整可独立联网的客户端：QUIC 传输（UDP、TLS 1.3、拥塞
// 控制、流复用、流控）以及 ALPN "h3" 协商都由调用方提供。只有在底层 Connection
// 是真正的 QUIC 连接、且 Stream 的 Close/CloseWrite 符合「只关发送方向」语义
// 时，才能与真实服务端互通；若底层是简化版仿 QUIC 流，则只能与本包相同的
// 简化服务端互通。包内单元测试使用 net.Pipe 模拟流，验证的是编解码与流程，
// 不构成对真实网络互通的证明。
package http3proto
