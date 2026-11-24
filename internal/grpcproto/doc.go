// Package grpcproto 提供仅依赖 Go 标准库的 gRPC 双向流传输层框架。
//
// # 重要兼容性声明（务必先读）
//
// 真实的 gRPC 双向流建立在 HTTP/2 之上：客户端先发 HEADERS，随后在 DATA 帧里
// 发送若干「gRPC 消息」（5 字节头：1 字节压缩标志 + 4 字节大端长度 + 载荷），
// 服务端同样以 HEADERS + DATA 回传，两个方向完全独立、可全双工并发。
// gRPC 还要求 HTTP/2 的 trailers（grpc-status 等）以及内容类型 application/grpc。
//
// Go 标准库没有导出 http2 包：HTTP/2 的实现藏在 net/http/internal/http2 里，
// 可被 net/http 内部使用，但无法被外部包直接构造一个「双向流」对象。
// 另一方面，net/http 的 Transport.ForceAttemptHTTP2（标准库字段，Go 1.13+）
// 在 HTTPS + ALPN 下会自动走标准库内置的 HTTP/2，无需 x/net/http2。
//
// 本包利用这一点，采用务实方案：
//
//   - 用 net/http 发起一个长连接 POST（io.Pipe 作为流式请求体），请求体里持续
//     写入 gRPC 消息帧，相当于客户端流；
//   - 响应用 io.ReadCloser 流式读取，按同样的帧格式解帧，相当于服务端流；
//   - 两个方向由独立的 io.Pipe / 响应体承载，因此可真正并发（full duplex）。
//   - 用 http.Transport.ForceAttemptHTTP2 = true 尽力启用标准库 HTTP/2。
//
// 本包实现的是 gRPC 的「线格式层 + 双向流语义」，Conn 把它包装成 net.Conn，
// 便于代理协议（VMess/VLESS/Trojan 等）像普通 TCP 连接一样读写。
//
// # 与真实 gRPC 服务端的兼容性（诚实说明）
//
//  1. 当 cfg.TLS = true 且对端支持 h2（ALPN）时，标准库 HTTP/2 会被启用，
//     此时本包的请求在传输层面接近真实 gRPC 客户端：POST + :path +
//     content-type: application/grpc + te: trailers，消息帧格式完全一致。
//     但真实 gRPC 服务端会额外校验 :method/:path/:authority、grpc-timeout、
//     grpc-encoding、grpc-accept-encoding 等头部，并在 HTTP/2 trailers 中返回
//     grpc-status/grpc-message。本包不解析 trailers，也不生成完整的 gRPC 元数据；
//     对一个严格实现的通用 gRPC 服务端，本包【不保证】能直接互通。
//  2. 当 cfg.TLS = false 且 cfg.H2C = true 时，本包使用自带的 h2c
//     (prior knowledge) 客户端：自行完成 HTTP/2 preface / SETTINGS 握手、
//     HPACK（含 Huffman 解码与动态表）、DATA 帧收发、流控、PING / SETTINGS ACK
//     以及 grpc-status trailers 解析。这使明文模式【可以】与真实 gRPC 服务端
//     互通，不需要 x/net/http2 或 grpc-go。
//     若 cfg.H2C 为 false（默认），则保持旧的 HTTP/1.1 流式 POST 行为，只能与
//     使用本包相同帧格式的自建服务端通信；此类服务端若要真正双向流，必须在
//     handler 中调用 http.NewResponseController(w).EnableFullDuplex() 并尽早
//     Flush 响应头。
//  3. 与真实 gRPC 的互通仍需要：正确的 ServiceName/Path（/pkg.Service/Method）、
//     服务端允许流式请求体、以及由调用方补齐所需元数据（如 grpc-timeout）。
//     DialH2C 也可直接调用，绕过 Config.H2C 开关。
//
// 不导入任何第三方包，特别是不导入 golang.org/x/* 与 google.golang.org/grpc。
package grpcproto
