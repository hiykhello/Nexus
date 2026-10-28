# 0005：自研 HTTP/1.1 与 HTTPS

日期：2026-10-27。状态：方向已确定；HTTP/2 接入优先级已提高，核心依赖实验已开始。来源：用户追加要求。

## 决策

- HTTP/1.1 的解析、编码及连接状态由 Nexus 自研。
- HTTPS 使用自研 HTTP 与自研 TLS 的组合，client/server 共用分层能力。
- 后续若支持 HTTP/2，允许采用 libnghttp2 核心作为无网络 I/O 的协议引擎，由 Nexus 管理连接、TLS、协程和应用策略。
- HTTP/2 接入优先级提高，先验证固定 libnghttp2 的无 I/O 核心、模块边界和内存 client/server 驱动，再接 TLS ALPN、Corosio 和应用适配；在端到端验证前不通告 h2。

## 边界

HTTP/HTTPS 自研不自动包括通用 Web 服务器、缓存代理、透明 TLS 解密或 HTTP/3。通过 CONNECT 转发目标 HTTPS 与 Nexus 自己建立/终止 HTTPS 分别建模。密码原语来源继续独立决策，本记录不将 libcrypto 候选自动改为已采用。

协议核心与 OS、Corosio 驱动、应用用途分开。nghttp2 仅核心库进入未来依赖候选，不把其工具/示例的 TLS 和事件循环栈一并引入。

详细设计见 [HTTP 栈](../architecture/http.md)，验证见[网络路线](../planning/network-validation.md)。
