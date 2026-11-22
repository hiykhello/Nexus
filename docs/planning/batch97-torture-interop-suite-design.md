# 第 97 批实现蓝图 · 复杂环境互通与弱网拷打套件

更新：2026-11-21。本蓝图承接第 96 批下一代性能引擎收官，利用多协议双向黑盒互通测试矩阵及 Linux `tc netem` 隔离命名空间弱网注入，对 Nexus 协议互通、弱网鲁棒性与长期稳定性进行高强度拷打。

## 97A · 双向全协议黑盒互通矩阵

- **核心覆盖矩阵（双方向：Nexus Client ↔ 外部协议服务端 & 外部协议客户端 ↔ Nexus Server）**：
  - **基础协议**：SOCKS5 TCP / 多目标 UDP NAT、HTTP CONNECT / Forward / TLS
  - **TLS / REALITY / ECH**：REALITY `X25519MLKEM768` + fallback、ECH / GREASE ECH / SNI 嗅探重放
  - **经典与现代协议**：Trojan、SS-2022（TCP / 原生 UDP / UoT）、ShadowTLS v3 + TFO
  - **VLESS 与现代 HTTP 承载**：TLS 1.2 / Vision / WebSocket / HTTPUpgrade / gRPC / XHTTP（`stream-one`、`packet-up`、`stream-up`，含 early data、半关闭、大帧与并发流）
  - **QUIC 与 L3 隧道**：Hysteria 2、TUIC v5、MASQUE、WireGuard 及 3 跳混合 detour 链
- **差异归档原则**：严格区分“协议级缺陷（必修）”与“刻意保持的安全语义边界（如拒绝弱算法或空认证，显式登记理由）”。

## 97B · Linux `tc netem` 隔离弱网与异常注入拷打

- 在独立网络命名空间通过 `tc netem` 注入：
  - 5% 丢包 + 35 ms ± 12 ms 抖动 + 0.1% 包损坏；
  - 15% 乱序 + 2% 重复包；
  - 1280 B MTU 黑洞与动态 PMTU 探测；
  - 并发 `SO_LINGER=0` 突发 RST + 周期性 `SIGHUP` 热重载 + `/metrics` 零活跃会话与零 FD 泄漏核验。

## 验收标准（已完成）

- `epoll` 与 `io_uring` 双后端全部 46/46 项互通与弱网拷打用例通过；
- 高压故障与热重载后 `/metrics` 活跃会话与进程 FD 精确归零。
