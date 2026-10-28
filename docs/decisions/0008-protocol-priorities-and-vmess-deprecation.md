# 0008：协议优先级与旧协议范围

日期：2026-10-27。状态：协议优先级与排除范围已确定；具体实现和互操作均待验证。

## 决定

| 优先级 | 目标 |
| --- | --- |
| P0 | 自研 TUN、Shadowsocks 2022、VLESS/Reality、Mixed（SOCKS5/HTTP）、Direct/Block |
| P1 | WireGuard、MASQUE、Tailscale、Hysteria 2、AnyTLS、Trojan、HTTPUpgrade/gRPC |
| P2 | TUIC v5、ShadowTLS v3、Snell 等生态补充，具体范围待确认 |
| 不提供 | VMess、经典 Shadowsocks AEAD 和旧流加密版本 |

用户将 TUN、SS-2022 提升到核心梯队，WireGuard、MASQUE、Tailscale、AnyTLS 纳入扩展梯队，并明确排除 VMess 与旧版 Shadowsocks。VLESS/Reality 面向有伪装需求的网络，SS-2022 面向对固定密钥和性能特征合适的场景；MASQUE 与 Tailscale 作为双向 L3 隧道 Endpoint 分别覆盖 IETF 现代标准与私网 Mesh 组网；AnyTLS 面向 TCP+TLS 预热 0-RTT 极速场景；实际检测、吞吐和资源开销须测量，不能保证任何协议免于识别或主动探测。P0 是交付目标，不是已实现能力。

## 实现边界

SS-2022 计划覆盖 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`，逐项验证 TCP、UDP 和实际 EIH 组合。SIP022 的 Unix 时间戳与 TCP salt 保存、UDP 会话重放窗口共同作用，不能用“单调时间戳”或极小固定内存替代；BLAKE3 原语来源尚待核查，见[协议设计](../architecture/protocols/vless-trojan-ss.md)。拒绝经典 AEAD 是项目范围选择，不需要断言所有旧实现都有同样漏洞或缓存方案。

WireGuard 的 WARP profile 与 Tailscale、MASQUE 均作为独立拥有的 `Endpoint` 架构推进：WireGuard 验证对等链路、防环回与 MTU；Tailscale 接入自建 Headscale 与 DERP 中继回退；MASQUE 基于 HTTP/3 不可靠数据报（RFC 9221）承载 CONNECT-IP 与 CONNECT-UDP。AnyTLS 接入空闲 TLS 会话预热池（min_idle_session）与 UoT v2，默认置空客户端元数据以杜绝指纹收集。Hysteria 2 拟评估通用无 I/O QUIC/HTTP3 核心适配自研 TLS，Brutal 的接入尚未验证，也不等同恒速发送，见[Hysteria 2](../architecture/protocols/hysteria2.md)。

Reality、Vision、TLS、TUN 和网络配置属于独立验证边界；一个组合成功不代表任意组合或平台成功。初期可以先用更小的内存/静态转发实验建立生命周期与配置验证，再完成 P0 链路。协议和平台的具体兼容矩阵应随实现及实测证据更新。
