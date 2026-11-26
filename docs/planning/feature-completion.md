# 功能完整度推进清单

本文维护协议、拨号字段、detour、流量路由与 DNS 专用规则的完整度边界；当前生产支持范围见 [支持矩阵](proxy-kernel-support-matrix.md) 与 [协议与内核演进蓝图](protocol-and-kernel-roadmap.md)。

## 协议和承载

| 范围 | 后续要求 |
| --- | --- |
| P0：Direct/Block、SOCKS5/Mixed、SS-2022、VLESS/Reality、TUN | 继续清点 client/server、TCP/UDP、认证、配置、DNS、路由、detour、错误和生命周期，关闭既有限制；不能将局部互通称为完整支持。 |
| Vision、UoT、XUDP 和协议组合 | 完成直通独立观测、会话/ID/换代、空包、链式出站、背压、取消和停止，保留帧边界和半关闭；分别说明对端限制。 |
| P1：WireGuard/WARP、MASQUE、Tailscale、Hysteria 2/QUIC、AnyTLS、Trojan、HTTPUpgrade、gRPC | 依决策 0008 逐项提供真实实现、配置、双端及互操作，复用通用流/数据报和 TLS；不以类型名或接受未执行字段代替能力。 |
| P2：TUIC v5、ShadowTLS v3、Snell | 保留原待确认范围，不擅自扩大或删除。VMess 与旧 SS 不在提供范围。 |

## 拨号和 detour

各协议须执行统一拨号契约，明确物理 socket、流承载层、DNS 和内层目标的归属，不能静默忽略或自动降级。

| 能力 | 当前状态与后续要求 |
| --- | --- |
| detour、依赖和环 | 生产 SS/VLESS、Hysteria 2、TUIC 和 MASQUE CONNECT-UDP 已接数据面 detour；具名 HTTP/3 支持代理数据报。继续其余协议组合、异常、上下文放弃和 Vision 直通证据。普通 CONNECT-IP 和独立 CONNECT-IP TUN 已接 Trojan UDP、Shadowsocks UoT 及具名 direct。独立 CONNECT-IP TUN 已验证两跳、下层具名解析及实际物理端点的路由覆盖检查。其余协议和组合继续按第 81 批推进。显式 direct 继承 direct 的 socket 配置。 |
| 连接期限 | direct TCP、SS/VLESS TCP、UoT/XUDP 已有一次绝对期限；所有协议、DNS、排队、候选/回退和取消都须共用完整预算。 |
| TCP 保活 | 已接入启停、idle/interval/count，双后端有真实 socket 和故障证据；继续默认、单协议及发布图。 |
| 接口、IPv4/IPv6 源地址、无端口绑定 | 已接通用物理TCP与各direct UDP适配；21100 io的111实际场景及双族/双backend组件通过，epoll/关闭图/最终验收继续，见[socket绑定](../development/socket-binding.md)。 |
| protect、routing mark、地址复用、netns | 通用mark/reuse已接且21100在隔离netns验证TCP/UDP双族实际mark路由、设置失败/恢复；第 71B 的 `netns` 与 `protect-path` 已在 epoll/io_uring 验证双栈 TCP、UDP、Hy2 Initial、拒绝及恢复。交付矩阵仍需覆盖其余出站及权限组合。 |
| TCP Fast Open、MPTCP | MPTCP 已接入物理 TCP 拨号，并有 direct 与 Trojan 的协商及回退证据；其他协议、故障、关闭图和多子流仍待验证。TCP Fast Open 已接 direct 预读首包及 SS-2022/Snell/Trojan/AnyTLS/VLESS 物理出站；其余路径、Vision 直通观察和完整故障验收仍待，须保留连接期限、首写及读先行语义，见 [接入边界](../development/tcp-fast-open.md)。不能以设置 socket 成功代替协议验收。 |
| UDP fragment、绑定和数据报选项 | 通用 fragment 配置、各 direct UDP 适配及 `udp-bind-port` 已接入物理 UDP/direct/Hy2，完成双族源地址、端口冲突、SS native/UoT 与 Hy2 Initial/stop 验证；原则见 [协议与策略组原则](../design-principles/protocols-and-groups.md)。 |
| Domain resolver 及选项 | bootstrap 只是子集；继续解析器选择、期限、地址策略、缓存/乐观缓存、TTL、ECS、视图和依赖。 |
| 网络选择和回退 | 第 71C 的系统网络快照及候选选择支持 strategy/type/fallback 和 TCP 等待上限，双后端验证双栈 TCP 回退、IPv6 UDP 首包同步失败回退与旧流保留。更多协议、权限及最终发布图另验。 |

## 流量和 DNS 规则

规则能力与设计原则见 [路由、DNS 与状态原则](../design-principles/routing-dns-and-state.md)。已有域名/IP/私有地址/地址族、端口/网络、来源、入站名和认证用户继续保留格式、首命中及三态 unknown；补全正则、嗅探协议、进程/用户/系统网络等类型与可靠数据源，不从远端来源猜测进程或身份。

DNS 要有独立问题与答复上下文：query type、ECS/DNSSEC、来源与网络，以及 rcode、answer/authority/additional、地址等响应条件。按真实 question 和答复阶段执行，不能在整次双栈解析前猜 qtype。保留 local search、hosts、bootstrap、TCP 回退、A/AAAA 规范名一致性、缓存剩余 TTL 和视图隔离。

当前内部地址解析已接入独立的域名/后缀与 query-type 首命中选择，TCP、SOCKS UDP 和 SS UDP 的分流、共享缓存及 local/搜索/在途快照均有网络实测证据，详见 [支持矩阵](proxy-kernel-support-matrix.md)。

接通真实有序动作：流量 route/options/bypass/reject/hijack-dns/sniff/resolve，DNS route/evaluate/respond/options/reject/predefined。参数、继续/终止、取消、预算、响应评估及缓存/合并键一起实现；现有纯核心和域名后缀选择不等于完整执行器。反查/FakeIP/嗅探的代次、歧义与重放见[路由元数据](../architecture/routing-metadata.md)。

规则集兼容/导入、远程更新和数据集须实际语义转换、资源上限、获取/校验/原子发布和失败保留；不能改变旧顶层顺序 OR，不能用无界正则回溯满足字段名。

## uTLS、HTTP client 和最终验收

继续自研 TLS + libcrypto，完整实现和验证 [uTLS](../architecture/utls-engine.md) 的指纹、扩展顺序、随机化、PSK/PQ 等；每个通告算法须能完成相应握手，现代/历史 profile 限制有真实依据。

[具名 HTTP client](../architecture/http-clients.md) 走内部连接器和 DNS/出口联合依赖，覆盖 HTTP/1/2/3 及回退、headers/TLS、全部拨号字段、窗口/并发、保活/期限、QUIC 包大小/PMTU、取消和背压，不以本机代理回环或单次 exchange 代替系统。

生产规则下载支持具名 DNS、TCP 代理出站、HTTP/1.1 和 HTTP/2，以及直连与代理链上的 HTTP/3。显式 HTTP/3 支持静态 ECH，`auto` 订阅支持同主机 Alt-Svc 和原期限内回退。周期刷新校验后原子发布文件，物理直连可跨轮复用连接。已支持热加载的代理入口通过 SIGHUP 取得流量和 DNS 规则代次，其余独立数据面及通用客户端能力继续按实施批次推进。

每个纵向切片验证配置、关闭/开启/组合图、双后端、真实网络及故障后更新支持矩阵。最终仍须共享 DNS 的资源/真实性能、协议与 feature 隔离、构建迁移、冷缓存/发布/打包、全面复核及原要求的提交。源码、锁文件、实际链接/运行产物和覆盖范围才是证据；局部绿色测试不能证明其余范围完成。
