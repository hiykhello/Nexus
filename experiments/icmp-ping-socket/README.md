# Linux ping socket 探测

运行 `python3 experiments/icmp-ping-socket/probe.py`。需要 Linux、用户和网络命名空间、`ip` 和 `sysctl`。脚本在独立网络命名空间启用回环，并仅在该命名空间将 `net.ipv4.ping_group_range` 设置为映射后的组 0；不修改宿主网络配置。

2026-10-29，本机 Linux 7.3.0-4-cachyos：IPv4 和 IPv6 的两个连接式 `SOCK_DGRAM` ping socket 均可向回环目标发送 Echo。每个 socket 的 `getsockname` 报告不同的内核标识符；即使请求填写 `0x1234`，回复中的标识符仍为内核分配值。两个序号和奇数长度 payload 均原样返回，独立计算的 IPv4 ICMP 及 IPv6 伪首部校验和有效。每种地址族各发送两次，仅验证本机回环及本次分配结果，不证明不同网络命名空间或所有 Linux 版本的标识符策略。

接入真实出口时不能直接把 socket 收到的标识符返回给 TUN 客户端。需要按客户端源地址、目的地址和原始标识符隔离流，将内核标识符与客户端标识符分开，并在返回包中恢复原始标识符；socket 的权限失败、流与在途请求上限、过期、路由策略、socket mark 和停止回收都须明确定义。成功发送后才可授权匹配回复，未知或已过期请求不得产生回复；不能仅凭 Echo 标识符视为认证。目标超时、ICMP 错误、并发、背压和拒绝服务行为尚未验证。真实出口尚未实现，当前探测不能说明外网可达或 TUN 已支持 ping。
