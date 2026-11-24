# 代码文件行数规范

状态：项目代码规范。适用于 Nexus 手写的 C/C++、C++ Modules、Kotlin、Swift、Slint、TypeScript、构建脚本和辅助脚本；第三方原始源码、生成文件与文档不属于本限制。文件以**物理行**计数，包括空行和注释；末行即使没有换行也计一行。

- 以每个文件不超过 **300 行**为日常目标；超过时检查是否能按职责、公共接口/实现或独立测试场景自然拆分。
- 手写代码文件上限 **500 行**。确实存在紧密耦合且拆分会明显损害可维护性的例外时，记录具体文件、原因和复核日期，并在检查脚本中显式放行；不要为了达标删除注释、压缩语句或把单一职责机械切碎。
- 保持公开接口小而稳定，优先按模块职责组织；小文件不是目的，也不因固定行数制造额外模块、间接调用或循环依赖。
- 在项目根目录运行 `scripts/check-source-lines.sh` 检查已纳入范围的手写源码；当前保留以下 8 项历史超限例外（`src/` 核心代码已全部清零，严格 ≤ 500 行）。文件大小检查不替代代码审查、复杂度分析或测试。

## 例外记录

| 文件路径 | 说明与原因 | 复核日期 |
| --- | --- | --- |
| `tests/config.cpp` | 配置解析全量 schema 边界单测集 | 2026-11-22 |
| `tests/dns_message.cpp` | DNS 报文编解码与压缩指针单测集 | 2026-11-22 |
| `tests/http2/http2_server.cpp` | HTTP/2 服务端行为集成单测 | 2026-11-22 |
| `tests/http2/http2_tls_backpressure.cpp` | HTTP/2 over TLS 背压边界测试 | 2026-11-22 |
| `experiments/dns-shared-cache/group_shared_capacity_test.cpp` | 共享缓存容量与淘汰实验测试 | 2026-11-22 |
| `experiments/dns-shared-cache/group_singleflight_test.cpp` | 单飞合并并发竞态实验测试 | 2026-11-22 |
| `experiments/dns-shared-cache/group_snapshot_test.cpp` | 快照发布与生命周期实验测试 | 2026-11-22 |
| `experiments/dns-shared-cache/proxy_group_bench.py` | 共享缓存吞吐实验压测驱动 | 2026-11-22 |
