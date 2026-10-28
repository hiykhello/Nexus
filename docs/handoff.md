# 接手记录

更新日期：2026-10-28。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- 完成 Capy 0.2.2 / Corosio 0.3.3 升级后的收口。代理 accept loop 已使用值返回 `tcp_acceptor::accept()`；`reuse_port` 已使用 Corosio 选项 API；FakeIP TCP 夹具已使用 acceptor 便捷构造。GCC 16 的 io_uring/epoll 受影响目标、I/O、代理、UDP、VLESS、FakeIP chain、reuseport 和故障回归已有通过记录。
- 清除仓库生成的 `build/`、`.xmake/`、`gcm.cache/`、实验构建目录及旧的 `/tmp/nexus-*` 隔离产物，保留固定依赖源码/安装目录。
- 建立本地 Git 基线：`aa2e710 where:baseline`，随后以 `3ba538a where:handoff` 和 `8619ae7 where:handoff:document scoped commit convention` 记录 handoff 收口和提交主题约定。

## 当前

- 工作区处于干净提交状态，当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 已完成升级后 Corosio 地址工厂边界：`3rdparty/modules/corosio.cppm` 导出 `make_endpoint`、`make_local_endpoint`、格式识别和组合 `connect`；新增 `nexus-corosio-endpoint-test` 覆盖 IPv4/IPv6、缺省端口、非法输入、本地路径和路径长度。隔离 GCC 16/io_uring 目标构建及运行通过；尚未覆盖组合 `connect` 的真实候选重试。
- HTTP/2 无 I/O 服务端、TLS/Corosio 握手和应用记录适配器仍保持上一步已验证状态；没有把未完成的 HTTP/2 客户端草稿留在树中。

## 下一步

1. 提交本轮地址工厂 Module 和独立消费测试。
2. 继续核对 Corosio/Capy 的协程 owner unwind、`io_context` stop/drain、取消和 io_uring/epoll 对称性，补最小回归。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再用 `where:<功能块或位置>:<具体变更>` 提交，并更新本窗口，只保留新的上一步/当前/下一步。
