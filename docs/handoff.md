# 接手记录

更新日期：2026-10-28。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- 在 `f6762ff where:corosio.endpoint:export address factories and validate module boundary` 及 `5e2fa66 where:corosio.module:keep composed connect private until capy condition export` 中，Corosio Module 导出了 `make_endpoint`、`make_local_endpoint` 和格式识别；独立测试覆盖 IPv4/IPv6、缺省端口、非法输入、本地路径及路径长度。尝试导出组合 `connect` 时发现上游模板依赖未穿透 Module 的 Capy error-condition 特化，已撤回该公共导出并记录边界。隔离 GCC 16/io_uring 构建与运行通过。
- 在 `ff67327 where:capy.quitter:verify stop-aware owner unwind with async waker` 中，新增 `async_waker` 停止回归：Capy `quitter` 在 epoll/io_uring 下收到 stop 后执行 RAII unwind 并排空 owner。该证据限于无 socket 的等待器。
- 上一个窗口完成 Capy 0.2.2 / Corosio 0.3.3 升级收口：代理 accept loop 使用值返回 `tcp_acceptor::accept()`，`reuse_port` 使用 Corosio 选项 API，FakeIP TCP 夹具使用 acceptor 便捷构造；I/O、代理、UDP、VLESS、FakeIP chain、reuseport 和故障回归已有通过记录。

## 当前

- 工作区处于干净提交状态，当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 工作区保持干净；地址工厂正反例和无 socket 的 quitter owner unwind 已通过。组合 `connect` 尚未从 Module 导出，真实候选重试和 socket owner 取消仍未覆盖。
- HTTP/2 无 I/O 服务端、TLS/Corosio 握手和应用记录适配器仍保持上一步已验证状态；没有把未完成的 HTTP/2 客户端草稿留在树中。

## 下一步

1. 核对 Corosio/Capy 的 `io_context` stop/drain、真实 socket 取消和 owner unwind，补最小回归。
2. 评估 Capy condition 的 Module 导出边界，再验证组合 `connect` 的候选重试、失败回收和取消语义。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再用 `where:<功能块或位置>:<具体变更>` 提交，并更新本窗口，只保留新的上一步/当前/下一步。
