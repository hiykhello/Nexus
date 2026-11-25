# 上游问题与待调查现象

## 2026-11-25 上游升级与补丁收口（Capy / Corosio）

- **上游版本**：Capy 升级至 `93e5f15ab964a64f80fa2d10e4860ae02319831f`（`0.2.9`），Corosio 升级至 `bc952757610c8b80d82bf862af712f41ca6aca21`（`0.3.13`）。
- **现保留补丁（共 3 项）**：
  - [cpo_modules.patch](../../3rdparty/patches/capy/cpo_modules.patch)：Capy 缓冲 CPO 具名化以支持 C++ 模块导出。
  - [thread_local_modules.patch](../../3rdparty/patches/corosio/thread_local_modules.patch)：Corosio `thread_local_ptr` 改为类内 `inline static`。
  - **保留的功能修复**：`empty_datagram.patch`（`io_uring` UDP/local datagram 允许 0 字节 `sendmsg`）。
- **已撤销并适配的补丁**：`when_all_startup.patch`、`run_async_startup.patch`、`cold_allocation.patch`、`timeout_allocation.patch`、`persistent_timer.patch`（业务与测试中 `timer.cancel_wait()` 全部改用 Corosio `io::timeout` + `capy::async_event` + 截止时间重设检查）、`cleanup_lifetime.patch`。原为上述 OOM/构造/挂起抛异常补丁编写的独立测试目标与冷 OOM 注入轮次已清理或收敛为稳态零分配/正常恢复测试。

以下是上述补丁精简前的历史排查记录（仅供参考）：

## 2026-10-28 上游升级复核

Capy 更新至 `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2`（项目包版本 `0.2.2`），Corosio 更新至 `70adbd5aff90569aac588e78a717fecbd5b7dedc`（项目包版本 `0.3.3`）。现有 CPO 与线程局部模块补丁在两个最新源码树上均通过 `git apply --check`。GCC 16、io_uring 隔离安装及 `nexus-io-test`、`nexus-proxy-test`、`nexus-udp-test` 均通过；尚未声称其他平台或完整全量回归。
与待调查现象

本文件记录 Nexus 实际遇到的依赖和工具链问题、复现范围、影响及处理。记录不等于已向上游提交 issue，也不预判责任归属。每次升级相关组件时复验并更新状态；只有确认上游跟踪地址后才填写链接。

## Capy run_async 启动帧分配失败

- 固定提交的 `run_async_wrapper` 构造函数标为 `noexcept`，但它先分配 trampoline；实际注入资源分配失败会调用 `std::terminate`，无法由代理的 accept 协程捕获。
- 历史补丁 `run_async_startup.patch`（已于 2026-11-22 撤销）曾移除该构造函数的 `noexcept`，使分配异常传播。
- Linux/GCC 测试在真实代理登记会话后分别注入启动帧及根任务帧分配失败，单、双 worker 均验证连接和线程释放及重新启动；还覆盖登记后的直接异常。启动帧测试使用专门的内存资源，根任务帧测试依赖弱符号替换；尚未验证其他工具链或向上游报告。

## Capy when_all 启动时 runner 分配失败

- 固定提交的可变参数重载逐个创建并投递 runner；后续分配失败时，已投递的 runner 仍借用父状态。范围重载先创建再投递，但分配失败时未释放已创建的帧。任务悬挂包装器为 `noexcept`，启动异常直接传播还会终止进程。
- 历史补丁 `when_all_startup.patch`（已于 2026-11-22 撤销）曾先创建全部未绑定帧并在失败时清理回收。
- Linux/GCC 测试对两个重载的三个 runner 分别注入分配失败，检查已分配帧释放、无子任务启动及异常经真实协程传到调用方；原实现的直接启动器测试在第二个分配失败时观察到未释放帧。正常完成、取消、子任务异常和 socket 上下文销毁在 epoll、io_uring 回归通过。尚未向上游报告；未验证其他工具链。

## Capy 匿名函数对象影响 Corosio 类型模块导出

- **状态**：固定版本可复现；项目内补丁及空缓存安装、GCC 构建和关键回归通过。尚未向上游报告。
- **环境**：Linux x86_64、GCC 16.2.1、C++26 modules；Capy `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2`，Corosio `70adbd5aff90569aac588e78a717fecbd5b7dedc`。
- **现象**：在 global module fragment 包含 `boost/corosio/tcp_socket.hpp`，以 `export namespace test { using ::boost::corosio::tcp_socket; }` 导出完整类型，GCC 报 `boost::capy::begin` / `end` 暴露 TU-local 匿名类型；Corosio `buffer_param` 引用这些对象。仅包含头文件而不导出该类型可编译。不能由此断言其他全部模块导出失败均有同一原因。
- **处理和证据**：在隔离副本中为 `begin`、`end`、`buffer_size`、`buffer_empty`、`buffer_copy`、`front` 使用具名函数对象类型和 `inline constexpr`；原报错消失。项目测试 `nexus-cpo-module-test` 的独立消费者通过命名模块导入 `tcp_socket`、构造并关闭 socket，调用六个缓冲区对象，编译、链接、运行成功。另在同一消费者中先包含普通头文件再导入模块，静态检查六种类型一致，并与另一头文件翻译单元比较六个对象地址，均通过。补丁见 [cpo_modules.patch](../../3rdparty/patches/capy/cpo_modules.patch)。这不证明 ABI、所有调用形式或所有编译器完全等价；对象的类型和跨翻译单元地址语义发生变化。为防止复用未修补缓存，Capy 项目包版本改为 `0.2.1`、依赖它的 Corosio 改为 `0.3.1`，上游提交不变；空缓存 recipe 安装确认补丁生效，Corosio 重建及 GCC 16 默认 epoll 全量构建通过；I/O、UDP、SOCKS 代理和解析器等关键回归通过。现有业务模块继续使用私有网络实现。
- **待办**：补充不同导入顺序及更多模块消费者测试；升级时检查上游是否已修复，再决定是否移除补丁。

## GCC 模块中 Corosio 线程局部变量重复定义

- 固定的 Corosio `1f6e774b240c09f228d15d4a8e63cdaa3cc965a6` 将 `thread_local_ptr<T>::ptr_` 定义在头文件中。GCC 16 在代理模块接口持有 Corosio 对象时，为同一实例在多个模块实现单元发出强定义，链接报重复符号；此现象不证明所有工具链或普通头文件用法均有问题。
- [补丁](../../3rdparty/patches/corosio/thread_local_modules.patch)将成员改为类内 `inline static` 并保持线程局部存储和初始空指针。项目包版本升级至 `0.3.2`，上游提交不变；重新安装包后，GCC 16/io_uring 代理及单、双 worker 回环和 VLESS 互操作通过。这是当前固定提交与模块构建组合的验证，尚未调查新版上游或其他编译器。

## GCC 扫描 Corosio io_uring 源码时内部错误

- **状态**：本机曾观察到 GCC 16 扫描相关源码时 ICE；最小独立复现与根因尚未确认，未向上游报告。
- **范围**：固定 Corosio `1f6e774b240c09f228d15d4a8e63cdaa3cc965a6` 的 CMake 构建，Linux x86_64、GCC 16。现有 recipe 对该上游 target 设置 `CMAKE_CXX_SCAN_FOR_MODULES=OFF`；其源码不含模块单元。项目自身模块扫描仍保留。
- **待办**：保存完整诊断与最小源码、精确编译命令和 GCC 构建版本，验证更新版本后再判断是否需要向 GCC 或构建系统报告。不能从此现象推断 io_uring 运行时故障。

## 增量构建的模块缓存不一致

此前 Linux/GCC 16 的旧构建布局曾发生模块 CRC 不一致；强制全量重建后通过，根因未确认，不能归责于特定工具。当前 mcpp 工作区的独立回归 `python3 tests/mcpp_module_incremental.py` 验证跨包修改模块接口、重导出的布局及实现时的重建和空构建；依赖图不完整、第三方输入或其他工具链仍需分别验证。

## GCC Corosio application CMI cluster74读取顺序

2026-11-01，raw TLS提取后，纯TLS工作区的旧HTTPS夹具在GCC16.2.1报corosio_application cluster74 Bad file data/std::vector pendings。删除多余backend文本头并不能单独解决。使用同一CMI/精确编译参数的六个独立消费者，只有完整夹具先直接import corosio_application的变体编译成功，其余基线/先flight/Capy/crypto与最小消费者仍失败。最终只调整夹具的直接模块依赖顺序，81896正式构建成功，HTTPS七种响应framing在epoll/io_uring均通过；生产TLS布局/owner没有为此改动。失败源码、全部编译参数/日志和结果在home缓存2026-11-01/tls-bmi-debug，未清依赖缓存，尚未向上游报告，不据此认定其他Bad file data有同一根因。

## 冷分配中when_all/await_suspend的noexcept

2026-11-01，新通用UDP driver的完整普通/array/aligned C++new故障扫独立复现三处terminate：Capy when_all_core构造std::stop_source、Capy task forwarding await_suspend、Corosio timeout_coro forwarding await_suspend。PMR协程帧失败单独通过不能覆盖这些native/标准库分配。修复已通过immutable Capy0.2.5/Corosio0.3.6 recipe正式纳入：条件noexcept、timeout启动异常传播/未发布frame清理及allocator RAII；独立及正式150 freshprocess回归、旧when-all/CPO/allocation/crypto专图均通过。原安装身份和失败栈保留，未覆盖已安装包，未向上游报告。后续Corosio0.3.7只增持久timer cancel_wait API，三个已修generated头逐字不变；当前正式图继续验证。持久timer减少新driver每次expiry的timeout actor是独立成本/调度改动，不替代TLS/H2的异常传播修复。

随后第四个when_all逐runner投递SIGSEGV已核实为独立overlay取错base：临时复制raw upstream头覆盖了优先级更高的mcpp_generated/include有效头，重引入项目现有when_all_startup补丁已修的缺陷。该栈保留为实验错误证据，不能记作当前生产第四缺陷。代理已从有效generated头恢复，只叠加新noexcept修补后全量重验；原38/PMR/cold结果在其最终清单中必须标明输入版本。有效头的SHA和raw差别已存home缓存2026-11-01/effective-coro-headers.json。

## 持续分配失败时 context 析构仍可分配

2026-11-01，WireGuard hostname bootstrap 的逐次普通/array/aligned C++故障实测中，业务失败已join后，Corosio context 析构仍因 `object_pool::shutdown` 的 `vector::reserve` 抛出而terminate。原bin/source/hash/GDB保存在 `/tmp/nexus-wg-endpoint-active-20261101/evidence/cold-dns-failure42/` 和 `cold-dns-failure55/`。后者确认业务resolver已销毁，但reactor ready队列保留一个fd=-1/read_op=null/is_enqueued=true的descriptor引用；无work的run不处理该队列。该初始化路径已在join/reset owner后用原executor work guard及一次非阻塞poll释放引用，未更改第三方依赖；这是有序初始化清理的实证，不能外推成活动context放弃在持续OOM下安全。

主线程核固定Corosio0.3.7有效源码还发现 `uring_socket_service_base::shutdown` 的live vector，以及 `timer_service::shutdown` 的impls/waiters reserve同样存在。当前只读确认这些分配点，未以新实验声称每一处均已复现，未提交新的pool修补。后续需保留并发引用/回调锁与一次释放语义，联合验证活动socket/timer/acceptor及自然上下文放弃，再制定immutable新recipe；单修一个reserve不足以证明整个析构无分配。

后续在 Linux epoll/io_uring 活动 context 的持续 C++ 分配失败试验中，旧版本还在信号服务快照和文件工作线程占用 FD 时的延迟关闭路径终止。历史补丁 `cleanup_lifetime.patch`（已于 2026-11-22 撤销）曾用侵入式链表和预留 FD ledger 来规避此类关闭期 OOM。

该补丁已封装为不可变 Corosio 项目包 `0.3.9`，固定上游提交不变；归档、生成头和已安装源码审计通过，中央组合构建及对应运行回归正在进行。旧安装保留，尚未向上游提交问题。

## io_uring 将空数据报误报为发送成功

2026-11-01，通用数据报驱动的真实空包验证发现，固定 Corosio 提交的 `uring_udp_socket::submit_send` 和 `uring_local_datagram_socket::submit_send` 在 iovec 数量为零时绕过系统调用并返回成功。有效 0.3.7 对照中，UDP 发送回调已记成功，但接收方到期限仍未收到空包；无效 UDP 目的端口也被误报为成功。local datagram 的 connected/send_to 在空队列和实际填满至 EAGAIN 的队列上均复现，epoll 对照正常。

独立冻结修补只移除这两个发送路径的空缓冲提前完成分支，保留取消处理、接收路径及所有权。修补后的真实 UDP 12 场覆盖双族、双后端、发送失败与同 context 新 owner 恢复；local datagram 8 场另覆盖先提交、延迟 20ms 再消费 278 个已排队普通数据报，随后确实收到最后的空数据报。冻结证据位于 `/tmp/nexus-coro-empty-datagram-20261101`，原失败、有效输入 SHA、编译与链接命令均保留，未向上游报告。

主线程已独立验证固定 archive 加四个补丁与生成结果逐字相等，旧五个 generated 文件保持原字节。中央集成将使用新包身份 0.3.8；在正式构建与运行前，这些独立结果不表示中央 0.3.7 已修复。驱动的 `optional` 空值表示无输出，已存在且大小为零的输出表示一个实际空数据报，两者保持区别。
