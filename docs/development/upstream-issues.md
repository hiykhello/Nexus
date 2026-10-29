# 上游问题与待调查现象

## 2026-10-28 上游升级复核

Capy 更新至 `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2`（项目包版本 `0.2.2`），Corosio 更新至 `70adbd5aff90569aac588e78a717fecbd5b7dedc`（项目包版本 `0.3.3`）。现有 CPO 与线程局部模块补丁在两个最新源码树上均通过 `git apply --check`。GCC 16、io_uring 隔离安装及 `nexus-io-test`、`nexus-proxy-test`、`nexus-udp-test` 均通过；尚未声称其他平台或完整全量回归。
与待调查现象

本文件记录 Nexus 实际遇到的依赖和工具链问题、复现范围、影响及处理。记录不等于已向上游提交 issue，也不预判责任归属。每次升级相关组件时复验并更新状态；只有确认上游跟踪地址后才填写链接。

## Capy run_async 启动帧分配失败

- 固定提交的 `run_async_wrapper` 构造函数标为 `noexcept`，但它先分配 trampoline；实际注入资源分配失败会调用 `std::terminate`，无法由代理的 accept 协程捕获。
- [项目补丁](../../3rdparty/packages/n/nexus-capy/run_async_startup.patch)移除该构造函数的 `noexcept`，使分配异常传播；Capy 项目包改为 `0.2.4`，Corosio 改为 `0.3.5`，上游提交不变。
- Linux/GCC 测试在真实代理登记会话后分别注入启动帧及根任务帧分配失败，单、双 worker 均验证连接和线程释放及重新启动；还覆盖登记后的直接异常。启动帧测试使用专门的内存资源，根任务帧测试依赖弱符号替换；尚未验证其他工具链或向上游报告。

## Capy when_all 启动时 runner 分配失败

- 固定提交的可变参数重载逐个创建并投递 runner；后续分配失败时，已投递的 runner 仍借用父状态。范围重载先创建再投递，但分配失败时未释放已创建的帧。任务悬挂包装器为 `noexcept`，启动异常直接传播还会终止进程。
- [项目补丁](../../3rdparty/packages/n/nexus-capy/when_all_startup.patch)先创建全部未绑定帧；失败时释放已有帧、保存异常并恢复 `when_all`，由它向调用者传递异常。全部创建成功才绑定和投递。Capy 包版本升至 `0.2.3`，Corosio 升至 `0.3.4` 以避免旧缓存；上游提交不变。
- Linux/GCC 测试对两个重载的三个 runner 分别注入分配失败，检查已分配帧释放、无子任务启动及异常经真实协程传到调用方；原实现的直接启动器测试在第二个分配失败时观察到未释放帧。正常完成、取消、子任务异常和 socket 上下文销毁在 epoll、io_uring 回归通过。尚未向上游报告；未验证其他工具链。

## Capy 匿名函数对象影响 Corosio 类型模块导出

- **状态**：固定版本可复现；项目内补丁及空缓存安装、GCC 构建和关键回归通过。尚未向上游报告。
- **环境**：Linux x86_64、GCC 16.2.1、C++26 modules；Capy `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2`，Corosio `70adbd5aff90569aac588e78a717fecbd5b7dedc`。
- **现象**：在 global module fragment 包含 `boost/corosio/tcp_socket.hpp`，以 `export namespace test { using ::boost::corosio::tcp_socket; }` 导出完整类型，GCC 报 `boost::capy::begin` / `end` 暴露 TU-local 匿名类型；Corosio `buffer_param` 引用这些对象。仅包含头文件而不导出该类型可编译。不能由此断言其他全部模块导出失败均有同一原因。
- **处理和证据**：在隔离副本中为 `begin`、`end`、`buffer_size`、`buffer_empty`、`buffer_copy`、`front` 使用具名函数对象类型和 `inline constexpr`；原报错消失。项目测试 `nexus-cpo-module-test` 的独立消费者通过命名模块导入 `tcp_socket`、构造并关闭 socket，调用六个缓冲区对象，编译、链接、运行成功。另在同一消费者中先包含普通头文件再导入模块，静态检查六种类型一致，并与另一头文件翻译单元比较六个对象地址，均通过。补丁见 [cpo_modules.patch](../../3rdparty/packages/n/nexus-capy/cpo_modules.patch)。这不证明 ABI、所有调用形式或所有编译器完全等价；对象的类型和跨翻译单元地址语义发生变化。为防止复用未修补缓存，Capy 项目包版本改为 `0.2.1`、依赖它的 Corosio 改为 `0.3.1`，上游提交不变；空缓存 recipe 安装确认补丁生效，Corosio 重建及 GCC 16 默认 epoll 全量构建通过；I/O、UDP、SOCKS 代理和解析器等关键回归通过。现有业务模块继续使用私有网络实现。
- **待办**：补充不同导入顺序及更多模块消费者测试；升级时检查上游是否已修复，再决定是否移除补丁。

## GCC 模块中 Corosio 线程局部变量重复定义

- 固定的 Corosio `1f6e774b240c09f228d15d4a8e63cdaa3cc965a6` 将 `thread_local_ptr<T>::ptr_` 定义在头文件中。GCC 16 在代理模块接口持有 Corosio 对象时，为同一实例在多个模块实现单元发出强定义，链接报重复符号；此现象不证明所有工具链或普通头文件用法均有问题。
- [补丁](../../3rdparty/packages/n/nexus-corosio/thread_local_modules.patch)将成员改为类内 `inline static` 并保持线程局部存储和初始空指针。项目包版本升级至 `0.3.2`，上游提交不变；重新安装包后，GCC 16/io_uring 代理及单、双 worker 回环和 VLESS 互操作通过。这是当前固定提交与模块构建组合的验证，尚未调查新版上游或其他编译器。

## GCC 扫描 Corosio io_uring 源码时内部错误

- **状态**：本机曾观察到 GCC 16 扫描相关源码时 ICE；最小独立复现与根因尚未确认，未向上游报告。
- **范围**：固定 Corosio `1f6e774b240c09f228d15d4a8e63cdaa3cc965a6` 的 CMake 构建，Linux x86_64、GCC 16。现有 recipe 对该上游 target 设置 `CMAKE_CXX_SCAN_FOR_MODULES=OFF`；其源码不含模块单元。项目自身模块扫描仍保留。
- **待办**：保存完整诊断与最小源码、精确编译命令和 GCC 构建版本，验证更新版本后再判断是否需要向 GCC 或构建系统报告。不能从此现象推断 io_uring 运行时故障。

## 增量构建的模块缓存不一致

- **状态**：待定位，不将其归责于特定上游；未报告。
- **环境和现象**：Linux x86_64，GCC 16.2.1、xmake `3.1.2+20261016`。修改 `nexus.udp` 接口后，对部分目标增量构建，随后全量增量构建下游 `nexus.udp.route` 消费者时报 `nexus.udp CRC mismatch`。强制全量重建成功。此前共享 xmake 全局目录的隔离副本也曾影响主工程的模块签名；两次现象的关系未证明。
- **处理**：`nexus.module_tracking` 将 target 自身和传递依赖的 `.cppm`/`.ixx` 源文件内容指纹加入编译参数，接口内容变化时保守重编译该 target；新增隔离回归 `uv run --no-project python tests/module_incremental.py`。在独立最小工程复现先构建模块后消费者未重编译且返回错误；启用规则后消费者重编译并通过，无改动再次构建不重编译。项目 DNS 模块的布局变更及恢复同样验证通过。
- **范围与待办**：规则只追踪构建图中的 `.cppm`/`.ixx` 源内容，不证明第三方头文件、生成接口、编译器内建模块或缓存污染均被覆盖；依赖图必须完整。接口中任意文本变化都会触发相关 target 重编译；升级 xmake 后应复核并考虑移除。继续隔离构建目录及 global/config，异常时强制重建。
