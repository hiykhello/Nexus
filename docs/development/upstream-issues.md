# 上游问题与补丁边界

本文件记录 Nexus 当前工具链（Clang `llvm@23.1.6` + 静态 `libc++` + C++26 Modules）与固定上游依赖实际保留的补丁、复现背景及复验要点。每次升级相关组件时复验并更新状态；只有确认上游跟踪地址后才填写链接。

## 当前工具链与上游版本（2026-11）

- **编译器与标准库**：统一为 **Clang（`llvm@23.1.6`）+ 静态链接 `libc++` + C++26 Modules**（零 `-freflection`）。早期 Linux GCC 16 模块 ICE / CMI 读取顺序等历史工具链问题已随统一至 `llvm@23.1.6` 归档，不再影响当前构建。
- **Capy / Corosio 固定版本**：
  - Capy：`93e5f15ab964a64f80fa2d10e4860ae02319831f`（`0.2.9`）
  - Corosio：`bc952757610c8b80d82bf862af712f41ca6aca21`（`0.3.13`）
- **现保留上游补丁（共 3 项，经 `mcpp-pins.json` 与锁文件固定）**：
  1. [cpo_modules.patch](../../3rdparty/patches/capy/cpo_modules.patch)：将 Capy 缓冲 CPO（`begin`、`end`、`buffer_size`、`buffer_empty`、`buffer_copy`、`front`）改为具名函数对象类型与 `inline constexpr`，支持在 C++26 命名模块中导出而不暴露 TU-local 匿名类型。
  2. [thread_local_modules.patch](../../3rdparty/patches/corosio/thread_local_modules.patch)：将 Corosio `thread_local_ptr<T>::ptr_` 改为类内 `inline static`，避免跨模块实现单元链接重复定义。
  3. **空数据报修复**（`empty_datagram.patch` / 精确补丁）：移除 `uring_udp_socket::submit_send` 与 `uring_local_datagram_socket::submit_send` 在 0 字节 `iovec` 时跳过系统调用直接报成功的分支，使 `io_uring` 与 `epoll` 在 0 字节 UDP/local datagram 语义上保持一致。
- **已撤销并收敛的历史补丁**：`when_all_startup.patch`、`run_async_startup.patch`、`cold_allocation.patch`、`timeout_allocation.patch`、`persistent_timer.patch`（业务与测试中 `timer.cancel_wait()` 全部改用 Corosio `io::timeout` + `capy::async_event` + 截止时间重设检查）与 `cleanup_lifetime.patch`。

## 现存补丁的验证与升级复查要点

### 1. Capy 缓冲 CPO 模块导出（`cpo_modules.patch`）
- **背景**：在 global module fragment 包含 `boost/corosio/tcp_socket.hpp` 并经命名模块导出时，匿名类型的 CPO 会触发模块导出诊断。
- **验收**：独立模块消费者通过命名模块导入 `corosio`/`capy` 并验证 CPO 类型与跨翻译单元身份；升级 Capy 时先检查上游是否已具名化上述 CPO，再决定是否撤下补丁。

### 2. Corosio `thread_local_ptr` 类内定义（`thread_local_modules.patch`）
- **背景**：头文件中的非 `inline` 线程局部变量定义在多模块实现单元中可能引发重复符号。
- **验收**：补丁改为类内 `inline static` 并保持零初始化语义；升级 Corosio 时核对上游头文件是否已采用 `inline static`。

### 3. `io_uring` 零长度数据报发送语义
- **背景**：上游 `uring_udp_socket::submit_send` 与 `uring_local_datagram_socket::submit_send` 曾将空缓冲区提前完成为成功而不提交 `sendmsg`，导致 0 字节 UDP 包丢失或无效目的端口误报成功。
- **验收**：`epoll` 与 `io_uring` 双后端及双栈 UDP / local datagram 测试均验证实际空包送达与错误传播；协议驱动层保持 `std::nullopt`（无输出）与空载荷（实际 0 字节数据报）的区分。

### 4. 增量模块重建回归
- 当前工作区通过 `python3 tests/mcpp_module_incremental.py` 持续验证跨包修改模块接口、重导出布局与实现单元后的增量重建与空构建。
