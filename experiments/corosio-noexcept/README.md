# Corosio io_uring 结果接口实验

此目录保存针对 Corosio `1f6e774b240c09f228d15d4a8e63cdaa3cc965a6` 和 Capy `158c009de04ca2af632c434d5b4f705f3f79a096` 的隔离原型，不是正式依赖补丁。`uring-result.patch` 增加 `io_context::try_create_uring()`，在 ring、唤醒 eventfd 或初次提交失败时返回系统错误，并由工厂销毁失败的 context。原有抛异常接口保留。固定版 Capy 的 `run_callbacks.hpp` 在 `-fno-exceptions` 下无法编译，`capy-probe.patch` 仅供这个不使用 `quitter` 的实验：非空异常指针在无异常模式终止，不能代表通用取消语义。

GCC 16/Linux 的实验中，更新后的 Corosio 静态库使用常规异常选项重新构建；`probe.cpp` 用 `-fno-exceptions` 和临时 Capy 头编译。注入 ring setup、eventfd 和首次 submit 的 `EPERM`，三种情况均返回错误，FD/线程数回到基线，随后创建新 context、执行协程、本地 socket 往返及取消挂起读成功。

`scheduler-probe.cpp` 直接构造同一个内部 scheduler，用链接器包装注入一次 `EPERM`。新的实验补丁以 mutex 串行化初始化，用原子标志提供成功后的快速路径；失败不缓存，下一个调用可以重试，保留原异常接口的错误位置描述。setup、eventfd、首次 submit 各自验证了两种调用顺序、成功后重复调用和 FD/线程回收；16 个线程混合调用异常接口和结果接口，注入一次 setup 失败，恰有一个调用失败、其他调用成功，后续调用不再初始化。成功时可因不支持可选 flag 多调用一次 setup。

复现需在已打补丁并以常规异常模式编译的 Corosio 和固定 Capy 上构建，例如将下列路径替换为对应的源码及静态库：

```sh
g++ -std=c++26 -pthread -DBOOST_COROSIO_HAVE_LIBURING=1 \
  -DBOOST_COROSIO_STATIC_LINK -DBOOST_CAPY_STATIC_LINK \
  -I<COROSIO_SOURCE>/include -I<CAPY_PREFIX>/include \
  scheduler-probe.cpp <COROSIO_BUILD>/libboost_corosio.a \
  <CAPY_PREFIX>/lib/libboost_capy.a -Wl,--wrap=io_uring_queue_init_params -Wl,--wrap=eventfd \
  -Wl,--wrap=io_uring_submit -luring -o scheduler-probe
./scheduler-probe
```

`thread-pool-probe.patch` 是另一个只针对 Linux/POSIX 的探索：用预留的稳定地址槽位和 `pthread_create` 获得直接返回的系统错误，首次创建失败时拒绝 post，部分创建成功时保留已启动线程，关闭时 join。`thread-pool-probe.cpp` 使用链接器包装创建和 join：GCC 16 `-fno-exceptions` 消费者验证首次 `EAGAIN` 后重试、第二个线程失败后部分启动、任务执行、关闭时等待在途任务并销毁排队任务、线程数回收，连续 20 次通过。夹具直接使用头文件中的 pool，并链接以异常模式构建的 Capy；不是完整 Corosio 无异常构建。

复现时将补丁应用到隔离的固定 Corosio 源码副本，以该副本头文件和固定 Capy 构建：

```sh
g++ -std=c++26 -fno-exceptions -pthread -DBOOST_COROSIO_STATIC_LINK \
  -DBOOST_CAPY_STATIC_LINK -I<COROSIO_SOURCE>/include -I<CAPY_PREFIX>/include \
  thread-pool-probe.cpp <CAPY_PREFIX>/lib/libboost_capy.a \
  -Wl,--wrap=pthread_create -Wl,--wrap=pthread_join -o thread-pool-probe
./thread-pool-probe
```

此补丁故意只供探测：零线程参数及 join 错误直接终止，未保持原构造器异常契约，也未实现其他平台；`vector::reserve` 的长度错误、mutex/条件变量、线程创建与 shutdown 竞争、join 故障、真实阻塞 DNS/文件调用及异常模式兼容均未验证。正式方案须保留可预期错误，不能以此补丁替代生产实现。

隔离 CMake 构建使用 GCC 16、C++26、liburing 2.15 和 `-fno-exceptions` 对整个 Corosio 静态库进行编译，未成功。编译器报告了 Capy `run_callbacks.hpp`、Corosio `detail/except.cpp`、IP 地址格式化、线程池、reactor、timer 和 `tcp_server` 等异常语法。线程池用 `std::thread` 启动工作线程并捕获 `system_error` 返回错误，不能将捕获替换为终止；timer 的异常清理和 `tcp_server::bind` 的错误返回也需保留。一次未显式设置 C++26 的实验还因本原型的 `std::expected` 接口在上游默认语言版本不可用而失败；正式方案须明确语言版本或提供兼容的结果类型。

局限：Corosio/Capy 库本身仍以异常模式编译；服务构造、后端运行期错误和资源分配等仍可能抛异常。混合接口竞争只注入 setup 失败；尚未覆盖并发多次故障、SQE 不可用、关闭竞态、选项、其他后端、异步停止或代理集成。`std::mutex::lock` 等仍可能报告异常，新的同步路径及成功快路径的性能也尚未评估。此原型不应直接用于生产，也不表明 Corosio 已支持无异常构建。
