# AK Vector 可失败分配探测

仅为隔离实验，未引入正式依赖。SerenityOS 固定提交 `a9f9a0940618dc579d144826037a873aae846b54`，Linux x86_64、GCC 16.2.1，使用其原始 AK 头文件。最小探测的断言处理符是测试替身，触发时 `_Exit(90)`，并非 AK 的完整构建或生产错误策略。

```sh
g++ -std=c++26 -fno-exceptions -I<SERENITY_SOURCE> vector-probe.cpp \
  -Wl,--wrap=malloc -o vector-probe
./vector-probe
```

链接器包装仅拦截此测试目标直接调用的 `malloc`，依次注入首次插入、已有数据时扩容、填满时追加的分配失败，均得到 `ENOMEM`、原内容和容量保持，随后重试成功。

另有安全的容量溢出探测：以 `SIZE_MAX / sizeof(int) + 1` 请求容量，拦截分配并强制失败，观察到分配大小为零，表明该版本 `needed_capacity * sizeof(StorageType)` 在检查前已回绕。测试刻意拒绝分配，避免后续使用不足大小的缓冲区；这不是对实际写越界的运行验证。上游 `kmalloc_array` 内也有触发 `VERIFY` 的路径，非 `try` API 有 `MUST` 包装，均需在适配时处理；不能把 `try` 命名当作全面保证。

尚未构建 AK 完整库或验证模块接入、其他容器、非平凡元素、并发、多种分配器及正式调用链；该版本不能未经边界校验直接接入。必须处理增长、大小加法与字节乘法溢出并验证无终止行为，才能用于不抛异常、不直接 abort 的目标。

## 容量检查隔离原型

`vector-overflow-probe.patch` 对上述固定版本的实验副本增加容量加法、乘法和扩容余量检查，无法表示的大小返回 `EOVERFLOW`，接近上限时避免余量计算溢出；移动追加先检查并预留目标容量，避免失败时提前清空源容器。此补丁尚未进入正式依赖，也未声称覆盖 AK 所有 API 或平台。

```sh
patch -p1 -d <SERENITY_SOURCE> < vector-overflow-probe.patch
g++ -std=c++26 -fno-exceptions -I<SERENITY_SOURCE> vector-patched-probe.cpp \
  -Wl,--wrap=malloc -o vector-patched-probe
./vector-patched-probe
g++ -std=c++26 -fno-exceptions -DNEXUS_AK_PATCHED -I<SERENITY_SOURCE> vector-probe.cpp \
  -Wl,--wrap=malloc -o vector-regression
./vector-regression
```

GCC 16 测试覆盖容量乘法、追加/前置长度加法及增长上限，确认拒绝溢出前不调用 malloc；用受控分配失败测试余量接近上限的回退、移动追加失败后双方内容保持及成功重试，原有 ENOMEM 测试也通过。未验证全部重载、非平凡元素、别名、其他平台、AK 库和模块边界；其他 VERIFY/MUST、资源回滚与第三方调用仍须独立审查。

## 生命周期、别名与模块

`vector-lifetime-probe.cpp` 用不可复制、可移动的元素统计构造、移动和析构；GCC 16 `-fno-exceptions` 验证移动追加在分配失败后两边内容和存活数不变、随后重试和析构平衡。与上方补丁使用相同编译命令，将源文件改为此夹具即可。

`vector-alias-repro.cpp` 先填满 vector，再用其 `data()` 作为源执行 `try_append(pointer, 1)`。固定上游版本及仅应用容量检查补丁的版本在 GCC 16 AddressSanitizer 下均报告 heap-use-after-free：扩容释放原内存后仍从旧指针读取。以下命令为故意触发诊断的负向实验，预期进程失败；不应在生产中执行此调用：

```sh
g++ -std=c++26 -fno-exceptions -fsanitize=address -fno-omit-frame-pointer \
  -I<SERENITY_SOURCE> vector-alias-repro.cpp -o vector-alias-repro
./vector-alias-repro
```

这个测试只覆盖同一 vector 的指针追加触发扩容；其他别名形式和上游对该用法的契约还需核查。不能直接将该原型当作通用容器适配。

`module-probe.cppm` 和 `module-consumer.cpp` 在隔离目录编译 GCC 16 标准模块及 AK 私有模块：前者使用 global module fragment 包含 AK 头并 `import std`，对外只导出整数错误；后者通过链接器注入一次 malloc 失败，收到 `ENOMEM` 后正常重试。模块和消费者均以 `-fno-exceptions` 编译，AK 仍只使用头文件和测试断言替身；并非 xmake、完整 AK 或真实业务接入验证。以 GCC 16 安装的标准模块源文件路径为例：

```sh
g++ -std=c++26 -fmodules -fno-exceptions -x c++ -c /usr/include/c++/16/bits/std.cc -o std.o
g++ -std=c++26 -fmodules -fno-exceptions -I<SERENITY_SOURCE> -x c++ -c module-probe.cppm -o ak_probe.o
g++ -std=c++26 -fmodules -fno-exceptions -c module-consumer.cpp -o main.o
g++ main.o ak_probe.o std.o -Wl,--wrap=malloc -o module-probe
./module-probe
```

## 指针追加别名隔离原型

在容量检查补丁之后应用 `vector-alias-probe.patch`：对源指针指向当前有效元素的追加记录偏移，增长成功后按偏移重新定位；范围超出有效元素返回 `EINVAL`。`try_extend(ReadonlySpan)` 复用这一路径。此实验按 AK `FlatPtr` 的地址比较做识别，尚未验证所有架构及指针模型。

GCC 16 下原 ASan 复现不再报错；`vector-alias-probe.cpp` 验证自身子范围触发扩容、扩容失败后原数据不变和重试、无效范围拒绝及自身 span 跨扩容。容量和非平凡元素既有测试也通过。先应用容量补丁，再应用别名补丁；构建方式与前述一致，别名故障测试需链接 `-Wl,--wrap=malloc`。

这只处理指针追加与 span 扩展；单元素右值引用、前置、插入、其他类型或不合法指针等路径尚未验证或修复。生产接入前仍须审查别名契约、平台行为及 AK 的断言和其他容器。

另有独立 `xmake.lua`，在显式指定项目目录、隔离 `TMPDIR`、`XMAKE_GLOBALDIR` 与 `XMAKE_CONFIGDIR` 后，用 GCC 16 和 `-fno-exceptions` 构建私有 AK 模块与消费者。模块导入 `std`，分配失败返回 `ENOMEM` 后重试成功；仅证明该最小构建组合，未证明完整 AK 或正式工程依赖接入。必须显式传 `-P <此实验目录>`，避免 xmake 选择上级项目。

## AK 源码库构建

`library-build/CMakeLists.txt` 从固定版 AK 自身 CMake 源码清单选出 `.cpp`，生成 `AK/Debug.h`，在 Linux 用 GCC 16、C++26 和 `-fno-exceptions` 建静态库。它是独立实验构建，不是上游完整 Lagom 构建。应用前述两个实验补丁后：

```sh
cmake -S library-build -B /tmp/ak-library-build -DAK_ROOT=<SERENITY_SOURCE> -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/ak-library-build -j 4
/tmp/ak-library-build/vector-patched-probe
/tmp/ak-library-build/vector-alias-probe
```

两个测试链接真实 AK 静态库及其 `ak_verification_failed` 实现，而非测试断言替身；溢出、分配失败、移动追加和自身指针/跨度追加的已列场景通过。真实断言实现仍可能终止进程，此构建未消除 `VERIFY`、`MUST`、其他容器或其他平台的终止路径，不满足项目最终要求，也未接入生产。

## 自身右值追加隔离原型

`vector-rvalue-probe.patch` 在容量和指针别名补丁之后应用，令非引用元素的 `try_append(move(vector[i]))` 在扩容前记录源偏移，成功后从新存储中的对应元素移动。`vector-rvalue-probe.cpp` 用不可复制元素和 malloc 故障验证：失败时源值与对象数量不变；成功时追加元素接收源值、原元素处于其类型定义的已移动状态，最后所有对象被销毁。GCC 16 `-fno-exceptions`、AddressSanitizer 及链接真实 AK 静态库均通过；已有容量、指针/跨度别名和独立 xmake 模块回归也通过。

这只是 `try_append(T&&)` 的实验；`try_insert`、`try_prepend`、`try_empend` 的别名以及其他平台、异常元素、断言路径尚未处理。使用前必须按容量、指针别名、右值别名顺序应用三个补丁；实验仍未纳入项目正式依赖。

## 插入与前置隔离原型

在上述三个补丁之后应用 `vector-insert-probe.patch`：`try_insert` 对无效索引返回 `EINVAL`，对于类型相同的自身元素记录位置并在扩容、移位后重新定位；`try_prepend(pointer, count)` 也检查自身范围，在扩容和移位后重定位。非平凡元素的前置移位逐个移动并销毁旧对象，避免在仍存活对象上直接构造。

GCC 16 `-fno-exceptions`、AddressSanitizer 和真实 AK 库测试覆盖源元素位于插入位置前后、跨扩容、分配失败、无效索引/范围、非平凡元素的复制与移动及析构平衡，也验证简单引用元素插入。容量、先前别名及右值追加回归通过。

此补丁仍是 Linux 目标实验，使用 `FlatPtr` 检查地址；尚未涵盖 `try_empend` 的引用参数、`try_prepend(Vector&&)` 自身别名、不同但可转换的元素类型、其他平台、AK 断言以及其他容器。不得将此实验等同通用 AK 安全改造。构建真实库测试时，依次应用容量、指针追加、右值追加、插入前置四个补丁。
