# mcpp 构建迁移

**历史记录**：本文记录早期验证及已废弃的临时构建布局，所列命令、路径和生成器不再是当前入口。现行步骤与覆盖范围见 [mcpp 工作区](mcpp-workspace.md)。工作区特定成员的条件导入曾经通过真实构建验证；不应将早期配置错误归咎于工具。

## 当前工作区入口（2026-10-30）

现在使用根 `mcpp.toml` 声明的工作区：根包装配命令行程序，其他成员分别提供代理、协议、策略、DNS、密码及协议和 DNS 测试。生产功能由 feature 选择，默认启用 io_uring；例如：

```sh
MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked --home /tmp/nexus-mcpp-host-home \
  build --target x86_64-linux-gnu --strict --features crypto,vless -j 1
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked --home /tmp/nexus-mcpp-host-home \
  test -p nexus.protocol-tests --target x86_64-linux-gnu --strict
```

以 mcpp 2026.10.31.1、GCC 16.2.1 和系统根 `/`，默认图与 `crypto,vless` 图均已离线锁定构建，切换时使用同一锁文件；工作区联合构建通过。实际编译记录中加密源码属于 `nexus.crypto`，代理源码启用 VLESS 宏，程序不动态链接系统 libcrypto。协议测试成员的 18 项已通过；工作区产物与独立互通对端的 Reality 双向传输、并发关闭及错误身份拒绝通过。这些验证复用本机已安装依赖，不代表冷缓存、release 或其他平台已验证。

下文保留迁移过程的历史记录；其中 `mcpp/crypto`、`mcpp/shadowsocks` 和其他生成式子包的结果属于旧配置与旧工具版本，不能作为当前工作区的验收结果，也不再作为新的架构入口。原 xmake 构建文件已按用户要求移除；Shadowsocks、HTTP/2、TUN 及其网络和故障夹具仍需在真实工作区中按职责迁移并验证。当前仅承诺 Linux x86-64。

## 基准与范围

以下历史基准依据 [mcpp 使用 skill](https://github.com/mcpp-community/mcpp/blob/9c65437a67d7717753e5055bf24cc5c013e6e82b/.agents/skills/mcpp-usage/SKILL.md) 和同一提交的 [docs](https://github.com/mcpp-community/mcpp/tree/9c65437a67d7717753e5055bf24cc5c013e6e82b/docs)，使用 `mcpp 2026.10.30.1`；文档快照提交为 `9c65437a67d7717753e5055bf24cc5c013e6e82b`。版本升级时应重新核对文档、命令行行为及构建结果，不以浮动 `main` 代替验证记录。

迁移范围包括 Linux 正式程序、其 C++26 命名模块和第三方模块封装、可选协议与平台后端、测试和互操作夹具，以及当前实验目标。先建立能验证的基础图，再逐步覆盖所有目标；尚未迁移的目标继续由原构建提供。既有源码改动、补丁和 `xmake-requires.lock` 不能因迁移被覆盖或丢弃。

上游文档按用途分为：`00–03` 的概念、入门、场景和示例；`04–08` 的 manifest、依赖、feature、workspace 和测试；`09–12` 的命令、打包、发布与二进制分发；`20–25` 的工具链、目标三元组、target side、项目环境、交叉环境和本地仓库；`30–35` 的构建程序、规则与平台包；`40–42` 的裸机、设备和异构构建；`50–52` 的机器输出、版本与程序调用；`90–92` 的源码构建、工具链内部和发布。`docs/specs/` 是构建数据库、构建插件、并发、manifest、包身份和工具链等更具体的契约；`docs/zh/` 是正文的中文对应版。当前 Linux 主机构建首先受 `04–08`、`20–23`、`30`、`50` 及相关 specs 约束；交叉、设备和发布能力仍须在真正迁移对应目标时验证。

已分段通读该提交的英文和中文正文、`docs/specs/` 及资源文件。文档并非所有段落都同步：例如英文 `12` 对公开接口可达的实现分区一处称拒绝打包，另一处称会发布源码并告警；`24` 对缺失接口的 capability 数据也有相反表述。涉及这些功能时应对照此提交的实现和实测，不能把两种说法同时视为保证。构建目录指纹与缓存布局不属于上游稳定接口，自动化应从实际构建结果定位产物，不依赖本文记录的示例指纹。

## 已确认的语义

- 一个构建图采用根包的 C++ 标准；标准和改变标准库声明的 dialect flags 进入标准模块 BMI 的身份。保持 `c++26`，并实测一个图是否只生成一份可复用的 `std` BMI。不能仅以“支持 `import std`”推断增量重建正确。
- `[build].sources` 明确限制编译单元，省略时默认遍历 `src/`；显式 `[]` 才表示没有源码。`module_extensions` 可增加 `.ixx` 等接口扩展。每个被选择的源必须进入产物；不能让整个 `src/` 的实验和可选实现被默认 glob 意外编译或链接。
- 同一包中的共享源只编译一次；`[targets.*]` 的宏和编译选项只作用于各自的入口文件。需要对共享实现使用不同宏、链接器 `--wrap` 或源码组合的测试，须单独配置包/构建图；不能假设目标级选项会重新编译共享实现。
- feature 是加法并集，可门控源码、宏和依赖；根包默认 feature 由 manifest 决定，CLI 没有关闭根默认 feature 的选项。切换 `crypto`、`ss2022`、`http2`、`io_uring` 时需确认目标闭包、ABI 与不同图的缓存隔离；`ss2022` 的生产代理路径还要求 `crypto`。
- 默认 `mcpp test` 将每个 `tests/**/*.cpp` 当作单源独立程序。Nexus 包含辅助源、多源 fixture、不同故障宏、依赖外部服务/权限及 Python 驱动；必须显式选择和建模，不能把自动发现通过当作全套测试通过。
- 模块扫描默认不展开 `#include`；位于头文件里的 import 不自动形成扫描边。需要审查现有私有头中的条件 import、真实依赖和头文件修改后增量构建；必要时拆分或使用受编译器扫描校验的 `scan_overrides`。第三方 API 继续通过项目命名模块封装，逐步减少直接包含。
- `build.mcpp` 在规划期声明输入、flags 和构建动作；外部构建和生成应成为有输入输出的 action，不应在规划阶段悄悄下载或构建。必须对补丁、工具及环境变量登记增量依赖。

## 本机工具链和 target base

用户已确认使用 `/usr/bin/g++` 16.2.1 和系统根 `/`。上游不接受 `gcc@system` 或从 PATH 隐式选择 GCC；支持用 manifest 指定安装树、family 与驱动，并以 `glibc@system` 指定系统根。`{ path = "/" }` 在文档中与 `glibc@system` 等价；系统根的产物依赖本机 libc 和工具链，不能视为跨机器可复现的独立 SDK。

`--toolchain path:/usr` **不能用于本机选择 GCC**：`/usr/bin` 同时存在 Clang 和 GCC，mcpp 2026.10.30.1 优先识别 Clang，已实测启动了 `/usr/bin/clang++`。应使用明确的 manifest 声明，并且不要在命令行再用 `--toolchain path:/usr` 覆盖它：

```toml
[toolchain]
default = { path = "/usr", family = "gcc", tools = { cc = "/usr/bin/gcc", cxx = "/usr/bin/g++" } }

[target.x86_64-linux-gnu]
sysroot = "glibc@system"
```

隔离环境以此声明实际编译并运行了一个 `import std` 的跨模块程序；修改导出接口及其包含的头文件分别使接口和导入者重编译，输出随之改变，随后空构建没有工作。日志中的编译和链接命令均指向 `/usr/bin/g++` 与 `--sysroot=/`，`std` BMI 从该图的缓存暂存。mcpp 输出的编译器版本行显示 `20260810`，而驱动自身报告 GCC 16.2.1；记录两者，不把显示结果当成版本检测已正确。此小样本不代替 Nexus 全图验证。命令使用 `--offline` 禁止索引刷新、依赖或工具链下载，并限制并发：

```sh
mcpp --offline build --target x86_64-linux-gnu -j 1
```

空的 mcpp home 首次 `--offline` 构建会因 xlings 环境未初始化而失败。隔离初始化在 `/tmp/nexus-mcpp-host-home` 安装了 mcpp 所需的 patchelf 0.18.0 和 Ninja 1.12.1；后者自动下载超时后以原 recipe 中固定 SHA-256 校验的官方归档填入该临时环境的下载缓存。没有安装其他编译器。构建程序或依赖需要其他工具时，应显式记录来源和版本；缺失时失败，不静默改用 mcpp 私有工具链或其他编译器。上述工具链是本机验证设置，不能误称为所有平台默认值。

## 依赖及配置对照

源码依赖的最终迁移方式（mcpp 包、项目维护的包或构建 action）须逐一验证并锁定，不能直接使用 xmake 缓存作为可复现的交付方案。原 recipe、补丁和版本是对照基准：

| 依赖 | 固定来源 | 边界 |
| --- | --- | --- |
| Glaze KDL | `fc646588635c42cca142562d7b3d0484cc4493b7` | 指定 fork 的 KDL/BEVE，头文件经 Nexus 模块导出 |
| ngcpp/proxy | `9d9749d63766cdd9affb5ea7953237e38ce5ab63` | 原生 `proxy.v4` `.ixx` 接口 |
| Capy | `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2` | 保留 CPO、`when_all`、`run_async` 三个本地补丁与静态库配置 |
| Corosio | `70adbd5aff90569aac588e78a717fecbd5b7dedc` | 保留 thread-local 补丁和同一 Capy；无 TLS provider，可选系统 liburing |
| BoringSSL | `e651545da6e26e1f4420723a3b69a78ed1b9c51d` | `crypto` feature 只构建 libcrypto，不引入 libssl 或其他 TLS provider |
| BLAKE3 | `b97a24f8754819755ef78d8016c0391c65c943c5` | `ss2022` 可选，现为 portable 静态构建 |
| nghttp2 | v1.70.0，归档 SHA-256 `e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2` | `http2` 可选，仅核心库 |

Linux 的线程和 liburing 属于系统能力，应明确检测及链接，不以浮动下载的源码副本静默替换。根 `xmake.lua` 的 `crypto`、`ss2022`、`http2` 默认关闭，`io_uring` 默认开启；recipe 自身的 Corosio `uring` 默认值不同，迁移应按根配置和实际生成图核对，而不是只看 recipe 默认值。

## 验证及切换条件

1. 在隔离目录验证指定 host 工具链与系统根、`import std`、跨模块链接和接口/头文件变更后的增量依赖；记录实际命令、编译器和 BMI。
2. 迁移正式 Linux 图，明确源码列表、依赖、宏、链接参数与可选 feature；干净构建并核对最终链接及依赖来源。复制检出和禁网重建也要验证，缺失依赖必须明确失败。
3. 迁移单元测试、故障注入、多源 fixture 和 Python 驱动；逐项对照原测试清单，分别验证 feature 关闭与开启、增量修改和不同配置切换。运行 TLS、Reality/Vision、UoT、代理与网络等现有互操作测试时保留其固定对端版本和权限要求。
4. 审查其他平台、其他编译器、安装与发布能力，并明确记录未验证范围。用户已确定本轮移除旧入口的验收范围为 Linux x86-64；在该范围的迁移图、真实互操作及增量验证覆盖原构建后，才移除旧入口。其他平台不因此视为已支持。

性能基准按已有约束避免与其他高负载并行；构建成功或小流量 smoke 不代表性能和资源目标满足。

## 当前落地状态

根 `mcpp.toml` 现可构建 Linux Nexus 程序的默认图：SOCKS5 TCP/UDP、DNS、规则、HTTP/1 和命令行，以及已选的协议核心；可选协议使用下文的独立配置，其他测试和实验目标仍在迁移。以本机工具链、系统根、`--offline --locked`、`MCPP_VERIFY_MODGRAPH=1` 和单并发完成构建，显式选择的 25 个单元测试通过，包括代理并发、DNS、规则和协议测试；这不是全项目回归。当前版本的 `mcpp test` 命令行不接受 `-j`，故用 `MCPP_JOBS=1` 限制并发。实际程序的配置、规则、多个监听器、两 worker、SOCKS UDP、HTTP 转发和双栈 DNS 缓存/回退测试通过。

测试自动化需要检查实际执行状态，而不只统计构建出的二进制。固定上游版本的 `src/build/execute.cppm` 在有测试失败时返回 1，测试构建成功但无法执行时返回 2；`--no-run` 是单独的仅构建状态。工作空间达到总超时时也可能返回 1，返回码 2 还可表示其他命令或配置错误，因此应结合测试状态与诊断判断，不能将二者都写成“测试失败”或“测试通过”。

根图扩充后，release 模式以同一工具链及 P1689 审计通过 **31/31** 所选测试，构建数据库确认 `-O2 -DNDEBUG`；Vision 测试主动保留断言，确保 release 下检查和状态推进仍执行。实际 release 程序的配置、多监听器、双 worker、SOCKS UDP、HTTP 和完整 DNS 网络回归通过，后续离线锁定构建无工作。当前结果只覆盖本机 x86-64、默认功能与所选测试。

根 manifest 的 `[pack] include = ["docs/**"]` 使系统模式包携带 README 引用的文档。重新以 `mcpp pack nexus --mode system --pkg-format tar` 生成并解压 release 包，清单中 89 个文件的 SHA-256、README 与文档导航的链接均已核对；包内启动脚本与示例配置成功监听，配置、多个入站和 SOCKS UDP 网络测试通过。ELF 使用 `/lib64/ld-linux-x86-64.so.2`，无 RPATH/RUNPATH，动态依赖系统 `liburing.so.2`、`libm.so.6`、`libgcc_s.so.1`、`libc.so.6` 与加载器；程序最高直接要求 `GLIBC_2.38`。`HOST-REQUIREMENTS` 未列出系统 liburing，补充说明见[运行包说明](runtime-package.md)。这些是此主机系统模式结果，不代表其他机器或自包含分发已验证。目录格式实测即使 `-o /tmp/<name>` 也写到 `target/dist/<name>`；tar 格式则写到指定绝对路径。crypto/SS 生成配置包含同一打包规则，但尚未验证其打包结果。

CLI 使用 C++26 反射。只在入口源加 `-freflection` 时，GCC 拒绝同时导入未使用该方言构建的 `std` BMI；因此在 `[build].dialect_cxxflags` 中指定该选项，使同一构建图中的标准模块和所有编译单元一致。当前五个带条件 import 的服务器源使用只适用于默认配置的 `scan_overrides`，编译器 P1689 扫描会核对声明；启用新增功能或测试宏之前必须提供与该配置一致的模块图，不能将当前声明视为所有配置通用。

项目内 `3rdparty/mcpp-index` 对 Glaze 的固定提交归档指定 SHA-256 `f238db70dee9ef25d0898a0da062209453225832d0d82f10d1fb11037c81ef3b`，以项目已有的命名模块导出接口；试验时先将已校验的归档放进隔离项目缓存，再由 mcpp 安装。项目自身的 `.mcpp/` 是本地索引缓存并已忽略，`mcpp.lock` 保留；锁文件提示 index 依赖仍按版本约束重新解析，因此还须保留精确版本与 descriptor 的内容校验，不能仅靠锁文件断言源码字节固定。

### 代理与网络依赖

为逐项核对迁移范围，`docs/build/xmake-targets-linux-crypto-ss2022.json` 保存了本机 Linux x86-64、release、`crypto`/`ss2022`/`io_uring` 开启、`http2` 关闭时 xmake 解析出的 501 个目标及其源码、直接依赖、宏和选项。它是该配置的一次快照，不包含其他配置才会出现的目标，也不保存目标运行结果。`python3 scripts/capture-xmake-targets.py --output <path>` 可在另一配置生成独立快照；在已确认覆盖前不要覆盖现有快照。

`docs/build/xmake-targets-linux-crypto-ss2022-http2.json` 是在上述配置基础上临时将 HTTP/2 设为开启后枚举的 511 个目标；新增十个 HTTP/2 目标，其他目标元数据未变。使用 `--simulate-http2 --output <独立路径>` 只在枚举进程的内存中覆盖该选项，文件明确标记此方式；实测保存的 xmake 配置及 lock 哈希均未改变。此快照只用于目标清单，不代表使用该配置重新执行过 xmake 的配置、依赖安装或构建。

`docs/build/xmake-targets-windows-x64-inventory.json` 是用 `--simulate-windows --output <独立路径>` 在内存中枚举的 107 个 Windows x64 目标，关闭 crypto、SS2022、HTTP/2 和 io_uring。所有名称及源文件也出现在上述 Linux 快照中，但 Windows 的规则、配置和 HTTP 核心额外声明 `ws2_32`。这只是原清单的静态范围，未安装 Windows 工具链或构建和运行 Windows 目标；mcpp 的 Glaze 描述符目前只有 Linux 发布项，本轮各构建图也只在 Linux x86-64 验证，不能据源码提及宣称 Windows 构建已迁移。枚举后原 Linux 快照、已保存的 xmake 配置和锁文件字节不变。

`python3 scripts/mcpp-audit-targets.py` 根据源码路径列出当前没有完整源码匹配的目标，`--target <name>` 查询单项，`--snapshot <path>` 选择其他快照。匹配仅表示某个清单提到了同一组源文件，可能属于未启用的 feature 或需要专门驱动的夹具；脚本不验证依赖、宏、链接选项和测试，也可能漏掉由多个包组合的图。每项仍须人工核验配置与实际结果，不能把匹配数当成迁移完成数。

`ngcpp/proxy` 的固定归档 SHA-256 为 `21eecb3fef4d36055e030600c939465c4239516f8629051e7ea9ee68dd42dd3b`。当前 mcpp 的 Form B 描述符不接受 `module_extensions`，GCC 也不允许从 `#include` 引入模块控制行，因此描述符将原 `proxy.ixx` 字节逐字保存为生成的 `.cppm`；原接口 SHA-256 为 `91d957186597e0ae20178230789305c7f51de46c5bd0b499c538176479115538`。真实 `proxy.v4` 导入和类型擦除调用已通过。隔离试验中，以 `--cache=local` 修改其底层头文件使模块和消费者重建；默认全局缓存将索引包视作不可变源，手改已安装包不能作为重建验证。

`3rdparty/mcpp-pins.json` 独立保存七个依赖的版本、提交或发布版本、归档地址与 SHA-256；`3rdparty/patches/` 保存三项 Capy 补丁和 Corosio 的 thread-local 补丁。它们与原 xmake 配方和补丁逐一对照一致；迁移期间原 xmake 仍使用自己的补丁副本，若修改补丁需同步维护两份。`tests/mcpp_pinned_deps.py` 只读本地归档：校验七个 SHA-256、描述符 pin、补丁 SHA-256 与打补丁后的 Capy/Corosio 接口、proxy 接口，以及 Glaze 头文件、BLAKE3 portable CMake 配置和 BoringSSL/nghttp2 生成源码清单。Corosio 的被补丁头文件在归档中为 CRLF，检查时先转换为 LF，与原补丁对应。

根配置及由其生成的 crypto/SS 和部分故障、实验配置编译 `src/build/mcpp_pinned_guard.cpp`，用 C++26 `#embed` 和编译期 FNV-1a 检测 pin 表、七个描述符、四份补丁及相关校验脚本的意外漂移。`python3 scripts/mcpp-generate-pinned-guard.py` 先执行上述离线归档和快照校验，再更新 guard；`--check` 验证 guard 是否最新。再生或检查 guard 需要全部七份归档，可用 `--cache <目录>` 指定位置；正常构建仅需已纳入项目的输入。修改 pin 或补丁时应先更新快照、完成代码审查，再运行生成器。隔离构建测试已验证补丁及 BLAKE3 描述符变更会使增量构建失败，恢复后重建并得到空构建。

`python3 scripts/mcpp-verify-installed.py` 是显式离线缓存审计：对照校验过的归档检查七个已安装源码树的文件、权限、符号链接和额外项，并比较已安装描述符及生成文件；`--cache` 和 `--installed` 可指定位置，末尾可选包名限定范围。本机七包审计通过；隔离副本中源码、额外文件、权限、符号链接、生成文件和安装描述符六种变更均被拒绝。该脚本不修改缓存，也不会在每次构建自动运行。

FNV-1a 不是安全摘要，这个 guard 只检测通常增量构建中的意外漂移，不能证明文件未被蓄意篡改，也不自动检查已安装缓存；显式缓存审计只反映执行时刻，不覆盖系统 liburing、工具链、sysroot 或其他构建图。归档 SHA-256、代码审查、冷缓存及其余配置验证仍不可省略。

GCC 16 在编译 Corosio 的 io_uring 非模块源码时对 `-fmodules` 发生内部错误；描述符仅为这些无 import 的源码加 `-fno-modules`，项目自己的 Capy/Corosio 封装仍作为命名模块编译。根配置按原构建默认启用 `io-uring`，路径包 `3rdparty/mcpp-uring` 检查系统头文件的最低版本并链接系统 liburing；缺少能力提供者会在规划时失败。根默认 feature 在当前 mcpp 无命令行关闭选项：`mcpp/epoll` 通过 `default-features = false` 依赖 Nexus，并使用 Nexus 提供的同一 CLI 入口。该图以本机工具链和系统根构建，图及可执行文件均未链接 liburing，配置、SOCKS TCP/UDP 与双 worker 测试通过。验证时复用了已安装的项目依赖缓存；新检出需先安装依赖，不能把此结果称为冷缓存离线构建。mcpp 当前直接链接包的编译对象，与原 CMake 静态 archive 的按需抽取行为不同，仍须在所有可选配置和测试中验证影响。

```sh
# 在已经准备依赖的环境中，构建当前 epoll-only 图
cd mcpp/epoll
MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked build --target x86_64-linux-gnu -j 1 --strict
```

2026-11-18 的 epoll 组合在同一入口启用 `nexus/masque-ip-endpoint,nexus/masque-cli,nexus/hy2-cli,nexus/wireguard-outbound,nexus/ss2022,nexus/tuic,nexus/dns-response,nexus/tailscale-endpoint`。通过 `--features` 传入该列表，先运行离线 `build --configure-only` 更新组合的锁，再以相同 features 进行 `--offline --locked` 构建。恢复到无可选功能的默认图时，省略 features 并重新生成默认图的锁。两张图已分别通过构建与运行验收，组合产物的 ELF 动态依赖未包含 liburing。详见 [项目进度](../progress.md)。

本机测试包括代理模块、网络模块、协程取消、端点与连接；隔离双源 `when_all` 启动分配失败测试也通过。`build.mcpp` 的隔离试验另发现，当前 mcpp 以显式 native `--target` 错误走 host 工具链解析并拒绝 `path:/usr`；省略该参数仍要求下载私有 glibc。暂未将该构建程序接入项目，不能以下载私有运行时掩盖系统根构建问题。上游文档确认实验性的 `[hooks]` 失败只报告警告，且 `mcpp test` 不运行 hook，不能用它保证补丁快照检查必然成功。

`scripts/mcpp-generate-thirdparty-fixtures.py` 生成独立第三方探针：CPO 在头文件与模块中的地址一致性、Capy `when_all` 启动分配故障、分配行为以及 BoringSSL 原始向量均通过。另一个 Corosio 连接探针分别在 epoll 和 io_uring 验证候选地址重试、取消及失败清理；其测试宏仅作用于入口，模块包装和其他探针对象未混入该链接。实际 Ninja 链接边确认故障和分配替换对象仅进入所属程序；固定 BoringSSL 由源码对象提供，未链接系统 libcrypto。工作空间离线锁定空构建和生成器 `--check` 通过，当前结果为本机 debug 图。

### 代理故障与回滚夹具

`scripts/mcpp-generate-proxy-faults.py` 为根启动、DNS 取消与所有权、启动和会话异常生成独立构建图，避免将不同的测试钩子链接进正常服务器；这些变体按原目标关闭 SOCKS UDP，并由 P1689 核对实际 import。以本机 debug 图完成根启动故障及重配置（2 项）、DNS 生命周期（epoll 和 io_uring）、借用状态与挂起的 UDP/TCP 登记，以及启动和会话异常（2 项）测试。各图离线锁定重跑通过。测试使用已安装的依赖缓存，不能代表所有故障配置均已迁移。

代理预加载夹具及五个用途独立的共享库现由真实工作区成员构建，当前入口和验证范围见 [mcpp 工作区](mcpp-workspace.md)。实际测试验证监听、第二个 worker 创建和端口复用失败后的清理与重启；io_uring 初始化、eventfd、提交失败和降级；20 次双 worker accept 竞争、多监听器失败；以及单、双 worker 的瞬时 accept 错误和重试中停止。进程级 DNS 快照线程在建立测试基线前启动；线程注入随后重置计数，并要求第一个 worker 成功启动、第二个失败。旧生成图与此前 xmake release 的验证仅作为迁移历史。

慢解析器、系统解析防护、时钟故障和 SS UDP 大报文观察库分别通过独立解析线程池、DNS bootstrap、UDP 故障排空和双监听器网络测试。新旧五个预加载库的机器代码段一致；它们只在测试显式加载时生效。历史上依靠系统解析器拦截代理 DNS 的驱动还需要按当前解析路径重新验收。

原根启动故障测试依靠覆盖 Capy 的弱符号触发协程帧分配失败；优化构建可能内联原函数而绕过覆盖。现在测试在单次帧创建期间注入可失败的 memory resource，并在成功和异常时恢复原 allocator；xmake release 及 mcpp debug/release 的三个故障点和重启回归通过。该改动仅在测试宏启用时编入代理。

VLESS 会话与双向 relay 挂起析构、SS 入站重放状态和会话析构，以及 SS/VLESS 出站隧道借用 profile 的析构顺序，已在独立加密故障图的本机 debug 构建中通过。对应离线锁定重跑通过，实际编译命令确认预期故障宏生效且 SOCKS UDP 未启用。其余加密故障变体仍须逐项构建与运行。

FakeIP 独立图的六个网络故障和恢复驱动通过；生命周期图在 epoll/io_uring 下验证上下文放弃及异常排空时释放 pin。owner 图验证挂起会话以及 UDP、TCP DNS 拨号在借用的 owner 销毁前释放状态。各图离线锁定重跑通过；实际代理源的测试宏与禁用 SOCKS UDP 已核对，生产程序没有导出这些测试钩子。结果仍限于本机 debug 与这些显式场景。

### BoringSSL 源码包

`nexus.boringssl-crypto-source` 使用与原 recipe 相同的提交，GitHub 官方镜像归档 SHA-256 为 `8df889167a2ca2237073cfed3147ac7b2f548f7dbf3daf4928a0ae6504d2013f`。`scripts/mcpp-boringssl-sources.py` 从归档的 `gen/sources.cmake` 生成并校验非 FIPS `libcrypto` 的四组源码列表；脚本只读取调用者提供的已校验归档，不联网。包目前限定 Linux x86-64，保留原配置的 `BORINGSSL_IMPLEMENTATION`、关闭异常和 RTTI、预生成汇编及 `--noexecstack`。C++ 源码没有模块 import，单独关闭 GCC 的模块编译；库接口仍经项目的 `nexus.thirdparty.boringssl` 导出。

隔离构建以指定 GCC/系统根及 `-freflection` 编译全部源码，并以实际 `nexus.crypto` 模块通过 SHA-2、HKDF、AEAD 和 X25519 向量；链接没有依赖系统 libcrypto。原 CMake 使用 C++17，mcpp 图统一为 C++26；原 CMake 非 release 构建另启用内部 dispatch 测试计数，当前描述符没有启用。两者的更广泛行为及性能仍待验证。`crypto-primitives` 只是用于迁移期间验证基础模块的临时 feature；完整可选协议图及其验证仍在迁移中。

### 可选协议的构建图

根配置的 `crypto-primitives` 已实际构建并运行 SHA-2、HKDF、AEAD、X25519 和 ML-KEM 向量。完整 VLESS/Reality 图需要 `NEXUS_ENABLE_VLESS`，使 `session.cpp` 的 import 集合改变；mcpp 2026.10.30.1 的 `scan_overrides` 不能按 feature 条件选择。因此 `scripts/mcpp-generate-profiles.py` 从根 manifest 生成 `mcpp/crypto/mcpp.toml`，为该配置声明精确的 import、feature 和源码；`src`、`tests`、`3rdparty` 通过相对符号链接指向原树，不复制源码。执行脚本的 `--check` 可检查生成文件是否与根配置同步；修改根配置后应重新生成。此设计目前是迁移入口，其他配置及故障注入图仍须逐一建模。

`mcpp/crypto` 使用与根相同的 host、系统根、依赖锁和 io_uring 默认值，并启用 VLESS/Reality；`--offline --locked`、单并发以及 `MCPP_VERIFY_MODGRAPH=1` 下程序和 Reality 客户端夹具构建成功，GCC 的 P1689 扫描核对了条件 import。独立互通对端 Reality 的普通和 X25519-ML-KEM 混合连接、多 worker 双向数据与 EOF、错误身份拒绝均通过；Vision 普通 TLS 出站和入站、Nexus 双端延迟响应及配置测试也通过。部分外部客户端先半关闭的 Vision 延迟响应不兼容，属对端自身实现限制。测试期间临时复用了根目录的已安装依赖缓存；冷缓存、切换配置及增量修改仍待验证。示例：

扩充后的加密测试集以同一工具链、离线锁定、单并发和 P1689 审计通过 **82/82**，覆盖 TLS、Reality、Vision、VLESS 和 XUDP 所列的编解码、状态、背压及生命周期测试，以及连接、跨线程 I/O 和双栈 UDP socket。需要参数的服务器证书、握手及 Reality 夹具由 OpenSSL 与独立 REALITY 对端驱动：RSA、EC、Ed25519 证书、三种 TLS 套件、错误 Finished、ALPN、取消、证书 HMAC、回退及双向数据通过。两处旧测试仍期望证书 clone 共享存储，已改为验证当前独立复制、复制失败回滚及原所有者结束后的副本寿命。这些是显式选入的测试和夹具，不包括所有故障变体。

```sh
python3 scripts/mcpp-generate-profiles.py --check
cd mcpp/crypto
MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked build --target x86_64-linux-gnu -j 1 --strict
```

上游源码还提供实验性的 `MCPP_SCANNER=p1689` 全局开关，但当前规划期扫描代码未向编译器传入包定义和各单元 flags，不能据此假设它会正确扫描 Nexus 的 feature 条件；本配置仍使用精确 `scan_overrides` 和实际编译时的 P1689 审计。`mcpp.lock` 当前记录并核验解析结果，而非作为解析输入固定版本，仍需保留精确版本、描述符及归档校验。

`mcpp/shadowsocks` 是上述生成配置的 SS2022 变体，增加固定 BLAKE3 源码描述符：归档 SHA-256 `59de7e05c6683152e6db1c0ac1044ad3742eb7b0ba579d727a0a096e47029d9d`，编译命令已核对为上游 CMake `BLAKE3_SIMD_TYPE=none` 的三个 C 文件及相应禁用 SIMD 宏。以指定 host、离线锁定、单并发和 GCC P1689 审计构建，扩充后显式选入的 **99/99** 测试通过，包含 BLAKE3、SS 密钥和 AEAD 向量、TLS、代理、VLESS、Vision 及 XUDP。首次从子目录运行时，规则测试无法找到文档示例；`mcpp/crypto/docs` 和 `mcpp/shadowsocks/docs` 相对链接已补齐，随后全组重跑通过。独立互通对端的 SS 出入站 TCP、配置多监听器 UDP，以及 UoT 入站直连、SS 链式、XUDP 和 Vision XUDP 测试通过。单独的 SS UDP 夹具还验证了异步 DNS 的成功、策略、过期、超时和取消，epoll/io_uring 的异常取消与排空，以及独立对端下的策略、TCP DNS、IPv6 和八会话并发。部分外部 XUDP 实现仍会丢弃空数据报，后续非空包恢复。

扩充后的 SS 配置以相同工具链、离线锁定及 P1689 审计通过 **105/105** 已选测试。新加入的十组参数化夹具也对独立互通对端验证了 SS TCP 编解码、Corosio 与代理出入站、UDP 客户端与服务端，以及监听器重启时 DNS 视图隔离。UDP owner、pending 和接收错误注入另由 `mcpp/shadowsocks-udp-faults` 的独立工作空间提供：它不链接代理或 CLI，避免测试宏改变内联头定义与生产编译单元冲突；实际链接核对确认只有 relay 测试使用 `--wrap=recvfrom`。owner 与 pending 在 epoll 和 io_uring 的取消、异常和恢复测试及 relay 错误隔离通过，离线锁定重建通过。此前 SS 普通构建目录中若留有旧 owner 二进制，它不属于新的清单，不应作为隔离图的测试结果。

`mcpp/tls-https-fixture` 单独编译 HTTPS 测试模块，避免将测试模块加入生产服务器；其程序与 `mcpp/crypto` 夹具一起通过 OpenSSL TLS、HTTPS 分帧和独立 VLESS 互通对端验证。VLESS TLS 入站的独立夹具还验证 33 MiB 双向传输、背压及半关闭，错误用户、截断和拨号失败各确认进入对应拒绝阶段。测试夹具保留应用密钥的预算直至连接结束，不能以握手后的预算为零作为成功条件。

`mcpp/epoll-crypto` 和 `mcpp/epoll-shadowsocks` 分别关闭依赖的默认 feature，再启用所需协议。两个图的离线锁定构建与空构建通过；编译数据库、链接图和运行时依赖均没有 liburing。独立互通对端上，加密版的 Reality TCP 与 XUDP 双栈并发通过；SS 版的 SS 出入站 TCP、双监听器 UDP、以及 XUDP 普通/Vision Reality 双栈并发通过。SS 的入站重放测试使用同一 epoll 图构建的 wire fixture。这些为本机 debug 验证，其他后端、release 和完整特性矩阵仍需单独验证。

根 `mcpp.lock` 对应默认依赖集。当前 mcpp 的 `--locked` 会拒绝与锁中集合不同的解析，因此直接对根开启 `crypto-primitives` 会因缺少 BoringSSL 记录而失败；crypto/SS 的独立配置使用各自的锁。不能把单个根锁视为已覆盖 feature 切换。

此前 `mcpp/uot-fixture` 单独编译属于 `nexus.proxy` 的双源测试夹具；DNS 改造后由夹具持有本地 DNS 状态，确保它比协程上下文活得久。现在该夹具及故障对端由 `nexus.proxy-runtime/test-uot-fixture` 提供，写入竞争由独立 `test-uot-write-race` 功能提供；新工作区的真实网络和竞争测试通过后，旧生成清单和链接已清理，构建产物保留。XUDP 代理夹具已由 `nexus.proxy-runtime/test-xudp-fixture` 提供，新图对独立协议对端验证普通与 Vision Reality 的双会话，旧生成清单及链接已清理，构建产物保留。测试专用符号不进入普通生产程序。独立对端的 XUDP 代理工厂与生产 SOCKS 路径在普通和 Vision Reality 下通过，生产路径另通过双栈八会话并发、取消、策略与普通 TLS 回归。其他故障测试仍在迁移；这些结果不是完整迁移。

### HTTP/2 核心与 TLS

`mcpp/http2` 独立图使用 `nexus.nghttp2-source` 描述符。`scripts/mcpp-nghttp2-sources.py` 从与原 recipe 同一 SHA-256 的官方 1.70.0 发布归档读取 `lib/CMakeLists.txt` 的 26 个源，并校验归档、清单与源码存在性。配置快照限定 Linux x86-64，宏已与本机系统根按原 lib-only CMake 选项生成的 `config.h` 比对一致。编译数据库确认 26 个 C 单元使用指定 GCC、系统根、静态库宏和 `gnu23`，私有配置目录没有传给消费者。原 CMake 未指定 C 标准，本机 GCC 默认 GNU C23；若目标环境变化须重新核对。核心图以 `--offline --locked`、单线程及 GCC P1689 审计构建，三个请求、分片和内存预算测试通过。运行校验脚本时传已校验的归档；可用 `--cmake-config` 重新比较对应环境生成的宏。

`mcpp/http2-allocator` 将双源测试及 `--wrap=realloc` 独立建图，分配限额、失败回滚和恢复测试通过；该链接参数不作用于其他程序。`mcpp/http2-tls` 从 crypto 配置复用同一内存预算模块，并在本图编译 HTTP/2 模块。真实 OpenSSL TLS 与 curl 的请求、多路复用、流控、关闭、截断和取消测试在 epoll 与 io_uring 下通过；输入/输出内存预算、背压、故障与取消测试也通过。测试使用已安装依赖缓存和本机工具链；release、冷缓存、其他平台与打包尚未验证。

### Linux TUN、TCP 和 UDP

`mcpp/tun` 独立编译规则核心、包、TCP/UDP 和 TUN transport，使用指定 GCC/系统根、单并发和 P1689 审计构建。显式选入的 **48/48** 常规测试通过，包括双栈包、TCP 乱序/重传、直连、分配失败、UDP 和过期输出过滤。真实 TUN 及需要 `--wrap` 的测试不属于这 48 项。

历史布局曾按链接器包装参数生成独立包。当前工作区将 11 项非特权故障测试集中在 `nexus.tun-fault-tests`，通过同名 feature 和 profile 隔离包装参数，并用驱动核对实际链接命令；随机数故障由测试专用平台钩子在隔离网络命名空间验证。使用方法和本轮状态见 [mcpp 工作区](mcpp-workspace.md)。

真实 TUN 回归在隔离网络命名空间通过：Linux 双栈 TCP 的普通、数据丢失和双向 FIN 丢失；真实直连 TCP/UDP、IPv6 扩展选项、两个 MTU 的双向数据与 FIN 丢失；停止时关闭活动连接及释放设备。测试需要 Linux TUN、网络命名空间、`ip` 和 `nft`。规则核心目前在此图独立编译，尚须与服务器图整理共享包边界；release 与其他平台仍待验证。

原 TCP watch 性能探针已作为 `mcpp/tun` 的构建目标加入；离线锁定构建和空构建通过。本轮没有执行性能测试。

历史 `mcpp/udp-fixtures` 的三个故障入口已迁入真实工作区的 `nexus.udp-fault-tests`，依赖生产协议模块并按链接配置运行。实际命令确认前两种直连测试只包装 `sendto`，入站测试同时包装 `sendto` 与 `recvfrom`；双栈直连、错误重试、策略及回复过滤通过。入口见 [mcpp 工作区](mcpp-workspace.md)。

`mcpp/udp-async` 结合 TUN 包的 UDP 模块与固定 Capy/Corosio 构建异步桥接测试。发送、回复、预取消与接收取消通过，编译命令确认启用了 io_uring feature，锁定空构建通过；该程序使用 Corosio 默认后端，未单独强制两种后端。

### DNS 独立组件与历史记录

`mcpp/dns` 将 FakeIP 与共享缓存、刷新器和异步 DNS 测试独立建图；明确声明 `nexus-dns-core` 库，供依赖它的 `mcpp/dns-history` 获取 FakeIP 模块。使用本机 GCC、系统根、单并发、离线锁定及 P1689 审计，DNS 图的 15 项测试及 TCP、普通/缓存/双栈/本地解析的五个网络夹具通过；增加库目标后 15 项重新通过。

该图还以本机隔离的 dnsmasq 验证 A、AAAA、CNAME 和 NXDOMAIN，以独立 BIND 权威区验证 NODATA、CNAME 和 NXDOMAIN；新增夹具的离线锁定重建随后无工作。

历史记录图额外启用加密基础模块，两项认证格式与持久化测试通过；写入、文件同步、重命名和目录同步各阶段的 EIO 注入及独立重开验证通过。两个图的离线锁定空构建也通过。这些结果使用已安装的依赖缓存，不涵盖冷缓存、其他平台或发布接口；mcpp 提示 DNS 测试库没有常规发布模块根，不能据此发布该库。

历史记录的独立进程夹具还验证了提交锁竞争、进程被终止后的旧/新快照恢复、四个系统调用阶段的 EIO、后续重试，以及损坏、回退和不安全文件拒绝。

`mcpp/dns-cache-experiments` 提供 36 个独立缓存实验与基准入口。mcpp 将一个入口源码映射到一个对象；原 xmake 的 17 个变体对四个源码文件使用不同宏，若直接在同一包重复引用源码，宏会累加到同一对象。`scripts/mcpp-generate-dns-cache-variants.py` 按固定 xmake 快照生成各变体的独立符号链接入口，并核对原宏。`--check --verify-build <构建目录>` 进一步核对 36 个真实编译对象、宏、链接边以及共享模块不带实验宏；本机离线构建和锁定空构建通过，23 项正确性、差分、并发及分配故障实验通过。该图包含的性能基准只迁移了入口，此次没有运行或比较性能。

`mcpp/dns-network-experiments` 另提供九个网络、视图及刷新实验入口，其中同源的两种 singleflight 配置使用独立符号链接。相同脚本以 `--package dns-network-experiments --check --verify-build <构建目录>` 核对对象、宏和链接；离线构建与锁定空构建通过。六个正确性程序验证了预算耗尽和取消、两种时间粒度下 epoll/io_uring 的查询合并和刷新、DNS 视图隔离，以及多执行器租约、代次和停止。其余三个内存或吞吐实验只建立构建入口，没有据此作性能结论。

`mcpp/dns-group-fixed` 和 `mcpp/dns-coordinator-tests` 分别构建固定容量组模块与共享容量组模块、协调器；这两个同名模块有不同布局，不能链接在同一图中。固定组的跨组答复测试通过；协调器测试在 epoll 和 io_uring 下验证真实 DNS 查询合并、跨组缓存、取消、跨执行器停止与排空，代理视图测试验证真实路由类型及缓存隔离。实际编译命令确认共享容量宏只作用于共享组模块、协调器宏只作用于原目标及对应视图入口，两个图的离线锁定空构建通过。这里的测试代理使用根图的普通代理模块，尚不包含实验版代理。

`scripts/mcpp-generate-dns-proxy-experiments.py` 另生成含实验版代理的独立协调器图，不依赖含普通代理模块的根包。宏只附加到原代理、共享组模块、协调器和夹具各自的编译单元；生成器对照固定 xmake 快照检查源码和宏，`--check --verify-build <构建目录>` 检查实际对象、宏和两条链接边。离线构建及锁定空构建通过，两 SOCKS 入站、四 worker 的查询合并、换代排空和不同 DNS 上游视图隔离通过。测试访问钩子各由所属夹具定义，根生产程序没有该钩子。此结果限于实验夹具和本机 debug 图。

`--package dns-proxy-coordinator-udp` 生成另一独立图，包含固定 BoringSSL/BLAKE3 和 SS UDP 模块；不同入口的宏与 TCP 图隔离。对象、宏和链接审计及离线锁定空构建通过。独立互通对端下，两 SOCKS 入站、两组 SS UDP 的同键合并、旧查询排空和配置换代通过；分别由 TCP 和 UDP owner 持有后台刷新时的取消及换代也通过。访问钩子仅由夹具定义，程序没有依赖系统 libcrypto。

`scripts/mcpp-generate-dns-proxy-variants.py` 对照原目标生成共享锁、快照、固定容量组、共享容量组和容量基线五个独立 TCP 夹具图；每个图的实际对象、私有宏、链接和离线锁定空构建均已核对。共享锁与快照各通过两/四 worker 的正、负缓存复用；固定组通过两 SOCKS 入站共享视图、挂起查询排空和换代测试。共享容量与基线共同验证一组的 1200 个缓存成员及基线淘汰、两组容量借用/归还、跨组正负答复共享。它们仍是实验配置。

`scripts/mcpp-generate-dns-proxy-udp-variants.py` 生成固定组 UDP、固定组刷新、共享容量刷新及刷新启动故障四张隔离图。每图的实际对象、宏、链接和离线锁定空构建已核对；前三张均通过两 SOCKS 入站与两组 SS UDP 的共享、查询排空和换代网络测试，两张刷新图还分别验证 TCP 和 UDP 所有者挂起时的取消与换代。故障图验证单/双 worker 的刷新构造与启动故障恢复，以及双 SS UDP 组的 15 个启动分配失败。上述结果为本机 debug 实验图。

`scripts/mcpp-generate-dns-proxy-bench.py` 和 `scripts/mcpp-generate-dns-proxy-multi-bench.py` 分别生成四种单 SOCKS 与四种双 SOCKS、双 SS UDP 的基准构建图。八张图均完成离线构建、实际对象和私有宏及链接审计、锁定空构建，并通过启动、SOCKS 双向转发和停止检查；单 SOCKS 图另验证重启，多路图另验证两个 SS UDP 监听器的双向转发。这些是功能 smoke，未执行性能比较，也不能证明生产性能。

`mcpp/state-experiments` 复用独立 SS UDP 核心，分别构建 BEVE 快照与 SQLite replay 实验。两种 AES 密钥长度下，BEVE 的多会话、崩溃、提交歧义和各系统调用 EIO 恢复通过；系统 SQLite 3.54.0 的会话回调、锁竞争、ID 保留和崩溃恢复通过。链接检查确认 SQLite 仅作用于其程序，两者均不依赖系统 libcrypto；离线锁定空构建通过。这些是实验夹具，不是生产状态后端。
