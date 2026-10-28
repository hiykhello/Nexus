# xmake 第三方依赖 Lua 封装

状态：Glaze、Capy、Corosio recipe、仓库注册及锁文件已实现；其他依赖仍为设计草案。下文示例中的 `0.0.0` 和 `<经验证的完整提交>` 是占位符，不能直接用于获取依赖。

## 组织方式

xmake 是统一入口。依赖获取和构建收敛到项目内的 package recipe，在根 `xmake.lua` 使用 `add_repositories("nexus-repo 3rdparty")` 注册相对路径仓库；第三方模块 target 用 `add_packages` 声明所需包，业务 target 按模块依赖使用。对依赖上游 CMake 的库，由 recipe 调用上游构建系统，仍由 xmake 负责配置与交付；只有上游构建方式无法满足需求且经过验证时，才维护自有源码 target 或 port。

目录如下；Glaze、Capy、Corosio recipe、根构建文件与锁文件已创建，其余为规划：

```text
nexus/
├── xmake.lua
├── 3rdparty/                          # 项目内 package 定义，不存放浮动源码
│   └── packages/n/
│       ├── nexus-glaze-kdl/xmake.lua
│       ├── nexus-proxy/xmake.lua
│       ├── nexus-capy/xmake.lua
│       ├── nexus-corosio/xmake.lua
│       ├── nexus-boringssl-crypto/xmake.lua
│       └── nexus-nghttp2/xmake.lua     # HTTP/2 启用时才需要
├── xmake-requires.lock                # 首次锁定并验证后提交
└── src/
```

包名前缀用于区分 Nexus 维护的 recipe 与同名社区包；各 recipe 独立维护来源、版本、依赖、构建及安装步骤。业务代码不引用个人工作区绝对路径，也不依赖 xmake 全局安装目录的具体位置。package 的头文件、库和必要的编译定义通过 `add_packages` 传递；一个 package 不等于一个项目 C++ 命名模块。拟定的命名模块 target、导出内容和静态链接传播见[第三方 Modules 封装](third-party-modules.md)。

Hysteria 2 对 ngtcp2/nghttp3 仅作[候选验证](../architecture/protocols/hysteria2.md)，不在上面的已规划 recipe 清单中；尚无版本、补丁或 TLS 适配实验，不应把它们写成正式依赖或拉入现成 TLS helper。

## 依赖类别与系统库

按用户明确要求分别处理，不能把 `system = false` 扩散到所有依赖：

| 类型 | 例子 | 规则 |
| --- | --- | --- |
| 编译器/标准库运行时 | C/C++ runtime、libstdc++、libc | 由工具链驱动与平台规则处理，不作为项目固定源码 package；是否静态链接 C++ 运行时按目标选择并实测，例如 GCC 下评估 `set_runtimes("stdc++_static")`，不隐含全静态 libc |
| OS/内核接口库 | Linux liburing、线程设施；Windows bcrypt | 只在使用对应平台能力时接入系统库，以 `add_syslinks` 或 `add_requires(..., {system = true})` 查找；系统包缺失时明确失败或按显式后端策略禁用，不用 `system = false` 拉替代副本。线程还需核对编译与链接的 `-pthread` 等工具链选项 |
| 指定源码依赖 | 指定 Glaze 分支、ngcpp/proxy、BoringSSL libcrypto、Corosio/Capy 等 | 项目内 recipe 和固定提交，`system = false`，验证传递依赖与实际链接，不能回退到系统版本或引入系统 libssl |

系统库的名字、头文件、版本、可用性和静态/动态链接按目标平台逐一验证。`system = true` 适用于通过包接口发现的系统库；纯编译器选项或系统链接项无需为迎合表格包装成 xmake package。类别之外的候选依赖应先按用途评估再归类，不预设一个选项适合全部依赖。[xmake 系统包说明](https://xmake.io/guide/package-management/using-system-packages.html)、[系统链接项](https://xmake.io/guide/project-configuration/configure-targets)。

全局声明与 target 绑定的关系可按以下形式组织：

```lua
-- 根 xmake.lua：片段
set_policy("package.requires_lock", true)
add_repositories("nexus-repo 3rdparty")
add_requires("nexus-proxy 0.0.0", {system = false})

-- 未来的 target 示例，源文件和 target 名称仍待确定
target("nexus-thirdparty-proxy")
    set_kind("static")
    add_files("3rdparty/modules/proxy.cppm", {public = true})
    add_packages("nexus-proxy")

target("nexus_contracts")
    set_kind("static")
    add_files("src/contracts/*.cpp", "src/contracts/*.cppm")
    add_deps("nexus-thirdparty-proxy")
```

这里只展示尚未实现的 proxy 结构；实际 Glaze 版本和 target 以根构建文件为准。若采用上游原生 proxy 模块，还需提供并连接其模块 target。`system = false` 排除对该声明的系统包探测；传递依赖也需要逐项约束并验证，不能只设置直接依赖后假定整个依赖树已锁定。编译选项及包的 `public` 传播范围要按模块接口实际需要设置，避免全局导出第三方宏、头文件和链接参数。xmake 的用法参见[项目内 package 与包依赖管理](https://xmake.io/guide/package-management/using-official-packages)。

2026-10-27：根据用户的本机实测，改用根 `xmake.lua` 中不带 `rootdir` 的 `add_repositories("nexus-repo 3rdparty")`。本轮 xmake `3.1.2+20261016` 为真实 Glaze recipe 生成的锁文件记录 `url = "3rdparty"`；复制项目并移走临时原路径后，以已有包缓存重新配置并构建 Glaze 模块成功。此前绝对路径实验显式使用了 `{rootdir = os.projectdir()}`，其结果不能推广到用户给出的声明方式。其他 xmake 版本、传递依赖及空缓存离线重建仍需单独验证。

## 各依赖的封装边界

当前 Linux 配置使用 BSL-1.0 的 Capy `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2`（项目包版本 `0.2.2`）与 Corosio `70adbd5aff90569aac588e78a717fecbd5b7dedc`（项目包版本 `0.3.3`），均来自各自 `develop` 源码快照，以静态库构建。Corosio recipe 在 CMake 配置时显式注入同一份 Capy；测试、示例、基准和 OpenSSL/wolfSSL provider 均关闭。上游核心仍编译通用 TLS context 源文件，但没有启用或链接第三方 TLS provider。两个库安装许可证文件。

Capy 固定提交应用项目内 [CPO 模块补丁](../../3rdparty/packages/n/nexus-capy/cpo_modules.patch)，处理 GCC 16 导出 Corosio socket 时报告的 TU-local 匿名类型。隔离实验中模块导出与消费者通过；完整证据、限制及后续跟踪见[上游问题](../development/upstream-issues.md)。现有业务接口仍保持网络实现私有。历史的无补丁构建与 I/O 测试只验证了私有头文件路径。

Corosio 当前提交应用[线程局部模板补丁](../../3rdparty/packages/n/nexus-corosio/thread_local_modules.patch)，解决 GCC 16 在代理模块中遇到的重复定义；生产代理已使用新版值返回 `tcp_acceptor::accept()`，具体范围见[上游问题](../development/upstream-issues.md)。

默认禁用 liburing，选择 epoll；`--io_uring=y` 时以 `system = true` 查找系统 liburing 2.5 及以上，并要求 CMake 的 pkg-config 检查成功。上游无模块单元，recipe 对其 CMake 构建关闭 `CMAKE_CXX_SCAN_FOR_MODULES`：GCC 16 在启用扫描构建 uring 源码时出现内部错误。Nexus 的命名模块仍启用。所测最终 I/O 程序的链接命令、动态依赖和符号未显示 libssl、OpenSSL libcrypto 或 wolfSSL；这不是对所有编译配置的证明。

| recipe | 来源与交付 | 需要保留的边界和验证 |
| --- | --- | --- |
| `nexus-glaze-kdl` | 指定 `hiykhello/glaze-kdl2.0-` 的 `feature/kdl2.0` 分支，固定提交 `fc646588635c42cca142562d7b3d0484cc4493b7`（MIT） | 头文件包与 C++26 命名模块已开始验证；通过 `NEXUS_GLAZE_SOURCE` 可指定含同一提交的本地 Git 镜像。完整 KDL/BEVE 能力和其他平台仍待测试 |
| `nexus-ngcpp-proxy` | `https://github.com/ngcpp/proxy.git` 固定提交 `9d9749d63766cdd9affb5ea7953237e38ce5ab63` | Git 源码包提供头文件及原生 `proxy.v4` 模块，由独立 target 构建；facade 用于代理私有实现 |
| `nexus-capy` | `cppalliance/capy` 的已验证提交 | 导出下游需要的头文件、编译定义及库；形式和传递依赖按所选提交核实 |
| `nexus-corosio` | `cppalliance/corosio` 的已验证提交，并显式依赖匹配的 `nexus-capy` | 只接 I/O 核心，核对线程、平台后端及可选 liburing；禁用或剔除 OpenSSL、wolfSSL 等 TLS provider，不引入它们的链接输入 |
| `nexus-blake3` | 官方 BLAKE3 1.8.4，提交 `b97a24f8754819755ef78d8016c0391c65c943c5`，Apache-2.0；Linux/GCC 16 静态 portable 构建及派生向量通过 | 可选 `ss2022`，尚未接代理协议；未验证 SIMD 或其他平台 |
| `nexus-boringssl-crypto` | BoringSSL `e651545da6e26e1f4420723a3b69a78ed1b9c51d`；Linux/GCC 16 已验证上游 `crypto` 静态目标 | 只交付 libcrypto，不构建或链接 libssl、工具和测试；平台汇编、系统链接项与密码学能力需要逐项验证 |
| `nexus-nghttp2` | nghttp2 v1.70.0 发布源码，SHA-256 `e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2`，MIT；Linux/GCC 16 静态包和模块内存请求/响应测试通过 | 仅 libnghttp2 核心；不构建应用、示例及它们的 TLS/事件循环依赖，选项默认关闭 |

这些是预期的独立 package，不意味着所有上游当前均为头文件库，或其依赖闭包已经核查。上游选项名称和目标可能随提交变化；应以锁定源码而不是浮动分支文档为准。

## Recipe 的基本结构

以 proxy 为例，下述路径和版本均是拟定内容。选择并验证提交后，将占位符替换为完整 Git SHA，检查所选提交仍使用相同的 include 布局：

```lua
-- 3rdparty/packages/n/nexus-proxy/xmake.lua
package("nexus-proxy")
    set_homepage("https://github.com/ngcpp/proxy")
    set_description("Nexus pinned ngcpp/proxy headers")
    set_kind("library", {headeronly = true})
    add_urls("https://github.com/ngcpp/proxy.git")
    add_versions("0.0.0", "<经验证的完整提交>")

    on_install(function (package)
        os.cp("include/*", package:installdir("include"))
    end)

    on_test(function (package)
        assert(package:has_cxxincludes("proxy/proxy.h", {
            configs = {languages = "c++20"}
        }))
    end)
package_end()
```

`on_test` 这里只验证头文件可见；还要单独编译实际使用的 facade、所有权和模块导入示例。安装时应保留许可证文件，并先核实选定提交的许可证和其分发要求。头文件复制必须保持上游的目录层级，不能只复制入口文件或任意裁剪内部头文件。proxy 当前上游示例使用 `include/proxy` 和 `proxy/proxy.h`，但正式封装仍以选定提交为准，见[上游仓库](https://github.com/ngcpp/proxy)。

`nexus-glaze-kdl` 可沿用头文件包结构，使用指定仓库与验证后的提交：

```lua
-- 3rdparty/packages/n/nexus-glaze-kdl/xmake.lua，版本和提交为占位符
package("nexus-glaze-kdl")
    set_homepage("https://github.com/hiykhello/glaze-kdl2.0-")
    set_description("Nexus pinned Glaze KDL/BEVE headers")
    set_kind("library", {headeronly = true})
    add_urls("https://github.com/hiykhello/glaze-kdl2.0-.git")
    add_versions("0.0.0", "<经验证的完整提交>")

    on_install(function (package)
        os.cp("include/*", package:installdir("include"))
    end)

    on_test(function (package)
        local opts = {configs = {languages = "c++23"}}
        assert(package:has_cxxincludes("glaze/kdl.hpp", opts))
        assert(package:has_cxxincludes("glaze/beve.hpp", opts))
    end)
package_end()
```

以上 `on_test` 只检查头文件；实际解析/编码与模块组合需要另外验证，并核实许可证及保留其文件。已读取的本地快照将 Glaze 定义为 C++23 interface target，并有默认关闭的 `glaze_ENABLE_SSL` 选项；直接复制头文件也要检查业务构建没有自行定义 `GLZ_ENABLE_SSL`。该快照的最小读写和模块实验结果见下文及[模块封装](third-party-modules.md)，不能据此推断其他提交或完整格式覆盖。

`nexus-corosio` 需要在 recipe 顶层或 `on_load` 声明 Capy，不能在 `on_install` 才添加依赖。例如：

```lua
-- nexus-corosio recipe 中的片段；版本为占位符
add_deps("nexus-capy 0.0.0", {system = false})
```

依赖默认需要向下游传递时，应保留匹配的头文件、编译定义与链接要求；仅构建工具才应考虑设为 `private`。如果采用上游 CMake，必须让它消费同一份已经锁定的 Capy，而不是让 `FetchContent`、系统查找或上游子模块再解析另一份；还要检查剩余传递依赖。当前 Corosio 上游 CMake 展示了对 Capy 和线程的公开依赖、可选 liburing，以及 TLS provider 查找，实际选项须在锁定提交核查。[上游构建文件](https://github.com/cppalliance/corosio/blob/develop/CMakeLists.txt)，[xmake recipe 规范](https://xmake.io/guide/best-practices/package-spec.html)。

## 编译型依赖的 Lua 接入要点

对于 `nexus-boringssl-crypto`，项目已有实验 recipe，下面是其设计示例。这里选择性构建 `crypto`，再复制静态库和头文件；上游的通用 install 规则同时包含其他目标，因此不能只凭 `cmake.install()` 断言只构建了 crypto。目标及产物路径须以最终锁定提交、生成器和平台实测为准。

```lua
-- nexus-boringssl-crypto recipe 的 Linux 部分，尚未验证
add_links("crypto")

on_install("linux", function (package)
    local builddir = "build-nexus"
    local configs = {"-DBUILD_SHARED_LIBS=OFF", "-DBUILD_TESTING=OFF"}
    import("package.tools.cmake").build(package, configs, {
        target = "crypto", builddir = builddir
    })
    local archive = path.join(builddir, "libcrypto.a")
    assert(os.isfile(archive), "确认所选提交和生成器的 crypto 产物路径")
    os.cp(archive, package:installdir("lib"))
    os.cp("include/*", package:installdir("include"))
end)
```

Linux 实验 recipe 已固定提交与许可证，只安装 crypto 静态归档和头文件；GCC 16/x86_64 下 SHA-256、AES-GCM 空消息已知答案和篡改拒绝通过。实际链接命令指向包内仅有的 `libcrypto.a`，动态依赖不含 SSL/crypto provider；其他构建模式、架构、交叉编译、原语与完整依赖图仍须确认。启用实验使用 `xmake f --crypto=y`，构建并运行 `nexus-crypto-smoke-test`；默认关闭。上游 CMake 的 `crypto` 和 `ssl` 是不同目标，但要核对所选提交的目标图和实际产物；不能用 `crypto/**.cc` 自行猜测源文件集合或遗漏生成代码和汇编。[BoringSSL 构建文件](https://boringssl.googlesource.com/boringssl/+/HEAD/CMakeLists.txt)。

后续 nghttp2 的 CMake recipe 可以从以下参数开始实验，并核查锁定版本的实际配置、构建日志和最终链接：

```lua
-- nexus-nghttp2 recipe 中的 on_install 参数草案
local configs = {
    "-DENABLE_LIB_ONLY=ON",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DBUILD_STATIC_LIBS=ON",
    "-DBUILD_TESTING=OFF",
    "-DENABLE_DOC=OFF"
}
import("package.tools.cmake").install(package, configs)
```

这些参数来自目前上游的 [CMake 选项](https://github.com/nghttp2/nghttp2/blob/master/CMakeOptions.txt)，不代表已经验证。即使只构建核心，上游配置阶段也可能探测系统库；应区分“探测到”与“实际编译/链接进入产物”，同时防止自动下载及未声明的依赖进入构建。

对于所有编译型包，recipe 应继承 xmake 选择的目标平台、架构、工具链、构建模式及必要 ABI 配置；宿主构建工具与目标库分开。不要把 `-freflection`、LTO、异常或 RTTI 等项目选项无条件注入所有第三方：先检查所选上游版本的要求，记录最终编译和链接参数，验证 ABI 与混用行为。决策 0007 对 libcrypto 关闭异常和 RTTI 的要求应针对该目标及具体工具链单独验证。

## 已完成的临时实验

- xmake `3.1.2+20261016`、Linux x86_64：使用本地模拟 Git 头文件包验证 `includes`、固定提交、`on_install`/`on_test`、target 消费及 package 传递依赖；复制项目后的复用缓存构建通过。另用模拟 CMake 库验证上述 `crypto` target 的构建和静态链接片段，未运行其故意设为失败的 `ssl` 目标。这不等于验证真实 proxy、Corosio 或 BoringSSL。
- 使用同一 xmake 和 GCC 16.2.1，以临时 recipe 从本地 Git 获取 Glaze `fc646588635c42cca142562d7b3d0484cc4493b7`，复制头文件后用 C++23 编译、运行了单字段 `port 443` 的 KDL 读取、BEVE 写入/读取及 KDL 再写入/读取，结果一致。另以独立 consumer 验证四个读写函数的命名模块导出、跨 target 重导出和接口修改后的增量重建，详见[模块封装](third-party-modules.md)。这些实验不是完整 KDL/BEVE 测试，也没有验证跨平台、空缓存离线重建或正式版本锁定。

## 锁定、升级与验证

1. 每个直接及必要传递依赖记录仓库 URL、完整提交或归档版本及 SHA-256、来源分支、许可证、配置项、补丁及补丁校验。Git 分支只标明来源；普通构建使用固定提交，不解析浮动 HEAD。Git 子模块及上游构建脚本自行下载的内容也必须固定或显式关闭。
2. 将 recipe、版本映射、必要补丁和生成后的 `xmake-requires.lock` 一同纳入版本管理；`package.requires_lock` 锁住解析结果，但并不代替 Git 提交/归档校验、recipe 源码、工具链和构建参数的固定。检查锁文件没有绑定个人路径，并在不同检出位置验证；首次拉取及缓存准备后，应验证禁网构建。缺少固定来源时明确失败，不静默回退系统包、其他版本或其他 TLS 实现。
3. 独立升级依赖：检查上游变更、许可证和安全修复，更新提交、补丁与锁文件，检查 Capy/Corosio 配对；为变化后的源码或构建配置更新 package 版本映射，不要只改同一版本的 SHA 后假定旧缓存自动失效。重新构建并核对实际来源与产物，分别做干净构建、增量构建、消费包的编译链接及项目模块实验，再记录结果。
4. 证据覆盖 xmake/编译器/标准库、目标平台、实际源码与构建配置、依赖图、编译和链接命令、静态归档成员、链接 map/符号和最终产物。动态依赖列表只能发现一部分问题；检查不存在 `libssl`、另一份 OpenSSL/BoringSSL、wolfSSL 等 TLS 实现，同时确认使用的是预期的 BoringSSL libcrypto。
5. 各包做最小消费验证：proxy facade；Glaze KDL/BEVE 双向读写；Capy/Corosio 协程 I/O 与取消；libcrypto 的实际密码原语与已知答案；启用 HTTP/2 时验证 nghttp2 内存接口。额外验证模块扫描、接口修改后的增量重建和功能关闭时的依赖裁剪。

Glaze、Capy 与 Corosio 的正式项目 recipe、模块和锁文件现已创建，当前构建与验证命令见[xmake 构建](xmake.md)；其他依赖仍遵循上述后续实现和验收要求。
