# 第三方依赖的 C++ Modules 封装与导出

第三方模块封装源文件存放在 `3rdparty/modules`；`src` 只存放项目自有源码。

状态：`nexus.thirdparty.glaze` 已由规则集使用，导出的名称位于 `nex::glaze`。`nexus.thirdparty.capy` 和 `nexus.thirdparty.corosio` 已分别成为独立的可复用 target，导出目前使用的有限接口；其他业务代码仍可能直接使用头文件，其他模块仍为**设计草案**。包的获取、固定与构建由[项目内 xmake recipe](third-party-xmake.md)负责；`add_packages` 不会创建 C++ 模块，`export` 或 `import` 也不会自动链接静态库。

实验记录（2026-10-27）：Linux x86_64、xmake `3.1.2+20261016`。GCC 16.2.1 在无补丁、无头文件单元下验证完整构建和私有 I/O 测试。静态 C 库链接传递只通过了模拟库实验。proxy、真实 BoringSSL 和 nghttp2 的模块均未验证，下列相应名称仍是工作方案。

2026-10-28：Capy 和 Corosio 分别由 `nexus-thirdparty-capy`、`nexus-thirdparty-corosio` target 编译，在 `nex::capy`、`nex::corosio` 导出实际使用的任务、缓冲、事件、socket、context 和地址等接口。封装自身不导入 `std`，关闭这两个 target 的 xmake 自动 `std` 模块生成，避免各自产生不同 BMI；其他目标正常使用 `import std`。GCC 16/io_uring 独立消费者、TLS 连接和 VLESS/TLS 入站测试通过。消费者仍需配置后端宏；Capy EOF 判断经封装内显式转换，以处理 GCC 模板实例化时的 ADL。导出集合不是完整上游 API，后续按使用需求扩展并验证。

## 层次与依赖方向

```text
业务模块                                      第三方模块                 package
nexus.config / 规则格式适配  ───────────────> nexus.thirdparty.glaze ──> nexus-glaze-kdl
nexus.contracts              ───────────────> nexus.thirdparty.proxy ──> nexus-proxy
nexus.runtime（待实现）      ───────────────> 私有实现 -> nexus-corosio -> nexus-capy
nexus.crypto / nexus.pki     ───────────────> nexus.thirdparty.boringssl_crypto
                                                                         -> nexus-boringssl-crypto
nexus.http.h2（可选）        ───────────────> nexus.thirdparty.nghttp2 -> nexus-nghttp2
```

箭头表示依赖方向，不表示所有接口都必须公开重导出。规则语义模型不依赖 Glaze；HTTP 公共语义不依赖 nghttp2。网络接口应导出 Nexus 自有契约，在实现单元中使用 Capy 和 Corosio；其所有权、取消和错误语义须随实际业务验证。

`nexus.thirdparty.ngtcp2` 与 `nexus.thirdparty.nghttp3` 仅为[Hysteria 2](../architecture/protocols/hysteria2.md)的条件性模块名候选，未添加包、接口或依赖；选定前须验证自研 TLS、QUIC crypto 接口、HTTP/3 流分流及第三方 TLS 排除。

第三方模块可以导出实际使用的类型、函数和模板，也可以选择由私有实现封装。对已导出的第三方接口，使用 `nex` 作为顶层命名空间并按库分组，例如 `nex::glaze`；模块名与 C++ 命名空间是不同概念。每次增加或移除导出应记录清单和兼容影响。

例如 `import nexus.thirdparty.glaze;` 面向集成代码；`import nexus.config;` 面向配置使用者。一个业务模块只有在有意将下层接口纳入自身公共契约时才写 `export import nexus.thirdparty.glaze;`：普通 `import` 不会把导入的名称传递给其消费者。图中独立模块可供直接导入，即使业务模块不重导出。公开了第三方类型或模板的业务接口还要检查其名称可见性、定义可达性和依赖的模块是否对消费者可用；仅能编译模块自身不够。

## 各模块的首批导出与消费目标

| 命名模块草案 | 首批导出目标 | 最小消费与业务边界 |
| --- | --- | --- |
| `nexus.thirdparty.glaze` | `read_kdl`、`write_kdl`、`read_beve`、`write_beve`；按实际配置模型需要补充错误类型、选项及其他公开模板 | 无 Glaze 头的独立消费者执行 KDL→BEVE→KDL，验证自定义映射、错误和限制；`nexus.config`/规则格式适配负责 Nexus schema 与校验 |
| `nexus.thirdparty.proxy` | 可用的 facade builder、`pro::proxy`、构造/借用及调用相关公开接口；具体名称以 Git 提交为准 | 在独立消费者中定义或导入 facade，使用拥有和借用两种场景并调用；`nexus.contracts` 负责业务能力与生命周期契约 |
| 网络运行时（待实现） | Nexus 自有的网络契约；Capy 与 Corosio 在实现单元私有使用 | 验证真实 I/O、关闭、取消和消费者生命周期；不上抛 Corosio 的可选 TLS provider |
| `nexus.thirdparty.boringssl_crypto` | 随需要导出 BoringSSL libcrypto 的类型和函数，包括 AEAD、摘要/MAC、密钥派生、密钥交换/签名、随机数与证书解析所需能力；逐项确认所选提交 | 独立消费者通过模块调用真实静态 libcrypto 并做已知答案与失败路径测试；`nexus.crypto`/`nexus.pki` 包装资源及策略，不向一般业务公共接口暴露裸句柄 |
| `nexus.thirdparty.nghttp2`（可选） | 固定 libnghttp2 1.70.0 的 session、callbacks、帧提交及内存收发接口；以锁定版本 API 为准 | `nexus-nghttp2-memory-test` 已驱动 client/server preface、SETTINGS 及逐字节分片的请求/响应头交换；`nexus.http.h2` 转换事件、管理 session 与背压仍待实现，不把 C 对象放进公共 HTTP 模型 |

Capy 的任务与缓冲区、Corosio 的网络对象及两者的关系可参考[Capy 仓库](https://github.com/cppalliance/capy)和[Corosio 仓库](https://github.com/cppalliance/corosio)。这些上游入口会变化，不能替代对固定提交的验证。每个模块的完整公开名称、头文件、宏、链接需求和允许的使用层级，应在真正接入时随锁定提交记录；此表只规定首批能力与验收，不宣称现已满足。

## 已验证的私有 I/O

直接导出完整 `tcp_socket` 的实验触发 GCC 16 对 TU-local 类型的诊断，因此撤掉了相应模块。实验代理的 `nexus.proxy` 接口只导出 Nexus 自有服务类型，上游头文件位于实现单元；已在 GCC 上通过本地端到端测试。它不是通用网络 facade，支持范围见 [SOCKS5 说明](../architecture/protocols/socks5-mixed.md)。

[`tests/io.cpp`](../../tests/io.cpp) 直接在测试实现中包含上游头文件，验证数据传输、预取消、读取挂起后取消、停止/恢复、关闭及连接失败，并对每次事件循环设置时间上限。对象关闭后需继续驱动 context，让完成项清理完毕；单纯 `stop()` 不等于取消挂起的工作。无补丁版本的测试覆盖 GCC/Linux epoll 和可选系统 liburing 的一小部分路径，尚未覆盖跨线程竞争、UDP、半关闭或其他平台。链接限制见[依赖封装](third-party-xmake.md)。

## 已验证的 Glaze 最小示例

临时项目从本地 Git 获取指定分支提交 `fc646588635c42cca142562d7b3d0484cc4493b7`，通过项目内 recipe 安装头文件。下列代码摘取其实验的接口；省略了用于触发增量构建的测试常量。`module;` 后的头文件处于 global module fragment，`using` 显式把选定名称导出到 Nexus 命名空间，并非导出整个 `glz` 命名空间。

```cpp
// 3rdparty/modules/glaze.cppm
module;
#include <glaze/kdl.hpp>
#include <glaze/beve.hpp>

export module nexus.thirdparty.glaze;

export namespace nex::glaze {
    using ::glz::read_kdl;
    using ::glz::write_kdl;
    using ::glz::read_beve;
    using ::glz::write_beve;
}
```

实验特意用一个业务模块测试传递导出；这只展示机制，正式的 `nexus.config` 是否重导出 Glaze 尚未决定：

```cpp
// src/config.cppm
export module nexus.config;
export import nexus.thirdparty.glaze;
```

下述 xmake 片段展示实验的 target 关系；省略了实验用 recipe、`includes` 和 `add_requires`，因此不能直接作为当前仓库的构建脚本。`{public = true}` 对接口文件和依赖的作用分别是公开模块源及传递 target 依赖；示例也把包的 usage requirements 公开给下游。实际项目应检查这些要求，避免无必要地向所有消费者扩散第三方编译定义。

```lua
set_languages("c++23")
set_policy("build.c++.modules", true)

target("nexus-thirdparty-glaze")
    set_kind("static")
    add_files("3rdparty/modules/glaze.cppm", {public = true})
    add_packages("nexus-glaze-kdl", {public = true})

target("nexus-config")
    set_kind("static")
    add_files("src/config.cppm", {public = true})
    add_deps("nexus-thirdparty-glaze", {public = true})

target("consumer")
    set_kind("binary")
    add_files("src/consumer.cpp")
    add_deps("nexus-config")
```

独立 consumer 只 `import nexus.config;`，不包含 Glaze 头，也不直接声明包依赖：

```cpp
// src/consumer.cpp
#include <string>
import nexus.config;

struct config { int port = 0; };

int main() {
    config original{};
    if (nex::glaze::read_kdl(original, "port 443")) return 1;
    std::string data;
    if (nex::glaze::write_beve(original, data)) return 2;
    config decoded{};
    if (nex::glaze::read_beve(decoded, data) || decoded.port != 443) return 3;
    auto kdl = nex::glaze::write_kdl(decoded);
    if (!kdl) return 4;
    config reparsed{};
    return nex::glaze::read_kdl(reparsed, *kdl) || reparsed.port != 443 ? 5 : 0;
}
```

它读取 `port 443`，写 BEVE、读回、再写并读 KDL，字段值一致。另一个实验直接导入 `nexus.thirdparty.glaze` 也通过。修改模块导出接口后，xmake 重编了 Glaze 模块、重导出模块和 consumer，重新链接并运行成功。[xmake Modules 示例](https://xmake.io/examples/cpp/cxx-modules.html)也描述了公开接口文件及跨 target 依赖。

这个历史实验只覆盖单字段与指定提交/工具链。现在项目已固定同一提交，并在 Linux/GCC 16 的 C++26 模块中验证规则集子集的 KDL/BEVE 读写；复杂元数据、所有模板及其他编译器仍未全面验证。

## 上游模块、头文件与宏

当前锁定的 ngcpp/proxy 提供原生 `proxy.v4`；`nexus-thirdparty-proxy` 直接构建包内上游 `proxy/v4/proxy.ixx`，代理私有实现导入该模块，并在全局模块片段包含仅含宏的 `proxy/proxy_macros.h`。GCC 16 C++26 编译和跨实现单元链接通过。上游接口仍使用 `pro` 名称，未在 Nexus 的公开模块接口中暴露。参见 [Proxy 4 Modules 文档](https://microsoft.github.io/proxy/modules_support/)。

可验证的重导出接口形态如下；它依赖构建图中另有提供 `proxy.v4` 的上游模块 target，当前未实测：

```cpp
// 3rdparty/modules/proxy.cppm，条件性草案
export module nexus.thirdparty.proxy;
export import proxy.v4;
```

命名模块的导入不会把模块内的预处理宏导出到使用者。Proxy 的 `PRO_DEF_*` 宏如需在接口单元中定义 dispatch，可按其文档在该单元的 global module fragment 中显式包含选定提交提供的宏头；公开使用者确实需要自行展开宏时，也须在自己的翻译单元显式包含兼容头。对固定的项目契约，优先在模块内定义并导出所需 C++ 类型，让消费者只导入模块。不要假装导入命名模块可以让调用者的预处理器看到宏；header unit 的宏处理是另一套规则，不等同于命名模块。

头文件接入使用 global module fragment 并显式导出经过选择的名称；宏型常量只有在语义、类型和配置均确认后才能转换为具名 C++ 常量。宏也可能改变声明、布局或模板定义：同一依赖在模块、普通头文件和不同 target 间必须使用相容配置，验证重复包含、不同导入顺序、ODR 和类型身份。不要把上游头文件放在 `export { #include ... }` 中就宣称全部接口可靠可用；header unit、头文件与命名模块混用也须单独验证。

## C 库与静态链接

对 BoringSSL 和 nghttp2，模块层可以在 global module fragment 中包含上游 C 兼容头，再用显式 `using` 导出选择的类型和函数；具体表面及错误适配按提交验证。应遵守上游头文件自己的 C linkage 声明，不随意给包含 C++ 内容的整个头文件套一层 `extern "C"`。例如当前 BoringSSL 的 [AEAD 头](https://boringssl.googlesource.com/boringssl/+/HEAD/include/openssl/aead.h)本身声明了相应 C linkage，也包含 C++ 内容；这不是对未来固定提交的构建保证。

下面只是待验证的 BoringSSL 接口形态，展示原始能力如何导出；它不是完整密码接口，也没有在真实 libcrypto 上编译或链接：

```cpp
// 3rdparty/modules/boringssl_crypto.cppm，草案
module;
#include <openssl/aead.h>

export module nexus.thirdparty.boringssl_crypto;
export namespace nexus::thirdparty::boringssl_crypto {
    using ::EVP_AEAD;
    using ::EVP_AEAD_CTX;
    using ::EVP_aead_aes_128_gcm;
    using ::EVP_AEAD_CTX_new;
    using ::EVP_AEAD_CTX_free;
    using ::EVP_AEAD_CTX_seal;
    using ::EVP_AEAD_CTX_open;
}
```

nghttp2 可以采用同样的选择性导出方式；使用者和 `nexus.http.h2` 所需类型、回调与函数须共同验证，并确保选定版本提供 `mem_recv2`/`mem_send2`。

业务适配层仍需遵守库的资源及安全语义：释放与创建配对，检查返回值，管理密钥、nonce 和生命周期。对 nghttp2，[`mem_send2` 文档](https://nghttp2.org/documentation/nghttp2_session_mem_send2.html)明确输出指针的有效期受下一次发送调用限制；适配层须在到期前完成处理或复制，并结合背压管理。仅把 C 函数导出并不提供这些约束。

静态库通常要在最终可执行文件链接时提供；模块 BMI 中的声明不能取代 `libcrypto` / `libnghttp2` 或其必要系统库。xmake 的包使用要求和 target 依赖要正确传递，链接顺序、静态链接项、平台宏及配置均需实测。临时模拟 C 静态库实验中，模块 target 使用 `add_packages(..., {public = true})`，无头文件、仅导入模块的独立 consumer 编译、链接、运行成功；这是**模拟库**，并非真实 BoringSSL 或 nghttp2 的验证。

## 验收与变更

1. **独立消费**：每个启用的模块有独立 target，仅通过模块使用该表面；需要宏时按上节单独测试显式兼容头，不把宏说成模块导出。测试导出类型、常量、模板、重载、实际调用与失败路径，并验证模块间传递值及类型身份。
2. **功能行为**：Glaze 测两个格式双向转换及错误；proxy 测 facade 拥有/借用；Capy/Corosio 测协程、I/O、取消和析构；真实 libcrypto 测已知答案及失败；可选 nghttp2 测内存收发、回调和 session 生命周期。
3. **依赖与裁剪**：检查模块扫描图、公开/私有 target 关系、静态库及系统项、编译命令、最终链接 map；核对仅引入所选 libcrypto，不引入 libssl 或其他 TLS 实现。关闭 HTTP/2 时 nghttp2 不进入目标图或产物。
4. **构建与重建**：分别验证干净构建、跨 target 导入和必要的 `export import`；修改接口与实现后检查实际重建、重新链接及运行。变化依赖提交、宏、工具链或标准档位时重建受影响模块及消费者。
5. **可复现性**：记录每项依赖及传递依赖的完整提交、许可证、构建参数、xmake/编译器/标准库、C++ 档位和目标平台；验证不同路径、空缓存及准备缓存后的离线构建。BMI/CMI 属于具体工具链与构建配置的编译产物，不作为跨编译器、跨版本、跨配置的通用 ABI 分发；换工具链或相关参数时重新生成。

上述为持续验收要求；当前 Glaze、Capy、Corosio 和固定 nghttp2 的有限项目目标已通过对应测试，其余依赖仍需继续验证。依赖的来源、锁定、升级与分发要求仍以[第三方 xmake 封装](third-party-xmake.md)为准。
