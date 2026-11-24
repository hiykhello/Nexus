# 第三方依赖的 C++ Modules 封装与导出

第三方模块封装源文件存放在 `3rdparty/modules`；`src` 只存放项目自有源码。

状态：当前工作区已将 `3rdparty/modules/` 下的第三方模块封装统一去前缀为裸模块名与命名空间：`glaze`（`namespace glaze`）、`capy`（`namespace capy`）、`corosio`（`namespace corosio`）、`boringssl`（`namespace boringssl`）、`blake3`（`namespace blake3`）、`nghttp2`（`namespace nghttp2`）、`ngtcp2`（`namespace ngtcp2`）与 `nghttp3`（`namespace nghttp3`）。`capy`、`corosio`、`ngtcp2` 与 `nghttp3` 同时覆盖 Linux / Apple Darwin / Windows 多平台 ABI。包的获取、固定与构建由[mcpp 工作区](mcpp-workspace.md)管理。

历史实验记录（2026-10-27 至 2026-10-29）：早期 Linux x86_64 + GCC 16.2.1 阶段验证了在无头文件泄漏下通过模块封装导出 Glaze/Capy/Corosio/BoringSSL/nghttp2 能力；第 153 批起工作区全面切换为 Clang（`llvm@23.1.3`）+ C++26 + 静态 `libc++`，第 161–163 批完成去 `nexus.thirdparty.` / `thirdparty.` / `nex::` 前缀收拢。下文保留早期设计示意图与验收准则说明（历史示例代码中的旧名以当前源码为准）。

## 层次与依赖方向

```text
业务模块                                      第三方模块                 package
config / policy（规则格式适配）  ───────────> glaze     ──> nexus.glaze-kdl
functional（contracts）          ───────────> proxy.v4  ──> nexus.ngcpp-proxy
net / proxy / dns                ───────────> capy / corosio
crypto                           ───────────> boringssl ──> nexus.boringssl-crypto-source
http2（可选）                    ───────────> nghttp2   ──> nexus.nghttp2-source
quic（quic-native / http3-core） ───────────> ngtcp2 / nghttp3
```

箭头表示依赖方向，不表示所有接口都必须公开重导出。规则语义模型不依赖 Glaze；HTTP 公共语义不依赖 nghttp2。网络接口应导出 Nexus 自有契约，在实现单元中使用 Capy 和 Corosio；其所有权、取消和错误语义须随实际业务验证。

`ngtcp2` 与 `nghttp3` 已按固定 release 生成无文本包含的跨平台 C ABI 模块，分别由 `quic-native` 和 `http3-core` 选择。来源、布局校验和正式图状态见[QUIC 依赖边界](quic-dependencies.md)；自研 raw TLS 与生产网络仍须独立验收。

第三方模块可以导出实际使用的类型、函数和模板，也可以选择由私有实现封装。对已导出的第三方接口，目前直接采用无前缀同名命名空间（例如 `glaze::`、`capy::`、`corosio::`、`boringssl::`、`blake3::`、`nghttp2::`、`ngtcp2::`、`nghttp3::`）；模块名与 C++ 命名空间是不同概念。每次增加或移除导出应记录清单和兼容影响。

例如 `import glaze;` 面向集成代码；`import config;` 面向配置使用者。一个业务模块只有在有意将下层接口纳入自身公共契约时才写 `export import ...;`：普通 `import` 不会把导入的名称传递给其消费者。图中独立模块可供直接导入，即使业务模块不重导出。公开了第三方类型或模板的业务接口还要检查其名称可见性、定义可达性和依赖的模块是否对消费者可用；仅能编译模块自身不够。

## 各模块的当前导出与消费边界

| 命名模块 | 核心导出目标 | 消费与业务边界 |
| --- | --- | --- |
| `glaze` | `read_kdl`、`write_kdl`、`read_beve_at`、`write_beve`、`Context` 等 | `policy`（`src/rules/`）负责 Nexus schema 与校验，不泄漏 Glaze 头文件 |
| `proxy.v4` | `pro::facade_builder`、`pro::proxy`、`make_proxy_inplace` 等 | `functional`（`src/functional/`）与 `relay-runtime` 在内部契约使用 |
| `capy` / `corosio` | `task`、`when_all`/`when_any`、`quitter`、`io_context`、`tcp_socket`、`udp_socket` 等（含 `epoll`/`uring`/`kqueue`/`iocp` `make_io_context`） | `protocols`、`dns`、`relay-runtime` 等仅通过命名模块交互 |
| `boringssl` | AEAD、摘要/MAC、HKDF、X25519/ECDSA/Ed25519、ML-KEM、RAND 与 X.509 验证能力 | `crypto` 包装资源及策略，不向业务公共接口暴露裸句柄 |
| `nghttp2`（可选） | 固定 libnghttp2 1.71.0 的 session、callbacks、帧提交及内存收发接口 | 供 `http2` 适配转换事件，不把 C 对象泄漏到公共 HTTP 模型 |

Capy 的任务与缓冲区、Corosio 的网络对象及两者的关系可参考[Capy 仓库](https://github.com/cppalliance/capy)和[Corosio 仓库](https://github.com/cppalliance/corosio)。这些上游入口会变化，不能替代对固定提交的验证。每个模块的完整公开名称、头文件、宏、链接需求和允许的使用层级，应在真正接入时随锁定提交记录；此表只规定首批能力与验收，不宣称现已满足。

## 已验证的私有 I/O

直接导出完整 `tcp_socket` 的实验触发 GCC 16 对 TU-local 类型的诊断，因此撤掉了相应模块。实验代理的 `relay` 接口只导出 Nexus 自有服务类型，上游头文件位于实现单元；已在 GCC 上通过本地端到端测试。它不是通用网络 facade，支持范围见 [SOCKS5 说明](../architecture/protocols/socks5-mixed.md)。

[`tests/io.cpp`](../../tests/io.cpp) 直接在测试实现中包含上游头文件，验证数据传输、预取消、读取挂起后取消、停止/恢复、关闭及连接失败，并对每次事件循环设置时间上限。对象关闭后需继续驱动 context，让完成项清理完毕；单纯 `stop()` 不等于取消挂起的工作。两个独立监听器的 accept 和一条本地读取同时挂起时，epoll 与 io_uring 均验证停止不完成操作、关闭各操作 owner 后重启并排空取消；不在同一监听器上并发 accept。若同时关闭读取对端，读取结果也可能是 EOF，不能依赖取消与 EOF 的先后。无补丁版本的测试覆盖 GCC/Linux epoll 和可选系统 liburing 的一小部分路径，尚未覆盖跨线程竞争、UDP、半关闭或其他平台。链接限制见[工作区构建](mcpp-workspace.md)。

## 已验证的 Glaze 最小示例

项目从 `hiykhello/glaze-kdl` 固定提交 `4e3230a6c1a3e665a6d81ca18e804291f894e876`（见 `3rdparty/mcpp-pins.json`）通过项目内 recipe 安装头文件。下列代码摘取其实验的接口；省略了用于触发增量构建的测试常量。`module;` 后的头文件处于 global module fragment，`using` 显式把选定名称导出到 Nexus 命名空间，并非导出整个 `glz` 命名空间。

```cpp
// 3rdparty/modules/glaze.cppm
module;
#include <glaze/kdl.hpp>
#include <glaze/beve.hpp>

export module glaze;

export namespace glaze {
    using ::glz::read_kdl;
    using ::glz::write_kdl;
    using ::glz::read_beve;
    using ::glz::write_beve;
}
```

实验特意用一个业务模块测试传递导出；这只展示机制：

```cpp
// 示例转发接口
export module config.example;
export import glaze;
```

工作区成员需要明确声明模块源和依赖，以便消费者获得实际的模块及链接输入；只导入名称不会自动提供静态库。

独立 consumer 只 `import config.example;`，不包含 Glaze 头，也不直接声明包依赖：

```cpp
// consumer.cpp
#include <string>
import config.example;

struct config { int port = 0; };

int main() {
    config original{};
    if (glaze::read_kdl(original, "port 443")) return 1;
    std::string data;
    if (glaze::write_beve(original, data)) return 2;
    config decoded{};
    if (glaze::read_beve(decoded, data) || decoded.port != 443) return 3;
    auto kdl = glaze::write_kdl(decoded);
    if (!kdl) return 4;
    config reparsed{};
    return glaze::read_kdl(reparsed, *kdl) || reparsed.port != 443 ? 5 : 0;
}
```

它读取 `port 443`，写 BEVE、读回、再写并读 KDL，字段值一致。另一个实验直接导入 `glaze` 也通过。修改模块导出接口后，当时的构建重编了 Glaze 模块、重导出模块和 consumer，重新链接并运行成功。当前工作区的增量构建还应通过 `tests/mcpp_module_incremental.py` 验证。

这个历史实验只覆盖单字段与指定提交/工具链。现在项目已固定同一提交，并在 Clang（`llvm@23.1.3`）C++26 模块中验证规则集子集的 KDL/BEVE 读写；复杂元数据、所有模板及其他编译器仍未全面验证。

## 上游模块、头文件与宏

当前锁定的 ngcpp/proxy 提供原生 `proxy.v4`；`nexus.ngcpp-proxy` 直接构建包内上游 `proxy/v4/proxy.ixx`，`functional` 与代理私有实现导入该模块，并在全局模块片段包含仅含宏的 `proxy/proxy_macros.h`。上游接口使用 `pro` 命名空间，未在公共业务接口中泄漏头文件。参见 [Proxy 4 Modules 文档](https://microsoft.github.io/proxy/modules_support/)。

可验证的重导出接口形态如下；它依赖构建图中另有提供 `proxy.v4` 的上游模块 target：

```cpp
// functional 示例转发
export module functional.example;
export import proxy.v4;
```

命名模块的导入不会把模块内的预处理宏导出到使用者。Proxy 的 `PRO_DEF_*` 宏如需在接口单元中定义 dispatch，可按其文档在该单元的 global module fragment 中显式包含选定提交提供的宏头；公开使用者确实需要自行展开宏时，也须在自己的翻译单元显式包含兼容头。对固定的项目契约，优先在模块内定义并导出所需 C++ 类型，让消费者只导入模块。不要假装导入命名模块可以让调用者的预处理器看到宏；header unit 的宏处理是另一套规则，不等同于命名模块。

头文件接入使用 global module fragment 并显式导出经过选择的名称；宏型常量只有在语义、类型和配置均确认后才能转换为具名 C++ 常量。宏也可能改变声明、布局或模板定义：同一依赖在模块、普通头文件和不同 target 间必须使用相容配置，验证重复包含、不同导入顺序、ODR 和类型身份。不要把上游头文件放在 `export { #include ... }` 中就宣称全部接口可靠可用；header unit、头文件与命名模块混用也须单独验证。

## C 库与静态链接

对 BoringSSL 和 nghttp2，模块层可以在 global module fragment 中包含上游 C 兼容头，再用显式 `using` 导出选择的类型和函数；具体表面及错误适配按提交验证。应遵守上游头文件自己的 C linkage 声明，不随意给包含 C++ 内容的整个头文件套一层 `extern "C"`。例如当前 BoringSSL 的 [AEAD 头](https://boringssl.googlesource.com/boringssl/+/HEAD/include/openssl/aead.h)本身声明了相应 C linkage，也包含 C++ 内容；这不是对未来固定提交的构建保证。

下面只是待验证的 BoringSSL 接口形态，展示原始能力如何导出；它不是完整密码接口：

```cpp
// 3rdparty/modules/boringssl.cppm 示意
module;
#include <openssl/aead.h>

export module boringssl;
export namespace boringssl {
    using ::EVP_AEAD;
    using ::EVP_AEAD_CTX;
    using ::EVP_aead_aes_128_gcm;
    using ::EVP_AEAD_CTX_new;
    using ::EVP_AEAD_CTX_free;
    using ::EVP_AEAD_CTX_seal;
    using ::EVP_AEAD_CTX_open;
}
```

nghttp2 可以采用同样的选择性导出方式；使用者和 `http2` 所需类型、回调与函数须共同验证，并确保选定版本提供 `mem_recv2`/`mem_send2`。

业务适配层仍需遵守库的资源及安全语义：释放与创建配对，检查返回值，管理密钥、nonce 和生命周期。对 nghttp2，[`mem_send2` 文档](https://nghttp2.org/documentation/nghttp2_session_mem_send2.html)明确输出指针的有效期受下一次发送调用限制；适配层须在到期前完成处理或复制，并结合背压管理。仅把 C 函数导出并不提供这些约束。

静态库通常要在最终可执行文件链接时提供；模块 BMI 中的声明不能取代 `libcrypto` / `libnghttp2` 或其必要系统库。工作区的包使用要求和依赖要正确传递，链接顺序、静态链接项、平台宏及配置均需实测。临时模拟 C 静态库实验中，模块依赖正确传递时，无头文件、仅导入模块的独立 consumer 编译、链接、运行成功；这是**模拟库**，并非真实 BoringSSL 或 nghttp2 的验证。

## 验收与变更

1. **独立消费**：每个启用的模块有独立 target，仅通过模块使用该表面；需要宏时按上节单独测试显式兼容头，不把宏说成模块导出。测试导出类型、常量、模板、重载、实际调用与失败路径，并验证模块间传递值及类型身份。
2. **功能行为**：Glaze 测两个格式双向转换及错误；proxy 测 facade 拥有/借用；Capy/Corosio 测协程、I/O、取消和析构；真实 libcrypto 测已知答案及失败；可选 nghttp2 测内存收发、回调和 session 生命周期。
3. **依赖与裁剪**：检查模块扫描图、公开/私有 target 关系、静态库及系统项、编译命令、最终链接 map；核对仅引入所选 libcrypto，不引入 libssl 或其他 TLS 实现。关闭 HTTP/2 时 nghttp2 不进入目标图或产物。
4. **构建与重建**：分别验证干净构建、跨 target 导入和必要的 `export import`；修改接口与实现后检查实际重建、重新链接及运行。变化依赖提交、宏、工具链或标准档位时重建受影响模块及消费者。
5. **可复现性**：记录每项依赖及传递依赖的完整提交、许可证、构建参数、mcpp/编译器/标准库、C++ 档位和目标平台；验证不同路径、空缓存及准备缓存后的离线构建。BMI/CMI 属于具体工具链与构建配置的编译产物，不作为跨编译器、跨版本、跨配置的通用 ABI 分发；换工具链或相关参数时重新生成。

上述为持续验收要求；当前 Glaze、Capy、Corosio 和固定 nghttp2 的有限项目目标已通过对应测试，其余依赖仍需继续验证。依赖的来源、锁定、升级与分发要求仍以[工作区构建](mcpp-workspace.md)为准。

2026-10-29（历史里程碑）：新增 BoringSSL libcrypto 封装模块（现已去前缀为 `boringssl`），导出当前使用的 libcrypto 类型与函数，项目代码通过模块导入。当前全仓统一使用 Clang（`llvm@23.1.3`）与静态 `libc++` 构建并共用 `std` BMI。
