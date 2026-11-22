# 0007：BoringSSL libcrypto 底座与 Linux kTLS 方向

日期：2026-10-27。状态：密码底座和 kTLS 方向已确定；源码版本、集成及运行效果待验证。

## 决定

本记录修订[决策 0002](0002-self-developed-network-stack.md)中完全排除 BoringSSL 的约束：Nexus 自研 TLS 协议状态机与 ClientHello profile，采用**静态 BoringSSL libcrypto** 作为密码底座，不使用 BoringSSL/OpenSSL `libssl`、系统动态 OpenSSL 或其他第三方 TLS 实现。密码原语、证书处理和平台随机能力仍须核验；这项决策不声称选定提交覆盖项目需要的所有算法。

Linux 计划在自研 TLS 握手后评估 kTLS 接管符合条件的记录收发，再有条件地使用 `splice()`；自研 TLS 不被内核握手取代。密码库、TLS 状态机和 kTLS 各自职责见[底座评估](../architecture/boringssl-libcrypto.md)、[TLS](../architecture/tls.md)及[kTLS 设计](../architecture/ktls.md)。

## 接入与验证

- 依赖构建固定完整提交，只构建并静态链接经确认的 crypto 目标；Linux 实验固定提交 `e651545da6e26e1f4420723a3b69a78ed1b9c51d`，GCC 16 已构建静态 crypto 并验证 SHA-256、AES-GCM 已知答案；其他平台及能力仍待验证。依赖证据需检查构建参数、平台库、链接输入、符号和最终产物，不能仅依赖动态库列表。
- 自研 TLS 状态机拥有并派生 traffic secret、key、IV 与记录序列号；libcrypto 提供相应密码运算，不自行保存或导出整个 TLS 会话。验证锁定提交的原语覆盖、证书校验、密钥清理和已知答案，包括 SS-2022 的 BLAKE3 等仍待确定能力。
- kTLS 的 TLS ULP、TX/RX 密钥与记录序列需要正确交接；仅在安全可回退的状态下回到用户态处理。部分方向已接管、KeyUpdate 或记录状态无法恢复时可能必须关闭连接，不能承诺任何失败都能无缝降级。
- `-fno-exceptions`、`-fno-rtti`、LTO 及汇编选项须按所选提交、目标平台和工具链验证，不假定所有依赖可全局使用相同开关。
- 二进制体积、各密码算法支持、握手互操作、TLS 性能、CPU 开销及 kTLS/splice 收益均须针对 Nexus 实测；当前没有正式项目的体积数据或性能基准，也不能将 kTLS 等同于任意网卡硬件卸载。
