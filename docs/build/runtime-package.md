# Linux 系统模式运行包

`mcpp pack nexus --mode system` 生成的运行包使用目标机器提供的动态库；与 `vendored` 等模式的依赖边界不同。包内 `nexus` 是启动脚本，`bin/nexus` 是程序。解压后可从包目录运行 `./nexus run 1080`，或指定包内配置示例，例如 `./nexus run --config docs/configuration/examples/socks5.kdl`。配置示例的功能范围见[示例说明](../configuration/examples/README.md)。

当前验证环境为 Linux x86-64，GCC 16.2.1 和系统 glibc；启用默认 io_uring 的程序动态依赖 `liburing.so.2`，即使运行时选择其他后端也需要动态加载器找到该库。本机此前构建的系统模式程序还动态依赖 glibc、libm 和 libgcc_s，程序直接引用的最高 glibc 符号版本为 2.38。这是该次构建的结果，不保证其他工具链、库或目标机器具有相同的最低要求。

目标机器应有与程序及其动态库兼容的加载器和运行库。可对待分发的具体文件运行 `readelf -l bin/nexus`、`readelf -d bin/nexus` 和 `readelf --version-info bin/nexus` 检查解释器、直接依赖与符号版本；在目标环境还需检查依赖库本身的要求。当前 mcpp 在该系统模式包内生成的 `HOST-REQUIREMENTS` 记录了 glibc 要求，但不会完整列出本次程序所需的系统 liburing。包的依赖及可运行性应以目标环境的实际验证为准。

2026-11-19 的代理内核对照通过 `mcpp/epoll` 包装入口构建 Linux x86-64 的 epoll 和 io_uring release 组合。两种组合启用 SRS，直接依赖 `libz.so.1`，io_uring 组合还依赖 `liburing.so.2`。本次 io_uring 包的 `HOST-REQUIREMENTS` 只列出 glibc ≥ 2.38，直接动态库清单以包内 ELF 为准。构建选项、运行证据和样本位置见 [项目进度](../progress.md) 与 [Linux 验收记录](../planning/proxy-kernel-linux-validation.md)。
