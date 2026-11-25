# Nexus 发行打包与系统集成清单

本目录维护 Linux（systemd）、OpenWrt 路由器与交互式 Shell 补全的正式部署资源。

## 1. Linux systemd 单元

- [nexus.service](systemd/nexus.service)：单实例服务，默认读取 `/etc/nexus/config.kdl`。
- [nexus@.service](systemd/nexus@.service)：模板多实例服务，按 `%i` 隔离配置（`/etc/nexus/%i.kdl`）与 `StateDirectory` / `CacheDirectory` / `RuntimeDirectory`。

关键安全与运维特性：

- `DynamicUser=yes` + 最小能力集（`CAP_NET_BIND_SERVICE`、`CAP_NET_ADMIN`）与严格文件系统只读保护；
- `ExecStartPre` 与 `ExecReload` 均先运行 `nexus check --config ...`，配置非法时保留旧实例继续服务；
- 支持通过 `scripts/package-linux-release.sh` 一键组装包含二进制、systemd 单元、Shell 补全与 `SHA256SUMS` 的发布压缩包。

```bash
# 安装单实例服务并热重载
sudo install -Dm755 nexus /usr/bin/nexus
sudo install -Dm644 packaging/systemd/nexus.service /etc/systemd/system/nexus.service
sudo systemctl daemon-reload
sudo systemctl enable --now nexus
sudo systemctl reload nexus
```

## 2. OpenWrt 打包与 `procd` 自愈

- [nexus.init](openwrt/nexus.init)：基于 `USE_PROCD=1` 的服务脚本，启动与重载前调用 `nexus check --config`；采用 `respawn 3600 5 5` 自动拉起，并将易失状态与缓存隔离至 `/tmp/nexus` 以保护 SquashFS/Flash。
- [Makefile](openwrt/Makefile)：兼容 OpenWrt 25+（`.apk`）与 OpenWrt 24 及以下（`.ipk`）的打包模板，推荐搭配 `aarch64-linux-musl` / `x86_64-linux-musl` 纯静态内核产物使用。

## 3. macOS `launchd` 与 Windows SCM 服务管理

- 内置 `nexus service install|uninstall|start|stop|restart|status` CLI：在 Linux 上生成并管理 `systemd` 单元，在 macOS 上生成并引导 `launchd` `.plist`（见 [io.nexus.proxy.plist](launchd/io.nexus.proxy.plist)），在 Windows 上通过 Win32 SCM 注册/启停服务（见 [install-service.ps1](windows/install-service.ps1)）。
- 内置 `nexus system-proxy status|on|off [--dry-run] [--shell-env]` CLI：统一管理系统代理（Windows WinINet 注册表、macOS `networksetup`、Linux GNOME `gsettings` / KDE `kwriteconfig` 或 POSIX Shell 环境变量）。
- 配置转换与 Provider 运维：`nexus convert-config` 与 `nexus provider inspect|sync`。

## 4. Shell 自动补全

- Bash：[completions/nexus.bash](completions/nexus.bash) → `/usr/share/bash-completion/completions/nexus`
- Zsh：[completions/_nexus](completions/_nexus) → `/usr/share/zsh/site-functions/_nexus`
- Fish：[completions/nexus.fish](completions/nexus.fish) → `/usr/share/fish/vendor_completions.d/nexus.fish`

## 5. Arch Linux 打包（`PKGBUILD`，默认 `io_uring`）

- [arch/PKGBUILD](arch/PKGBUILD)：默认启用 `NEXUS_FEATURES=profile-linux-uring` 构建旗舰 Linux `x86_64` `io_uring` 发行二进制，并在 `check()` 中自动校验 `--help`、`liburing.so.2` 动态链接以及 PIE / Full RELRO / NX `GNU_STACK` / `__stack_chk_fail` ELF 加固属性。
- 安装路径覆盖 `/usr/bin/nexus`、`/usr/include/nexus/core_c_api.h`、`/usr/lib/systemd/system/nexus{,@}.service`、Bash/Zsh/Fish 补全脚本与 `/usr/share/doc/nexus/README.md`。
- GitHub Actions `arch-pkg` 任务在 `archlinux:base-devel` 容器中自动构建、校验并发布 `nexus-*.pkg.tar.zst` 与 `SHA256SUMS` 产物。

```bash
# 从本地仓库直接构建并安装（默认 profile-linux-uring）
cd packaging/arch && makepkg -si

# 切换为 epoll 配置构建
NEXUS_FEATURES=profile-linux-epoll makepkg -f

# 复用已构建的 Release 二进制快速重新打包
NEXUS_PREBUILT_BIN=/path/to/nexus makepkg -f
```
