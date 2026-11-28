# uTLS 指纹引擎与浏览器基线演进架构

自研 TLS 将 ClientHello 的协议语义与可选浏览器 profile 分离。profile 负责扩展集、顺序、GREASE、套件/签名排序与 padding，证书验证与密钥调度独立执行；TCP、QUIC 与 REALITY 共享同一编排器与密钥交换实现，**不链接任何第三方 uTLS 运行时库**，且严格遵循「**只通告真实实现的 TLS 能力，绝不构造无法完成握手的伪扩展**」原则。

---

## 1. 单一真源分层设计

Nexus 将指纹命名、浏览器线特征数据与握手编排彻底解耦为三层，使浏览器大版本跟进从“全仓四处手改”收敛为“单表数据更新 + 自动化审计验证”：

| 层次 | 源码模块 | 职责 |
| --- | --- | --- |
| **身份与别名真源** | `utility.tls_fingerprint`（[tls_fingerprint.cppm](../../src/utility/tls_fingerprint.cppm)） | 定义唯一枚举 `TlsFingerprintId`（`config::TlsFingerprint` 与 `tls::Fingerprint` 均为其类型别名，编译期杜绝漂移）、版本基线元数据、KDL 严格别名表及外部订阅归一化器 `normalize_external_tls_fingerprint()`（兼容 `chrome_120`/`chrome_auto`/`firefox_148`/`safari_26_3`/`randomized` 等外部写法，被 [kdl_emit.cpp](../../src/provider/kdl_emit.cpp) 与 [workspace_emit.cpp](../../src/provider/workspace_emit.cpp) 共用）。 |
| **声明式规格表** | `tls.browser_profiles`（[browser_profiles.cppm](../../src/tls/browser_profiles.cppm)） | 以 `constexpr BrowserPresetSpec` 声明各浏览器的基线版本、GREASE 位置（含 `signature_algorithms` 首部 GREASE）、扩展乱序/固定顺序表、TLS 1.3/1.2 套件顺序、签名列表、证书压缩算法、是否含 `P-521`、`record_size_limit`、ALPS、GREASE ECH 与 TCP 最小 padding。 |
| **编排与扩展构造** | `tls.fingerprint`（[fingerprint.cpp](../../src/tls/fingerprint.cpp)、[fingerprint_profiles.cpp](../../src/tls/fingerprint_profiles.cpp)）与 `tls.browser_extensions`（[browser_extensions.cppm](../../src/tls/browser_extensions.cppm)） | 纯数据驱动生成 TCP/QUIC ClientHello，结合 `tls.hello_config`、真实 `X25519` / `X25519MLKEM768` 密钥对、动态 `required_signature`（如 REALITY 所需 `0x0807`）与拒绝采样 Fisher-Yates 扩展乱序，不新增协程、虚派发或额外堆对象所有权。 |

---

## 2. 当前浏览器基线矩阵

配置中推荐使用家族短名（自动跟踪最新已验证基线），同时向后兼容带版本号别名：

| 家族短名 | 当前基线 | 兼容别名 | 核心线特征（全部由真实 TLS 状态机支撑） |
| --- | --- | --- | --- |
| `chrome` | `chrome-158` | `chrome-133`, `chrome-155`, `chrome-158` | 对照 Chromium `main`（`ssl_client_socket_impl.cc` 与 `root_store.textproto`）核验：套件/组/版本/KeyShare/扩展首尾/`signature_algorithms` GREASE、后量子签名 `ML-DSA-44/65/87`、28 项 `trust_anchors (0xca34)`、Brotli 证书压缩、ALPS `0x44cd`（TCP h2）、GREASE ECH、扩展内部随机乱序、TCP 最小 517B padding |
| `edge` | `edge-158` | `edge-133`, `edge-155`, `edge-158` | 对齐 Chromium 158 BoringSSL 栈（与 `chrome-158` 一致） |
| `firefox` | `firefox-161` | `firefox-135`, `firefox-148`, `firefox-161` | 对照实机 Mozilla Firefox 161.0 核验：无 GREASE、3 槽初始 KeyShare（`X25519MLKEM768 + X25519 + P256`）、`X25519MLKEM768 / X25519 / P256 / P384 / P521`（已不含 FFDHE）、`zlib/brotli/zstd` 三算法证书压缩、ChaCha 优先套件序、`record_size_limit=16385`、`delegated_credentials`、GREASE ECH 与 17 项固定扩展序 |
| `safari` | `safari-26.3` | `safari-18`, `safari-26`, `safari-26.3` | AES-256-GCM 优先 TLS 1.3/1.2 套件序、GREASE、`X25519MLKEM768 + P-521`、zlib 证书压缩、5 项 TLS 1.3 签名与 Apple 15 项固定扩展序 |
| `ios` | `ios-26.3` | `ios-14`, `ios-18`, `ios-26`, `ios-26.3` | 对齐 iOS 26 WebKit / `Network.framework`（与 Safari 26.3 TLS 栈一致） |
| `android` | `android-16` | `android-11`, `android-16` | 现代 Conscrypt TLS 1.3 + AEAD TLS 1.2 套件序、PQ 混合曲线支持与固定扩展序 |

另有非浏览器策略：`native`、`tls13-grease`、`tls13-randomized`、`random`（从各浏览器与随机形态池中按 CSPRNG 抽样）以及显式 `tls12`（仅限支持的 TCP 出站）。

---

## 3. 离线自动审计与版本跟进流程

仓库内置零外部依赖的离线审计链路，由 C++ 线字节导出器 [utls_dump.cpp](../../tests/utls_dump.cpp)（target `utls-dump`）与 Python 审计工具 [audit-utls.py](../../scripts/audit-utls.py) / [utls_wire.py](../../scripts/utls_wire.py) 组成。

### 3.1 差异自动分流模型

审计脚本对 Nexus 实际编码出的 ClientHello 字节与参考样本做逐字段比对（含 JA4），并将所有差异明确归为两类：

- **`[DATA DRIFT]`（数据漂移）**：参考浏览器调整了 Nexus **已支持**的能力（如套件/签名排序、扩展顺序、证书压缩算法列表、`P-521` 开关、`signature_algorithms` GREASE、RSL 数值、ALPS codepoint）。此类差异只需修改 [browser_profiles.cppm](../../src/tls/browser_profiles.cppm) 与 [tls_fingerprint.cppm](../../src/utility/tls_fingerprint.cppm) 即可零风险同步。
- **`[CAPABILITY GAP]`（能力缺口）**：参考浏览器通告了 Nexus TLS 状态机**尚未实现**或有意不提供的协议项（如历史 CBC/3DES/RSA-kex 套件或 SHA-1 签名）。此类差异会被明确汇报但不触发数据漂移告警，严禁通过拼假字节掩盖。

### 3.2 标准升级步骤（Runbook）

1. **构建导出器**：
   ```bash
   mcpp run --features profile-linux-uring,test-bins batch94c-utls-unit
   ```
2. **运行上游对照或实机浏览器抓包审计**：
   ```bash
   # 对照上游 refraction-networking/utls 最新 master（或省略 --fetch-upstream 使用本机 Go 缓存）
   python3 scripts/audit-utls.py --fetch-upstream --fail-on-data-drift

   # 对照本机真实浏览器发出的 ClientHello 抓包（示例：Firefox）
   TMPPROF=$(mktemp -d)
   python3 scripts/audit-utls.py --capture-profile firefox \
     --capture-cmd "firefox --headless --no-remote --profile $TMPPROF https://127.0.0.1:{port}/" \
     --fail-on-data-drift
   rm -rf "$TMPPROF"
   ```
3. **收敛同步**：
   - 若仅出现 `DATA DRIFT`：更新 [browser_profiles.cppm](../../src/tls/browser_profiles.cppm) 的对应规格项，并在 [tls_fingerprint.cppm](../../src/utility/tls_fingerprint.cppm) 推进基线标签同时保留旧版本别名；
   - 若评估需要补齐某项 `CAPABILITY GAP`：先在 `src/tls/` 实现完整状态机与握手校验，再在 `audit-utls.py` 能力集合与 `browser_profiles.cppm` 中开启。
4. **回归验证**：运行 `batch94c-utls-unit`、`tls-fingerprint`、`config-protocols-ext-test` 与 `audit-utls.py --fail-on-data-drift`，确认全部通过且 0 数据漂移。

---

## 4. 关键协议语义与实现边界

- **混合后量子与多槽 KeyShare**：`X25519MLKEM768`（`0x11ec`）按 [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) 编码（客户端 ML-KEM-768 公钥 1184B 在前、X25519 32B 在后；服务端密文 1088B 在前、X25519 32B 在后）。`ClientHelloExchange` 支持最多 3 个初始真实 KeyShare（覆盖 Firefox 161 的 `X25519MLKEM768 + X25519 + P-256`），HRR 保持随机数与扩展顺序并按新 share 重算 padding。
- **后量子签名（ML-DSA-44/65/87）**：基于 BoringSSL `libcrypto` 内置的 `EVP_PKEY_ML_DSA_{44,65,87}` 完整支持 TLS 1.3 `0x0904`/`0x0905`/`0x0906` 的 `CertificateVerify` 签发与验签。
- **TrustAnchors（`0xca34`）**：按 `draft-ietf-tls-trust-anchor-ids` 在 Chrome/Edge ClientHello 通告 Chrome Root Store ID 列表，并在 `EncryptedExtensions` 校验解析服务端回传列表（拒绝畸形或未通告的扩展），证书链校验仍严格以本地配置信任锚为准。
- **GREASE（[RFC 8701](https://www.rfc-editor.org/rfc/rfc8701)）**：由 CSPRNG 采样，保证首尾扩展 GREASE 互异且不与其他扩展冲突；不通过静默移除 GREASE 重试来掩盖互操作失败。
- **证书压缩（[RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html)）**：启用 `tls-certificate-compression` 特性时支持 zlib、Brotli 与 Zstandard 解压；压缩消息原文进入 transcript，解压后长度须与声明严格一致并走完整 PKI 校验。关闭特性时各 profile 自动省略扩展 `27`。
- **ALPS、GREASE ECH 与委托凭据**：Chrome/Edge 的 TCP `h2` ALPS 以 EncryptedExtensions 进入 Finished transcript；显式启用真实 ECH 时自动抑制 GREASE ECH；Firefox 委托凭据当前覆盖 ClientHello 声明，服务端选用委托凭据时的验签仍属独立待实现项。
- **同连接 TLS 1.3/1.2 与 1-RTT 恢复**：浏览器 TCP 形状由同一 ClientHello 协商 TLS 1.3 或 TLS 1.2（四个 ECDHE AES-GCM + 两个 ECDHE ChaCha20-Poly1305）；QUIC 形状仅协商 TLS 1.3 并写入真实 transport parameters。普通物理 TCP 出站维护 32 张按目的端点、验证身份、信任锚与 ALPN 隔离的恢复票据，详见 [TLS 会话恢复](tls-resumption.md)。
- **不可仅凭 JA3/JA4 断言拟真**：ALPN 仅通告真实支持的协议（未实现 HTTP/2 时不可宣称 `h2`），SNI、主机名校验与信任根完全独立于 fingerprint 配置。
