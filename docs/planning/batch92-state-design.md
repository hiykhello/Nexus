# 第 92 批实现蓝图 · 统一持久化引擎（`state`）

更新：2026-11-20。本蓝图直接承接[持久化对象清单](../architecture/persistence-inventory.md)、[缓存与持久状态](../architecture/state-and-cache.md)与[状态数据库设计](../architecture/database.md)，将设计草案冻结为第 92 批可直接编码落地的 C++26 Modules 架构。所有新模块与命名空间**禁止使用 `nexus` 前缀**。

## 1. 模块划分（`src/state/`）

每个源文件目标 ≤ 300 行（硬上限 500 行），统一导出 `namespace state`：

| 模块 | 文件 | 职责 |
| --- | --- | --- |
| `state.core` | `src/state/core.cppm` | `Tier`、`CommitState`（`accepted`/`visible`/`committed`/`uncertain`）、`StateError`（含阶段/OS `errno`/是否已替换）、`EnvelopeHeader`（magic/format/schema/owner/BLAKE3 校验与编码）、`ClearEpoch` |
| `state.owner` | `src/state/owner.cpp{,m}` | `InstanceLock`（复用 `selector_state.cpp` 的 `O_DIRECTORY\|O_NOFOLLOW` + `0700` + 属主 + 非阻塞 `flock` + `nlink==1` 校验）与 `StateOwner`（单一后台 I/O 线程 + 有界拥有型命令队列 + 内存硬预算 + `drain(deadline)`） |
| `state.snapshot` | `src/state/snapshot.cpp{,m}` | Tier 1 原子文件快照引擎（`O_CREAT\|O_EXCL\|0600`、`write_all`、`fsync(stage)`、`renameat`、`fsync(dir)`，精确区分 `committed` 与 `uncertain`；损坏隔离为 `.corrupt.<ts>` 不静默覆盖）；承载 `selectors.state` 与 `net-journal` |
| `state.ruleset_cache` | `src/state/ruleset_cache.cpp{,m}` | Tier 3 远程规则集内容寻址缓存（`/var/cache/nexus/<instance>/rulesets/`）：`<sha256>.blob` + 原子 `index.state`；缓存键强制包含 `canonical_url + format(kdl\|beve\|srs) + parser_version`（避免格式切换命中旧缓存）；损坏清理若 `unlink` 失败必须上报真实 `rm_err` |
| `state.fakeip` | `src/state/fakeip.cpp{,m}` | Tier 2 FakeIP 持久化存储：默认 `CrashMode::range_reserve`（每次预留 N=256 地址段先落盘 1 次 `fsync`，段内映射走内存 + 异步批写 WAL + 定期 BEVE Checkpoint，崩溃后跳过未落盘段绝不复用）；可选 `CrashMode::per_mapping` 强逐条落盘 |
| `state.dns_cache` | `src/state/dns_cache.cpp{,m}` | Tier 3 多视图 DNS 缓存持久化：将现有 `NXDNS2` 演进为按视图语义指纹（上游类型/身份/策略哈希）分片的有界快照，支持加密上游与外部规则集视图，兼容 `NXDNS1/NXDNS2` 迁移 |
| `state` | `src/state/state.cppm` | 聚合导出与可选 `ngcpp/proxy` `StoreFacade`（为后续可选 `state-sqlite` 特性预留零虚函数接入点） |

## 2. 统一二进制封装头（`EnvelopeHeader`）

所有文件级快照与 WAL 均以固定 64 字节小端头起始，读取前先验魔数、版本、大小上限与 BLAKE3-256：

```text
Offset  Size  Field
0       6     magic ("NXST01" / "NXRS01" / "NXFP01" / "NXDN03")
6       2     schema_version (uint16 LE)
8       1     tier (1=authority, 2=lease, 3=cache, 4=secret)
9       1     flags (bit0=compressed, bit1=encrypted/mac)
10      2     reserved (must be 0)
12      4     payload_bytes (uint32 LE, bounded per tier)
16      8     revision (uint64 LE, monotonic)
24      8     clear_epoch (uint64 LE, invalidation barrier)
32      32    blake3_256(header[0..32] || semantic_fingerprint || payload)
```

- 未知 `schema_version`：Tier 1/2/4 拒绝启动并保留原文件；Tier 3 记录告警、隔离旧文件并冷启动。
- `clear_epoch` 屏障：任何清缓存或视图切换操作递增原子 `clear_epoch`，后台 `StateOwner` 线程跳过所有 `req.epoch < current_clear_epoch` 的在途旧批次，杜绝清空后旧批复活。

## 3. FakeIP `range-reserve` 段预留协议

1. **段元数据（权威同步）**：`fakeip.meta` 保存 `cidr`、`exclude_cidrs`、`owner_id`、`cursor_reserved_end`、`generation`。每次分配器耗尽当前已预留段时，先同步推进 `cursor_reserved_end += 256` 并 `fsync` 落盘后，才允许对外答复新段内的 FakeIP。
2. **映射日志（异步批写 + Checkpoint）**：新映射先入内存双表（domain↔ip），异步追加到 `fakeip.wal`（同键合并、按 250ms 或 64 条批刷）；WAL 超过阈值（如 2 MiB）时由 `StateOwner` 重写完整 `fakeip.ckpt` 并原子替换截断 WAL。
3. **崩溃恢复**：先校验 `cidr`/`exclude`/`owner` 完全匹配，重放 `ckpt + wal`（忽略尾部半条截断记录），把分配游标设到 `max(replayed_max, cursor_reserved_end)`——保证**崩溃丢失的未落盘映射绝不会被立即重新分配给其他域名**，未知地址反查返回明确失败。

## 4. KDL 配置与 CLI 运维入口

```kdl
state {
    directory "/var/lib/nexus/default"       // Tier 1 & 2 权威/租约目录 (0700)
    cache-directory "/var/cache/nexus/default" // Tier 3 可重建缓存目录 (0700)
    fakeip-crash-mode "range-reserve"        // "range-reserve" (default) | "per-mapping"
    dns-cache-max-bytes 4194304
    ruleset-cache-max-bytes 67108864
}
```

新增运维子命令：
- `nexus state inspect --config ...`：只读输出各 Tier 版本、条目数、字节占用、最近提交时间与错误计数（不含域名与凭据）。
- `nexus state clear-cache --config ... [--dns] [--rulesets]`：仅清 Tier 3，绝不触碰 `selectors.state`、`fakeip` 与 `net-journal`。
- `nexus state reset --config ... --target fakeip|selectors --confirm`：先备份旧目录再重置。

## 5. 分切片验收矩阵（92A / 92B / 92C）

- **92A**：`state.core` + `state.owner` + `state.snapshot` 单元测试 + `SIGKILL` 故障注入（写前/rename 前/dir-fsync 前）、双实例 `flock` 冲突、symlink/非 `0700` 拒绝、迁移现有 `selector_state.cpp` 复用 `state.snapshot`。
- **92B**：`state.ruleset_cache` 接入 `rule_fetch.cpp` 与规则订阅：验证 ETag/304、离线冷启动、**`kdl ↔ beve ↔ srs` 切换格式必失效重拉（`#4136`）**、损坏 blob 隔离及只读目录删错如实返回（`#4727`）。
- **92C**：`state.fakeip` + `state.dns_cache` 接入运行时：验证 `range-reserve` 与 `per-mapping` 两种模式崩溃重启、地址段不复用、加密上游/外部规则集多视图 DNS 快照恢复、`clear_epoch` 防旧批复活与双后端集成回归。
