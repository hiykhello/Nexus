# TCP 转发循环对照

`benchmark.py` 交错运行两个明确指定的 Nexus 二进制，对比同机回环中的双向流量。它先通过 SOCKS 建立连接并完成预热前缀，再同时上传和接收固定载荷；真实目标逐段回送，上传和下载分别核对 SHA-256。每次以新进程运行一个单 worker 代理，记录完整流量耗时、代理 CPU tick 和 RSS 高水位。每对样本轮换先后顺序，预热轮、成功及失败记录均写入 JSONL；失败会终止该次命令。CPU 亲和性将代理与驱动、固定版本 sing-box 分开，运行期间不应并行编译或执行其他基准。

模式 `direct` 使用 SOCKS 入站直连；`ss-direct`、`vless-direct` 使用 sing-box 客户端连接对应入站；`ss-ss` 和 `vless-vless` 另外使用 sing-box 出口，覆盖入站到协议出站的链路。程序检查固定 sing-box revision，记录两份二进制和关键源码的摘要、工具版本、CPU、调度范围、内核、负载、回环 MTU 与运行时间。`--mib` 为每方向字节数，必须以未优化测试及独立网络回归验证正确性，再对相同工具链、配置和依赖构建的 release 程序采样。

例如：

```sh
python3 experiments/stream-relay/benchmark.py <baseline> <candidate> <new-output.jsonl> \
  --mode ss-ss --rounds 4 --mib 256 --proxy-cpu 2 --peer-cpus 6,8,12,14 \
  --baseline-tree <baseline-source> --candidate-tree <candidate-source>
```

输出路径必须不存在。CPU 编号仅为示例，应先检查允许的亲和性及物理核心拓扑；也应记录实际编译命令、工作区差异和可能的共享主机负载。这里使用 Python 驱动及同机 TCP，单条流受对端、内核和调度影响；CPU tick 有系统时钟粒度，RSS 包含进程其他内存。这些结果不能推断跨机吞吐、连接并发、公平性、尾延迟或全部硬件上的性能，也不能用一次较快的样本证明无回退。

`pre-unification.patch` 保存本次两个中继模块的前后差异。可在与记录中 candidate 源码摘要一致的隔离副本内执行 `patch -R -p1 < experiments/stream-relay/pre-unification.patch` 重建对照源码；不要在正在工作的源树中逆向应用。其他源码、配置、依赖和工具链也须保持一致。

选端口时同时检查 TCP 和 UDP，并避开 Linux 的临时端口范围：SS 入站会绑定同号 UDP。已保留早期未检查 UDP 的失败样本，失败不计入对照；更改驱动后应重新采集该场景的完整轮次。

## 2026-10-31 本机初筛

使用 i9-13900H、Linux 7.3.0-4-cachyos、glibc 2.44、GCC 16.2.1 和 mcpp 2026.10.31.3；release 实际参数为 `-O2 -DNDEBUG`，启用 `ss2022,vless,http2-tls`、io_uring 和相同锁文件。隔离基线的 `src` 与候选只相差补丁中的两个模块。代理固定 CPU 2，驱动和 sing-box 使用 CPU 6、8、12、14，CPU governor 为 `performance`；主机未隔离，起始负载见每份记录。每方向 2 GiB，先各预热一次，再交错八对；每次校验双向载荷。两个程序的跨协议链路、Vision 延迟回复和 HTTP 上传正确性回归在测量前均通过。

下表时间是每方向 2 GiB 双向传输耗时的中位数；比例是同轮候选耗时除以基线耗时的中位数，括号为八对的范围。原始样本包含每次 CPU tick、RSS 和环境；不完整的一次 SS 链路尝试单独保留。

| 场景 | 基线 / 候选中位数 | 配对比例中位数（范围） | 原始记录 |
| --- | ---: | ---: | --- |
| SOCKS 直连 | 2.016 / 1.865 秒 | 0.953（0.845–1.176） | [direct](results/20261031-long-direct.jsonl) |
| SS 入站直连 | 2.142 / 2.151 秒 | 0.991（0.923–1.096） | [ss-direct](results/20261031-long-ss-direct.jsonl) |
| VLESS 入站直连 | 2.298 / 2.323 秒 | 1.008（0.955–1.087） | [vless-direct](results/20261031-long-vless-direct.jsonl) |
| SS 入站到 SS 出站 | 2.907 / 2.916 秒 | 1.005（0.989–1.056） | [ss-ss](results/20261031-long-ss-ss-retry.jsonl) |
| VLESS 入站到 VLESS 出站 | 2.950 / 2.961 秒 | 1.004（0.965–1.040） | [vless-vless](results/20261031-long-vless-vless.jsonl) |

早期 256 MiB 短样本和 [SS 双隧道启动失败](results/20261031-long-ss-ss.jsonl)也保留。失败由测试挑选的同号 UDP 端口被占用引起；修正选端口后完整重跑。此次长样本未显示稳定的大幅回退，但配对波动和共享主机负载仍限制结论，尤其不能证明小流延迟、多连接公平性、跨机网络或其他 CPU 没有变化。
