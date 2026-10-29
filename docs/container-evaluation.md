# 容器评估

评估日期：2026-10-29。结论：PLF 二选一时优先考虑 `plf::hive`，因为本项目使用 C++26，接口更接近未来的 `std::hive`；但先不加入依赖或批量替换容器。`ankerl::unordered_dense` 是另一类容器，可在合适的键值查找路径试用，不能替代需要稳定对象地址的存储。

| 方案 | 适用条件 | 主要限制 |
| --- | --- | --- |
| `plf::hive` | 元素需要稳定地址，插删频繁，遍历顺序不重要 | 插入位置不固定；删除元素后其引用失效；重排、缩容等操作需要单独核对失效规则。不是标准库实现 |
| `plf::colony` | 需要旧版 C++ 支持或它独有的接口 | 与标准接口差异更大；本项目目前没有发现需要这些差异的场景 |
| `ankerl::unordered_dense::map/set` | 以键查找为主，元素可移动，调用方不跨修改保存引用或迭代器 | 默认容器增长时元素可搬迁，删除时也可能搬迁其他元素；并非 `std::unordered_map` 的无条件替代 |
| `ankerl::unordered_dense::segmented_map/set` | 需要插入时稳定地址且可以接受分段存储 | 删除仍可能搬迁其他元素；不能把插入稳定误认为完整生命周期稳定 |

PLF 的 [hive 项目](https://github.com/mattreecebentley/plf_hive)明确说明它是 [colony](https://github.com/mattreecebentley/plf_colony) 的分支，追随标准提案，并列出了接口差异。C++26 `std::hive` 的设计见 [WG21 P0447](https://wg21.link/p0447)。两个 PLF 实现均在 `std` 命名空间加入函数重载，这与标准对用户向 `std` 添加声明的限制存在兼容风险，尤其应在未来标准库引入 `std::hive` 或升级工具链时重新检查；不能假定 `plf::hive` 与 `std::hive` 是 ABI 或源码完全兼容的替身。

[unordered_dense 官方说明](https://github.com/martinus/unordered_dense)描述了紧凑存储及不同容器的引用稳定性。默认哈希种子固定，不应把默认哈希视为针对恶意输入的随机化防护；对网络可控的键，需先分析碰撞攻击和选用合适的哈希策略。PLF 为 zlib 许可，unordered_dense 为 MIT 许可；实际引入时应保留相应许可并固定版本。

## 对 Nexus 的影响

`src/tcp/table.cpp` 的 `ConnectionTable::next` 依赖按递增 ID 遍历，并在末尾回到首元素。hive 会复用被删除的位置：本机插入 1、2、3，删除 2，再插入 4 后遍历为 1、4、3。因此直接替换该表会破坏轮转语义，必须先重新设计并验证排序和公平性。

`src/tcp/direct.cppm` 的流列表和 `src/http2/server.cppm` 的流列表可作为未来稳定地址存储的调查对象，但必须先核对所有借用、删除和异常路径，再以真实工作负载测量。`src/tcp/stack.cppm` 以及 Shadowsocks 的若干 `std::map` 可逐一评估是否需要有序遍历、稳定地址或抗碰撞；只有约束满足且性能收益经验证时才考虑 dense。此处只是候选，不表示已验证替换安全。

## 验证范围

本机 GCC 16.2.1：三个库的普通 C++26 头文件最小程序通过；hive 和 unordered_dense 的临时 xmake 模块包装、`import std` 最小程序通过；两份 PLF 上游完整测试报告 PASS。当前本机标准库没有 `<hive>` 或 `__cpp_lib_hive`。被测提交分别为 hive `1f17d11001580b7a4fd1a14c2ae96523b4a2637e`、colony `b027591ab6280a131450a0b33e92e42676fc7219`、unordered_dense `7c58a8b7a48e790fe72f6508eb3b46317cbba9d5`（头文件版本 5.3.3）。

这些检查只覆盖一套本机工具链和最小模块示例；尚未将库接入 Nexus、验证其他编译器、进行项目负载基准或完成调用点生命周期审计。上游性能数据不能直接推断本项目收益。
