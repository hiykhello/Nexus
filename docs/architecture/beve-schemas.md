# BEVE 规则集与持久状态模型

状态：本文的扩展规则与持久状态为**设计草案，未实现、未冻结**。有限谓词规则集的 KDL/BEVE 互转已实现；以下类型只是解释未来可能的语义字段，不是其 wire schema。它们不替代[规则集格式](rule-set-format.md)的版本化模型和[互转约束](../configuration/rule-sets.md)。

## 规则表示与索引

规则文件保留有序规则、条件、逻辑组合、动作和必要元数据，以便反向导出 KDL；GeoIP/GeoSite 只是可能的条件或规则集，不能把运行时 IP 前缀树、域名树和不可逆编译结果作为唯一数据。文件中的 IP 可表示为地址族、明确的字节数组和前缀长度；域名条目包括精确、后缀、关键字或经验证的正则类型。动作与出口的关系以稳定语义标识表达，不能把当前 C++ 容器下标、enum 布局或成员顺序当作跨版本协议。

```cpp
// 说明性逻辑模型，非 wire DTO 或编译后对象布局
struct IpPrefix { AddressFamily family; ByteArray address; unsigned prefix_length; };
struct DomainPredicate { MatchType type; std::string pattern; };
struct OrderedRule { RuleId id; Condition condition; Action action; };
```

解析后校验地址范围、前缀、域名、引用、版本和预算，再编译独立的匹配索引；首命中语义由[路由引擎](routing-engine.md)保证。内存布局、平台端序、对齐、指针或 padding 均不是 BEVE 协议。若优化为数值 typed array，还须定义端序、各列对应关系及异常输入语义，并验证转换前后完整语义保持一致。

不能假设 `std::vector<结构体>` 自动序列化为单块 `memcpy` 或可直接 mmap 为 C++ 对象。所读 Glaze 本地提交 `fc646588635c42cca142562d7b3d0484cc4493b7` 的 `include/glaze/beve/write.hpp` 有数值连续数组的批量写入分支，这不证明任意 POD 结构体数组走同一路径。尚无 Nexus 吞吐、启动时间或内存占用基准；按[规则集格式](rule-set-format.md)分别测量解析、索引构建、查询与峰值内存。

## 状态的逻辑字段

若后续选择 BEVE 做状态编码，Fake-IP 记录至少需要地址族与地址、规范化域名、查询类型/视图、池与 owner 身份、代次、最后对外发布到期界限以及恢复时必要的分配状态。普通 DNS 缓存还需要问题及视图身份、RRset/负缓存所需语义、原 TTL、取得和到期时间；不能只以字符串答案数组替代完整 DNS 消息与 TTL 规则。具体 DTO、容器、校验和迁移尚未确定。

Fake-IP 与普通 DNS 缓存分开管理。异步批写或定期快照无法保证每个已应答映射崩溃后可反查；若要求此保证，必须在应答前持久提交并定义同步和故障处理。若采用较弱保证，未知映射与地址隔离按 [Fake-IP 设计](dns-fakeip-engine.md)处理。DNS 的过期窗口和恢复语义见 [DNS 设计](dns.md)。

文件临时写入后 `rename` 可用来避免部分替换，但本身不证明数据和目录项在掉电后持久；必须针对文件同步、目录同步、文件系统语义、错误路径和恢复过程设计并测试。状态文件路径、保存格式和后端尚未决定，更没有已运行的定期持久化或恢复性能数据。详见[缓存与持久状态](state-and-cache.md)。
