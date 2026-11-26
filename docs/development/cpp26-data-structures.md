# C++26 实用数据结构与容器规范

状态：设计规范。针对 Nexus 代理平台高性能场景，提取 C++26（及 C++23 完善）的现代数据结构，规范其在内核各子系统中的选用原则。

---

## 一、概述与核心设计哲学

在高性能网络代理平台（如 Nexus）中，**内存分配（Heap Allocation）与缓存未命中（Cache Miss）是吞吐量与长尾延迟的两大首要杀手**。

C++26 标准与项目基础叶子包（依托 Clang `llvm@23.1.6` + 静态 `libc++` + C++26 Modules）提供了一批轻量级数据结构与词汇类型（Vocabulary Types）。它们的核心特征是：
1. **栈上就地分配 / 零堆开销（Zero Heap Allocation）**；
2. **极高的缓存局部性（Cache Locality）**；
3. **针对高频增删场景的指针与迭代器绝对稳定性（Iterator Stability）**；
4. **轻量无拥有权借用（Non-owning Borrowing）**。

---

## 二、核心数据结构清单与场景映射

| 数据结构 | 标准提案 / 状态 | 核心特征与内存布局 | Nexus 最佳应用场景 |
| :--- | :--- | :--- | :--- |
| **`std::inplace_vector<T, N>`** | P0843R14 (C++26) | 栈上连续存储，固定最大容量 $N$，动态大小，**零堆分配** | 协议数据包头切片、TLS 扩展列表、IP 候选列表、HTTP 单行请求解析 |
| **`std::hive`** | P0447R26 (C++26) | 分块跳跃式紧凑存储，**高频增删下迭代器与指针永不失效** | 活动连接池（Active Session Map）、定时器时间轮槽位、流控待发队列 |
| **`std::flat_map` / `std::flat_set`** | P0429 / P1222 (C++23/26) | 基于两个连续 `vector`/`array` 的有序扁平映射，二分查找 | 节点元数据检索、小规模配置属性字典、TLS CipherSuite 优先级查找 |
| **`std::function_ref<Sig>`** | P0792R14 (C++26) | 仅占 2 个指针大小，非拥有型借用，**绝对不触发堆分配** | 零拷贝网络数据包流式回调、深度包检测（DPI）访问器、解析器 Visitor |
| **`std::move_only_function<Sig>`** | P0288R9 (C++23/26) | 支持仅移动可调用对象（如捕获 `std::unique_ptr` 或 Socket fd） | 异步 I/O 完成回调（Corosio 协程恢复）、跨线程一次性任务投递 |
| **`std::span` / `std::mdspan`** | C++20 / P2630 (C++26) | 连续或多维内存的零拷贝安全切片，支持子切片（Submdspan） | 接收缓冲区网络包分割、零拷贝流式转发、加密多段关联数据（AAD）拼接 |

---

## 三、各数据结构深度解析与代码规范

### 1. `std::inplace_vector<T, N>`：终结网络热路径上的小堆分配

#### (1) 痛点背景
在网络代理中，我们经常需要临时存储一组小对象（如解析出的 5~10 个 TLS 扩展、从网络包提取的若干个 IP 地址、HTTP 头的分段切片）。传统的 `std::vector<T>` 哪怕只有 1 个元素也会触发 `malloc`；而 `std::array<T, N>` 虽然在栈上，但没有 `size()` 动态管理，且必须在声明时默认构造全部 $N$ 个对象。

#### (2) 机制与优势
* 连续内存直接内嵌在栈帧或所属父结构体中；
* 维护动态 `size()`（$0 \le \text{size} \le N$），仅在 `push_back` 时就地构造，在 `pop_back` 或销毁时逐个调用析构函数；
* **当元素超出 $N$ 时抛出异常或触发终止（在 Nexus 中优先使用 `try_push_back` 返回 `expected` 风格的指针/布尔，避免异常）**。

#### (3) Nexus 实战场景规范
```cpp
// 示例：TLS ClientHello 扩展收集器（最大容忍 32 个扩展，完全在栈上完成）
struct ClientHelloContext {
    // 零堆内存分配！占用父结构体内存空间
    std::inplace_vector<ExtensionView, 32> extensions;
    std::inplace_vector<uint16_t, 16> cipher_suites;
    std::inplace_vector<uint16_t, 8> supported_groups;

    auto append_extension(this ClientHelloContext& self, ExtensionView ext) noexcept -> bool {
        // try_push_back 是 C++26 提供的安全无异常追加方法
        return self.extensions.try_push_back(ext) != nullptr;
    }
};
```

---

### 2. `std::hive` (Colony)：高频并发会话池的终极容器

#### (1) 痛点背景
在代理服务器管理成千上万条活动长连接时，连接会随时接入并随机断开。使用 `std::vector` 删除中间元素会导致 $O(N)$ 元素搬移并使所有迭代器失效；使用 `std::list` 则指针乱飞、内存极其碎片化、遍历命中率极低；使用 `std::unordered_map` 会面临 Rehash 停顿以及节点分配开销。

#### (2) 机制与优势
* `std::hive` 是由 Matthew Bentley 提出并进入 C++26 的全新容器类型；
* 内部以多个连续的内存“块”（Blocks）组织，结合跳跃计数（Skipfield）跳过已释放的槽位；
* **核心承诺**：
  1. **插入/删除均为 $O(1)$**；
  2. **删除某个元素绝不导致其他元素的内存地址、指针或迭代器失效**；
  3. **遍历性能接近连续数组（极高 CPU L1/L2 Cache 命中率）**。

#### (3) Nexus 实战场景规范
```cpp
// 示例：入站连接跟踪表（Active Session Tracker）
class SessionManager {
private:
    // 连续块存储会话对象，高并发增删下指针绝对稳定
    std::hive<ActiveSession> active_sessions_;

public:
    // 创建会话，返回稳定的引用包装
    auto register_session(ActiveSession&& session) -> ActiveSession& {
        auto it = active_sessions_.insert(std::move(session));
        return *it; // 指针终生有效，直到显式 erase
    }

    // 会话断开，O(1) 删除，不影响其他正在通信的会话指针
    auto unregister_session(std::hive<ActiveSession>::iterator it) noexcept -> void {
        active_sessions_.erase(it);
    }
};
```

---

### 3. `std::flat_map` / `std::flat_set`：紧凑高缓存的查找字典

#### (1) 机制与优势
* 区别于红黑树实现的 `std::map`（每个节点有左右子树指针、内存分散），`std::flat_map` 将 Key 和 Value 分别保存在两个平坦连续的数组中（默认 `std::vector`，也可以定制为 `std::inplace_vector` 实现栈上无堆 map！）；
* 元素有序排列，查找走 CPU 缓存极度友好的二分查找（Binary Search）。

#### (2) Nexus 实战场景规范
* **适用条件**：元素数量少（$< 128$ 个）、“读远多于写”的静态/准静态配置；
* **最佳场景**：
  * HTTP Header 精准匹配；
  * 入站端口到虚拟主机的映射表；
  * 出站 Tag 别名索引表。

---

### 4. `std::function_ref<Sig>`：流式包处理的无分配回调

#### (1) 痛点背景
在网络框架中，流经 TUN 或 TCP 栈的数据包需要经过多级处理器（如：包嗅探、统计计数、分流匹配、加密注入）。传统使用 `std::function` 会在闭包捕获超过 16~32 字节时触发堆分配，并且有虚表级间接调用开销。

#### (2) 机制与优势
* 相当于可调用对象的 `std::string_view`：它**不拥有**可调用对象，只借用其指针和调用转换入口；
* `sizeof(std::function_ref)` 恒等于 2 个裸指针大小（16 字节），传递开销与寄存器传递一致；
* **绝对 0 堆分配**。

#### (3) Nexus 实战场景规范
```cpp
// 示例：网络包流式过滤器定义
using PacketHandler = std::function_ref<auto(std::span<std::byte const> packet) noexcept -> bool>;

auto inspect_and_forward(std::span<std::byte const> raw_frame, PacketHandler handler) noexcept -> bool {
    // 同步执行借用的回调，绝不分配堆内存
    return handler(raw_frame);
}
```

> [!WARNING]
> **生命周期铁律**：`std::function_ref` 只能用于**同步借用**（Synchronous Invocations）。绝不能将其保存到异步任务、跨线程投递或存储在堆对象中留待后续调用。

---

### 5. `std::move_only_function<Sig>`：原生移动语义异步任务

#### (1) 优势与规范
* 传统的 `std::function` 要求可调用对象必须可复制（CopyConstructible）。当回调闭包中捕获了 `std::unique_ptr`、Socket 描述符或异步连接句柄时，`std::function` 无法通过编译。
* 在与 `Boost.Corosio` 或 `io_uring` 交互的异步完成事件中，**一律使用 `std::move_only_function`** 传递单所有权资源。

---

## 四、工程接入建议与工作区模块对应

1. **Clang `llvm@23.1.6` + 静态 `libc++` 与基础叶子包**：
   * `std::span`、`std::expected`、`std::optional` 等标准词汇类型直接经 `import std;` 使用；
   * 固定容量就地容器与缓存索引统一由独立叶子包 `containers`（`src/containers/inplace_vector.cppm` 的 `containers::inplace_vector<T, N>` 与 `src/containers/cache_index.cppm`）提供；
   * 函数包装统一由独立叶子包 `functional`（`src/functional/functional.cppm`，基于 `proxy.v4` 提供 `functional::function_ref` 与 32B SBO 的 `functional::move_only_function` / `functional::copyable_function`）提供，跨平台通用工具位于 `utility`（`src/utility/`）。
2. **显式容量边界原则**：
   * 使用 `containers::inplace_vector` 时，优先调用不抛异常的 `try_push_back()` / `try_emplace_back()` 显式处理容量上限。
