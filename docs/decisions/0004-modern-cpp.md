# 0004：优先采用现代 C++ 能力

日期：2026-10-27。状态：已部分演进（见下文 2026-11 状态更新）。来源：用户追加的编码规范要求。

> **2026-11 状态更新（替代原 GCC 16 与 `-freflection` 约定）**：
> 项目现已统一采用 **Clang（`llvm@23.1.6`）+ C++26 Modules + 静态链接 `libc++`**，并**放弃 `-freflection` / `<meta>`**（改用显式静态表分发与 `GLZ_REFLECTION26 = 0` 路径）。
> - 保留并持续执行：C++26 Modules（`import std;`）、显式对象参数（`this`）、concepts / `requires`、尾置返回类型、`ngcpp/proxy`（`proxy.v4`）、`std::expected` / `std::optional`。
> - 基础词汇与容器收拢为独立叶子包：`containers`（`containers::inplace_vector`、`CacheIndex`）、`functional`（基于 `proxy.v4` 的 `function_ref` / `move_only_function` / `copyable_function`）与 `utility`。

## 原始决策（2026-10-27）

- 非静态成员函数优先使用显式对象参数（显式 this）。
- 模板约束优先使用 concept 与 `requires`。
- 函数优先使用 `auto function(...) -> Type { ... }` 后置返回类型。
- 优先使用现代 C++26/C++23 能力。
- 需要动态多态时优先使用 ngcpp/proxy。
- ~~需要反射时优先使用 C++26 原生静态反射~~（已被 2026-11 零 `-freflection` 静态表分发替代）。
- 编译期断言优先使用 `static_assert`，运行期内部断言按工具链支持选用（不引入函数级 `pre`/`post` 契约）。
- 函数包装按借用、仅移动拥有、可复制拥有分别优先使用 `functional::function_ref`、`functional::move_only_function`、`functional::copyable_function`（或标准库等价类型），不默认使用 `std::function`。

## 影响

项目语言方向固定为 C++26 Modules，延续决策 0003 的 `expected`/`optional` 与尽量无异常要求。全仓使用 Clang（`llvm@23.1.6`）与静态 `libc++`，不依赖 `-freflection` 或旧 GCC 探测开关。

概念、语言断言与业务错误各有语义，不因引入新能力而混用。配置解析继续使用指定 KDL 2.0 库，函数包装和动态组件 facade 分别按所需能力使用。

规范细节见[C++ 编码规范](../development/cpp-guidelines.md)与[C++26 数据结构](../development/cpp26-data-structures.md)。
