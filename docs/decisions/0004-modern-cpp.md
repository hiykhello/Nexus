# 0004：优先采用本机现代 C++ 能力

日期：2026-10-27。状态：方向已确定。来源：用户追加的编码规范要求。

## 决策

- 非静态成员函数优先使用显式对象参数（显式 this）。
- 模板约束优先使用 concept 与 `requires`。
- 函数优先使用 `auto function(...) -> Type { ... }` 后置返回类型。
- 优先使用本机 GCC 已提供的 C++26/C++23 能力。
- 需要动态多态时优先使用 ngcpp/proxy。
- 需要反射时优先使用 C++26 原生静态反射。
- 编译期断言优先使用 `static_assert`，运行期内部断言优先使用 C++26 `contract_assert`；不使用函数级 `pre`/`post` 契约。
- 函数包装按借用、仅移动拥有、可复制拥有分别优先使用 `std::function_ref`、`std::move_only_function`、`std::copyable_function`，不默认使用 `std::function`。

## 影响

项目语言方向优先 C++26，延续决策 0003 的 expected/optional 与尽量无异常要求。本机 GCC 16.2.1 的上述能力最小编译探测已通过；反射需要 `-freflection`。正式构建、Modules 集成和契约运行策略仍需验证。

概念、语言断言与业务错误各有语义，不因引入新能力而混用。原生反射不改变已确定的配置解析库，函数包装和动态组件 facade 分别按所需能力使用。

规范细节见[C++ 编码规范](../development/cpp-guidelines.md)，本机结果见[GCC 能力记录](../development/gcc-capabilities.md)。
