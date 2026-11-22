# 本机 GCC 能力记录

日期：2026-10-27。状态：最小编译探测通过，尚未验证完整项目集成。

## 环境与方法

本机 `gcc --version`、`g++ --version` 均为 `16.2.1 20260810`。随编译器使用的标准库报告 `_GLIBCXX_RELEASE=16`、`__GLIBCXX__=20260810`。

探测通过标准输入提交最小 C++ 单元，使用 `g++ -Wall -Wextra -pedantic-errors -fsyntax-only -x c++ -`，并为各项添加下表选项。没有向项目加入运行实现，也没有安装或升级工具链。

| 能力 | 标准与额外选项 | 最小验证内容 | 结果 |
| --- | --- | --- | --- |
| 显式对象参数、concept、后置返回类型 | `-std=c++23` | const 对象参数、约束模板及编译期调用 | 通过 |
| expected / optional | `-std=c++23` | 构造并返回 `expected<optional<int>, int>` | 通过 |
| move_only_function | `-std=c++23` | 持有捕获 `unique_ptr` 的 lambda 并调用 | 通过 |
| copyable_function / function_ref | `-std=c++26` | 复制拥有型包装并传给借用型包装调用 | 通过 |
| 原生静态反射 | `-std=c++26 -freflection` | 类型反射及非静态数据成员枚举 | 通过 |
| contract_assert | `-std=c++26` | 在函数体使用契约断言 | 通过 |

## 特性宏快照

`-std=c++26 -freflection` 下包含 `<version>` 后，选取以下实际输出：

```text
__cplusplus = 202400L
__cpp_explicit_this_parameter = 202110L
__cpp_concepts = 202002L
__cpp_impl_reflection = 202603L
__cpp_contracts = 202502L
__cpp_lib_expected = 202211L
__cpp_lib_optional = 202506L
__cpp_lib_move_only_function = 202110L
__cpp_lib_copyable_function = 202306L
__cpp_lib_function_ref = 202603L
```

该快照用于复核实际安装能力；不使用 `__cplusplus` 的单个数值推断整个标准已实现，也不由宏存在推断所有相关操作都可用。

## 复核片段

以下反射片段已在本机以 `-std=c++26 -freflection` 进行语法与编译期求值检查：

```cpp
#include <meta>

static_assert(std::meta::is_type(^^int));

struct S { int value; };

static_assert(std::meta::nonstatic_data_members_of(
    ^^S, std::meta::access_context::current()).size() == 1);
```

以下契约断言已在 `-std=c++26` 下通过语法检查：

```cpp
auto positive(int value) -> int {
    contract_assert(value > 0);
    return value;
}
```

本节探测没有运行这些片段，未检查契约违反时的处理策略，也未验证反射与标准库类型跨 Modules 导出、构建系统扫描及各依赖的组合。另有不含反射的 Glaze 模块最小实验，范围见[第三方 Modules 封装](../build/third-party-modules.md)；正式集成需继续覆盖本节场景。

官方资料：[GCC C++ 支持表](https://gcc.gnu.org/projects/cxx-status.html)列出 GCC 16 的反射与契约支持，并注明反射需要 `-freflection`；库能力还需分别核对 [libstdc++ 状态](https://gcc.gnu.org/onlinedocs/libstdc++/manual/status.html)与本机编译结果。
