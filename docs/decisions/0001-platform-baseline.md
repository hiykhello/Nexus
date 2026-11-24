# 0001：平台定位与初始技术基线

日期：2026-10-27。状态：已确定。来源：项目初始要求。

## 决策

| 范围 | 决定 |
| --- | --- |
| 项目定位 | 通用 proxy 平台 |
| 角色 | 同时支持 client 与 server |
| C++ 组织方式 | 全面采用 C++ Modules |
| 构建 | mcpp 工作区（2026-10-30 修订） |
| 配置格式 | KDL 2.0 |
| 配置解析 | [hiykhello/glaze-kdl](https://github.com/hiykhello/glaze-kdl)（原 `glaze-kdl2.0-` 已更名） |
| 抽象接口 | [ngcpp/proxy](https://github.com/ngcpp/proxy) |
| 协程与 I/O | [cppalliance/corosio](https://github.com/cppalliance/corosio) |
| 当前阶段 | 文档沉淀 |

## 影响

后续设计与实验围绕上述基线展开。第三方接入需要验证 Modules 兼容性，构建需要覆盖 Corosio 的 Capy 依赖，配置解析需要验证指定分支的实际接口与 KDL 2.0 覆盖。

本记录不代表选型已通过集成验证。协议范围、模块名、程序拆分、工具链版本、配置字段和依赖锁定提交均未确定。

未来如调整已确定的基线，应新增决策记录，说明变更原因及对既有设计的影响，并同步文档入口。
