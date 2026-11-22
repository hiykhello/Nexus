# HTTP/1 头部语法对照

`tests/http_header_compat.py` 接收重构前后两个 `http-header-compat-fixture` 程序，以固定随机种子比较 CONNECT、正向请求、响应和 chunked trailer。覆盖完整及不完整头、字段语法、Connection 选项、策略优先级、字段/单行/总长上限，以及不同分片下的解码器事件、消费量和输出。直接解析阶段还记录常规 C++ `operator new` 分配次数及请求字节数；此计数不涵盖绕过该运算符的其他分配。状态机轨迹以 64 位哈希比较，不是形式化证明。

`baseline.patch` 只供独立源码副本使用：它将上述三个解析器恢复为抽取 `nexus.http.header` 前的实现，保留当时已有的 CONNECT、请求和响应驱动。先将当前源码复制到隔离目录，保持所需固定依赖与工作区设置，在副本中应用补丁，然后分别在补丁版和当前源码中按 [工作区说明](../../docs/build/mcpp-workspace.md) 构建根包并选择 `--features test-http-header-fixture`。该 feature 仅生成对照程序，其分配计数实现不进入普通程序。比较各自 `bin/http-header-compat-fixture`：

```sh
python3 tests/http_header_compat.py /path/to/baseline/http-header-compat-fixture /path/to/current/http-header-compat-fixture
```

2026-10-31 的本机 GCC 16 debug 对照中，13,654 个案例的结果、分片轨迹与记录的分配计数一致；基线是抽取前实际构建的程序，并非由补丁重新构建。本结果不替代网络互通、性能和其他平台验证。
