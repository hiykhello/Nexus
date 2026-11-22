# Nexus Web 控制台

基于 **pnpm + Node + Vite 8 + Lit + `@elelcode/lit-router`** 构建的轻量只读前端控制台，编译产物（`web/dist/`）可直接挂载至 Nexus `control dashboard-root="..."`，零运行时 Node 依赖。

## 本地开发与构建

```bash
cd web
pnpm install
pnpm build       # 生成静态产物至 web/dist/
pnpm dev         # 开发模式（自动代理 /v1/* 与 /metrics 到 http://127.0.0.1:9090）
```

## 接入 Nexus 控制面

在 KDL 配置中启用只读静态沙箱目录：

```kdl
control http-listen="127.0.0.1:9090" bearer-token-file="/path/to/token" dashboard-root="/path/to/web/dist" metrics=#true
```

浏览器访问 `http://127.0.0.1:9090/` 即可加载 SPA 界面；所有 `/v1/*` 与 `/metrics` 控制接口仍强制校验 `Authorization: Bearer` 令牌（前端仅存于当前标签页 `sessionStorage`，绝不通过 URL 查询串传递）。
