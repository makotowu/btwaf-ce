# 贡献指南（CONTRIBUTING）

感谢你愿意参与宝塔WAF社区版。

这是一个仍在成长中的社区项目，欢迎提交 Issue、改进文档、补充规则、修复代码或提交 PR。开始前请先阅读：

- [README](README.md)（项目定位与免责声明）
- [SECURITY.md](SECURITY.md)（漏洞报告流程）
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)（社区行为准则）

## 你可以贡献什么

- 复现并报告问题：附环境、步骤、日志（先脱敏）。
- 改进文档：安装、配置、规则说明、排错。
- 修复代码：后端 Python、Lua 引擎、前端控制台。
- 改进规则与测试：增加误报/漏报样例、补充语料和 NOTICE。
- 改进安装/卸载脚本与 Nginx 冲突处理。
- 提交 PR：从 fork 切分支，保持改动聚焦。

## 开发环境

- 宝塔 Linux 面板 + 带 `lua-nginx-module` 的 Nginx（或 OpenResty）；
- Python 3.7+ 语法兼容，目标运行环境 Python 3.13；
- Node.js + `wasmoon` 用于离线 Lua 测试；
- 不需要构建前端：`static/` 是可直接加载的 Vue 3 + Element Plus UMD 资源。

```bash
git clone https://github.com/makotowu/btwaf-ce btwaf-ce
cd btwaf-ce
cd tests && npm install && cd ..
node tests/run.mjs
python tests/python/test_backend.py
python tools/check_frontend.py
python tools/check_lua51.py
python tools/check_rules.py
```

安装到测试面板时，请先备份 Nginx 配置和站点数据；不要在未授权的生产环境测试。安装脚本会处理 Nginx Lua 冲突并在失败时回滚，但仍建议先在测试机验证。

## 代码约定

- **Python**：保持 3.7+ 语法子集，不使用 `:=`、`dict |`、`match`、已移除的 `cgi`/`imp` 等；对外错误使用项目现有异常/返回格式。
- **Lua**：兼容 5.1/5.4 公共子集；不使用 `goto`、`//`、`bit32`、`utf8.`、`table.move`、`string.pack`。
- **前端**：沿用现有 Vue/Element Plus 结构与 CSS 变量；不引入构建链、CDN 外链或新 UI 依赖；优先用布局和标签表达，不堆叠解释性提示。
- **规则**：新增/修改规则需说明来源、许可证、模块、tier、score 和误报边界；不要复制不兼容许可证的规则或代码。
- **注释**：只为非显而易见的逻辑、安全边界和兼容性写注释；不要用注释复述代码。
- **改动范围**：一个 PR 只做一件事；避免无关格式化、重命名和大规模重排。

## 测试要求

提交 PR 前至少运行：

```bash
node tests/run.mjs
python tests/python/test_backend.py
python tools/check_frontend.py
python tools/check_lua51.py
python tools/check_rules.py
```

涉及规则/引擎时，请运行全量语料门禁：

```bash
BTWAF_CE_CORPUS_PER_FILE=0 BTWAF_CE_CORPUS_GATE=1 node tests/run.mjs
```

需要真实面板的 E2E 请按 `tests/e2e/panel_ui.mjs` 文件头的环境变量说明执行，并在 PR 中说明测试环境（不要提交真实凭据/IP）。

## 规则与语料贡献

- 说明样例来源与许可证；新增语料目录必须附 `NOTICE.md`。
- 不提交无许可证或与 AGPL-3.0 不兼容的代码/规则。
- 提交误报样例时，附原始请求、期望行为、实际行为和可复现命令。
- 对可能影响正常业务的规则，先在观察模式/测试站点验证，并说明白名单/排除方式。
- 不在 PR 中提交真实攻击流量中的用户数据或生产日志。

## 提交 PR

1. Fork 仓库，从 `main` 切出主题分支。
2. 保持提交信息清晰，例如 `fix: ...`、`feat: ...`、`docs: ...`、`test: ...`。
3. 更新必要的文档、注释和测试；不要提交 `node_modules`、`dist`、日志、截图或本地配置。
4. 确认没有提交凭据、真实 IP、面板入口、数据库密码或个人信息。
5. 在 PR 描述中写清：问题、方案、影响范围、测试命令与结果、已知限制。
6. 维护者会尽力评审；对较大改动建议先开 Issue 讨论设计，避免无效实现。

## 安全漏洞

不要用公开 Issue 报告可利用漏洞；请按 [SECURITY.md](SECURITY.md) 的私密渠道提交。

## 许可证

提交代码/文档即表示你同意以本项目的 **AGPL-3.0** 许可证发布你的贡献，并确认你有权提交相关内容。第三方内容必须保留其原有许可证与归属。
