# 测试

本项目提供离线的 Lua 引擎测试、Python 后端测试、面板 E2E 冒烟，以及按来源标注的第三方语料回归。

## 1. 快速开始

```bash
cd tests && npm install && cd ..
node tests/run.mjs
python tests/python/test_backend.py
python tools/check_frontend.py
python tools/check_lua51.py
python tools/check_rules.py
```

## 2. 测试分层

| 层 | 命令 | 说明 |
|---|---|---|
| Lua 引擎 | `node tests/run.mjs` | 用 wasmoon 加载真实的 `lua/**`，注入 `ngx` 垫片，不需要 nginx/LuaJIT |
| 后端 | `python tests/python/test_backend.py` | 配置、日志、规则、站点、HTTP 控制器等纯函数/模块测试 |
| 前端检查 | `python tools/check_frontend.py` | 版本、资源加载、命名、主题等静态检查 |
| Lua 兼容 | `python tools/check_lua51.py` | 扫描 Lua 5.1/5.4 公共子集禁用构造 |
| 规则检查 | `python tools/check_rules.py` | 规则 ID/模块/分值/变换/索引一致性 |
| 面板 E2E | `node tests/e2e/panel_ui.mjs` | 需要可访问的宝塔面板和测试插件；参数见文件头部 |

## 3. Lua 测试环境变量

| 变量 | 默认 | 含义 |
|---|---|---|
| `BTWAF_CE_FAST` | 未设置 | `=1` 跳过 Lua 语法关和语料跑批，只跑 suites |
| `BTWAF_CE_SUITES` | 全部 | 只跑名称包含这些子串的 suite，如 `05,06` |
| `BTWAF_CE_CORPUS_PER_FILE` | `60` | 每个语料文件抽样行数；`0` 为全量 |
| `BTWAF_CE_CORPUS_GATE` | 未设置 | `=1` 启用语料门禁：恶意检出率 ≥95% 且良性误报 = 0 |
| `BTWAF_CE_CORPUS_BUDGET_SEC` | `240` | 语料跑批 CPU 秒预算，超预算提前收敛 |

全量门禁：

```bash
BTWAF_CE_CORPUS_PER_FILE=0 BTWAF_CE_CORPUS_GATE=1 node tests/run.mjs
```

## 4. 语料与来源

`tests/corpus/NOTICE.md` 汇总语料来源、许可证与统计。OWASP CRS、libinjection、PayloadsAllTheThings、DOMPurify、aaWAF 公开 Payload 语料的使用方式与许可证见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) 和 `licenses/`。

测试语料不随安装包分发，只用于源码仓库的回归测试。

## 5. 限制

- 测试使用 WASM Lua 与近似的 PCRE 实现，行为和线上 LuaJIT + `ngx.re` 存在差异；PCRE 兼容性问题需在真实 Nginx 环境复核。
- 语料门禁只代表当前语料集，不代表对所有真实业务的误报/漏报承诺。
- E2E 需要真实面板环境，不在离线 CI 中默认执行。
