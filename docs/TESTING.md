# 测试

本项目提供离线的 Lua 引擎测试、Python 后端测试、面板 E2E 冒烟，以及按来源标注的第三方语料回归。

## 1. 快速开始

```bash
cd tests && npm install && cd ..
node tests/run.mjs
python tests/python/test_backend.py
python tests/python/test_nginx.py
python tools/check_frontend.py
python tools/check_lua51.py
python tools/check_rules.py
```

## 2. 测试分层

| 层 | 命令 | 说明 |
|---|---|---|
| Lua 引擎 | `node tests/run.mjs` | 用 wasmoon 加载真实的 `lua/**`，注入 `ngx` 垫片，不需要 nginx/LuaJIT |
| 后端 | `python tests/python/test_backend.py` | 配置、日志、规则、站点、HTTP 控制器等纯函数/模块测试 |
| 服务器兼容 | `python tests/python/test_nginx.py` | Nginx/Tengine/OpenResty 识别、Lua 指令探测、动态模块/DSO 和路径发现；Lua `13_tengine` 套件覆盖旧定时器 |
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
- 真实 Tengine 复核：已在隔离构建的 Tengine 3.1.0 静态/动态 Lua 模块上运行 `check → install → update → uninstall`，通过 HTTP 验证正常放行、SQLi/XSS 拦截、观察模式热更新、`ngx.timer.at` 兼容、CC 封锁与解封，并确认卸载恢复原配置、处理链和预先存在的数据/日志。路径包含空格的自定义数据/Lua 目录也已覆盖；旧版 DSO 仅有解析回归，未运行旧 Tengine 实例。
- 面板 E2E 仍需要真实宝塔环境，不在离线 CI 中默认执行；本地插件宿主仅能验证诊断界面与后端，不代表面板安装/卸载已验证。
