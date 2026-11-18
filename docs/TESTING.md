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
| 服务器探测 | `python tests/python/test_nginx.py` | `-V` 名称/版本显示、Lua 指令探测、动态模块/DSO 解析；路径测试确认 Tengine 版本标记仍映射到宝塔 Nginx 布局 |
| 安装器 shell | `python3 tests/shell/test_install_check.py` | Linux + bubblewrap；在私有 `/www` fixtures 中实际执行原始 `bash install.sh check`，覆盖系统/面板 Python、缺二进制/主配置/Lua 模块和旧环境变量残留 |
| 前端检查 | `python tools/check_frontend.py` | 版本、资源加载、命名、主题等静态检查 |
| Lua 兼容 | `python tools/check_lua51.py` | 扫描 Lua 5.1/5.4 公共子集禁用构造 |
| 规则检查 | `python tools/check_rules.py` | 规则 ID/模块/分值/变换/索引一致性 |
| 面板 E2E | `node tests/e2e/panel_ui.mjs` | 需要可访问的宝塔面板和测试插件；参数见文件头部 |

Python 测试通过 `mock.patch` 替换路径常量或调用依赖，覆盖全部派生文件路径后再导入业务模块；生产安装器与后端没有测试模式开关，也不读取路径覆盖环境变量。另有独立 subprocess 用例验证旧环境变量不会改变生产路径。

安装器 shell 回归需要 Linux 的 user/mount namespace 和 `bubblewrap`（Debian/Ubuntu：`sudo apt-get install bubblewrap`），可在 Linux 或 WSL 中执行：

```bash
python3 tests/shell/test_install_check.py
```

该测试在 tmpfs 根目录中只读挂载运行库和原始仓库，将临时 fixture 挂载到 `/www`，不会写宿主的面板目录。fixture 提供模拟 Nginx 可执行文件，验证安装脚本、Python 包装函数、真实探测器及错误返回之间的集成，不声称验证真实 Lua 模块。CI 必须执行此回归，缺少依赖或沙箱不可用时失败，不静默跳过；`bash -n install.sh` 仍保留为独立语法检查。

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
- 附加运行验证使用手工构建的 Tengine 3.1.0（静态/动态 Lua 模块），在独立文件系统与网络命名空间中挂载固定的 `/www/server/nginx`、`/www/server/panel/vhost/nginx` 和 `/etc/init.d/nginx`，直接执行未改写的 `check → install → update → uninstall`。旧版安装器复现了 `env: ‘py’: No such file or directory`；修复后完成正常放行、SQLi/XSS 拦截、热更新与卸载恢复，并确认旧测试/路径环境变量残留不改变目标。构建目录只读导致编译前缀的默认日志文件有非致命告警，配置内日志与临时目录显式放在沙箱可写目录。此验证不等同于真实面板集成：面板的 `version.pl` / `version_check.pl` 和服务脚本由面板管理，面板安装脚本的 Tengine 分支及切换流程尚未覆盖，不能据此宣称面板切换开箱即用。
- 面板 E2E 仍需要真实宝塔环境，不在离线 CI 中默认执行；本地插件宿主仅能验证诊断界面与后端，不代表面板安装/卸载已验证。
