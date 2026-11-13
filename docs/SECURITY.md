# 安全设计（SECURITY）

## 1. 威胁模型

| 资产/入口 | 威胁 | 缓解 |
|---|---|---|
| 面板插件接口 `/plugin?action=a&name=btwaf_ce` | 未授权调用、CSRF、越权 | 依赖面板登录态 + `x-http-token` CSRF 校验；所有方法只做本插件数据操作；不提供匿名接口 |
| 配置/规则/名单输入 | 命令注入、路径穿越、正则拒绝服务 | 全部走 JSON + 白名单校验；路径固定根 + `realpath` 前缀校验；正则 `re.compile` 预检 + 长度限制；不拼接 shell（`subprocess` list 形式） |
| 自定义拦截页 | 存储型 XSS / 脚本注入 | 保存与预览时过滤 `<script>`、`on*=`、`javascript:`，限制 64KB；渲染时以 HTML 返回但已清洗 |
| 拦截日志 | 日志注入、payload 泄漏、目录可访问 | 控制字符替换、字段截断；日志目录 `/www/wwwlogs/btwaf_ce`（不在 webroot）、属主 `www`、0750；UI 用文本插值 |
| Lua 引擎 | 引擎被恶意配置拖垮、绕过 | 每次请求限额（参数量/长度/body 上限）；规则异常单条跳过；`pcall` + fail-open；共享字典容量受限 |
| Nginx 配置 | 错误配置导致全站不可用 | 安装/自愈时 `nginx -t`，失败回滚；conf 无 `server{}`/`listen`；不修改 `nginx.conf` |
| 数据目录 | 权限过大/被篡改 | `/www/server/btwaf_ce` 755 root；lua 644；data 750（`www:www` 仅日志/封锁文件）；插件目录 600 后复制运行期文件 |
| 第三方内容 | 许可/供应链 | 不下载二进制；构建期仅拉取 CRS/libinjection 等文本并留痕（`THIRD_PARTY_NOTICES.md`）；不在运行期联网 |

## 2. 安全默认值

- `fail_open=true`：引擎异常放行，保证业务可用；可在全局配置改为 fail-close。
- 观察模式（`observe`）默认关闭，但首次使用引导先观察 24 小时。
- 拦截状态默认 403 + 内置拦截页；CC 默认 444 断连。
- 只记录命中/封锁请求，避免日志膨胀与敏感数据大面积落盘。
- 上传扫描默认上限 20MB，超限跳过并在日志中标注（不阻断正常大文件上传）。

## 3. 面板侧校验清单

- 站点名：`^[A-Za-z0-9._\-_*\u4e00-\u9fa5]+$`，长度 ≤253，且必须是面板已有站点（`save_site_config` 等）。
- 日期：`YYYY-MM-DD`；分页/行数有上下限。
- IP/CIDR：`util.valid_ip` / `valid_cidr`；名单上限 2000 条。
- 正则：`util.valid_regex`；非 regexp 操作符不做正则解析。
- 拦截页：`sanitize_block_page`。
- 导入配置：逐字段 `clean_*` 合并，未知字段忽略；不执行任何代码。
- 自测接口：只允许请求 `127.0.0.1`，`Host` 必须是已存在站点；payload ≤2048。

## 4. 运行期权限

```
/www/server/btwaf_ce             root:root 755
  config.json/site.json/hosts.json 644（Lua 只读）
  lua/**                          644/755
  rule/custom.json                644
  data/                           750 root:root
    block.log/unban.log/perf.json www:www 664（Lua 写、Python 读写）
    state.json/blockpage.html    644 root:root
  logs/plugin.log                644 root:root
/www/wwwlogs/btwaf_ce            www:www 750（Lua 写/轮转，面板 root 读）
```

## 5. 已知限制

- 不防御 L3/L4 攻击（由面板防火墙/云清洗负责）。
- 不扫描响应体（v1 仅请求侧）。
- 规则移植自 CRS，可能对特定业务产生误报，需通过观察模式 + 规则排除/白名单调优。
- 自测接口会向本机发真实请求，仅在明确知情时使用。
- 面板"配置接管/格式化"工具可能改动第三方 lua 配置；插件提供自愈，但不建议在插件启用时使用该工具。

## 6. 漏洞报告

请通过项目 Issue 私密报告，附版本、复现步骤与影响；不要在公开 Issue 中贴可被利用的 payload。修复流程：确认 → 补丁 → 回归语料 → 发版说明。
