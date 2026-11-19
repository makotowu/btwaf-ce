# btwaf_ce 后端 API 文档

## 0. 通用约定

- 入口：`POST /plugin?action=a&name=btwaf_ce&s=<method>`
- Header：`x-http-token: <CSRF>`；`Content-Type: application/x-www-form-urlencoded`
- 参数：form 字段（对象/数组一律 `JSON.stringify` 后作为字符串传，后端 `json.loads`）
- 响应：`{"status": true, "msg": "", "data": <object>}`；失败 `{"status": false, "msg": "错误信息", "data": null}`
- 分页：`data = {"list": [...], "total": 0, "page": 1, "rows": 20}`
- 时间：unix 秒（int）；日期字符串统一 `YYYY-MM-DD`
- 错误码不单列，直接返回中文 `msg`

## 1. 系统 / 状态

### `get_engine_status`
获取引擎与配置状态。
- 参数：无
- 返回 `data`：
```json
{
  "version": "0.2.0",
  "ready": true,
  "enabled": true,
  "observe": false,
  "sensitivity": 2,
  "nginx": {"name": "Nginx", "version": "1.24.0", "bin": "/www/server/nginx/sbin/nginx", "lua": true, "lua_detail": "Lua 指令探测通过", "conf_exists": true, "conf_ok": true, "conf_hash_ok": true},
  "dirs": {"data": true, "logs": true, "lua": true, "writable": true},
  "lua_files": 30,
  "rules": {"crs_version": "4.x.y", "total": 0, "by_src": {"crs": 0, "ce": 0, "custom": 0},
            "skipped": [{"id": "crs-920xxx", "reason": "unsupported ctl"}], "skipped_count": 0,
            "generated_at": 1730000000, "index_ok": true},
  "config_apply_at": 1730000000,
  "last_reload": 1730000000,
  "errors": [{"time": 1730000000, "msg": "..."}],
  "perf": {"requests": 0, "hits": 0, "avg_ms": 0.0}
}
```

### `check_env`
不修改，仅检测。参数：无。返回 `data = {"items": [{"name": "...", "ok": true, "detail": "...", "repairable": true}], "repairable": false, "needs_repair": false, "manual_required": false, "all_ok": true}`；`needs_repair` 仅当存在“可修复且失败”的项，`manual_required` 表示存在需人工处理的失败项。

### `repair_env`
恢复 conf/lua/目录/权限并 `nginx -t` + reload。参数：无。返回 `data = {"actions": ["restore conf", "reload nginx"], "nginx_test": "ok"}`

### `get_overview`
参数：`date`（可选，默认今天）
返回 `data`：
```json
{
  "date": "2026-11-13",
  "stats": {"blocks": 0, "cc_blocks": 0, "attack_ips": 0, "sites_total": 0, "sites_open": 0, "requests": null},
  "trend": [{"date": "2026-11-07", "blocks": 0, "cc": 0}],
  "types": [{"name": "SQL注入", "module": "sqli", "count": 0}],
  "top_ips": [{"ip": "1.2.3.4", "count": 0, "area": "美国-加州"}],
  "top_urls": [{"uri": "/x", "count": 0}],
  "recent": [<日志行对象，最多 10 条>]
}
```

### `get_logs` / `clear_logs`
插件操作日志（`<data>/logs/plugin.log` + 操作流水）。
- 参数：`p=1, rows=50`；可选 `date=YYYY-MM-DD`、`keyword`（内容过滤）
- 返回分页，`list` 元素 `{"time": 1730000000, "content": "..."}`

## 2. 全局配置

### `get_plugin_config`
参数：无。返回 `data = <config.json 完整对象>`（含 `rule_exclude`、`protocol.from_data`）。

### `save_plugin_config`
参数：`config`（JSON 字符串，完整对象或部分字段；后端做 schema 合并与字段校验）
返回 `data = {"saved": true, "apply_at": 1730000000}`
`protocol.from_data` 为布尔值，默认 `false`；开启后校验 `multipart/form-data` 结构。

### `get_modules`
参数：无。返回 `data = {"modules": {"sqli": {"open": true, "tier": 1, "total": 0, "enabled": 0}, ...}, "sensitivity_options": [1,2,3]}`

### `save_modules`
参数：`modules`（JSON：`{"sqli": {"open": true, "tier": 1}, ...}`）
返回 `data = {"saved": true}`

### `get_rules`
参数：`source`、`module`、`keyword`、`status`（`enabled`/`disabled`，可空）、`scope`（`global|site`）、`site_name`（scope=site 时必填）、`p`、`rows`；`status=disabled` 表示当前未启用的规则（可能因排除/模块关闭/灵敏度 tier）。
规则清单与来源。
- 返回 `data` 分页，`list` 元素：
```json
{"id": "crs-942100", "module": "sqli", "name": "...", "tier": 1, "score": 5, "src": "crs", "enabled": true, "status_override": 0, "hits": 0}
```
- `status_override`：0=继承，其他值为该规则被拦截时使用的状态码。
- 顶层同时返回：`{"scope": "global", "site_name": "", "skipped": [...], "crs_version": "4.x.y"}`。

### `set_rule_status`
参数：`scope`（`global|site`）、`site_name`（scope=site 时必填）、`rule_id`、`status`（`0/403/404/444/429/503`，0=继承）
返回 `data = {"saved": true, "rule_id": "...", "status": 403}`

### `set_rule_exclude`
参数：`scope`（`global|site`）、`site_name`（scope=site 时必填）、`type`（`crs|ce`）、`ids`（JSON 数组，`[]` 表示清空）
返回 `data = {"saved": true}`

### `save_block_page` / `preview_block_page`
参数：`html`（字符串，≤ 64KB；后端过滤 `<script`、`on\w+=`、`javascript:`）
返回 `data = {"saved": true}` / `data = {"html": "<已渲染>", "removed": ["<script>"], "intercepted": ["<script>"], "size": 0}`（`removed` 与 `intercepted` 内容相同，后者为兼容旧前端）

## 3. 站点

### `get_sites`
参数：`keyword`、`status`（`open`/`unprotected`，可空）、`p`、`rows`。
参数：`keyword`（可选）、`p=1, rows=50`
返回分页，`list` 元素：
```json
{"site_name": "www.example.com", "domains": ["www.example.com", "m.example.com"], "path": "/www/wwwroot/x", "status": 1,
 "open": true, "sensitivity": 0, "today_blocks": 0, "last_hit": 1730000000}
```

### `sync_sites`
从面板 DB（`public.M('sites')` + `public.M('domain')`）重建 `hosts.json`，并补齐 `site.json` 条目。
参数：无。返回 `data = {"sites": 0, "hosts": 0}`

### `get_site_config`
参数：`site_name`（必填）
返回：`data = {"site_name": "...", "config": <站点配置合并后对象>, "raw": <站点原始对象>, "global": <全局对象>, "panel_cdn": {"open": false, "scope": "", "header": "", "site": false, "global": false}}`
- `config.block.status`：0=继承全局；其他为允许的拦截状态码。
- `config.rule_status`：规则 ID → 响应码，站点覆盖全局。

### `save_site_config`
参数：`site_name`、`config`（JSON；可包含 `block.status`、`rule_status` 和 `geo`）
返回 `data = {"saved": true, "apply_at": 1730000000}`

### 地区访问字段
全局配置：

```json
"geo": {
  "open": false,
  "mode": "allow",
  "regions": ["CN"],
  "unknown": "allow",
  "status": 403
}
```

- `mode=allow`：仅允许 `regions`；
- `mode=block`：拒绝 `regions`；
- `regions` 仅支持 `CN`；
- `unknown`：无法识别/内网/IPv6 的处理，`allow|block`；
- `status`：允许 `403/404/444/429/503`。

站点配置使用相同字段，`open/mode/regions/unknown=null` 继承全局，`status=0` 继承全局。
`status.geo` 返回：

```json
{"open": false, "available": true, "source": "DB-IP Lite Country",
 "license": "CC BY 4.0", "source_release": "2026-11",
 "generated_at": "...", "records": 5314}
```

### `set_site_open`
参数：`site_names`（JSON 数组）、`open`（`true|false`）
返回 `data = {"updated": 2}`

## 4. 拦截记录 / 封锁

### `get_log_dates`
参数：无
返回 `data = {"dates": ["2026-11-19", "2026-11-18"]}`，用于站点日志的日期选择。

### `get_attack_logs`
参数：`site`、`date`（`YYYY-MM-DD`，默认今天）、`keyword`、`type`（module）、`ip`、`log_action`（`block|allow|...`；**不能叫 `action`**，会与面板路由的 `action=a` 冲突并返回 `ARGS_ERR`）、`p=1, rows=20`
返回分页：
```json
{"list": [{
  "time": 1730000000, "site": "www.a.com", "ip": "1.2.3.4", "area": "美国-加州",
  "method": "GET", "uri": "/a.php", "query": "id=1%27", "status": 403,
  "action": "block", "score": 5, "sensitivity": 2,
  "hits": [{"module": "sqli", "rule": "crs-942100", "name": "...", "score": 5, "tier": 1, "src": "crs"}],
  "ua": "...", "referer": "...", "ctype": "...", "body_len": 0, "snippet": "",
  "block_time": 0, "rule_source": "crs", "req_id": "...",
  "country": "CN|OTHER|PRIVATE|UNKNOWN", "geo_source": "builtin-cn", "reason": ""
}], "total": 0, "page": 1, "rows": 20, "types": [{"module":"sqli","name":"SQL注入","count":0}], "limited": false}
```
说明：`types` 总是返回（供类型下拉）；`limited=true` 表示只扫描了尾部窗口，`total` 为窗口内数量。
```

### `get_attack_stat`
参数：`date`、`site`（可选）
返回 `data = {"types": [...], "sites": [...], "ips": [...], "total": 0}`

### `get_block_list`
参数：`site`（可选）、`status`（`current` 默认 / `history` / `all`）、`p=1, rows=50`
返回分页：
```json
{"list": [{"ip": "1.2.3.4", "site": "...", "reason": "cc|attack", "time": 1730000000,
           "expire": 1730000300, "block_time": 300, "state": "blocked|expired|unbanned",
           "unban_time": 0, "area": "...", "system_blocked": false}],
 "total": 0, "page": 1, "rows": 50, "status": "current", "window": 5000,
 "system": {"available": true, "source": "panel-firewall", "sync_count": 0}}
```
说明：`current`=仍生效；`history`=已过期或已解封；数据取自 `block.log` 尾部最近 5000 条记录。
`system_blocked` 表示该 IP 同时存在于系统防火墙；`system.sync_count` 是当前筛选结果中同时被系统防火墙封禁的数量。

### `get_system_firewall`
参数：无
返回：
```json
{"available": true, "source": "panel-firewall",
 "list": [{"id": 8, "ip": "1.2.3.4", "ps": "", "addtime": "", "can_unban": true}],
 "total": 1, "error": ""}
```
数据来自面板 `firewall` 表；面板系统防火墙不可用时 `available=false`，`list=[]`。

### `unban_ip` / `unban_all`
参数：`ip`、`site`（可选；`unban_all` 只需 `site` 可选）、`sync_system`（可选，`1` 表示同步解封系统防火墙中的同一 IP）
返回 `data`：
- `unban_ip`：`{"unbanned": 1, "ip": "...", "site": "...", "system_unbanned": 0|1}`
- `unban_all`：`{"unbanned": N, "system_unbanned": M}`

### `unban_system_ip` / `unban_system_all`
- `unban_system_ip`：参数 `ip`，返回 `{"unbanned": 1, "ip": "..."}`
- `unban_system_all`：无参数，逐条通过面板 `firewalls.DelDropAddress` 解封当前系统防火墙 IP，返回 `{"unbanned": N, "errors": []}`

## 5. 黑白名单

### `get_lists`
参数：`scope`（`global|site`）、`site_name`（scope=site 必填）
返回 `data = {"lists": {"ip_black": [], "ip_white": [], "url_black": [], "url_white": [], "ua_black": [], "ua_white": [], "param_white": []}}`

### `set_lists`
参数：`scope`、`site_name`（scope=site 必填）、`type`（键名）、`items`（JSON 数组）
- 校验：ip 支持单 IP/CIDR/IP 范围（`start-end`）；url 支持 `^` 前缀或正则（以 `~` 开头）；ua 字符串；param 名称
返回 `data = {"saved": true, "count": 3}`

### `import_lists`
参数：`scope`、`site_name`（scope=site 必填）、`type`（`ip_black|ip_white`）、`base`（当前编辑区，JSON 数组）、`text`（文件内容）
- 文本一行一条，支持单 IP/CIDR/IP 范围，空行和 `#` 注释忽略
- 追加到 `base`，去重；无效行跳过并返回数量
- 文件最大 1MB、最多 10000 行；最终名单受 2000 条上限约束
返回 `data = {"saved": true, "added": 3, "duplicates": 1, "invalid": 0, "total": 10, "truncated": false, "items": [...]}`

## 6. 自定义规则

### `get_custom_rules`
参数：`keyword`、`p=1, rows=50`
返回分页，`list` 元素同 `rule/custom.json` 的 rule 结构 + `hits`。

### `save_custom_rule`
参数：`rule`（JSON：完整 rule；`id` 为空则新增，否则更新）
- 校验：field/operator/action 合法；regexp 可编译；value 长度 ≤ 2048；sites 存在
返回 `data = {"id": "custom-1", "saved": true}`

### `del_custom_rule`
参数：`id`
返回 `data = {"deleted": 1}`

## 7. 配置导入导出

### `export_config`
参数：无。返回 `data = {"config": {...}, "site": {...}, "custom": {...}, "exported_at": 1730000000}`（前端下载为 JSON）

### `import_config`
参数：`payload`（JSON 字符串，结构同 `export_config` 的 data）
返回 `data = {"imported": true}`

## 8. 中国 IP 段自定义

有效 CN 集合为“内置 CN 范围 ∪ 补充范围 − 排除范围”，排除优先。

### `get_geo_custom`
参数：无
返回：
```json
{
  "builtin": {"available": true, "records": 5314, "source": "DB-IP Lite Country", "release": "2026-11"},
  "include": [{"start": "1.2.3.0", "end": "1.2.3.255"}],
  "exclude": [{"start": "1.2.4.0", "end": "1.2.4.255"}],
  "effective": 5314,
  "error": ""
}
```
`error` 非空表示自定义文件无法解析；内置数据仍然可用。

### `save_geo_custom`
参数：`include`（JSON 数组）、`exclude`（JSON 数组）
- 仅接受 IPv4 范围对象 `{start,end}`；
- 自动去重、排序、合并；
- 每类最多 10000 条；
- 保存后重载 Nginx；
- 返回保存后的数据、`saved` 和 `reloaded`。

如果 Nginx 重载失败：

```json
{"saved": true, "reloaded": false, "reload_error": "...", "data": {...}}
```

数据已保存，但运行时需要手动重载后生效。

## 9. Webshell 查杀（可选 YARA）

YARA 不随插件分发。以下接口只操作本机引擎和扫描任务，不修改被扫描文件。

### `get_webshell_status`
参数：无
返回 `data = {"engine": {...}, "rules": {...}, "sites": [...], "job": {...}, "limits": {...}}`
- `engine.installed` 表示系统是否检测到 `yara`；
- `engine.install_supported` 表示是否有可用包管理器；
- `engine.install_hint` 为手动安装提示；
- `rules.count` 为内置规则数；
- `job` 为当前或最近一次扫描任务。

### `install_webshell_engine`
参数：无
- 仅当 `engine.installed=false` 时执行；
- 只调用系统包管理器安装 `yara`，不下载任意二进制；
- 成功返回最新 `get_webshell_status` 数据；失败返回 `status=false` 和错误信息。

### `start_webshell_scan`
参数：`site_name`
- 校验站点和站点目录；
- 校验引擎、规则；
- 同一时间只允许一个扫描任务；
- 启动独立 worker 后返回任务对象。

### `get_webshell_scan`
参数：无
返回当前或最近一次任务：
```json
{"id": "...", "status": "running|done|failed|cancelled",
 "site_name": "...", "started": 0, "finished": 0,
 "scanned": 0, "total_files": 0, "matched": 0,
 "truncated": false, "error": "",
 "results": [{"file": "uploads/x.php", "rule": "webshell_php_eval_request"}]}
```
`results` 只包含相对路径和规则名。

### `cancel_webshell_scan`
参数：无
- 只取消当前运行中的任务；
- 返回取消后的任务对象。

## 10. 自测（可选）

### `run_selftest`
参数：`site`（必填）、`payload`（字符串，≤ 2048）、`location`（`query|body|header|ua`，默认 query）
说明：向 `http://127.0.0.1` 发送带 `Host: <site>` 的本地请求，随后 tail `waf.log` 匹配 `req_id`，返回命中结果。仅当站点解析到本机时有效。
返回 `data = {"blocked": true, "status": 403, "hits": [...], "request_id": "..."}`

## 11. 前端状态映射

- `status.ready=false` → 顶部红色"引擎未就绪"，引导到系统诊断。
- `status.enabled=false` → 顶部黄色"防护已关闭"。
- `status.observe=true` → 顶部蓝色"观察模式（只记录不拦截）"。
- 所有 `sensitivity` 显示：1=宽松 2=标准 3=严格。
- 所有 `tier` 显示：1=PL1 2=PL2 3=PL3。
