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
  "version": "0.1.0",
  "ready": true,
  "enabled": true,
  "observe": false,
  "sensitivity": 2,
  "nginx": {"bin": "/www/server/nginx/sbin/nginx", "lua": true, "conf_exists": true, "conf_ok": true, "conf_hash_ok": true},
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
- 参数：`p=1, rows=50`
- 返回分页，`list` 元素 `{"time": 1730000000, "content": "..."}`

## 2. 全局配置

### `get_plugin_config`
参数：无。返回 `data = <config.json 完整对象>`（含 `rule_exclude`）。

### `save_plugin_config`
参数：`config`（JSON 字符串，完整对象或部分字段；后端做 schema 合并与字段校验）
返回 `data = {"saved": true, "apply_at": 1730000000}`

### `get_modules`
参数：无。返回 `data = {"modules": {"sqli": {"open": true, "tier": 1, "total": 0, "enabled": 0}, ...}, "sensitivity_options": [1,2,3]}`

### `save_modules`
参数：`modules`（JSON：`{"sqli": {"open": true, "tier": 1}, ...}`）
返回 `data = {"saved": true}`

### `get_rules`
参数：`source`、`module`、`keyword`、`status`（`enabled`/`disabled`，可空）、`p`、`rows`；`status=disabled` 表示当前未启用的规则（可能因排除/模块关闭/灵敏度 tier）。
规则清单与来源。
- 参数：`module`（可选）、`source`（`crs|ce|custom` 可选）、`keyword`（可选）、`p=1, rows=50`
- 返回 `data` 分页，`list` 元素：
```json
{"id": "crs-942100", "module": "sqli", "name": "...", "tier": 1, "score": 5, "src": "crs", "enabled": true, "hits": 0}
```
- 顶层同时返回：`{"skipped": [{"id": "...", "reason": "..."}], "crs_version": "4.x.y"}`（规则库页的"未移植清单"直接用它）。

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
返回：`data = {"site_name": "...", "config": <站点配置合并后对象>, "raw": <站点原始对象>, "global": <全局对象>}`

### `save_site_config`
参数：`site_name`、`config`（JSON）
返回 `data = {"saved": true, "apply_at": 1730000000}`

### `set_site_open`
参数：`site_names`（JSON 数组）、`open`（`true|false`）
返回 `data = {"updated": 2}`

## 4. 拦截记录 / 封锁

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
  "block_time": 0, "rule_source": "crs", "req_id": "..."
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
           "unban_time": 0, "area": "..."}],
 "total": 0, "page": 1, "rows": 50, "status": "current", "window": 5000}
```
说明：`current`=仍生效；`history`=已过期或已解封；数据取自 `block.log` 尾部最近 5000 条记录。

### `unban_ip` / `unban_all`
参数：`ip`、`site`（可选；`unban_all` 只需 `site` 可选）
返回 `data = {"unbanned": 1}`

## 5. 黑白名单

### `get_lists`
参数：`scope`（`global|site`）、`site_name`（scope=site 必填）
返回 `data = {"lists": {"ip_black": [], "ip_white": [], "url_black": [], "url_white": [], "ua_black": [], "ua_white": [], "param_white": []}}`

### `set_lists`
参数：`scope`、`site_name`（scope=site 必填）、`type`（键名）、`items`（JSON 数组）
- 校验：ip 支持单 IP/CIDR；url 支持 `^` 前缀或正则（以 `~` 开头）；ua 字符串；param 名称
返回 `data = {"saved": true, "count": 3}`

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

## 8. 自测（可选）

### `run_selftest`
参数：`site`（必填）、`payload`（字符串，≤ 2048）、`location`（`query|body|header|ua`，默认 query）
说明：向 `http://127.0.0.1` 发送带 `Host: <site>` 的本地请求，随后 tail `waf.log` 匹配 `req_id`，返回命中结果。仅当站点解析到本机时有效。
返回 `data = {"blocked": true, "status": 403, "hits": [...], "request_id": "..."}`

## 9. 前端状态映射

- `status.ready=false` → 顶部红色"引擎未就绪"，引导到系统诊断。
- `status.enabled=false` → 顶部黄色"防护已关闭"。
- `status.observe=true` → 顶部蓝色"观察模式（只记录不拦截）"。
- 所有 `sensitivity` 显示：1=宽松 2=标准 3=严格。
- 所有 `tier` 显示：1=PL1 2=PL2 3=PL3。
