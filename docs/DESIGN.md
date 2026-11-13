# 技术设计（DESIGN）

> 后端 API 见 `API.md`；第三方来源见 `THIRD_PARTY_NOTICES.md`。

## 1. 为什么是"插件 + Nginx Lua"

宝塔用户已有面板托管的 Nginx 站点，插件的目标是**就地保护**：

- 不改变站点架构、不改 DNS/回源；
- 不额外监听端口、不引入 Docker/Go 控制台；
- 复用面板自带的 Nginx（含 `lua-nginx-module`）与 LuaJIT；
- 零外网依赖：规则、页面、UI 全部随包。

## 2. 组件与数据流

```
                    ┌──────────────────────── 面板 (Python 3.13) ────────────────────────┐
浏览器（面板 UI）──► │ btwaf_ce_main.py → wafcore/{config,sites,logs,rules,engine,state}  │
                    │        │                                   │                      │
                    │        ├─ 写 config.json / site.json / hosts.json                  │
                    │        ├─ 读 waf.log / block.log / unban.log                       │
                    │        └─ nginx -t / reload（仅安装、自愈、conf 漂移）              │
                    └────────┼───────────────────────────────────────────────────────────┘
                             │ 文件（免 reload 生效，≤3s）
                             ▼
┌──────────────────────────── 站点 Nginx（http 级） ───────────────────────────────────┐
│ btwaf_ce.conf: lua_shared_dict ×3 / init_worker_by_lua_file / access_by_lua_file      │
│   init.lua  ── 载入配置+规则；2–3s 定时器：配置热更新 / unban 增量 / 日志轮转 / perf   │
│   access.lua ── 管线：站点匹配→IP/CC→名单→协议/敏感→UA/扫描器→取参→解码→规则→决策     │
│        ├─ 命中 → 拦截页/status（403/444）                                              │
│        ├─ 写 waf.log（JSONL，仅命中/封锁请求）                                         │
│        └─ 临时封锁 → shared dict + block.log；解封 ← unban.log                          │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

## 3. 关键设计决策

| 决策 | 理由 |
|---|---|
| http 级单入口 `access_by_lua_file` + 站点配置表 | 不向站点 server 块注入 include，避免面板重写站点配置时丢失；站点未开启时开销接近 0 |
| `init.lua` 自设 `package.path`，不用 `lua_package_path` 指令 | 避免与面板/官方 WAF/加速插件的路径设置互相覆盖，也避免面板"配置接管"告警 |
| 配置走文件 + 定时器热更新，只有安装/升级/自愈才 reload | 改配置不需要 `nginx -s reload`，避免 reload 抖动 |
| 规则 = CRS 移植 + 自研 + 用户自定义，统一 Lua 表 | 运行期是 LuaJIT + PCRE（`ngx.re`），CRS 正则可直接复用；统一评分模型 |
| 异常量评分（CRS 模型）：severity 5/4/3/2，阈值随灵敏度 10/5/3 | 成熟模型、可解释；避免单条弱规则误拦 |
| 阻断状态 403（可自定义拦截页）/ 444（断连），两级可配 | 满足普通站点与"静默阻断"两类需求 |
| 临时封锁用 shared dict + 文件双写 | Lua 侧快速判定，Python 侧可查询/解封；不暴露额外监听端口 |
| fail-open 默认开启、可切 fail-close | 引擎异常时不拖垮业务；错误在 UI 可见 |
| 日志只记命中/封锁请求 | 正常请求零写盘；日志目录不在 webroot |
| 零二进制、零编译 | 宝塔环境差异大；纯 Lua + Python 最稳 |

## 4. 请求生命周期（access.lua）

1. 读取 `ngx.var.host` → `hosts.json` 映射站点；未映射直接 `return`（不检测）。
2. 站点 `open=false` → 直接放行。
3. 解析客户端 IP（CDN 头仅在可信代理内采信）。
4. IP 白/黑名单、CC、URL/UA 名单（命中即决策）。
5. 协议检查（方法/Content-Type/字符集/后缀/头长度）。
6. 敏感路径（AC 预筛）、扫描器/爬虫（UA + 头）。
7. 取参与解码（限额；multipart 落盘时读临时文件头部）。
8. CRS/自研/自定义规则匹配（AC 预筛 + `ngx.re`），累计异常分与命中明细。
9. 语义补充分（SQL 词法 / XSS 折叠）。
10. 攻击计数 → 超限临时封锁。
11. 决策：观察模式或分数不足 → 放行（有命中则记 `action=allow`）；否则阻断。
12. 写一行 JSON 日志；异常一律 `pcall` + 去重 + fail-open。

## 5. 失败模式

| 场景 | 行为 |
|---|---|
| 配置 JSON 缺失/损坏 | 使用上一份内存配置；启动时无配置则放行全部；`data/logs/error.log` 记录 |
| 规则文件缺失 | 跳过该文件并计数；不影响其它规则 |
| 共享字典写满 | 降级为不缓存/不封锁，记录错误 |
| 日志目录不可写 | 跳过日志，计数错误，不影响拦截 |
| `nginx -t` 失败（安装/自愈） | 回滚 conf，保持站点可用，安装失败并提示 |
| Lua VM 异常 | `pcall` 包裹；`fail_open=true` 放行；UI 显示错误数 |

## 6. 性能

- 未匹配站点：< 10µs（一次 hash 查找）。
- 普通 GET：关键词预筛后仅跑命中的少量正则，目标 ≤0.5ms。
- POST：按 `scan.*` 限额读 body；超过上限跳过 body 检测并记录。
- AC 自动机（纯 Lua）用于大列表（扫描器 UA、敏感后缀、pm 列表），避免逐条正则。
- 定时器仅在 worker 0 执行轮转；perf 每 60s 落盘，不参与请求路径。
- 提供"性能模式"建议（关闭 body/上传扫描、仅 PL1），在 README 说明。

## 7. 扩展点

- 新增内置规则：在 `lua/rules/ce_*.lua` 增加规则表（格式参考现有 `lua/rules/ce_*.lua`）。
- 新增规则源：扩展规则构建流程的变量/变换/操作符映射。
- 地区限制（v2）：在管线第 4 步后插入 `region` 模块（需要 CN CIDR/GeoLite 派生数据，另行评估授权）。
- 人机验证（v2）：在阻断决策处替换为 challenge 页面。
- 面板站点列表联动（后续版本）：同步面板站点与域名。
