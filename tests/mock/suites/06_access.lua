-- 06-access：请求管线（contract §9 / §4 / §5）
local t = require("mock.framework")
t.suite("06-access")

local mock = require("mock.ngx")
local config = require("lib.config")
local matcher = require("lib.matcher")
local paths = require("lib.paths")
local cc = require("lib.cc")

-- 加载真实 access.lua，但不自动执行（由用例显式调用）
rawset(_G, "BTWAF_CE_ACCESS_AUTORUN", false)
local access_src = mock.file_read(__LUA_ROOT .. "/access.lua")
if type(access_src) ~= "string" then
  error("无法读取 access.lua: " .. tostring(__LUA_ROOT))
end
local access_chunk = assert(load(access_src, "@btwaf_ce/lua/access.lua"))
local access = access_chunk()
if type(access) ~= "function" then
  error("access.lua 未返回可调用入口")
end

-- ---------------------------------------------------------------------------
-- 辅助
-- ---------------------------------------------------------------------------
local function rule_base(over)
  local r = {
    id = "ce-test-1",
    module = "sqli",
    tier = 1,
    score = 5,
    name = "UNION SELECT 测试",
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "urlDecode", "lowercase" },
        op = "@contains",
        value = "union",
      },
    },
  }
  for k, v in pairs(over or {}) do
    r[k] = v
  end
  return r
end

-- 每个用例重建配置与规则
local function setup(opts)
  opts = opts or {}
  local global = {
    enabled = true,
    observe = opts.observe == true,
    sensitivity = opts.sensitivity or 2,
    fail_open = opts.fail_open ~= false,
    modules = { sqli = { open = true, tier = 1 } },
    lists = opts.global_lists or {},
    cc = opts.cc or { open = false },
    attack_block = opts.attack_block or { open = false },
    block = { status = 403, use_custom = false, page = "" },
  }
  local site = {
    open = true,
    lists = opts.site_lists or {},
    custom_rules = {},
  }
  local custom = opts.custom or { rules = {} }
  mock.boot(global, { ["www.example.com"] = site }, { ["www.example.com"] = "www.example.com" }, custom)
  matcher.reset()
  if opts.rules then
    matcher.load({ { meta = { source = opts.rule_source or "ce", module = "sqli" }, rules = opts.rules } }, opts.ac_lists)
  end
  -- 清理本例的日志与共享字典计数，避免用例之间串扰
  __BTWAF_FS_WRITE(paths.waf_log(), "")
  for _, d in pairs(mock.dicts) do
    if d.flush_all then
      pcall(d.flush_all, d)
    end
  end
end

local function request(opts)
  mock.set_request(opts)
  access()
  local status = ngx.status or 200
  return {
    status = status,
    exit = mock.exit_status,
    blocked = status >= 400 or mock.exit_status ~= nil,
    body = mock.response_body(),
  }
end

local function last_log()
  local lines = mock.read_jsonl(paths.waf_log())
  return lines[#lines]
end

local function log_count()
  return #mock.read_jsonl(paths.waf_log())
end

-- ---------------------------------------------------------------------------
-- 用例
-- ---------------------------------------------------------------------------
t.test("正常 GET：放行、不读 body、不写日志", function()
  setup({ rules = { rule_base() } })
  local res = request({ method = "GET", uri = "/index.php", query = "id=1" })
  t.eq(res.blocked, false)
  t.eq(res.status, 200)
  t.eq(mock.body_read_count(), 0, "GET 且无 Content-Length 时不应读取 body")
  t.eq(log_count(), 0, "正常请求不应写攻击日志")
end)

t.test("未匹配站点：直接放行（不读 body、不写日志）", function()
  setup({ rules = { rule_base() } })
  local res = request({ host = "unknown.example.org", uri = "/index.php", query = "id=union" })
  t.eq(res.blocked, false)
  t.eq(mock.body_read_count(), 0)
  t.eq(log_count(), 0)
end)

t.test("IP 黑名单：block(blacklist) + 日志字段完整", function()
  setup({
    rules = { rule_base() },
    global_lists = { ip_black = { "203.0.113.9" } },
  })
  local res = request({ uri = "/index.php", remote_addr = "203.0.113.9" })
  t.eq(res.blocked, true)
  t.eq(res.status, 403)
  local entry = last_log()
  t.ok(entry ~= nil, "应写日志")
  local obj = entry.obj
  t.eq(obj.action, "blacklist")
  t.eq(obj.status, 403)
  t.eq(obj.ip, "203.0.113.9")
  t.eq(obj.site, "www.example.com")
  t.eq(obj.host, "www.example.com")
  t.eq(obj.method, "GET")
  t.eq(obj.uri, "/index.php")
  t.ok(type(obj.time) == "number")
  t.ok(type(obj.query) == "string")
  t.ok(type(obj.hits) == "table")
  t.ok(type(obj.ua) == "string")
  t.ok(type(obj.referer) == "string")
  t.ok(type(obj.ctype) == "string")
  t.ok(type(obj.body_len) == "number")
  t.ok(type(obj.snippet) == "string")
  t.ok(type(obj.block_time) == "number")
  t.ok(type(obj.rule_source) == "string")
  t.ok(type(obj.req_id) == "string" and obj.req_id ~= "")
  t.eq(obj.sensitivity, 2)
end)

t.test("IP 白名单：命中规则也放行", function()
  setup({
    rules = { rule_base() },
    global_lists = { ip_white = { "1.2.3.4" } },
  })
  local res = request({ uri = "/index.php", query = "id=union", remote_addr = "1.2.3.4" })
  t.eq(res.blocked, false)
  t.eq(log_count(), 0, "白名单请求不应写日志")
end)

t.test("规则命中超阈值：block + 日志 hits/action/score", function()
  setup({ rules = { rule_base({ score = 5 }) } })
  local res = request({ uri = "/index.php", query = "id=1+union+select+null" })
  t.eq(res.blocked, true)
  t.eq(res.status, 403)
  local obj = last_log().obj
  t.eq(obj.action, "block")
  t.eq(obj.score, 5)
  t.eq(obj.status, 403)
  t.eq(obj.rule_source, "ce")
  t.eq(#obj.hits, 1)
  t.eq(obj.hits[1].rule, "ce-test-1")
  t.eq(obj.hits[1].module, "sqli")
  t.eq(obj.hits[1].src, "ce")
  t.ok(type(obj.snippet) == "string")
end)

t.test("未达阈值：不拦截但记录 allow（链路内命中）", function()
  setup({ sensitivity = 1, rules = { rule_base({ score = 5 }) } }) -- 阈值 10
  local res = request({ uri = "/index.php", query = "id=union" })
  t.eq(res.blocked, false)
  local obj = last_log().obj
  t.eq(obj.action, "allow")
  t.eq(obj.score, 5)
  t.eq(#obj.hits, 1)
end)

t.test("未达阈值：放行请求不累计攻击次数（避免误封）", function()
  setup({
    sensitivity = 1,
    attack_block = { open = true, cycle = 120, limit = 1, block_time = 1800 },
    rules = { rule_base({ score = 5 }) },
  })
  local opts = { uri = "/index.php", query = "id=union", remote_addr = "198.51.100.31" }
  for i = 1, 3 do
    local res = request(opts)
    t.eq(res.blocked, false, "低分命中第 " .. i .. " 次应放行")
  end
  t.eq(cc.is_blocked("www.example.com", "198.51.100.31"), false, "放行请求不应触发攻击封禁")
end)

t.test("达到阈值的攻击才累计并触发 attack 封锁", function()
  setup({
    sensitivity = 2,
    attack_block = { open = true, cycle = 120, limit = 1, block_time = 1800 },
    rules = { rule_base({ score = 5 }) },
  })
  local res = request({ uri = "/index.php", query = "id=union", remote_addr = "198.51.100.32" })
  t.eq(res.blocked, true)
  t.eq(cc.is_blocked("www.example.com", "198.51.100.32"), true, "应写入 attack 封锁")
  local entries = mock.read_jsonl(paths.block_log())
  local hit = false
  for i = 1, #entries do
    if entries[i].obj.reason == "attack" and entries[i].obj.block_time == 1800 then
      hit = true
    end
  end
  t.eq(hit, true, "block.log 应记录 attack/1800s")
end)

t.test("IP 白名单优先于攻击封禁", function()
  setup({
    sensitivity = 2,
    attack_block = { open = true, cycle = 120, limit = 1, block_time = 1800 },
    global_lists = { ip_white = { "198.51.100.33" } },
    rules = { rule_base({ score = 5 }) },
  })
  local res = request({ uri = "/index.php", query = "id=union", remote_addr = "198.51.100.33" })
  t.eq(res.blocked, false)
  t.eq(cc.is_blocked("www.example.com", "198.51.100.33"), false, "白名单不应被攻击封禁")
end)

t.test("observe 观察模式：不拦截但记录 allow", function()
  setup({ observe = true, rules = { rule_base({ score = 9 }) } })
  local res = request({ uri = "/index.php", query = "id=union" })
  t.eq(res.blocked, false)
  t.eq(res.status, 200)
  local obj = last_log().obj
  t.eq(obj.action, "allow")
  t.ok(#obj.hits >= 1)
  t.eq(obj.status, 200)
end)

t.test("CC 限流：超过 limit 返回 444，解封后恢复", function()
  setup({
    rules = {},
    cc = { open = true, cycle = 60, limit = 2, block_time = 300, status = 444 },
  })
  local opts = { uri = "/index.php", remote_addr = "198.51.100.7" }
  t.eq(request(opts).blocked, false, "第 1 次")
  t.eq(request(opts).blocked, false, "第 2 次")
  local res = request(opts)
  t.eq(res.blocked, true, "第 3 次应被 CC 拦截")
  t.eq(res.exit, 444)
  local obj = last_log().obj
  t.eq(obj.action, "cc")
  t.eq(obj.block_time, 300)
  -- 封锁 key 已写入共享字典
  t.ok(cc.is_blocked("www.example.com", "198.51.100.7"), "应写入 b:<site>:<ip> 封锁 key")
  -- 解封
  cc.unblock("www.example.com", "198.51.100.7")
  t.eq(cc.is_blocked("www.example.com", "198.51.100.7"), false, "解封后 key 应删除")
  local res2 = request(opts)
  t.eq(res2.blocked, false, "解封后应放行")
end)

t.test("CC skip_static：静态资源不计数", function()
  setup({
    rules = {},
    cc = { open = true, cycle = 60, limit = 1, block_time = 300, status = 444, skip_static = true },
  })
  local opts = { uri = "/static/a.css", remote_addr = "198.51.100.8" }
  t.eq(request(opts).blocked, false)
  local res = request(opts)
  t.eq(res.blocked, false, "静态资源不应触发 CC")
end)

t.test("URL 黑名单（正则 ~ 前缀）", function()
  setup({ rules = {}, site_lists = { url_black = { "~^/secret" } } })
  local res = request({ uri = "/secret/data.php" })
  t.eq(res.blocked, true)
  t.eq(last_log().obj.action, "blacklist")
end)

t.test("UA 黑名单（子串，大小写不敏感）", function()
  setup({ rules = {}, site_lists = { ua_black = { "sqlmap" } } })
  local res = request({ uri = "/index.php", headers = { ["user-agent"] = "SQLMap/1.7" } })
  t.eq(res.blocked, true)
  t.eq(last_log().obj.action, "blacklist")
end)

t.test("自定义规则 block（src=custom）", function()
  setup({
    rules = {},
    custom = {
      rules = {
        {
          id = "custom-1", name = "拦截 sqlmap", open = true, priority = 10,
          scope = "global", sites = {},
          field = "ua", header = nil, operator = "contains", value = "sqlmap",
          action = "block", status = 403, score = 5, note = "",
        },
      },
    },
  })
  local res = request({ uri = "/index.php", headers = { ["user-agent"] = "sqlmap/1.0" } })
  t.eq(res.blocked, true)
  local obj = last_log().obj
  t.eq(obj.hits[1].src, "custom")
  t.eq(obj.hits[1].rule, "custom-1")
  t.eq(obj.rule_source, "custom")
end)

t.test("自定义规则 allow：覆盖内置规则命中", function()
  setup({
    rules = { rule_base() },
    custom = {
      rules = {
        {
          id = "custom-allow", name = "放行 /allowed", open = true, priority = 1,
          scope = "global", sites = {},
          field = "uri", operator = "prefix", value = "/allowed",
          action = "allow", status = 200, score = 0, note = "",
        },
      },
    },
  })
  local res = request({ uri = "/allowed/x", query = "id=union" })
  t.eq(res.blocked, false, "自定义 allow 应放行")
end)

t.test("POST body 参与检测（需要读 body）", function()
  setup({
    rules = {
      rule_base({
        chain = {
          { vars = { { type = "REQUEST_BODY" } }, op = "@contains", value = "cmd=" },
        },
      }),
    },
  })
  local res = request({
    method = "POST",
    uri = "/index.php",
    body = "cmd=whoami&x=1",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
  })
  t.eq(res.blocked, true)
  t.ok(mock.body_read_count() > 0, "POST 应读取 body")
  t.eq(last_log().obj.action, "block")
end)

t.test("fail_open=true：引擎异常时放行", function()
  setup({ rules = { rule_base() } })
  local orig = matcher.evaluate
  matcher.evaluate = function()
    error("模拟引擎异常")
  end
  local res = request({ uri = "/index.php", query = "id=union" })
  matcher.evaluate = orig
  t.eq(res.blocked, false, "fail_open 应放行")
end)

t.test("fail_open=false：引擎异常时返回 403", function()
  setup({ rules = { rule_base() }, fail_open = false })
  local orig = matcher.evaluate
  matcher.evaluate = function()
    error("模拟引擎异常")
  end
  local res = request({ uri = "/index.php", query = "id=union" })
  matcher.evaluate = orig
  t.eq(res.blocked, true, "fail_open=false 应失败关闭")
  t.eq(res.status, 403)
end)

t.test("日志行 ≤4KB 且为合法单行 JSON", function()
  setup({ rules = { rule_base() } })
  local long_value = string.rep("A", 4000)
  request({ uri = "/index.php", query = "id=union&big=" .. long_value })
  local entry = last_log()
  t.ok(entry ~= nil)
  t.ok(#entry.raw <= 4096, "单行日志不应超过 4KB，实际 " .. #entry.raw)
  t.ok(not entry.raw:find("\n"), "日志行不应包含换行")
  local obj = entry.obj
  t.eq(obj.action, "block")
  t.ok(obj.uri ~= nil and obj.ua ~= nil)
end)

t.test("性能计数写入共享字典（含 blocked，且在 ngx.exit 前记录）", function()
  setup({ rules = { rule_base() } })
  request({ uri = "/a.php" })
  request({ uri = "/index.php", query = "id=union" })
  local d = ngx.shared["btwaf_ce_cfg"]
  local req_count = d:get("perf:req")
  t.ok(type(req_count) == "number" and req_count >= 2, "perf:req 应累计")
  local hits = d:get("perf:hits")
  t.ok(type(hits) == "number" and hits >= 1, "perf:hits 应累计")
  local blocked = d:get("perf:blocked")
  t.ok(type(blocked) == "number" and blocked >= 1, "被拦截请求也应计数（ngx.exit 前记录）")
end)

