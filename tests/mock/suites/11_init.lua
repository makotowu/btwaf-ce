-- 11-init：init.lua 定时器（热更新/unban/perf/轮转）+ 真实规则集成
local t = require("mock.framework")
t.suite("11-init")

local mock = require("mock.ngx")
local json = require("lib.json")
local paths = require("lib.paths")

local MODULE_NAMES = {
  "sqli", "xss", "rce", "lfi", "php", "java",
  "scan", "crawler", "sensitive", "upload", "protocol", "custom",
}

local function write_fixtures()
  local modules = {}
  for i = 1, #MODULE_NAMES do
    modules[MODULE_NAMES[i]] = { open = true, tier = 1 }
  end
  mock.file_write(paths.config_file(), json.encode({
    schema = 1,
    enabled = true,
    observe = false,
    sensitivity = 2,
    modules = modules,
    cc = { open = false },
    attack_block = { open = false },
    log = { enabled = true, retain_days = 30, rotate_size = 52428800, snippet = 512 },
  }))
  mock.file_write(paths.site_file(), json.encode({
    ["www.example.com"] = {
      open = true,
      modules = modules,
      cc = { open = false },
      attack_block = { open = false },
      custom_rules = {},
    },
  }))
  mock.file_write(paths.hosts_file(), json.encode({ ["www.example.com"] = "www.example.com" }))
  mock.file_write(paths.custom_rule_file(), json.encode({ rules = {} }))
end

t.test("加载 init.lua：初始化配置/规则并注册 2–3s 定时器", function()
  write_fixtures()
  local init_src = mock.file_read(paths.LUA_DIR .. "/init.lua")
  t.ok(type(init_src) == "string", "应能读取 init.lua")
  local chunk = assert(load(init_src, "@init.lua"))
  chunk()

  local bootstrap = require("lib.bootstrap")
  local config = require("lib.config")
  t.eq(bootstrap.stats().initialized, true, "bootstrap 应完成初始化")
  t.eq(config.ready(), true)
  t.eq(config.site("www.example.com") ~= nil, true)
  t.ok(mock.timer_count() >= 1, "应注册定时器")
  local interval = mock.timers[1].interval
  t.ok(interval >= 2 and interval <= 3, "定时器间隔应为 2–3s，实际 " .. tostring(interval))
end)

t.test("定时器：perf.json 落盘（requests/blocked/avg_ms 更新）", function()
  local perf = require("lib.perf")
  perf.record(2.0, true, false)
  perf.record(4.0, false, true)
  mock.run_timers()
  local pf = json.decode(mock.file_read(paths.perf_file()))
  t.ok(type(pf) == "table", "perf.json 应存在且为合法 JSON")
  t.ok(pf.requests >= 2, "requests 应累计")
  t.ok(pf.blocked >= 1, "blocked 应累计")
  t.ok(pf.updated > 0, "updated 应刷新")
  t.ok(pf.avg_ms > 0, "avg_ms 不应恒为 0（µs 累计后换算）")
end)

t.test("定时器：unban.log 增量应用并持久化 unban_offset", function()
  local storage = require("lib.storage")
  local cc = require("lib.cc")
  local ctx = {
    ip = "203.0.113.77",
    site = { site_name = "www.example.com" },
    host = "www.example.com",
    headers = {},
    args = {},
  }
  storage.add_block(ctx, "cc", 300)
  t.eq(cc.is_blocked("www.example.com", "203.0.113.77"), true)
  -- Python 追加解封记录
  mock.file_write(paths.unban_log(), json.encode({
    time = mock.now(), ip = "203.0.113.77", site = "www.example.com",
  }) .. "\n")
  mock.file_write(paths.state_file(), json.encode({ unban_offset = 0 }))
  mock.run_timers()
  t.eq(cc.is_blocked("www.example.com", "203.0.113.77"), false, "封锁 key 应被删除")
  local state = json.decode(mock.file_read(paths.state_file()))
  t.ok(type(state) == "table")
  t.ok(state.unban_offset > 0, "unban_offset 应前进")
  -- 再次运行定时器不应重复处理（幂等）
  local state2 = json.decode(mock.file_read(paths.state_file()))
  mock.run_timers()
  local state3 = json.decode(mock.file_read(paths.state_file()))
  t.eq(state3.unban_offset, state2.unban_offset, "无新增记录时 offset 不变")
end)

t.test("定时器：配置热更新生效（≤ 一个 tick）", function()
  local config = require("lib.config")
  t.eq(config.global().enabled, true)
  mock.file_write(paths.config_file(), json.encode({ enabled = false, sensitivity = 3 }))
  mock.run_timers()
  t.eq(config.global().enabled, false, "热更新后应立即生效")
  t.eq(config.global().sensitivity, 3)
end)

t.test("真实规则 + access 集成：SQLi 请求被拦截", function()
  -- 恢复配置为启用
  write_fixtures()
  mock.run_timers()
  local config = require("lib.config")
  t.eq(config.global().enabled, true)

  rawset(_G, "BTWAF_CE_ACCESS_AUTORUN", false)
  local access_src = mock.file_read(paths.LUA_DIR .. "/access.lua")
  local access = assert(load(access_src, "@access.lua"))()

  mock.set_request({
    method = "GET",
    uri = "/index.php",
    query = "id=1%27+union+select+null%2Cnull--",
    host = "www.example.com",
    remote_addr = "1.2.3.4",
  })
  access()
  local blocked = (ngx.status or 200) >= 400 or mock.exit_status ~= nil
  t.eq(blocked, true, "真实规则（CRS/自研）应拦截 UNION SELECT 注入，实际 status=" ..
    tostring(ngx.status))
end)
