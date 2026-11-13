-- 07-config：配置加载/继承/合并/热更新（contract §3 / §6.2）
local t = require("mock.framework")
t.suite("07-config")

local mock = require("mock.ngx")
local config = require("lib.config")
local paths = require("lib.paths")
local json = require("lib.json")

local function reset()
  config.reset()
end

t.test("默认全局配置（字段齐全、类型正确）", function()
  reset()
  config.load_from_tables({}, {}, {}, {})
  local g = config.global()
  t.eq(g.sensitivity, 2)
  t.eq(g.enabled, true)
  t.eq(g.observe, false)
  t.eq(g.fail_open, true)
  t.eq(g.cc.open, true)
  t.eq(g.cc.limit, 120)
  t.eq(g.attack_block.limit, 20)
  t.eq(g.attack_block.block_time, 1800)
  t.eq(g.block.status, 403)
  t.eq(g.scan.body_limit, 1048576)
  t.eq(g.modules.sqli.open, true)
  t.eq(g.modules.sqli.tier, 1)
  t.eq(#g.crawler.allow > 0, true)
  t.eq(config.ready(), true)
end)

t.test("未匹配站点返回 nil；host 支持端口/大小写/末尾点", function()
  reset()
  config.load_from_tables({}, {
    ["www.example.com"] = { open = true },
  }, {
    ["www.example.com"] = "www.example.com",
  }, {})
  t.eq(config.site("unknown.com"), nil)
  t.ok(config.site("www.example.com") ~= nil)
  t.ok(config.site("WWW.EXAMPLE.COM:8080") ~= nil)
  t.ok(config.site("www.example.com.") ~= nil)
  t.eq(config.site_name_for_host("www.example.com:443"), "www.example.com")
end)

t.test("站点继承：0/null/空 = 继承全局", function()
  reset()
  config.load_from_tables({
    sensitivity = 2,
    cc = { limit = 100, block_time = 200, cycle = 60 },
    attack_block = { limit = 20, block_time = 86400 },
  }, {
    ["a.com"] = {
      open = true,
      sensitivity = 0,
      modules = { sqli = { open = true, tier = 0 } },
      cc = { limit = 0, block_time = 0, cycle = 0 },
      attack_block = { limit = 0 },
    },
  }, { ["a.com"] = "a.com" }, {})
  local site = config.site("a.com")
  t.ok(site ~= nil)
  t.eq(site.sensitivity, 2, "sensitivity=0 继承全局")
  t.eq(site.modules.sqli.tier, 1, "tier=0 继承全局 tier")
  t.eq(site.cc.limit, 100, "cc.limit=0 继承全局")
  t.eq(site.cc.block_time, 200)
  t.eq(site.attack_block.limit, 20)
  t.eq(site.observe, false, "observe=null 继承全局 false")
end)

t.test("站点覆盖：sensitivity/observe/modules tier", function()
  reset()
  config.load_from_tables({
    sensitivity = 1,
    observe = false,
    modules = { sqli = { open = true, tier = 1 } },
  }, {
    ["b.com"] = {
      open = true,
      sensitivity = 3,
      observe = true,
      modules = { sqli = { open = false, tier = 2 }, xss = { open = true, tier = 2 } },
    },
  }, { ["b.com"] = "b.com" }, {})
  local site = config.site("b.com")
  t.eq(site.sensitivity, 3)
  t.eq(site.observe, true)
  t.eq(site.modules.sqli.open, false)
  t.eq(site.modules.sqli.tier, 2)
  t.eq(site.modules.xss.tier, 2)
end)

t.test("列表合并 = 全局 ∪ 站点（去重保序）", function()
  reset()
  config.load_from_tables({
    lists = { ip_black = { "1.1.1.1", "2.2.2.2" }, url_white = { "^/health" } },
    rule_exclude = { crs = { "crs-1" } },
  }, {
    ["c.com"] = {
      open = true,
      lists = { ip_black = { "2.2.2.2", "3.3.3.3" } },
      rule_exclude = { crs = { "crs-2" }, ce = { "ce-1" } },
    },
  }, { ["c.com"] = "c.com" }, {})
  local site = config.site("c.com")
  t.eq(#site.lists.ip_black, 3)
  t.eq(site.lists.ip_black[1], "1.1.1.1")
  t.eq(site.lists.ip_black[3], "3.3.3.3")
  t.eq(#site.lists.url_white, 1)
  t.eq(#site.rule_exclude.crs, 2)
  t.eq(#site.rule_exclude.ce, 1)
end)

t.test("自定义规则：global + 站点 scope + 站点内联，按 priority 排序", function()
  reset()
  config.load_from_tables({}, {
    ["d.com"] = {
      open = true,
      custom_rules = {
        { id = "inline-1", open = true, priority = 20, field = "ua", operator = "contains", value = "x", action = "log" },
      },
    },
  }, { ["d.com"] = "d.com" }, {
    rules = {
      { id = "g1", open = true, priority = 30, scope = "global", field = "uri", operator = "contains", value = "/a", action = "block" },
      { id = "s1", open = true, priority = 10, scope = "site", sites = { "d.com" }, field = "uri", operator = "contains", value = "/b", action = "block" },
      { id = "s2", open = true, priority = 5, scope = "site", sites = { "other.com" }, field = "uri", operator = "contains", value = "/c", action = "block" },
    },
  })
  local site = config.site("d.com")
  local rules = config.custom_rules(site)
  t.eq(#rules, 3, "应为 g1 + s1 + inline-1（s2 不适用）")
  t.eq(rules[1].id, "s1", "priority 小的先执行")
  t.eq(rules[2].id, "inline-1")
  t.eq(rules[3].id, "g1")
end)

t.test("cfg.modules / cfg.custom_rules(nil) / stats", function()
  reset()
  config.load_from_tables({ modules = { sqli = { open = false, tier = 2 } } }, {
    ["e.com"] = { open = true },
  }, { ["e.com"] = "e.com" }, { rules = {} })
  local mods = config.modules()
  t.eq(mods.sqli.open, false)
  t.eq(mods.sqli.tier, 2)
  local stats = config.stats()
  t.eq(stats.sites, 1)
  t.eq(stats.hosts, 1)
  t.eq(stats.ready, true)
end)

t.test("读取文件 + 热更新（指纹变化才重载）", function()
  reset()
  mock.file_write(paths.config_file(), json.encode({ enabled = true, sensitivity = 2 }))
  mock.file_write(paths.site_file(), json.encode({ ["f.com"] = { open = true } }))
  mock.file_write(paths.hosts_file(), json.encode({ ["f.com"] = "f.com" }))
  mock.file_write(paths.custom_rule_file(), json.encode({ rules = {} }))
  t.eq(config.init(), true)
  t.eq(config.global().enabled, true)
  t.eq(config.site("f.com") ~= nil, true)

  -- 无变化：不重载
  t.eq(config.reload_if_changed(), false)

  -- 修改 config.json：应重载
  mock.file_write(paths.config_file(), json.encode({ enabled = false, sensitivity = 3 }))
  t.eq(config.reload_if_changed(), true)
  t.eq(config.global().enabled, false)
  t.eq(config.global().sensitivity, 3)
  t.eq(config.reload_if_changed(), false, "重复调用不应重载")
end)

t.test("配置文件损坏：降级默认配置 + 记录 last_error，不崩溃", function()
  reset()
  mock.file_write(paths.config_file(), "{ not valid json")
  local ok = config.init()
  t.eq(ok, true, "init 应容错返回")
  t.eq(config.global().sensitivity, 2, "使用默认值")
  t.ok(type(config.last_error()) == "string" and config.last_error() ~= "")
end)

t.test("规则加载容错：模块缺失只记录不崩溃", function()
  local rules_mod = require("lib.rules")
  local res = rules_mod.load({ modules = { "rules.__not_exist__" } })
  t.eq(res.total_rules, 0)
  t.eq(#res.failed, 1)
  t.eq(res.failed[1].name, "rules.__not_exist__")
end)

t.test("真实规则目录：manifest 可加载且不报错", function()
  local bootstrap = require("lib.bootstrap")
  mock.boot({ enabled = true }, {}, {}, { rules = {} })
  local stats = bootstrap.load_rules()
  t.ok(type(stats) == "table", "load_rules 应返回统计")
  if stats then
    t.ok(stats.total_rules > 0, "真实 rules/manifest.lua 应加载出规则，实际=" ..
      tostring(stats.total_rules))
    t.eq(stats.source, "manifest", "应通过 manifest 枚举规则文件")
    t.ok(require("lib.matcher").rule_count() > 0)
  end
end)
