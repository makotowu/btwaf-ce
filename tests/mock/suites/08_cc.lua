-- 08-cc：CC 限流 / 攻击计数 / 封锁解封（contract §6.10 / §5）
local t = require("mock.framework")
t.suite("08-cc")

local mock = require("mock.ngx")
local cc = require("lib.cc")
local paths = require("lib.paths")

local function site(over)
  return {
    site_name = "www.example.com",
    observe = false,
    cc = over and over.cc or { open = true, cycle = 60, limit = 3, block_time = 300, status = 444, skip_static = true },
    attack_block = over and over.attack_block or { open = true, cycle = 120, limit = 3, block_time = 86400 },
    block = { status = 403 },
  }
end

local function ctx(site_cfg, ip, uri)
  return {
    site = site_cfg,
    ip = ip,
    remote_addr = ip,
    uri = uri or "/index.php",
    method = "GET",
    host = "www.example.com",
    headers = {},
    args = {},
  }
end

t.test("CC 计数：达到 limit 后封锁并写 block.log", function()
  cc.reset()
  local s = site()
  local ip = "198.51.100.11"
  local blocked = false
  local counter = 0
  for i = 1, 3 do
    local b, c = cc.check(ctx(s, ip))
    blocked, counter = b, c
    t.eq(b, false, "第 " .. i .. " 次不应封锁")
  end
  t.eq(counter, 3)
  local b4, c4 = cc.check(ctx(s, ip))
  t.eq(b4, true, "第 4 次应封锁")
  t.ok(c4 >= 4)
  t.eq(cc.is_blocked("www.example.com", ip), true, "应写入封锁 key")
  -- block.log 已追加
  local entries = mock.read_jsonl(paths.block_log())
  t.ok(#entries >= 1)
  local last = entries[#entries].obj
  t.eq(last.reason, "cc")
  t.eq(last.ip, ip)
  t.eq(last.block_time, 300)
  t.eq(last.expire, mock.now() + 300)
end)

t.test("封锁 TTL 到期后自动解封", function()
  cc.reset()
  local s = site({ cc = { open = true, cycle = 60, limit = 1, block_time = 10, status = 444 } })
  local ip = "198.51.100.12"
  cc.check(ctx(s, ip)) -- 1
  local blocked = cc.check(ctx(s, ip)) -- 2 > 1 -> 封锁
  t.eq(blocked, true)
  mock.advance(61)
  t.eq(cc.is_blocked("www.example.com", ip), false, "block key TTL 到期应消失")
  local b = cc.check(ctx(s, ip))
  t.eq(b, false, "计数窗口也过期，应放行")
end)

t.test("observe 观察模式：只计数不封锁", function()
  cc.reset()
  local s = site({ cc = { open = true, cycle = 60, limit = 1, block_time = 300, status = 444 } })
  s.observe = true
  local ip = "198.51.100.13"
  for i = 1, 3 do
    local b = cc.check(ctx(s, ip))
    t.eq(b, false, "观察模式不应封锁")
  end
  t.eq(cc.is_blocked("www.example.com", ip), false)
end)

t.test("url_cc：按 URI 独立计数", function()
  cc.reset()
  local s = site({ cc = { open = true, cycle = 60, limit = 2, block_time = 300, url_cc = true } })
  local ip = "198.51.100.14"
  local c = ctx(s, ip, "/a")
  t.eq((cc.check(c)), false)
  t.eq(c.cc.counter, 1, "/a 计数 1")
  c = ctx(s, ip, "/a")
  t.eq((cc.check(c)), false)
  t.eq(c.cc.counter, 2, "/a 计数 2")
  -- /b 使用独立计数键（从 1 开始，而不是接着 /a 的 2）
  local cb = ctx(s, ip, "/b")
  t.eq((cc.check(cb)), false)
  t.eq(cb.cc.counter, 1, "/b 独立计数")
  local ca = ctx(s, ip, "/a")
  t.eq((cc.check(ca)), true, "/a 超过 limit 应封锁")
  t.eq(ca.cc.counter, 3)
end)

t.test("skip_static：静态资源不计数", function()
  cc.reset()
  local s = site({ cc = { open = true, cycle = 60, limit = 1, block_time = 300, skip_static = true } })
  local ip = "198.51.100.15"
  for i = 1, 3 do
    t.eq((cc.check(ctx(s, ip, "/static/app.css"))), false)
    t.eq((cc.check(ctx(s, ip, "/static/app.js"))), false)
  end
  t.eq(cc.is_blocked("www.example.com", ip), false)
end)

t.test("CC 关闭时完全不计数", function()
  cc.reset()
  local s = site({ cc = { open = false } })
  local ip = "198.51.100.16"
  for i = 1, 5 do
    t.eq((cc.check(ctx(s, ip))), false)
  end
  t.eq(cc.is_blocked("www.example.com", ip), false)
end)

t.test("攻击计数：达到 attack_block.limit 后封锁（reason=attack）", function()
  cc.reset()
  local s = site({ attack_block = { open = true, cycle = 120, limit = 2, block_time = 86400 } })
  local ip = "198.51.100.17"
  t.eq(cc.add_hit(ctx(s, ip)), false)
  t.eq(cc.add_hit(ctx(s, ip)), true, "第 2 次达到 limit 应封锁")
  t.eq(cc.is_blocked("www.example.com", ip), true)
  local entries = mock.read_jsonl(paths.block_log())
  local found = false
  for i = 1, #entries do
    if entries[i].obj.reason == "attack" and entries[i].obj.ip == ip then
      found = true
    end
  end
  t.eq(found, true, "block.log 应包含 reason=attack")
end)

t.test("攻击计数 observe 模式不封锁", function()
  cc.reset()
  local s = site({ attack_block = { open = true, cycle = 120, limit = 1, block_time = 86400 } })
  s.observe = true
  local ip = "198.51.100.18"
  t.eq(cc.add_hit(ctx(s, ip)), false)
  t.eq(cc.add_hit(ctx(s, ip)), false)
  t.eq(cc.is_blocked("www.example.com", ip), false)
end)

t.test("unblock：删除封锁 key 并清空计数（解封后立即可访问）", function()
  cc.reset()
  local s = site({ cc = { open = true, cycle = 60, limit = 1, block_time = 300, status = 444 } })
  local ip = "198.51.100.19"
  cc.check(ctx(s, ip))
  t.eq((cc.check(ctx(s, ip))), true, "应封锁")
  t.eq(cc.is_blocked("www.example.com", ip), true)
  cc.unblock("www.example.com", ip)
  t.eq(cc.is_blocked("www.example.com", ip), false)
  -- 计数被清空：下一次请求不应立即重新封锁
  local b = cc.check(ctx(s, ip))
  t.eq(b, false, "解封后计数应清零")
end)

t.test("攻击计数：同一 request_id 只计一次（内部重定向不放大）", function()
  cc.reset()
  local s = site({ attack_block = { open = true, cycle = 120, limit = 2, block_time = 1800 } })
  local ip = "198.51.100.21"
  local first = ctx(s, ip)
  first.req_id = "rid-same-1"
  t.eq(cc.add_hit(first), false, "首次不应封禁")
  local again = ctx(s, ip)
  again.req_id = "rid-same-1"
  t.eq(cc.add_hit(again), false, "同一 request_id 不应重复计数")
  local third = ctx(s, ip)
  third.req_id = "rid-same-2"
  t.eq(cc.add_hit(third), true, "不同 request_id 才累计到 limit")
end)

t.test("site 为 nil/无 cc 配置时安全", function()
  cc.reset()
  local b = cc.check({ ip = "1.2.3.4", uri = "/x", headers = {}, args = {} })
  t.eq(b, false)
  t.eq(cc.add_hit({ ip = "1.2.3.4", headers = {}, args = {} }), false)
  t.eq(cc.unblock("", "1.2.3.4"), false)
end)


