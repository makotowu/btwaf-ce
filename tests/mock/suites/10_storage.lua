-- 10-storage：日志/封锁/轮转/perf/拦截页（contract §4 / §5 / §6.11）
local t = require("mock.framework")
t.suite("10-storage")

local mock = require("mock.ngx")
local storage = require("lib.storage")
local paths = require("lib.paths")
local json = require("lib.json")
local util = require("lib.util")

local function ctx(over)
  over = over or {}
  return {
    site = { site_name = over.site_name or "www.example.com" },
    host = over.host or "www.example.com",
    ip = over.ip or "1.2.3.4",
    remote_addr = over.ip or "1.2.3.4",
    method = over.method or "GET",
    uri = over.uri or "/index.php",
    uri_raw = over.uri_raw or "/index.php?id=1",
    query = over.query or "id=1",
    headers = over.headers or { ["user-agent"] = "UA/1.0", ["referer"] = "-", ["content-type"] = "text/html" },
    args = {},
    body_len = 0,
    cfg = { log = { snippet = 512 } },
    req_id = over.req_id or "req-test-1",
  }
end

t.test("build_attack_record：字段/截断/控制字符清洗", function()
  storage.reset_cache()
  local c = ctx({
    uri_raw = "/a.php?" .. string.rep("x", 600),
    headers = { ["user-agent"] = string.rep("u", 300), ["referer"] = string.rep("r", 300), ["content-type"] = "text/html" },
  })
  local rec = storage.build_attack_record(c, {
    action = "block", status = 403, score = 5, sensitivity = 2,
    hits = { { module = "sqli", rule = "crs-942100", name = "SQLi", score = 5, tier = 1, src = "crs" } },
    snippet = "a\0b\nc", block_time = 300, rule_source = "crs",
  })
  t.eq(rec.site, "www.example.com")
  t.eq(rec.ip, "1.2.3.4")
  t.eq(rec.method, "GET")
  t.ok(#rec.uri <= 512, "uri 截断到 512")
  t.ok(#rec.ua <= 256, "ua 截断到 256")
  t.ok(#rec.referer <= 256, "referer 截断到 256")
  t.eq(#rec.hits, 1)
  t.eq(rec.hits[1].rule, "crs-942100")
  t.eq(rec.hits[1].src, "crs")
  t.eq(rec.action, "block")
  t.eq(rec.status, 403)
  t.eq(rec.block_time, 300)
  t.eq(rec.rule_source, "crs")
  t.ok(not rec.snippet:find("\0"), "控制字符应被替换")
  t.ok(not rec.snippet:find("\n"))
end)

t.test("write_attack：JSONL 合法、单行 ≤4KB", function()
  mock.file_write(paths.waf_log(), "")
  local c = ctx({})
  local line = storage.write_attack(c, {
    action = "block", status = 403, score = 5, sensitivity = 2,
    hits = { { module = "sqli", rule = "x", name = "n", score = 5, tier = 1, src = "ce" } },
    snippet = string.rep("A", 20000), rule_source = "ce",
  })
  t.ok(type(line) == "string")
  t.ok(#line <= 4096, "单行不应超过 4KB，实际 " .. #line)
  local entries = mock.read_jsonl(paths.waf_log())
  t.eq(#entries, 1, "应写入一行")
  t.ok(entries[1].obj ~= nil, "日志行必须是合法 JSON")
  t.eq(entries[1].obj.action, "block")
  t.eq(entries[1].obj.req_id, "req-test-1")
end)

t.test("add_block：共享字典 + block.log（expire 正确）", function()
  local blockmd = ngx.shared["btwaf_ce_block"]
  blockmd:flush_all()
  mock.file_write(paths.block_log(), "")
  local c = ctx({ ip = "203.0.113.50" })
  local expire = storage.add_block(c, "attack", 120)
  t.ok(type(expire) == "number")
  t.eq(expire, util.now() + 120)
  t.eq(blockmd:get("b:www.example.com:203.0.113.50"), 1, "共享字典应写入布尔封锁值")
  local entries = mock.read_jsonl(paths.block_log())
  t.eq(#entries, 1)
  t.eq(entries[1].obj.reason, "attack")
  t.eq(entries[1].obj.ip, "203.0.113.50")
  t.eq(entries[1].obj.site, "www.example.com")
  t.eq(entries[1].obj.block_time, 120)
  t.eq(entries[1].obj.expire, expire)
end)

t.test("rotate：超过 rotate_size 轮转为 waf-YYYYMMDD.log", function()
  storage.reset_cache()
  mock.file_write(paths.waf_log(), string.rep("x", 500))
  local now = util.now()
  storage.rotate({ log = { rotate_size = 100, retain_days = 30 } })
  t.eq(mock.file_exists(paths.waf_log()), true)
  -- 首次轮转、当天无历史文件：目标名固定为 waf-YYYYMMDD.log
  local rot = paths.rotated_log(os.date("%Y%m%d", now))
  t.eq(mock.file_exists(rot), true, "应生成轮转日志 " .. rot)
  t.eq(mock.file_read(rot), string.rep("x", 500), "轮转文件应保留原内容")
end)

t.test("rotate：清理保留期外历史日志", function()
  storage.reset_cache()
  local old = os.date("%Y%m%d", util.now() - 31 * 86400)
  local old_path = paths.rotated_log(old)
  mock.file_write(old_path, "old")
  t.eq(mock.file_exists(old_path), true)
  storage.rotate({ log = { rotate_size = 52428800, retain_days = 30 } })
  t.eq(mock.file_exists(old_path), false, "31 天前的日志应被清理")
end)

t.test("write_perf：写 data/perf.json", function()
  mock.file_write(paths.perf_file(), "")
  local ok = storage.write_perf({ requests = 10, hits = 3, blocked = 2, avg_ms = 1.5, updated = util.now() })
  t.eq(ok, true)
  local obj = json.decode(mock.file_read(paths.perf_file()))
  t.eq(obj.requests, 10)
  t.eq(obj.hits, 3)
  t.eq(obj.blocked, 2)
  t.eq(obj.avg_ms, 1.5)
  t.ok(obj.updated > 0)
end)

t.test("block_page：缓存 + 30 秒后重读", function()
  storage.reset_cache()
  mock.file_write(paths.block_page(), "<html>custom-1</html>")
  t.eq(storage.block_page(), "<html>custom-1</html>")
  -- 缓存期内修改不生效
  mock.file_write(paths.block_page(), "<html>custom-2</html>")
  t.eq(storage.block_page(), "<html>custom-1</html>")
  -- 超过 30 秒后重新读取
  mock.advance(31)
  t.eq(storage.block_page(), "<html>custom-2</html>")
  -- 文件不存在返回 nil
  __BTWAF_FS_REMOVE(paths.block_page())
  storage.reset_cache()
  t.eq(storage.block_page(), nil)
end)
