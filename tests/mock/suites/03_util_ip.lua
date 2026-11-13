-- 03-util-ip：IP/CIDR、字符串安全、错误去重（contract §6.3）
local t = require("mock.framework")
t.suite("03-util-ip")

local util = require("lib.util")
local mock = require("mock.ngx")

t.test("ip_to_int", function()
  t.eq(util.ip_to_int("0.0.0.0"), 0)
  t.eq(util.ip_to_int("1.2.3.4"), 16909060)
  t.eq(util.ip_to_int("255.255.255.255"), 4294967295)
  t.eq(util.ip_to_int("256.1.1.1"), nil)
  t.eq(util.ip_to_int("1.2.3"), nil)
  t.eq(util.ip_to_int("abc"), nil)
end)

t.test("cidr_match：网段/精确/边界/非法", function()
  t.eq(util.cidr_match("192.168.1.5", "192.168.1.0/24"), true)
  t.eq(util.cidr_match("192.168.2.5", "192.168.1.0/24"), false)
  t.eq(util.cidr_match("10.1.2.3", "10.1.0.0/16"), true)
  t.eq(util.cidr_match("10.2.2.3", "10.1.0.0/16"), false)
  t.eq(util.cidr_match("1.2.3.4", "0.0.0.0/0"), true)
  t.eq(util.cidr_match("1.2.3.4", "1.2.3.4/32"), true)
  t.eq(util.cidr_match("1.2.3.5", "1.2.3.4/32"), false)
  -- /25 边界：x.x.x.127/25 与 128/25 分属不同网段
  t.eq(util.cidr_match("10.0.0.127", "10.0.0.0/25"), true)
  t.eq(util.cidr_match("10.0.0.128", "10.0.0.0/25"), false)
  -- 纯 IP 精确匹配
  t.eq(util.cidr_match("1.2.3.4", "1.2.3.4"), true)
  t.eq(util.cidr_match("1.2.3.5", "1.2.3.4"), false)
  -- 非法输入安全
  t.eq(util.cidr_match(nil, "1.2.3.4"), false)
  t.eq(util.cidr_match("1.2.3.4", "bad/99"), false)
end)

t.test("ip_in_list 支持 CIDR 与普通 IP", function()
  local list = { "10.0.0.0/8", "203.0.113.5", "  " }
  t.eq(util.ip_in_list("10.9.9.9", list), true)
  t.eq(util.ip_in_list("203.0.113.5", list), true)
  t.eq(util.ip_in_list("203.0.113.6", list), false)
  t.eq(util.ip_in_list("1.2.3.4", {}), false)
  t.eq(util.ip_in_list("1.2.3.4", nil), false)
end)

t.test("is_ip", function()
  t.eq(util.is_ip("1.2.3.4"), true)
  t.eq(util.is_ip("2001:db8::1"), true)
  t.eq(util.is_ip(""), false)
  t.eq(util.is_ip("1.2.3"), false)
end)

t.test("truncate 不切断 UTF-8 多字节字符", function()
  t.eq(util.truncate("abcdef", 3), "abc")
  t.eq(util.truncate("abc", 10), "abc")
  -- "中" 占 3 字节：截 4 字节时只保留完整字符
  t.eq(util.truncate("中文ab", 4), "中")
  t.eq(util.truncate("中文", 3), "中")
  t.eq(util.truncate(nil, 3), "")
end)

t.test("strip_ctrl 控制字符替换为空格", function()
  t.eq(util.strip_ctrl("a\nb\tc"), "a b c")
  t.eq(util.strip_ctrl("a\0b"), "a b")
  t.eq(util.strip_ctrl("正常"), "正常")
end)

t.test("escape_json 转义", function()
  t.eq(util.escape_json('a"b'), 'a\\"b')
  t.eq(util.escape_json("a\nb"), "a\\nb")
end)

t.test("now 使用 ngx.time（可控时钟）", function()
  local before = mock.now()
  t.eq(util.now(), math.floor(before))
  mock.advance(10)
  t.eq(util.now(), math.floor(before) + 10)
end)

t.test("log_error 去重：60 秒内同错误只写一次", function()
  local paths = require("lib.paths")
  local path = paths.error_log()
  util.reset_error_log()
  __BTWAF_FS_REMOVE(path)
  util.log_error("测试错误A")
  util.log_error("测试错误A")
  local data = mock.file_read(path)
  t.ok(type(data) == "string", "应写入 error.log")
  local count = 0
  for _ in data:gmatch("[^\n]+") do
    count = count + 1
  end
  t.eq(count, 1, "去重后只应有一行")
  -- 超过 60 秒再去重窗口外，可再次记录
  mock.advance(61)
  util.log_error("测试错误A")
  data = mock.file_read(path)
  local count2 = 0
  for _ in data:gmatch("[^\n]+") do
    count2 = count2 + 1
  end
  t.eq(count2, 2)
end)

t.test("split/trim/startswith/endswith/contains", function()
  local parts = util.split("a,b,c", ",")
  t.eq(#parts, 3)
  t.eq(parts[2], "b")
  t.eq(util.trim("  x  "), "x")
  t.eq(util.starts_with("/admin/x", "/admin"), true)
  t.eq(util.ends_with("a.php", ".php"), true)
  t.eq(util.contains("hello world", "lo wo"), true)
end)



