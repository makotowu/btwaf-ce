-- 01-json：纯 Lua JSON 编解码（contract §6.1）
local t = require("mock.framework")
t.suite("01-json")

local json = require("lib.json")

t.test("encode/decode 往返：对象+数组+标量", function()
  local obj = json.decode('{"a":1,"b":[true,false],"c":"x","d":{"e":2.5}}')
  t.ok(type(obj) == "table", "应解码为 table")
  t.eq(obj.a, 1)
  t.eq(obj.b[1], true)
  t.eq(obj.b[2], false)
  t.eq(obj.c, "x")
  t.eq(obj.d.e, 2.5)
  local encoded = json.encode(obj)
  local again = json.decode(encoded)
  t.eq(again.a, 1)
  t.eq(again.b[1], true)
  t.eq(again.d.e, 2.5)
end)

t.test("encode 键排序稳定，可重复", function()
  local s1 = json.encode({ b = 2, a = 1 })
  local s2 = json.encode({ a = 1, b = 2 })
  t.eq(s1, s2)
  t.eq(s1, '{"a":1,"b":2}')
end)

t.test("数组/空数组/空对象区分", function()
  local arr = json.decode("[]")
  t.eq(json.encode(arr), "[]")
  local obj = json.decode("{}")
  t.eq(json.encode(obj), "{}")
  t.eq(json.encode({}), "{}")
  t.eq(json.encode(setmetatable({}, json.array_mt)), "[]")
end)

t.test("null 解码为 nil（键省略），数组内保留 null", function()
  local obj = json.decode('{"a":null,"b":1}')
  t.eq(obj.a, nil)
  t.eq(obj.b, 1)
  local arr = json.decode("[1,null,3]")
  t.eq(json.encode(arr), "[1,null,3]")
end)

t.test("Unicode 转义与代理对", function()
  t.eq(json.decode('"\\u4e2d\\u6587"'), "中文")
  t.eq(json.decode('"\\ud83d\\ude00"'), "😀")
  -- 编码时 UTF-8 原样输出
  local s = json.encode("中文")
  t.eq(s, '"中文"')
end)

t.test("字符串转义：控制字符/引号/反斜杠", function()
  local raw = 'a"b\\c\nd\te'
  local encoded = json.encode(raw)
  t.contains(encoded, '\\"')
  t.contains(encoded, "\\\\")
  t.contains(encoded, "\\n")
  t.contains(encoded, "\\t")
  t.eq(json.decode(encoded), raw)
  -- 控制字符 0x01 转 \u0001
  t.contains(json.encode("\1"), "\\u0001")
end)

t.test("数字格式：整数不带小数点，浮点保留", function()
  t.eq(json.encode(42), "42")
  t.eq(json.encode(-7), "-7")
  t.eq(json.encode(0), "0")
  t.eq(json.decode("3.5"), 3.5)
  t.eq(json.decode("-1.25e2"), -125)
end)

t.test("非法 JSON 返回 nil, err（不抛异常）", function()
  local cases = { "", "{", '{"a":}', "[1,", "tru", '"abc', '{"a" 1}', "{} extra", "01x" }
  for i = 1, #cases do
    local ok, val, err = pcall(json.decode, cases[i])
    t.ok(ok, "decode 不应抛异常: " .. cases[i])
    t.eq(val, nil, "应返回 nil: " .. cases[i])
    t.ok(type(err) == "string" and err ~= "", "应返回错误信息: " .. cases[i])
  end
end)

t.test("深层嵌套受深度限制（防栈溢出）", function()
  local s = string.rep("[", 80) .. "1" .. string.rep("]", 80)
  local val, err = json.decode(s)
  t.eq(val, nil)
  t.ok(err ~= nil, "超过深度上限应报错")
end)

t.test("decode 非字符串输入安全", function()
  local val, err = json.decode(nil)
  t.eq(val, nil)
  t.ok(err ~= nil)
  val, err = json.decode(123)
  t.eq(val, nil)
  t.ok(err ~= nil)
end)

t.test("循环引用编码报错不崩溃", function()
  local tbl = {}
  tbl.self = tbl
  local ok, val, err = pcall(json.encode, tbl)
  t.ok(ok, "encode 循环引用不应抛异常到调用方")
  t.eq(val, nil)
  t.ok(err ~= nil)
end)
