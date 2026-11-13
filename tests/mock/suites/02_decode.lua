-- 02-decode：多层解码（contract §6.12）
local t = require("mock.framework")
t.suite("02-decode")

local decode = require("lib.decode")

t.test("URL 单层/多层解码", function()
  t.eq(decode.url("%27"), "'")
  t.eq(decode.url("a%20b"), "a b")
  t.eq(decode.url("%2527"), "%27")
  t.eq(decode.url("%2527", 2), "'")
  t.eq(decode.url("%252527", 3), "'")
  -- 非法 %xx 原样保留
  t.eq(decode.url("%zz%2"), "%zz%2")
end)

t.test("url_once 支持 + 转空格（表单语义）", function()
  t.eq(decode.url_once("a+b", true), "a b")
  t.eq(decode.url_once("a+b", false), "a+b")
end)

t.test("urlDecodeUni：%uXXXX 与 \\uXXXX", function()
  t.eq(decode.url_uni("%u4E2D"), "中")
  t.eq(decode.url_uni("\\u0041"), "A")
  t.eq(decode.unicode("\\u4e2d\\u6587"), "中文")
end)

t.test("HTML 实体解码（命名/十进制/十六进制）", function()
  t.eq(decode.html_entities("&lt;script&gt;"), "<script>")
  t.eq(decode.html_entities("&#65;&#66;"), "AB")
  t.eq(decode.html_entities("&#x41;&#x42;"), "AB")
  t.eq(decode.html_entities("&amp;&quot;&apos;"), "&\"'")
  -- 未知实体保留
  t.eq(decode.html_entities("&unknown;"), "&unknown;")
end)

t.test("Base64 解码（标准/URL-safe/非法输入）", function()
  t.eq(decode.base64("SGVsbG8="), "Hello")
  t.eq(decode.base64("SGVsbG8"), "Hello")
  t.eq(decode.base64("5Lit5paH"), "中文")
  t.eq(decode.base64("SGVsbG8tXw=="), "Hello-_")
  t.eq(decode.base64("!!notbase64!!"), nil)
  t.eq(decode.base64(""), nil)
end)

t.test("base64_text：扫描安全过滤（data URI/超长/二进制跳过）", function()
  t.eq(decode.base64_text("c3FsbWFw"), "sqlmap")
  t.eq(decode.base64_text("data:image/png;base64,iVBORw0KGgo="), nil, "data URI 应跳过")
  t.eq(decode.base64_text(string.rep("c3FsbWFw", 400)), nil, "超长应跳过")
  t.eq(decode.base64_text("AAECAwQFBgcICQ=="), nil, "二进制解码结果应跳过")
  t.eq(decode.base64_text(""), nil)
end)

t.test("路径规范化（含 %2e%2e 绕过）", function()
  t.eq(decode.normalize_path("/a/../b//./c"), "/b/c")
  t.eq(decode.normalize_path("/a/%2e%2e/b"), "/b")
  t.eq(decode.normalize_path("/a/../../b"), "/b")
  t.eq(decode.normalize_path("/x/"), "/x/")
  t.eq(decode.normalize_path("\\windows\\system32", true), "/windows/system32")
end)

t.test("十六进制 / SQL hex / 转义序列 / JS / CSS", function()
  t.eq(decode.hex_str("414243"), "ABC")
  t.eq(decode.sql_hex("0x414243"), "ABC")
  t.eq(decode.sql_hex("X'414243'"), "ABC")
  t.eq(decode.escape_seq("\\x41\\x42"), "AB")
  t.eq(decode.js("\\u0041\\x42"), "AB")
  t.eq(decode.css("\\41 \\42"), "AB")
end)

t.test("null/空白处理", function()
  t.eq(decode.remove_nulls("a\0b\0"), "ab")
  t.eq(decode.replace_nulls("a\0b"), "a b")
  t.eq(decode.compress_whitespace("a \t\n b"), "a b")
  t.eq(decode.remove_whitespace(" a\tb\n c "), "abc")
end)

t.test("cmdLine：小写/去 ^/压缩空白", function()
  t.eq(decode.cmd_line("CMD.EXE /C \"dir\""), "cmd.exe /c dir")
  t.eq(decode.cmd_line("a^b"), "ab")
end)

t.test("utf8ToUnicode（含 BMP 外）", function()
  t.eq(decode.utf8_to_unicode("A中"), "A%u4e2d")
  local s = decode.utf8_to_unicode("😀")
  t.eq(s, "%ud83d%ude00")
end)

t.test("all_layers：返回原文与多级变体", function()
  local res = decode.all_layers("%2527", 3)
  t.eq(res.raw, "%2527")
  local found = false
  for i = 1, #res.variants do
    if res.variants[i] == "'" then
      found = true
    end
  end
  t.ok(found, "变体中应包含完全解码结果 '")
  -- 非字符串安全
  local empty = decode.all_layers(nil)
  t.eq(empty.raw, "")
end)
