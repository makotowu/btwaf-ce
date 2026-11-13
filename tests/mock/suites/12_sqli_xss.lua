-- 12-sqli-xss：SQLi/XSS 语义分析（contract §6.6）
local t = require("mock.framework")
t.suite("12-sqli-xss")

local sqli = require("lib.sqli")
local xss = require("lib.xss")

t.test("sqli：强特征命中（联合/时间/堆叠/注释/信息探测）", function()
  local cases = {
    "1' union select null, version()--",
    "x' OR '1'='1",
    "1;WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)#",
    "id=1; DROP TABLE users--",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "'; SELECT * FROM information_schema.tables--",
    "1 UNION/**/SELECT/**/password FROM users",
    "1/**/OR/**/1=1",
    "1/**/UNION/**/SELECT/**/1",
    "1/*!50000OR*/1=1",
  }
  for i = 1, #cases do
    local res = sqli.analyse(cases[i])
    t.eq(res.detected, true, "应检出: " .. cases[i])
    t.ok(res.score > 0)
    t.ok(type(res.features) == "table")
    t.eq(res.name, "SQL注入")
  end
end)

t.test("sqli：URL 编码/实体编码载荷也能检出", function()
  local res = sqli.analyse("1%27%20union%20select%20null--")
  t.eq(res.detected, true, "URL 编码载荷应检出")
  local res2 = sqli.analyse("1&#39; union select null--")
  t.eq(res2.detected, true, "HTML 实体编码载荷应检出")
end)

t.test("sqli：良性文本不误报", function()
  local benign = {
    "hello world",
    "中文普通文本，包含 select 选项",
    "id=12345",
    "user@example.com",
    "订单号 20260101001",
    "The union of two sets is a set",
    "please don't stop",
    "SELECT 是 SQL 关键字（正常帮助文档）",
    "hello/**/world",
    "see/**/this",
  }
  for i = 1, #benign do
    local res = sqli.analyse(benign[i])
    t.eq(res.detected, false, "不应误报: " .. benign[i] .. " features=" .. tostring(res.features))
  end
end)

t.test("sqli：空/非字符串输入安全", function()
  local res = sqli.analyse(nil)
  t.eq(res.detected, false)
  t.eq(res.score, 0)
  res = sqli.analyse("")
  t.eq(res.detected, false)
end)

t.test("xss：强特征命中（标签/事件/协议/危险标签）", function()
  local cases = {
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(document.cookie)>",
    "javascript:alert(1)",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<body onload=alert(1)>",
    "<a href=\"data:text/html;base64,PHNjcmlwdD4=\">x</a>",
    "<div style=\"background:url(javascript:alert(1))\">",
  }
  for i = 1, #cases do
    local res = xss.analyse(cases[i])
    t.eq(res.detected, true, "应检出: " .. cases[i])
    t.ok(res.score > 0)
    t.ok(type(res.features) == "table")
    t.eq(res.name, "XSS")
  end
end)

t.test("xss：编码混淆载荷", function()
  t.eq(xss.analyse("&lt;script&gt;alert(1)&lt;/script&gt;").detected, true)
  t.eq(xss.analyse("%3Cscript%3Ealert(1)%3C%2Fscript%3E").detected, true)
  t.eq(xss.analyse("&#x3C;script&#x3E;alert(1)").detected, true)
end)

t.test("xss：良性 HTML/文本不误报", function()
  local benign = {
    "hello world",
    "<b>加粗</b> <i>斜体</i>",
    "a < b and c > d",
    "5 < 10",
    "正常的中文文本，没有脚本",
    "https://example.com/path?q=1",
    "price: $100",
  }
  for i = 1, #benign do
    local res = xss.analyse(benign[i])
    t.eq(res.detected, false, "不应误报: " .. benign[i] .. " features=" .. tostring(res.features))
  end
end)

t.test("xss：空/非字符串输入安全", function()
  t.eq(xss.analyse(nil).detected, false)
  t.eq(xss.analyse("").detected, false)
  t.eq(xss.analyse(123).detected, false)
end)
