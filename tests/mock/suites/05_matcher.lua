-- 05-matcher：规则匹配引擎（contract §6.9 / §9）
local t = require("mock.framework")
t.suite("05-matcher")

local mock = require("mock.ngx")
local matcher = require("lib.matcher")
local pipeline = require("lib.pipeline")
local ac = require("lib.ac")
local tx = require("lib.tx")

-- 构造上下文：mock 请求 -> pipeline.new/collect
local function make_ctx(opts)
  opts = opts or {}
  mock.set_request({
    method = opts.method or "GET",
    uri = opts.uri or "/",
    query = opts.query or "",
    headers = opts.headers or {},
    body = opts.body,
    host = opts.host or "www.example.com",
    remote_addr = "1.2.3.4",
  })
  local ctx = pipeline.new(ngx.var, {})
  ctx.ip = "1.2.3.4"
  ctx.site = {
    site_name = "www.example.com",
    observe = false,
    sensitivity = 2,
    modules = {},
    rule_exclude = { crs = {}, ce = {} },
  }
  pipeline.collect(ctx, { scan = { max_args = 200 } }, { want_body = opts.want_body })
  return ctx
end

local function ruleset(rules, source)
  return { meta = { source = source or "ce", module = "sqli", version = "test" }, rules = rules }
end

local function base_rule(over)
  local r = {
    id = "test-1",
    module = "sqli",
    tier = 1,
    score = 5,
    name = "测试规则",
    chain = {
      { vars = { { type = "ARGS", parse = { "all" } } }, transforms = { "lowercase" }, op = "@contains", value = "union" },
    },
  }
  for k, v in pairs(over or {}) do
    r[k] = v
  end
  return r
end

local MOD = { sqli = { open = true, tier = 1 } }

local function evaluate(rule_or_rules, ctx, module_cfg, exclude, ac_lists)
  matcher.reset()
  if ac_lists then
    matcher.set_ac_lists(ac_lists)
  end
  local rules = rule_or_rules
  if rules.id then
    rules = { rules }
  end
  matcher.load({ ruleset(rules) }, ac_lists)
  return matcher.evaluate(ctx, module_cfg or MOD, exclude)
end

t.test("@regex/@rx：URL+lowercase 变换后命中 UNION SELECT", function()
  local ctx = make_ctx({ query = "id=1%27+union%2F**%2Fselect+null--" })
  local rule = base_rule({
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "urlDecode", "lowercase" },
        op = "@rx",
        value = [[\bunion\b[\s/\*\+]+\b(?:all\b[\s/\*\+]+)?select\b]],
      },
    },
  })
  local hits, total = evaluate(rule, ctx)
  t.eq(#hits, 1)
  t.eq(hits[1].rule, "test-1")
  t.eq(hits[1].module, "sqli")
  t.eq(hits[1].src, "ce")
  t.eq(total, 5)
end)

t.test("chain：多条件 AND，缺一不命中", function()
  local rule = base_rule({
    chain = {
      { vars = { { type = "REQUEST_URI" } }, op = "@beginsWith", value = "/admin" },
      { vars = { { type = "REQUEST_HEADERS", key = "user-agent" } }, transforms = { "lowercase" }, op = "@contains", value = "sqlmap" },
    },
  })
  local ctx = make_ctx({ uri = "/admin/x", headers = { ["user-agent"] = "sqlmap/1.0" } })
  local hits = evaluate(rule, ctx)
  t.eq(#hits, 1, "两条件都满足应命中")

  ctx = make_ctx({ uri = "/public/x", headers = { ["user-agent"] = "sqlmap/1.0" } })
  hits = evaluate(rule, ctx)
  t.eq(#hits, 0, "仅满足一个条件不应命中")

  ctx = make_ctx({ uri = "/admin/x", headers = { ["user-agent"] = "Mozilla/5.0" } })
  hits = evaluate(rule, ctx)
  t.eq(#hits, 0, "链中第二个条件不满足不应命中")
end)

t.test("negate：条件取反", function()
  local rule = base_rule({
    chain = {
      { vars = { { type = "REQUEST_HEADERS", key = "user-agent" } }, transforms = { "lowercase" }, op = "@contains", value = "mozilla", negate = true },
    },
  })
  local ctx = make_ctx({ headers = { ["user-agent"] = "sqlmap/1.0" } })
  t.eq(#(evaluate(rule, ctx)), 1, "不含 mozilla 时应命中")

  ctx = make_ctx({ headers = { ["user-agent"] = "Mozilla/5.0" } })
  t.eq(#(evaluate(rule, ctx)), 0, "含 mozilla 时取反不命中")
end)

t.test("count：&ARGS 计数语义", function()
  local rule = base_rule({
    chain = {
      { vars = { { type = "ARGS", count = true } }, op = "@ge", value = "3" },
    },
  })
  local ctx = make_ctx({ query = "a=1&b=2&c=3" })
  t.eq(#(evaluate(rule, ctx)), 1, "3 个参数应命中 >=3")

  ctx = make_ctx({ query = "a=1" })
  t.eq(#(evaluate(rule, ctx)), 0, "1 个参数不应命中")
end)

t.test("@pm 内联词表（lowercase 变换）", function()
  local rule = base_rule({
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "lowercase" },
        op = "@pm",
        value = { "union select", "sqlmap", "nikto" },
      },
    },
  })
  local ctx = make_ctx({ query = "q=" .. "1 UNION SELECT null" })
  t.eq(#(evaluate(rule, ctx)), 1)
end)

t.test("@pm + ac_list：共享 AC 自动机", function()
  local automaton = ac.build({ "sqlmap", "nikto", "nmap" })
  local ac_lists = { scanners = automaton }
  local rule = base_rule({
    chain = {
      {
        vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
        transforms = { "lowercase" },
        op = "@pm",
        ac_list = "scanners",
        value = { "sqlmap", "nikto", "nmap" },
      },
    },
  })
  local ctx = make_ctx({ headers = { ["user-agent"] = "SQLMap/1.7-dev" } })
  local hits = evaluate(rule, ctx, MOD, nil, ac_lists)
  t.eq(#hits, 1, "AC 自动机应命中 sqlmap")

  ctx = make_ctx({ headers = { ["user-agent"] = "Mozilla/5.0" } })
  hits = evaluate(rule, ctx, MOD, nil, ac_lists)
  t.eq(#hits, 0)
end)

t.test("操作符集合：contains/beginsWith/endsWith/streq/within/ipMatch", function()
  local cases = {
    { op = "@contains", value = "union", query = "q=xxunionxx", want = 1 },
    { op = "@contains", value = "union", query = "q=clean", want = 0 },
    { op = "@beginsWith", value = "1'", query = "q=1%27or", want = 1 },
    { op = "@endsWith", value = "//", query = "q=x//", want = 1 },
    { op = "@streq", value = "admin", query = "q=admin", want = 1 },
    { op = "@streq", value = "admin", query = "q=administrator", want = 0 },
    { op = "@within", value = { "admin", "root" }, query = "q=admin", want = 1 },
    { op = "@within", value = { "admin", "root" }, query = "q=guest", want = 0 },
  }
  for i = 1, #cases do
    local c = cases[i]
    local rule = base_rule({
      chain = { { vars = { { type = "ARGS", key = "q" } }, op = c.op, value = c.value } },
    })
    local hits = evaluate(rule, make_ctx({ query = c.query }))
    t.eq(#hits, c.want, c.op .. " " .. tostring(c.value) .. " ? " .. c.query)
  end

  local ip_rule = base_rule({
    chain = { { vars = { { type = "REMOTE_ADDR" } }, op = "@ipMatch", value = { "10.0.0.0/8" } } },
  })
  t.eq(#(evaluate(ip_rule, make_ctx({}))), 0, "1.2.3.4 不在 10/8")
end)

t.test("@ipMatch 命中内网地址", function()
  local ctx = make_ctx({})
  ctx.ip = "10.1.2.3"
  local rule = base_rule({
    chain = { { vars = { { type = "REMOTE_ADDR" } }, op = "@ipMatch", value = { "10.0.0.0/8" } } },
  })
  t.eq(#(evaluate(rule, ctx)), 1)
end)

t.test("@detectSQLi / @detectXSS", function()
  local sqli_rule = base_rule({
    chain = { { vars = { { type = "ARGS", parse = { "all" } } }, transforms = { "urlDecode" }, op = "@detectSQLi" } },
  })
  t.eq(#(evaluate(sqli_rule, make_ctx({ query = "id=1%27+union+select+null--" }))), 1)
  t.eq(#(evaluate(sqli_rule, make_ctx({ query = "id=12345" }))), 0)

  local xss_rule = base_rule({
    chain = { { vars = { { type = "ARGS", parse = { "all" } } }, transforms = { "urlDecode" }, op = "@detectXSS" } },
  })
  t.eq(#(evaluate(xss_rule, make_ctx({ query = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" }))), 1)
  t.eq(#(evaluate(xss_rule, make_ctx({ query = "q=hello+world" }))), 0)
end)

t.test("变换：htmlEntityDecode / base64Decode / removeNulls", function()
  local rule = base_rule({
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "htmlEntityDecode", "lowercase" },
        op = "@contains",
        value = "<script>",
      },
    },
  })
  t.eq(#(evaluate(rule, make_ctx({ query = "q=%26lt%3Bscript%26gt%3B" }))), 1)

  local b64_rule = base_rule({
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "base64Decode", "lowercase" },
        op = "@contains",
        value = "sqlmap",
      },
    },
  })
  t.eq(#(evaluate(b64_rule, make_ctx({ query = "q=c3FsbWFw" }))), 1)

  local null_rule = base_rule({
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "removeNulls", "lowercase" },
        op = "@contains",
        value = "union",
      },
    },
  })
  t.eq(#(evaluate(null_rule, make_ctx({ query = "q=uni%00on" }))), 1)
end)

t.test("base64Decode 变换：data: URI 不自动解码（避免二进制误报）", function()
  local rule = base_rule({
    chain = {
      {
        vars = { { type = "ARGS", parse = { "all" } } },
        transforms = { "base64Decode", "lowercase" },
        op = "@contains",
        value = "sqlmap",
      },
    },
  })
  -- 普通 base64：应解码后命中
  t.eq(#(evaluate(rule, make_ctx({ query = "q=c3FsbWFw" }))), 1)
  -- data: URI 内联 base64：跳过解码，不应命中
  t.eq(#(evaluate(rule, make_ctx({ query = "q=data%3Aimage%2Fpng%3Bbase64%2Cc3FsbWFw" }))), 0)
end)

-- 重要：ModSecurity 的 @validate* 语义是"发现非法才命中"（Lead 真机修复点）
t.test("@validateByteRange：合法不命中、非法命中", function()
  local rule = base_rule({
    module = "protocol",
    chain = {
      { vars = { { type = "REQUEST_BODY" } }, op = "@validateByteRange", value = "65-90,97-122" },
    },
  })
  local mod = { protocol = { open = true, tier = 1 } }
  -- 合法（纯字母）：不应命中
  t.eq(#(evaluate(rule, make_ctx({ method = "POST", body = "abcXYZ" }), mod)), 0)
  -- 非法（含数字 1）：应命中
  t.eq(#(evaluate(rule, make_ctx({ method = "POST", body = "abc1" }), mod)), 1)
end)

t.test("@validateUrlEncoding：合法不命中、非法命中", function()
  local rule = base_rule({
    module = "protocol",
    chain = {
      { vars = { { type = "REQUEST_BODY" } }, op = "@validateUrlEncoding" },
    },
  })
  local mod = { protocol = { open = true, tier = 1 } }
  t.eq(#(evaluate(rule, make_ctx({ method = "POST", body = "%41%42" }), mod)), 0, "合法编码不应命中")
  t.eq(#(evaluate(rule, make_ctx({ method = "POST", body = "%zz" }), mod)), 1, "非法编码应命中")
end)

t.test("@validateUtf8Encoding：合法不命中、非法命中", function()
  local rule = base_rule({
    module = "protocol",
    chain = {
      { vars = { { type = "REQUEST_BODY" } }, op = "@validateUtf8Encoding" },
    },
  })
  local mod = { protocol = { open = true, tier = 1 } }
  t.eq(#(evaluate(rule, make_ctx({ method = "POST", body = "中文abc" }), mod)), 0, "合法 UTF-8 不应命中")
  t.eq(#(evaluate(rule, make_ctx({ method = "POST", body = "a\255b" }), mod)), 1, "非法 UTF-8 应命中")
end)

t.test("tier 过滤：规则 tier 高于模块 tier 时不执行", function()
  local rule = base_rule({ tier = 2 })
  local ctx = make_ctx({ query = "q=union" })
  t.eq(#(evaluate(rule, ctx, { sqli = { open = true, tier = 1 } })), 0, "tier1 不应执行 tier2 规则")
  t.eq(#(evaluate(rule, make_ctx({ query = "q=union" }), { sqli = { open = true, tier = 2 } })), 1)
end)

t.test("module open=false 时跳过该模块", function()
  local rule = base_rule({})
  local ctx = make_ctx({ query = "q=union" })
  t.eq(#(evaluate(rule, ctx, { sqli = { open = false, tier = 1 } })), 0)
end)

t.test("rule_exclude：按 id 排除规则", function()
  local rule = base_rule({ id = "ce-1" })
  local ctx = make_ctx({ query = "q=union" })
  t.eq(#(evaluate(rule, ctx, MOD, { ce = { "ce-1" }, crs = {} })), 0)
  t.eq(#(evaluate(rule, make_ctx({ query = "q=union" }), MOD, { ce = { "ce-2" }, crs = {} })), 1)
end)

t.test("on_match：setvar inc anomaly_score", function()
  local rule = base_rule({
    score = 3,
    on_match = { { action = "setvar", scope = "tx", key = "anomaly_score", op = "inc", value = 7 } },
  })
  local ctx = make_ctx({ query = "q=union" })
  local hits, total = evaluate(rule, ctx)
  t.eq(#hits, 1)
  t.eq(hits[1].score, 3)
  t.eq(tx.get(ctx, "anomaly_score"), 7)
  -- 规则显式维护 anomaly_score 时不重复累加，total 取两者较大值
  t.eq(total, 7)
end)

t.test("多规则累计分数", function()
  local r1 = base_rule({ id = "a", score = 2, chain = { { vars = { { type = "ARGS", parse = { "all" } } }, op = "@contains", value = "union" } } })
  local r2 = base_rule({ id = "b", score = 3, chain = { { vars = { { type = "ARGS", parse = { "all" } } }, op = "@contains", value = "select" } } })
  local hits, total = evaluate({ r1, r2 }, make_ctx({ query = "q=union+select" }))
  t.eq(#hits, 2)
  t.eq(total, 5)
end)

t.test("单条规则异常只跳过并计数，不中断其它规则", function()
  local bad = base_rule({ id = "bad", chain = { { vars = { { type = "ARGS", parse = { "all" } } }, transforms = { "not-a-transform" }, op = "@contains", value = "x" } } })
  local good = base_rule({ id = "good", chain = { { vars = { { type = "ARGS", parse = { "all" } } }, op = "@contains", value = "union" } } })
  local hits = evaluate({ bad, good }, make_ctx({ query = "q=union" }))
  t.eq(#hits, 1, "坏规则应被跳过")
  t.eq(hits[1].rule, "good")
  t.ok(matcher.stats().errors >= 1, "应记录规则错误数")
end)

t.test("变量不存在时条件不成立（negate 也不成立）", function()
  local rule = base_rule({
    chain = { { vars = { { type = "REQUEST_HEADERS", key = "x-not-exist" } }, op = "@contains", value = "x", negate = true } },
  })
  t.eq(#(evaluate(rule, make_ctx({}))), 0)
end)
