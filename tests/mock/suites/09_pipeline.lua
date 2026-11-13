-- 09-pipeline：请求数据采集与变量解析（contract §6.7 / §9.1）
local t = require("mock.framework")
t.suite("09-pipeline")

local mock = require("mock.ngx")
local pipeline = require("lib.pipeline")

t.test("parse_pairs：URL 解码与 + 语义", function()
  local pairs_list = pipeline.parse_pairs("a=1%202&b=x+y&c&d=", true)
  t.eq(#pairs_list, 4)
  t.eq(pairs_list[1].name, "a")
  t.eq(pairs_list[1].value, "1 2")
  t.eq(pairs_list[2].value, "x y")
  t.eq(pairs_list[3].name, "c")
  t.eq(pairs_list[3].value, "")
  t.eq(pipeline.ext_of("shell.php"), "php")
  t.eq(pipeline.ext_of("a.b/c"), "", "无法识别扩展名时返回空串")
end)

t.test("new()：方法/URI/query/host/header/cookie", function()
  mock.set_request({
    method = "POST",
    uri = "/a/b.php",
    query = "x=1&y=2",
    host = "www.example.com",
    remote_addr = "1.2.3.4",
    headers = {
      ["User-Agent"] = "Mozilla/5.0",
      ["Cookie"] = "sid=abc; theme=dark",
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
  })
  local ctx = pipeline.new(ngx.var, {})
  t.eq(ctx.method, "POST")
  t.eq(ctx.uri, "/a/b.php")
  t.eq(ctx.uri_raw, "/a/b.php?x=1&y=2")
  t.eq(ctx.query, "x=1&y=2")
  t.eq(ctx.host, "www.example.com")
  t.eq(ctx.remote_addr, "1.2.3.4")
  t.eq(ctx.headers["user-agent"], "Mozilla/5.0")
  t.eq(ctx.cookies.sid, "abc")
  t.eq(ctx.cookies.theme, "dark")
  t.eq(ctx.http_version, "HTTP/1.1")
end)

t.test("collect GET：参数/来源/kind", function()
  mock.set_request({ method = "GET", uri = "/x.php", query = "id=1&q=union+select" })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } })
  t.eq(#ctx.args, 2)
  t.eq(ctx.args[1].name, "id")
  t.eq(ctx.args[1].value, "1")
  t.eq(ctx.args[1].kind, "get")
  t.eq(ctx.args[2].value, "union select")
end)

t.test("collect POST form（urlencoded）", function()
  mock.set_request({
    method = "POST", uri = "/login.php", body = "user=admin&pass=1%27",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded", ["Content-Length"] = "16" },
  })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  t.eq(#ctx.args, 2)
  t.eq(ctx.args[1].kind, "post")
  t.eq(ctx.args[2].value, "1'")
  t.ok(mock.body_read_count() > 0)
end)

t.test("collect JSON body：只展开字符串叶子（数字/布尔不进入 ARGS）", function()
  mock.set_request({
    method = "POST", uri = "/api",
    body = '{"user":"admin","nested":{"x":"one"},"arr":["a","b"],"n":5,"flag":true}',
    headers = { ["Content-Type"] = "application/json; charset=utf-8", ["Content-Length"] = "80" },
  })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  local found_user, found_nested, found_arr1, found_arr2 = false, false, false, false
  for i = 1, #ctx.args do
    local a = ctx.args[i]
    if a.name == "user" and a.value == "admin" then found_user = true end
    if a.name == "nested.x" and a.value == "one" then found_nested = true end
    if a.name == "arr[1]" and a.value == "a" then found_arr1 = true end
    if a.name == "arr[2]" and a.value == "b" then found_arr2 = true end
  end
  t.eq(found_user, true)
  t.eq(found_nested, true)
  t.eq(found_arr1, true)
  t.eq(found_arr2, true)
  t.eq(#ctx.args, 4, "数字/布尔叶子不应进入 ARGS")
end)

t.test("无 Content-Type 的 POST：按传统表单兜底解析", function()
  mock.set_request({ method = "POST", uri = "/legacy", body = "a=1&b=2" })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  t.eq(#ctx.args, 2, "无 Content-Type 时按 urlencoded 兜底")
  t.eq(ctx.args[1].name, "a")
  t.eq(ctx.args[2].value, "2")
end)

t.test("非表单 content-type：正文只进 REQUEST_BODY，不解析 ARGS", function()
  local body = "# Title\n\n<img class=\"size-full\">\n\nplain text"
  mock.set_request({
    method = "POST", uri = "/post",
    body = body,
    headers = { ["Content-Type"] = "text/markdown", ["Content-Length"] = tostring(#body) },
  })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  t.eq(#ctx.args, 0, "text/markdown 不应解析出 ARGS")
  t.eq(ctx.body, body, "正文仍保留在 ctx.body")
  t.eq(#pipeline.get_var(ctx, { type = "ARGS" }), 0)
  t.eq(pipeline.get_var(ctx, { type = "REQUEST_BODY" })[1], body)

  -- XML/SOAP 同理
  local xml = "<soap:Envelope><soap:Body>hello</soap:Body></soap:Envelope>"
  mock.set_request({
    method = "POST", uri = "/soap",
    body = xml,
    headers = { ["Content-Type"] = "text/xml", ["Content-Length"] = tostring(#xml) },
  })
  -- XML/SOAP：属性值与文本节点进入 ARGS（见下一条用例详细断言）
  ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  t.ok(#ctx.args >= 1, "text/xml 应提取文本节点/属性值进入 ARGS")
  t.eq(pipeline.get_var(ctx, { type = "REQUEST_BODY" })[1], xml, "正文仍保留在 REQUEST_BODY")
end)

t.test("XML/SOAP body：属性值与文本节点进入 ARGS（实体解码）", function()
  local xml = '<?xml version="1.0"?><root><a probe="&lt;script&gt;alert(1)&lt;/script&gt;">'
    .. '/etc/passwd</a></root>'
  mock.set_request({
    method = "POST", uri = "/soap",
    body = xml,
    headers = { ["Content-Type"] = "application/xml", ["Content-Length"] = tostring(#xml) },
  })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  local arg_values = {}
  local arg_names = {}
  for i = 1, #ctx.args do
    arg_values[ctx.args[i].value] = true
    arg_names[ctx.args[i].name] = true
  end
  t.eq(arg_values["<script>alert(1)</script>"], true, "属性值应实体解码后进入 ARGS")
  t.eq(arg_values["/etc/passwd"], true, "文本节点值应进入 ARGS")
  t.eq(arg_names["probe"], true, "属性名进入 ARGS_NAMES")
  t.eq(ctx.args[1].kind, "xml")
end)

t.test("collect multipart：参数 + 文件名/扩展名", function()
  local boundary = "----btwafboundary"
  local body = table.concat({
    "--" .. boundary,
    'Content-Disposition: form-data; name="title"',
    "",
    "hello",
    "--" .. boundary,
    'Content-Disposition: form-data; name="file"; filename="shell.PHP"',
    "Content-Type: application/octet-stream",
    "",
    "<?php echo 1; ?>",
    "--" .. boundary .. "--",
    "",
  }, "\r\n")
  mock.set_request({
    method = "POST", uri = "/upload.php", body = body,
    headers = {
      ["Content-Type"] = "multipart/form-data; boundary=" .. boundary,
      ["Content-Length"] = tostring(#body),
    },
  })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  t.ok(#ctx.args >= 1, "应解析出普通参数")
  t.eq(ctx.args[1].name, "title")
  t.eq(ctx.args[1].value, "hello")
  t.eq(#ctx.files, 1)
  t.eq(ctx.files[1].name, "file")
  t.eq(ctx.files[1].filename, "shell.PHP")
  t.eq(ctx.files[1].ext, "php", "扩展名应小写")
end)

t.test("body_limit 截断与标记", function()
  mock.set_request({
    method = "POST", uri = "/x", body = "abcdefghij",
    headers = { ["Content-Type"] = "text/plain", ["Content-Length"] = "10" },
  })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { body_limit = 5, max_args = 100 } }, { want_body = true })
  t.eq(ctx.body, "abcde")
  t.eq(ctx.body_truncated, true)
  t.eq(ctx.body_len, 10)
end)

t.test("want_body：GET 默认不读、POST 读", function()
  mock.set_request({ method = "GET", uri = "/x" })
  t.eq(pipeline.want_body(pipeline.new(ngx.var, {})), false)
  mock.set_request({ method = "POST", uri = "/x" })
  t.eq(pipeline.want_body(pipeline.new(ngx.var, {})), true)
end)

t.test("get_var：§9.1 变量全集", function()
  local boundary = "b1"
  local body = "--b1\r\nContent-Disposition: form-data; name=\"up\"; filename=\"a.jpg\"\r\n\r\nx\r\n--b1--\r\n"
  mock.set_request({
    method = "POST",
    uri = "/dir/file.php",
    query = "a=1&b=2",
    host = "www.example.com",
    remote_addr = "1.2.3.4",
    headers = {
      ["User-Agent"] = "test-ua",
      ["Cookie"] = "c1=v1",
    },
    body = body,
    headers_extra = nil,
  })
  -- 补 multipart 头
  ngx.req.set_header("content-type", "multipart/form-data; boundary=" .. boundary)
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, { scan = { max_args = 100 } }, { want_body = true })
  ctx.ip = "1.2.3.4"
  ctx.tx = { anomaly_score = 7 }

  local function vals(vd)
    return pipeline.get_var(ctx, vd)
  end
  t.eq(vals("ARGS")[1], "1")
  t.eq(#vals({ type = "ARGS_NAMES" }) >= 1, true)
  t.eq(vals({ type = "ARGS_GET", key = "b" })[1], "2")
  t.eq(vals({ type = "REQUEST_URI" })[1], "/dir/file.php")
  t.eq(vals({ type = "REQUEST_FILENAME" })[1], "/dir/file.php")
  t.eq(vals({ type = "REQUEST_BASENAME" })[1], "file.php")
  t.eq(vals({ type = "QUERY_STRING" })[1], "a=1&b=2")
  t.eq(vals({ type = "REQUEST_METHOD" })[1], "POST")
  t.eq(vals({ type = "REQUEST_HEADERS", key = "user-agent" })[1], "test-ua")
  t.eq(vals({ type = "REQUEST_HEADERS_NAMES" })[1] ~= nil, true)
  t.eq(vals({ type = "REQUEST_COOKIES", key = "c1" })[1], "v1")
  t.eq(vals({ type = "REMOTE_ADDR" })[1], "1.2.3.4")
  t.eq(vals({ type = "REQUEST_LINE" })[1], "POST /dir/file.php?a=1&b=2 HTTP/1.1")
  t.eq(vals({ type = "TX", key = "anomaly_score" })[1], "7")
  t.eq(vals({ type = "REQUEST_BODY" })[1], body)
  t.eq(vals({ type = "FILES" })[1], "a.jpg")
  t.eq(vals({ type = "FILES_NAMES" })[1], "up")
  t.eq(vals({ type = "FILES_EXT" })[1], "jpg")
  -- count 语义
  local cnt = vals({ type = "ARGS", count = true })
  t.eq(cnt[1], tostring(#ctx.args))
  -- 不存在的变量/未知类型返回空表
  t.eq(#vals({ type = "TX", key = "nope" }), 0)
  t.eq(#vals({ type = "__unknown__" }), 0)
end)

t.test("targets：去重 + kind 标注", function()
  mock.set_request({ method = "GET", uri = "/x.php", query = "id=union" })
  local ctx = pipeline.new(ngx.var, {})
  pipeline.collect(ctx, {})
  local targets = pipeline.targets(ctx)
  t.ok(#targets >= 2)
  local kinds = {}
  local values = {}
  for i = 1, #targets do
    kinds[targets[i].kind] = true
    t.eq(values[targets[i].value], nil, "targets 应去重")
    values[targets[i].value] = true
  end
  t.eq(kinds.uri, true)
  t.eq(kinds.query, true)
end)


