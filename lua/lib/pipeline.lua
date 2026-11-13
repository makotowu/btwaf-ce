--[[
  btwaf_ce / lib/pipeline.lua
  请求数据采集与变量解析（contract §6.7 / §9.1）。
  - pipeline.new(ngx_var_like)      构造 ctx（方法/URI/header/cookie）
  - pipeline.collect(ctx, site_cfg) 解析 query/body/json/multipart，填 args/files
  - pipeline.get_var(ctx, vardef)   按 §9.1 变量定义返回值数组
  - pipeline.targets(ctx)           需扫描的 value/kind 列表（ce_* 规则/启发式用）
  性能：正常 GET 不读 body；所有解析受 scan.* 限额约束。
]]

local ngx = ngx
local fs = require("lib.fs")
local util = require("lib.util")
local decode = require("lib.decode")
local json = require("lib.json")

local pipeline = {}

-- ---------------------------------------------------------------------------
-- 基础解析
-- ---------------------------------------------------------------------------
-- 解析 "a=1&b=2" 为 {name,value} 数组；plus=true 时 + 转空格
function pipeline.parse_pairs(s, plus)
  local out = {}
  if type(s) ~= "string" or s == "" then
    return out
  end
  local start = 1
  while start <= #s do
    local amp = s:find("&", start, true)
    local piece
    if amp then
      piece = s:sub(start, amp - 1)
      start = amp + 1
    else
      piece = s:sub(start)
      start = #s + 1
    end
    if piece ~= "" then
      local eq = piece:find("=", 1, true)
      local name, value
      if eq then
        name = piece:sub(1, eq - 1)
        value = piece:sub(eq + 1)
      else
        name = piece
        value = ""
      end
      if plus then
        name = decode.url_once(name, true)
        value = decode.url_once(value, true)
      else
        name = decode.url_once(name, false)
        value = decode.url_once(value, false)
      end
      out[#out + 1] = { name = name, value = value }
    end
  end
  return out
end

pipeline.decode_url = decode.url

-- 取扩展名（小写，不含点）
local function ext_of(filename)
  if type(filename) ~= "string" then
    return ""
  end
  local ext = filename:match("%.([%w]+)$")
  return ext and ext:lower() or ""
end

pipeline.ext_of = ext_of

-- ---------------------------------------------------------------------------
-- ctx 构造
-- ---------------------------------------------------------------------------
local function split_uri_query(vars, ctx)
  local raw = ctx.uri_raw
  local q = raw:find("?", 1, true)
  if ctx.uri == "" then
    ctx.uri = q and raw:sub(1, q - 1) or raw
  end
  if ctx.query == "" and q then
    ctx.query = raw:sub(q + 1)
  end
  if ctx.uri == "" then
    ctx.uri = "/"
  end
end

-- 读取 header：优先 ngx.req.get_headers（能拿到原始大小写与重复 header）
local function read_headers()
  local headers = {}
  local raw_list = {}
  local req = ngx and ngx.req
  if req and req.get_headers then
    local ok, h = pcall(req.get_headers, 200, true)
    if ok and type(h) == "table" then
      for name, value in pairs(h) do
        if type(name) == "string" then
          local lname = name:lower()
          local v = value
          if type(v) == "table" then
            v = table.concat(v, ", ")
          end
          headers[lname] = tostring(v)
          raw_list[#raw_list + 1] = { name = name, value = tostring(v) }
        end
      end
    end
  end
  -- 兜底：从 ngx.var.http_* 收集（部分场景 get_headers 不可用）
  local vars = ngx and ngx.var
  if type(vars) == "table" and #raw_list == 0 then
    local ok, all = pcall(function() return vars end)
    if ok and all then
      for k, v in pairs(vars) do
        if type(k) == "string" and k:sub(1, 5) == "http_" and type(v) == "string" then
          local lname = k:sub(6):gsub("_", "-")
          headers[lname] = v
          raw_list[#raw_list + 1] = { name = lname, value = v }
        end
      end
    end
  end
  return headers, raw_list
end

local function parse_cookies(headers)
  local cookies = {}
  local cookie = headers["cookie"]
  if type(cookie) ~= "string" or cookie == "" then
    return cookies
  end
  for part in cookie:gmatch("[^;]+") do
    local eq = part:find("=", 1, true)
    if eq then
      local name = util.trim(part:sub(1, eq - 1))
      local value = util.trim(part:sub(eq + 1))
      if name ~= "" then
        cookies[name] = decode.url_once(value, false)
      end
    end
  end
  return cookies
end

-- 构造上下文。vars 建议传 ngx.var（测试注入 mock）
function pipeline.new(vars, opts)
  opts = opts or {}
  vars = vars or {}
  local ctx = {
    method = vars.request_method or "GET",
    scheme = vars.scheme or "http",
    host = vars.host or vars.http_host or "",
    remote_addr = vars.remote_addr or "",
    http_version = vars.server_protocol or "HTTP/1.1",
    uri = vars.uri or "",
    uri_raw = vars.request_uri or "",
    query = vars.query_string or "",
    headers = {},
    headers_raw = {},
    cookies = {},
    args = {},
    files = {},
    body = nil,
    body_len = 0,
    body_truncated = false,
    tx = {},
    now = util.now(),
    vars = vars,
    cfg = opts.cfg,
    site = nil,
  }
  if type(ctx.host) == "string" then
    ctx.host = ctx.host:lower()
  end
  split_uri_query(vars, ctx)

  local headers, raw_list = read_headers()
  ctx.headers = headers
  ctx.headers_raw = raw_list
  -- 兜底：部分环境 get_headers 不返回 Host（真实 nginx 请求一定带 Host），
  -- 从 ngx.var.host 补齐，避免 CRS 920280（缺失 Host）类规则误报。
  if ctx.headers["host"] == nil and type(ctx.host) == "string" and ctx.host ~= "" then
    ctx.headers["host"] = ctx.host
    raw_list[#raw_list + 1] = { name = "Host", value = ctx.host }
  end
  ctx.cookies = parse_cookies(headers)
  return ctx
end

-- ---------------------------------------------------------------------------
-- body 读取
-- ---------------------------------------------------------------------------
-- 读取请求 body（受 scan.body_limit / upload_scan_limit 约束）
local function read_body(ctx, site_cfg)
  local req = ngx and ngx.req
  if not req then
    return nil
  end
  local scan = (site_cfg and site_cfg.scan) or {}
  local body_limit = tonumber(scan.body_limit) or 1048576
  local upload_limit = tonumber(scan.upload_scan_limit) or 20971520

  -- Content-Length 保护：超大上传直接跳过扫描（记录 body_len，不读入内存）
  local content_length = tonumber(ctx.headers["content-length"] or "") or 0
  if content_length > upload_limit then
    ctx.body_len = content_length
    ctx.body_truncated = true
    ctx.body_skipped = true
    return nil
  end

  if req.read_body then
    pcall(req.read_body)
  end
  local body = req.get_body_data and req.get_body_data()
  if body ~= nil and body ~= "" then
    ctx.body = body
    ctx.body_len = #body
  else
    -- body 可能落盘（超过 client_body_buffer_size）
    local body_file = req.get_body_file and req.get_body_file()
    if type(body_file) == "string" and body_file ~= "" then
      local size = fs.size(body_file)
      if size and size > upload_limit then
        ctx.body_len = size
        ctx.body_truncated = true
        ctx.body_skipped = true
        return nil
      end
      local data = fs.read(body_file)
      if data then
        ctx.body = data
        ctx.body_len = #data
      end
    end
  end
  if type(ctx.body) == "string" and #ctx.body > body_limit then
    ctx.body = ctx.body:sub(1, body_limit)
    ctx.body_truncated = true
  end
  return ctx.body
end

pipeline.read_body = read_body

-- ---------------------------------------------------------------------------
-- 参数采集
-- ---------------------------------------------------------------------------
-- 判断是否需要读取 body（GET/HEAD 不读；Content-Length>0 或方法带体时读）
function pipeline.want_body(ctx)
  local method = (ctx.method or "GET"):upper()
  if method == "GET" or method == "HEAD" or method == "OPTIONS" or method == "TRACE" then
    local cl = tonumber(ctx.headers and ctx.headers["content-length"] or "") or 0
    return cl > 0
  end
  return true
end

local function add_arg(ctx, name, value, kind, max_args)
  if type(name) ~= "string" then
    return
  end
  -- data: URI（尤其 data:image/*;base64,...）不作为 ARGS 扫描：原值仅保留在
  -- REQUEST_BODY，避免内联二进制/图片被当注入载荷（rules/qa 的 benign 用例）。
  if type(value) == "string" then
    local lower = value:lower()
    if lower:find("data:", 1, true) and (lower:find(";base64", 1, true)
      or lower:find("data:image/", 1, true) or lower:find("data:application/", 1, true)) then
      ctx.data_uri_skipped = true
      return
    end
  end
  if #ctx.args >= max_args then
    ctx.args_truncated = true
    return
  end
  ctx.args[#ctx.args + 1] = { name = name, value = tostring(value or ""), kind = kind }
end

-- JSON body 展平：只取字符串叶子（数字/布尔/null 不进入 ARGS，避免误扫）
local function flatten_json(ctx, value, prefix, depth, max_args)
  if depth > 2 then
    return
  end
  local tv = type(value)
  if tv == "table" then
    if #value > 0 then
      for i = 1, #value do
        if #ctx.args >= max_args then
          return
        end
        flatten_json(ctx, value[i], prefix .. "[" .. i .. "]", depth + 1, max_args)
      end
    else
      for k, v in pairs(value) do
        if #ctx.args >= max_args then
          return
        end
        local key = prefix == "" and tostring(k) or (prefix .. "." .. tostring(k))
        flatten_json(ctx, v, key, depth + 1, max_args)
      end
    end
  elseif tv == "string" then
    add_arg(ctx, prefix, value, "json", max_args)
  end
end

-- multipart/form-data：提取参数名与文件名/扩展名（文件内容仅保留片段）
local function parse_multipart(ctx, body, content_type, max_args)
  local boundary = content_type:match("boundary=([^;%s\"]+)")
    or content_type:match('boundary="([^"]+)"')
  if not boundary then
    return
  end
  local delim = "--" .. boundary
  local parts = util.split(body, delim)
  for i = 2, #parts do
    local part = parts[i]
    if part:sub(1, 2) ~= "--" then
      local head, content = part:match("^(.-)\r\n\r\n(.*)$")
      if head then
        local name = head:match('[Nn]ame="([^"]*)"')
        local filename = head:match('[Ff]ilename="([^"]*)"')
        content = content:gsub("\r\n$", "")
        if filename and filename ~= "" then
          ctx.files[#ctx.files + 1] = {
            name = name or "",
            filename = filename,
            ext = ext_of(filename),
            snippet = util.truncate(content, 512),
            size = #content,
          }
        elseif name then
          add_arg(ctx, name, content, "post", max_args)
        end
      end
    end
  end
end

-- 轻量 XML 解析：提取属性值与文本节点的值到 ARGS（kind="xml"）。
-- 契约未定义 XML 变量；将 XML 内容作为参数值参与 ARGS/ARGS_NAMES 扫描，
-- 覆盖 SOAP/XML 回放语料（LFI/RCE/XSS/SQLi 均可能出现在属性值中）。
local function parse_xml(ctx, body, max_args, arg_limit)
  local function push(name, value)
    value = util.trim(value)
    if value == "" then
      return
    end
    -- 实体解码后再扫描（&lt;script&gt; -> <script>）
    value = decode.html_entities(value)
    add_arg(ctx, name, util.truncate(value, arg_limit), "xml", max_args)
  end
  -- 属性值：name="value" / name='value'
  for name, value in body:gmatch("([%w_:%.%-]+)%s*=%s*\"([^\"]*)\"") do
    push(name, value)
  end
  for name, value in body:gmatch("([%w_:%.%-]+)%s*=%s*'([^']*)'") do
    push(name, value)
  end
  -- 文本节点：>text<
  for value in body:gmatch(">([^<]+)<") do
    push("__xml_text__", value)
  end
end

-- 采集 query / body / cookie / json / xml / multipart
function pipeline.collect(ctx, site_cfg, opts)
  opts = opts or {}
  if type(ctx) ~= "table" then
    return ctx
  end
  local scan = (site_cfg and site_cfg.scan) or {}
  local max_args = tonumber(scan.max_args) or 200
  local arg_limit = tonumber(scan.arg_limit) or 8192
  local header_limit = tonumber(scan.header_limit) or 8192

  ctx.now = util.now()

  -- header 限额：只截断超长值（不丢 header 名）
  if type(ctx.headers) == "table" then
    for name, value in pairs(ctx.headers) do
      if type(value) == "string" and #value > header_limit then
        ctx.headers[name] = util.truncate(value, header_limit)
      end
    end
  end

  -- query 参数
  local pairs_q = pipeline.parse_pairs(ctx.query, true)
  for i = 1, #pairs_q do
    if #ctx.args >= max_args then
      ctx.args_truncated = true
      break
    end
    local p = pairs_q[i]
    add_arg(ctx, p.name, util.truncate(p.value, arg_limit), "get", max_args)
  end

  -- body（按需）
  local need_body = opts.want_body
  if need_body == nil then
    need_body = pipeline.want_body(ctx)
  end
  if need_body then
    read_body(ctx, site_cfg)
    if type(ctx.body) == "string" and ctx.body ~= "" then
      local ctype = (ctx.headers["content-type"] or ""):lower()
      if ctype:find("multipart/form-data", 1, true) then
        -- multipart/form-data：表单字段进 ARGS，文件元数据进 ctx.files
        parse_multipart(ctx, ctx.body, ctype, max_args)
      elseif ctype:find("json", 1, true) then
        -- JSON（含 application/vnd.api+json、application/x-amz-json-1.1 等厂商类型）：
        -- 只展开字符串叶子；解析失败/非字符串内容仍由 REQUEST_BODY 扫描
        local obj = json.decode(ctx.body)
        if type(obj) == "table" then
          flatten_json(ctx, obj, "", 0, max_args)
        end
      elseif ctype:find("xml", 1, true) then
        -- XML/SOAP/SVG：属性值与文本节点作为 ARGS 参与扫描
        parse_xml(ctx, ctx.body, max_args, arg_limit)
      elseif ctype:find("application/x-www-form-urlencoded", 1, true) then
        local pairs_b = pipeline.parse_pairs(ctx.body, true)
        for i = 1, #pairs_b do
          if #ctx.args >= max_args then
            ctx.args_truncated = true
            break
          end
          local p = pairs_b[i]
          add_arg(ctx, p.name, util.truncate(p.value, arg_limit), "post", max_args)
        end
      elseif ctype == "" then
        -- 无 Content-Type 的 POST：按传统表单（urlencoded）兜底解析。
        -- 兼容老客户端与 CRS 回放语料（其 POST body 未带 Content-Type）；
        -- 显式声明 text/*、xml、multipart 非表单等仍只放 REQUEST_BODY。
        local pairs_b = pipeline.parse_pairs(ctx.body, true)
        for i = 1, #pairs_b do
          if #ctx.args >= max_args then
            ctx.args_truncated = true
            break
          end
          local p = pairs_b[i]
          add_arg(ctx, p.name, util.truncate(p.value, arg_limit), "post", max_args)
        end
      else
        -- 其它 content-type（text/*、xml、multipart 非表单等）：
        -- 不解析成 ARGS，正文仅保留在 ctx.body（REQUEST_BODY 仍可被规则扫描），
        -- 避免把 Markdown/XML/JSON 文本当作参数值误命中 ARGS 规则。
        ctx.body_only = true
      end
    end
  end

  ctx.site = site_cfg
  return ctx
end

-- ---------------------------------------------------------------------------
-- 变量解析（§9.1）
-- ---------------------------------------------------------------------------
local function matches_exclude(name, excludes)
  if not excludes then
    return false
  end
  return excludes[name] == true
end

-- 解析 parse 字段：返回 nil（全部）或 name 数组（含排除集）
local function parse_names(parse, key)
  if type(parse) == "table" then
    if parse[1] == "all" or parse.all == true then
      return nil, nil
    end
    local names = {}
    local start = 1
    if parse[1] == "specific" then
      start = 2
    end
    for i = start, #parse do
      if type(parse[i]) == "string" then
        names[#names + 1] = parse[i]
      end
    end
    if #names == 0 then
      return nil, nil
    end
    return names, nil
  elseif type(parse) == "string" then
    if parse == "" or parse == "all" then
      return nil, nil
    end
    return { parse }, nil
  end
  if type(key) == "string" and key ~= "" then
    return { key }, nil
  end
  return nil, nil
end

-- 从 name/value 列表中按 names/excludes 过滤
local function filter_pairs(pairs_list, names, excludes)
  local out = {}
  if not names then
    for i = 1, #pairs_list do
      local p = pairs_list[i]
      if not matches_exclude(p.name, excludes) then
        out[#out + 1] = p.value
      end
    end
    return out
  end
  local wanted = {}
  for i = 1, #names do
    wanted[names[i]] = true
  end
  for i = 1, #pairs_list do
    local p = pairs_list[i]
    if wanted[p.name] and not matches_exclude(p.name, excludes) then
      out[#out + 1] = p.value
    end
  end
  return out
end

-- 从 ctx.args 取按 kind 过滤的子集（kind 可 nil=全部）
local function args_by_kind(ctx, kind)
  local out = {}
  for i = 1, #ctx.args do
    local a = ctx.args[i]
    if kind == nil or a.kind == kind
      or (kind == "post" and (a.kind == "post" or a.kind == "json")) then
      out[#out + 1] = a
    end
  end
  return out
end

-- 返回变量值数组（字符串）
function pipeline.get_var(ctx, vardef)
  if type(ctx) ~= "table" then
    return {}
  end
  -- 兼容字符串形式："ARGS" / "ARGS:id" / "!ARGS"
  if type(vardef) == "string" then
    if vardef:sub(1, 1) == "!" then
      return {} -- 排除型变量由调用方处理，单独传字符串时忽略
    end
    local ty, key = vardef:match("^([^:]+):?(.*)$")
    vardef = { type = ty, key = (key ~= "" and key or nil) }
  end
  if type(vardef) ~= "table" then
    return {}
  end
  local ty = vardef.type
  if type(ty) ~= "string" then
    return {}
  end

  local names = nil
  local excludes = nil
  -- key 与 parse 都可用于限定具体参数名
  if type(vardef.key) == "string" and vardef.key ~= "" then
    names = { vardef.key }
  else
    names = parse_names(vardef.parse, vardef.key)
  end
  -- 排除名（parse 里以 ! 开头）
  if type(vardef.parse) == "table" then
    for i = 1, #vardef.parse do
      local n = vardef.parse[i]
      if type(n) == "string" and n:sub(1, 1) == "!" then
        excludes = excludes or {}
        excludes[n:sub(2)] = true
      end
    end
  end

  local out = {}
  if ty == "ARGS" then
    out = filter_pairs(args_by_kind(ctx, nil), names, excludes)
  elseif ty == "ARGS_GET" then
    out = filter_pairs(args_by_kind(ctx, "get"), names, excludes)
  elseif ty == "ARGS_POST" then
    out = filter_pairs(args_by_kind(ctx, "post"), names, excludes)
  elseif ty == "ARGS_NAMES" then
    local all = args_by_kind(ctx, nil)
    for i = 1, #all do
      if not excludes or not excludes[all[i].name] then
        out[#out + 1] = all[i].name
      end
    end
    if names then
      local wanted = {}
      for i = 1, #names do wanted[names[i]] = true end
      local filtered = {}
      for i = 1, #out do
        if wanted[out[i]] then filtered[#filtered + 1] = out[i] end
      end
      out = filtered
    end
  elseif ty == "ARGS_GET_NAMES" then
    local all = args_by_kind(ctx, "get")
    for i = 1, #all do
      out[#out + 1] = all[i].name
    end
  elseif ty == "ARGS_POST_NAMES" then
    local all = args_by_kind(ctx, "post")
    for i = 1, #all do
      out[#out + 1] = all[i].name
    end
  elseif ty == "REQUEST_URI" then
    out = { ctx.uri or "" }
  elseif ty == "REQUEST_FILENAME" then
    out = { decode.url(ctx.uri or "", 2) }
  elseif ty == "REQUEST_BASENAME" then
    local path = decode.url(ctx.uri or "", 2)
    out = { path:match("([^/]*)$") or "" }
  elseif ty == "REQUEST_DIRNAME" then
    out = { decode.url(ctx.uri or "", 2):match("^(.*)/[^/]*$") or "/" }
  elseif ty == "QUERY_STRING" then
    out = { ctx.query or "" }
  elseif ty == "REQUEST_METHOD" then
    out = { ctx.method or "" }
  elseif ty == "REQUEST_HEADERS" then
    if names then
      local wanted = {}
      for i = 1, #names do wanted[names[i]:lower()] = true end
      for lname, value in pairs(ctx.headers or {}) do
        if wanted[lname] then
          out[#out + 1] = value
        end
      end
    else
      for _, value in pairs(ctx.headers or {}) do
        if type(value) == "string" then
          out[#out + 1] = value
        end
      end
    end
  elseif ty == "REQUEST_HEADERS_NAMES" then
    for lname in pairs(ctx.headers or {}) do
      out[#out + 1] = lname
    end
  elseif ty == "REQUEST_COOKIES" then
    if names then
      for i = 1, #names do
        local v = ctx.cookies[names[i]]
        if v ~= nil then
          out[#out + 1] = v
        end
      end
    else
      for _, v in pairs(ctx.cookies or {}) do
        out[#out + 1] = v
      end
    end
  elseif ty == "REQUEST_COOKIES_NAMES" then
    for name in pairs(ctx.cookies or {}) do
      out[#out + 1] = name
    end
  elseif ty == "REQUEST_BODY" then
    if type(ctx.body) == "string" and ctx.body ~= "" then
      out = { ctx.body }
    end
  elseif ty == "FILES" then
    for i = 1, #ctx.files do
      local f = ctx.files[i]
      if names then
        local wanted = {}
        for j = 1, #names do wanted[names[j]] = true end
        if wanted[f.name] then
          out[#out + 1] = f.filename
        end
      else
        out[#out + 1] = f.filename
      end
    end
  elseif ty == "FILES_NAMES" then
    for i = 1, #ctx.files do
      out[#out + 1] = ctx.files[i].name
    end
  elseif ty == "FILES_EXT" then
    for i = 1, #ctx.files do
      out[#out + 1] = ctx.files[i].ext
    end
  elseif ty == "TX" then
    local key = vardef.key
    if type(key) == "string" and ctx.tx and ctx.tx[key] ~= nil then
      out = { tostring(ctx.tx[key]) }
    end
  elseif ty == "REMOTE_ADDR" then
    out = { ctx.ip or ctx.remote_addr or "" }
  elseif ty == "REMOTE_PORT" then
    out = { tostring(ctx.remote_port or "") }
  elseif ty == "REQUEST_LINE" then
    out = { string.format("%s %s %s", ctx.method or "", ctx.uri_raw or ctx.uri or "",
      ctx.http_version or "HTTP/1.1") }
  elseif ty == "REQUEST_PROTOCOL" then
    out = { ctx.http_version or "HTTP/1.1" }
  elseif ty == "SERVER_NAME" then
    out = { ctx.host or "" }
  elseif ty == "HTTP_USER_AGENT" then
    out = { ctx.headers["user-agent"] or "" }
  elseif ty == "HTTP_REFERER" then
    out = { ctx.headers["referer"] or "" }
  elseif ty == "HTTP_HOST" then
    out = { ctx.host or "" }
  elseif ty == "ARGS_COUNT" then
    out = { tostring(#ctx.args) }
  end

  -- count 语义：&ARGS 等返回数量
  if vardef.count == true then
    return { tostring(#out) }
  end
  return out
end

-- ---------------------------------------------------------------------------
-- 扫描目标列表
-- ---------------------------------------------------------------------------
-- 返回 {value=..., kind=...} 列表；kind 便于定位（uri/query/body/arg/header/cookie/file）
function pipeline.targets(ctx)
  local out = {}
  local seen = {}
  local function add(value, kind)
    if type(value) ~= "string" or value == "" then
      return
    end
    if seen[value] then
      return
    end
    seen[value] = true
    out[#out + 1] = { value = value, kind = kind }
  end
  add(ctx.uri, "uri")
  add(ctx.query, "query")
  add(ctx.body, "body")
  for i = 1, #ctx.args do
    add(ctx.args[i].value, "arg:" .. tostring(ctx.args[i].kind))
    add(ctx.args[i].name, "argname")
  end
  for name, value in pairs(ctx.headers or {}) do
    add(value, "header:" .. name)
  end
  for name, value in pairs(ctx.cookies or {}) do
    add(value, "cookie:" .. name)
  end
  for i = 1, #ctx.files do
    add(ctx.files[i].filename, "file:name")
    add(ctx.files[i].snippet, "file:content")
  end
  return out
end

return pipeline
