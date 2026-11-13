--[[
  tests/mock/ngx.lua
  OpenResty ngx API 垫片（Lua 5.4 / wasmoon 运行）。
  覆盖 btwaf_ce Lua 引擎使用的全部 ngx.*：
    shared（字典 + TTL）、var、ctx、req（headers/body/read_body/args）、
    header/status/say/exit、log、timer.every、time/now、escape_uri/unescape_uri、
    worker.id/pid、re.find（经 JS 桥，PCRE 近似）、config.prefix。
  同时提供 mock.* 辅助函数供测试用例驱动请求与断言。
]]

local mock = {}

local ngx_ = {}
_G.ngx = ngx_

-- 可控时钟（秒，浮点）
mock.clock = os.time()

-- 当前请求状态
local state = {
  method = "GET",
  headers = {},
  body = nil,
  body_file = nil,
  read_count = 0,
  http_version = 1,
}
mock.state = state

mock.worker_id = 0
mock.pid = 4242
mock.dicts = {}
mock.timers = {}
mock.logs = {}
mock.response = {}
mock.exit_status = nil

-- ---------------------------------------------------------------------------
-- 共享字典（TTL 逻辑与 OpenResty 一致：set/add/delete/incr/get_keys/flush_all）
-- ---------------------------------------------------------------------------
local function new_dict(name)
  local d = { name = name, data = {} }

  -- 内部方法：与 OpenResty 一样采用 self 形式（调用方可用 dict.get(dict, k) 或 dict:get(k)）
  local function get(self, key)
    local e = self.data[key]
    if not e then
      return nil
    end
    if e.exp and e.exp <= mock.clock then
      self.data[key] = nil
      return nil
    end
    return e.v
  end

  local function set(self, key, value, exptime)
    if value == nil then
      return false, "nil value"
    end
    local exp = nil
    if type(exptime) == "number" and exptime > 0 then
      exp = mock.clock + exptime
    end
    self.data[key] = { v = value, exp = exp }
    return true
  end

  function d.get(self, key)
    return get(self, key)
  end

  function d.set(self, key, value, exptime)
    return set(self, key, value, exptime)
  end

  function d.add(self, key, value, exptime)
    if get(self, key) ~= nil then
      return false, "exists"
    end
    return set(self, key, value, exptime)
  end

  function d.replace(self, key, value, exptime)
    if get(self, key) == nil then
      return false, "not found"
    end
    return set(self, key, value, exptime)
  end

  function d.delete(self, key)
    self.data[key] = nil
    return true
  end

  function d.incr(self, key, value, init, init_ttl)
    local entry = self.data[key]
    local cur = get(self, key)
    if cur == nil then
      if init == nil then
        return nil, "not found"
      end
      -- 与 OpenResty 一致：key 不存在时先置 init，再累加 value，返回 init + value
      cur = init + (value or 1)
      set(self, key, cur, init_ttl)
      return cur
    end
    cur = cur + (value or 1)
    self.data[key] = { v = cur, exp = entry and entry.exp or nil }
    return cur
  end

  function d.get_keys(self, max)
    local out = {}
    for k, e in pairs(self.data) do
      if not e.exp or e.exp > mock.clock then
        out[#out + 1] = k
        if type(max) == "number" and max > 0 and #out >= max then
          break
        end
      end
    end
    return out
  end

  function d.flush_all(self)
    self.data = {}
    return true
  end

  function d.get_stale(self, key)
    local e = self.data[key]
    if e then
      return e.v
    end
    return nil
  end

  return d
end
mock.new_dict = new_dict

ngx_.shared = setmetatable({}, {
  __index = function(_, name)
    if not mock.dicts[name] then
      mock.dicts[name] = new_dict(name)
    end
    return mock.dicts[name]
  end,
})

function mock.dict(name)
  return ngx_.shared[name]
end

-- ---------------------------------------------------------------------------
-- 时间
-- ---------------------------------------------------------------------------
function mock.advance(seconds)
  mock.clock = mock.clock + (tonumber(seconds) or 0)
end

function mock.now()
  return mock.clock
end

ngx_.time = function()
  return math.floor(mock.clock)
end
ngx_.now = function()
  return mock.clock
end
ngx_.update_time = ngx_.now
ngx_.localtime = function(t)
  return os.date("*t", t or mock.clock)
end
ngx_.utctime = function(t)
  return os.date("!%Y-%m-%d %H:%M:%S", t or mock.clock)
end
ngx_.today = function()
  return os.date("%Y-%m-%d", mock.clock)
end

-- ---------------------------------------------------------------------------
-- 日志 / 响应
-- ---------------------------------------------------------------------------
ngx_.ERR = 4
ngx_.WARN = 5
ngx_.NOTICE = 5
ngx_.INFO = 6
ngx_.DEBUG = 7
ngx_.STDERR = 0

function ngx_.log(level, ...)
  local parts = {}
  for i = 1, select("#", ...) do
    parts[#parts + 1] = tostring(select(i, ...))
  end
  mock.logs[#mock.logs + 1] = { level = level, msg = table.concat(parts) }
end

function ngx_.print(...)
  ngx_.log(ngx_.NOTICE, ...)
end

ngx_.header = {}
ngx_.status = 200
ngx_.headers_sent = false

function ngx_.say(...)
  local parts = {}
  for i = 1, select("#", ...) do
    parts[#parts + 1] = tostring(select(i, ...))
  end
  mock.response[#mock.response + 1] = table.concat(parts)
end

function ngx_.exit(status)
  mock.exit_status = status
  if type(status) == "number" then
    ngx_.status = status
  end
  ngx_.headers_sent = true
  return
end

ngx_.flush = function() end

-- ---------------------------------------------------------------------------
-- ngx.var / ngx.ctx
-- ---------------------------------------------------------------------------
mock.var = {}
mock.ctx = {}
ngx_.var = mock.var
ngx_.ctx = mock.ctx

-- ---------------------------------------------------------------------------
-- ngx.req
-- ---------------------------------------------------------------------------
ngx_.req = {}

function ngx_.req.get_headers(max_headers, raw)
  return state.headers
end

function ngx_.req.read_body()
  state.read_count = state.read_count + 1
end

function ngx_.req.get_body_data()
  if state.read_count == 0 then
    return nil -- 与 OpenResty 一致：未 read_body 时读不到
  end
  return state.body
end

function ngx_.req.get_body_file()
  return state.body_file
end

function ngx_.req.get_method()
  return state.method
end

function ngx_.req.get_uri()
  return mock.var.uri or "/"
end

function ngx_.req.set_uri(uri)
  mock.var.uri = uri
end

function ngx_.req.http_version()
  return state.http_version
end

function ngx_.req.get_uri_args(max)
  return {}
end

function ngx_.req.get_post_args(max)
  return {}
end

function ngx_.req.set_header(name, value)
  state.headers[name:lower()] = value
end

-- ---------------------------------------------------------------------------
-- ngx.re：经 JS 桥（run.mjs 实现 PCRE 近似 + 统计）
-- ---------------------------------------------------------------------------
local function apply_inline_flags(pattern, opts)
  -- JS 桥内部处理 (?i)(?m)(?s) 等；此处只透传
  return pattern
end

ngx_.re = {}

function ngx_.re.find(subject, pattern, opts)
  local res = __BTWAF_RE_FIND(subject or "", pattern or "", opts or "")
  if type(res) ~= "string" then
    return nil, "regex bridge 返回异常"
  end
  if res == "" then
    return nil -- 无匹配
  end
  if res:sub(1, 2) == "E:" then
    return nil, res:sub(3)
  end
  local from, to = res:match("^(%d+),(%d+)$")
  if not from then
    return nil, "regex bridge 返回格式错误: " .. res
  end
  return tonumber(from), tonumber(to)
end

function ngx_.re.match(subject, pattern, opts)
  local from, to = ngx_.re.find(subject, pattern, opts)
  if not from then
    return nil
  end
  return { [0] = subject:sub(from, to) }
end

function ngx_.re.sub(subject, pattern, replace, opts)
  -- 测试不依赖 gsub；提供最小实现
  local from, to = ngx_.re.find(subject, pattern, opts)
  if not from then
    return subject, 0
  end
  return subject:sub(1, from - 1) .. replace .. subject:sub(to + 1), 1
end

-- ---------------------------------------------------------------------------
-- ngx.timer
-- ---------------------------------------------------------------------------
ngx_.timer = {}

function ngx_.timer.every(interval, fn)
  mock.timers[#mock.timers + 1] = { kind = "every", interval = interval, fn = fn }
  return true
end

function ngx_.timer.at(delay, fn)
  mock.timers[#mock.timers + 1] = { kind = "at", delay = delay, fn = fn }
  return true
end

function mock.run_timers()
  local count = 0
  for i = 1, #mock.timers do
    local t = mock.timers[i]
    if t.kind == "every" then
      t.fn(false)
      count = count + 1
    end
  end
  return count
end

function mock.timer_count()
  return #mock.timers
end

-- ---------------------------------------------------------------------------
-- worker / config / escape
-- ---------------------------------------------------------------------------
ngx_.worker = {
  id = function() return mock.worker_id end,
  pid = function() return mock.pid end,
  exiting = function() return false end,
  count = function() return 1 end,
}

ngx_.config = {
  prefix = function() return "/tmp/btwaf_ce_test/" end,
  subsystem = function() return "http" end,
}

function ngx_.escape_uri(s)
  return (tostring(s):gsub("([^%w%-%._~])", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

function ngx_.unescape_uri(s)
  return (tostring(s):gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

-- ---------------------------------------------------------------------------
-- mock 辅助：请求构造/重置
-- ---------------------------------------------------------------------------
local function normalize_headers(headers)
  local out = {}
  if type(headers) == "table" then
    for k, v in pairs(headers) do
      if type(k) == "string" then
        out[k:lower()] = tostring(v)
      end
    end
  end
  return out
end

function mock.reset_request()
  state.method = "GET"
  state.headers = {}
  state.body = nil
  state.body_file = nil
  state.read_count = 0
  state.http_version = 1
  mock.var = {}
  ngx_.var = mock.var
  ngx_.ctx = {}
  ngx_.header = {}
  ngx_.status = 200
  ngx_.headers_sent = false
  mock.response = {}
  mock.exit_status = nil
  return mock
end

-- opts: method, uri, query, host, headers, body, remote_addr, http_version
function mock.set_request(opts)
  opts = opts or {}
  mock.reset_request()
  local method = (opts.method or "GET"):upper()
  local uri = opts.uri or "/"
  local query = opts.query or ""
  local headers = normalize_headers(opts.headers)
  state.method = method
  state.headers = headers
  state.body = opts.body
  state.body_file = opts.body_file
  state.http_version = opts.http_version or 1

  mock.var.request_method = method
  mock.var.uri = uri
  mock.var.request_uri = uri .. (query ~= "" and ("?" .. query) or "")
  mock.var.query_string = query
  mock.var.host = opts.host or "www.example.com"
  mock.var.http_host = mock.var.host
  mock.var.remote_addr = opts.remote_addr or "1.2.3.4"
  mock.var.server_protocol = opts.server_protocol or "HTTP/1.1"
  mock.var.scheme = opts.scheme or "http"
  mock.var.request_id = opts.request_id or ("req-" .. tostring(os.time()) .. "-" .. method)
  return mock
end

function mock.body_read_count()
  return state.read_count
end

function mock.response_body()
  return table.concat(mock.response)
end

function mock.clear_logs()
  mock.logs = {}
end

-- ---------------------------------------------------------------------------
-- mock 辅助：配置与文件
-- ---------------------------------------------------------------------------
-- 注入配置表并标记引擎已初始化（避免 bootstrap.ensure 从文件重读）
function mock.boot(global_overrides, sites, hosts, custom)
  local config = require("lib.config")
  config.reset()
  local ok = config.load_from_tables(global_overrides or {}, sites or {}, hosts or {}, custom or {})
  local bootstrap = require("lib.bootstrap")
  bootstrap.initialized = true
  bootstrap.init_ok = ok
  local matcher = require("lib.matcher")
  matcher.reset()
  matcher.load({}, nil)
  local storage = require("lib.storage")
  storage.reset_cache()
  local util = require("lib.util")
  util.reset_error_log()
  return config, ok
end

function mock.file_read(path)
  return __BTWAF_FS_READ(path)
end

function mock.file_write(path, data)
  return __BTWAF_FS_WRITE(path, data)
end

function mock.file_exists(path)
  return __BTWAF_FS_EXISTS(path) == true
end

-- 读取 JSONL 日志并解析（用于断言日志合法性）
function mock.read_jsonl(path)
  local json = require("lib.json")
  local data = __BTWAF_FS_READ(path)
  local out = {}
  if type(data) ~= "string" or data == "" then
    return out
  end
  for line in data:gmatch("[^\n]+") do
    local obj = json.decode(line)
    out[#out + 1] = { raw = line, obj = obj }
  end
  return out
end

-- 清空全部状态（每个 suite 开始调用）
function mock.reset_all()
  mock.clock = os.time()
  mock.worker_id = 0
  mock.dicts = {}
  mock.timers = {}
  mock.logs = {}
  mock.response = {}
  mock.exit_status = nil
  ngx_.shared = setmetatable({}, {
    __index = function(_, name)
      if not mock.dicts[name] then
        mock.dicts[name] = new_dict(name)
      end
      return mock.dicts[name]
    end,
  })
  mock.reset_request()
  local ok1, util = pcall(require, "lib.util")
  if ok1 then
    util.reset_error_log()
  end
  local ok2, storage = pcall(require, "lib.storage")
  if ok2 then
    storage.reset_cache()
  end
  return mock
end

-- 断言辅助：读取共享字典计数
function mock.dict_get(dict_name, key)
  local d = ngx_.shared[dict_name]
  return d.get(d, key)
end

return mock

