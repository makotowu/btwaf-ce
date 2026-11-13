--[[
  btwaf_ce / lib/util.lua
  通用工具：IP/CIDR、字符串安全处理、JSON 转义、错误日志（带去重）。
  contract §6.3：ip_to_int / cidr_match / ip_in_list / truncate / strip_ctrl /
  now / escape_json / log_error。
  编码规范：Lua 5.1/5.4 公共子集；顶部 local ngx = ngx；所有 ngx.* 可被 mock 替换。
]]

local ngx = ngx
local fs = require("lib.fs")
local paths = require("lib.paths")
local json = require("lib.json")

local util = {}

-- ---------------------------------------------------------------------------
-- 时间
-- ---------------------------------------------------------------------------
function util.now()
  if ngx and ngx.time then
    local ok, t = pcall(ngx.time)
    if ok and type(t) == "number" then
      return t
    end
  end
  return os.time()
end

-- 毫秒时间戳（用于性能统计），无 ngx.now 时用 os.clock 兜底
function util.now_ms()
  if ngx and ngx.now then
    local ok, t = pcall(ngx.now)
    if ok and type(t) == "number" then
      return t * 1000
    end
  end
  return os.time() * 1000
end

-- ---------------------------------------------------------------------------
-- IP 处理
-- ---------------------------------------------------------------------------
-- IPv4 转整数：返回 number 或 nil
function util.ip_to_int(ip)
  if type(ip) ~= "string" then
    return nil
  end
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then
    return nil
  end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not a or a > 255 or b > 255 or c > 255 or d > 255 then
    return nil
  end
  -- 使用算术而非位移，兼容 5.1/5.4（禁 bit32）
  return a * 16777216 + b * 65536 + c * 256 + d
end

-- IPv6/非法地址的退化比较：仅做大小写不敏感的精确字符串匹配
local function exact_ip_match(ip, base)
  return type(ip) == "string" and type(base) == "string" and ip:lower() == base:lower()
end

-- 判断 ip 是否落在 cidr 内。cidr 可以是纯 IP（精确匹配）或 a.b.c.d/n。
-- 说明：IPv6 网段计算不在 v1 范围，退化为精确匹配，避免误放行/误拦截。
function util.cidr_match(ip, cidr)
  if type(ip) ~= "string" or type(cidr) ~= "string" then
    return false
  end
  local base, bits = cidr:match("^([^/]+)/(%d+)$")
  if not base then
    return exact_ip_match(ip, cidr)
  end
  bits = tonumber(bits)
  if not bits or bits < 0 or bits > 32 then
    return false
  end
  base = util.trim(base)
  local ipn = util.ip_to_int(ip)
  local basen = util.ip_to_int(base)
  if not ipn or not basen then
    return exact_ip_match(ip, base)
  end
  if bits == 0 then
    return true
  end
  if bits == 32 then
    return ipn == basen
  end
  local scale = 2 ^ (32 - bits)
  return math.floor(ipn / scale) == math.floor(basen / scale)
end

-- 判断 ip 是否命中列表（支持 IP 与 CIDR）
function util.ip_in_list(ip, list)
  if type(ip) ~= "string" or type(list) ~= "table" then
    return false
  end
  for i = 1, #list do
    local item = list[i]
    if type(item) == "string" then
      item = util.trim(item)
      if item ~= "" then
        if util.cidr_match(ip, item) then
          return true
        end
      end
    end
  end
  return false
end

-- IP 是否合法（非空且能解析；IPv6 做宽松校验）
function util.is_ip(ip)
  if type(ip) ~= "string" or ip == "" then
    return false
  end
  if util.ip_to_int(ip) then
    return true
  end
  return ip:match("^[%x:]+$") ~= nil and ip:find(":", 1, true) ~= nil
end

-- ---------------------------------------------------------------------------
-- 字符串处理
-- ---------------------------------------------------------------------------
function util.trim(s)
  if type(s) ~= "string" then
    return s
  end
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- 按字节截断，且不截断多字节 UTF-8 字符（避免日志出现乱码）
function util.truncate(s, n)
  if type(s) ~= "string" then
    return ""
  end
  if n == nil or n < 0 then
    n = 0
  end
  if #s <= n then
    return s
  end
  local cut = s:sub(1, n)
  local len = #cut
  local i = len
  -- 从末尾向前最多找 3 个字节，定位最后一个字符的首字节
  local start = nil
  while i > 0 and i > len - 4 do
    local b = string.byte(cut, i)
    if b < 0x80 then
      return cut -- 以完整 ASCII 字符结尾
    elseif b >= 0xC0 then
      start = i
      break
    end
    i = i - 1
  end
  if not start then
    -- 末尾全是 continuation 字节（非法 UTF-8）：截到最后一个可能的安全边界
    if i < 1 then
      return ""
    end
    return cut:sub(1, i)
  end
  local b = string.byte(cut, start)
  local need = 2
  if b >= 0xF0 then
    need = 4
  elseif b >= 0xE0 then
    need = 3
  end
  local finish = start + need - 1
  if finish == len then
    return cut -- 末尾恰好是一个完整字符
  elseif finish < len then
    -- 末尾还有不完整的下一个字符：只保留到上一个完整字符
    return cut:sub(1, finish)
  end
  return cut:sub(1, start - 1) -- 首字节后字节不足：丢弃该字符
end

-- 控制字符替换为空格（日志安全）
function util.strip_ctrl(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("[%z\1-\31\127]", " "))
end

-- 清洗非法 UTF-8 字节（日志契约要求 UTF-8）：非法字节替换为空格
function util.sanitize_utf8(s)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  local out = {}
  local i = 1
  local len = #s
  while i <= len do
    local b = string.byte(s, i)
    if b < 0x80 then
      out[#out + 1] = s:sub(i, i)
      i = i + 1
    else
      local need = 0
      if b >= 0xC2 and b <= 0xDF then
        need = 1
      elseif b >= 0xE0 and b <= 0xEF then
        need = 2
      elseif b >= 0xF0 and b <= 0xF4 then
        need = 3
      end
      local ok = need > 0 and (i + need <= len)
      if ok then
        for k = 1, need do
          local cb = string.byte(s, i + k)
          if not cb or cb < 0x80 or cb > 0xBF then
            ok = false
            break
          end
        end
      end
      if ok then
        out[#out + 1] = s:sub(i, i + need)
        i = i + need + 1
      else
        out[#out + 1] = " "
        i = i + 1
      end
    end
  end
  return table.concat(out)
end

-- JSON 字符串转义（不含引号），单行化
function util.escape_json(s)
  if type(s) ~= "string" then
    s = tostring(s)
  end
  return json.escape_string(s)
end

-- 按纯文本分隔符切分
function util.split(s, sep)
  local out = {}
  if type(s) ~= "string" or s == "" then
    return out
  end
  sep = sep or ","
  local start = 1
  while true do
    local i, j = s:find(sep, start, true)
    if not i then
      out[#out + 1] = s:sub(start)
      break
    end
    out[#out + 1] = s:sub(start, i - 1)
    start = j + 1
  end
  return out
end

function util.starts_with(s, prefix)
  return type(s) == "string" and type(prefix) == "string" and #prefix > 0
    and s:sub(1, #prefix) == prefix
end

function util.ends_with(s, suffix)
  return type(s) == "string" and type(suffix) == "string" and #suffix > 0
    and s:sub(#s - #suffix + 1) == suffix
end

function util.contains(s, needle)
  return type(s) == "string" and type(needle) == "string"
    and s:find(needle, 1, true) ~= nil
end

-- 取表长度（nil 安全）
function util.tlen(t)
  if type(t) ~= "table" then
    return 0
  end
  return #t
end

-- 表转逗号字符串（日志/调试）
function util.join(t, sep)
  if type(t) ~= "table" then
    return ""
  end
  local parts = {}
  for i = 1, #t do
    parts[#parts + 1] = tostring(t[i])
  end
  return table.concat(parts, sep or ",")
end

-- 深拷贝（仅 table/标量；用于配置快照）
function util.deep_copy(v, depth)
  depth = depth or 0
  if depth > 32 or type(v) ~= "table" then
    return v
  end
  local t = {}
  for k, val in pairs(v) do
    t[k] = util.deep_copy(val, depth + 1)
  end
  return t
end

-- ---------------------------------------------------------------------------
-- 错误日志（去重）
-- ---------------------------------------------------------------------------
-- 去重策略：同一 msg 60 秒内只写一次；记录条数超限时清空，避免内存增长。
local err_seen = {}
local err_count = 0
local ERR_MAX = 200
local ERR_DEDUP_SEC = 60

-- 测试用：重置去重状态
function util.reset_error_log()
  err_seen = {}
  err_count = 0
end

-- 测试用：读取去重表大小
function util.error_count()
  return err_count
end

function util.log_error(msg)
  local text = tostring(msg)
  local now = util.now()
  local last = err_seen[text]
  if last and (now - last) < ERR_DEDUP_SEC then
    return
  end
  if err_count >= ERR_MAX then
    -- 简单容量控制：整体清空（错误日志不是审计日志，可丢失）
    err_seen = {}
    err_count = 0
  end
  err_seen[text] = now
  err_count = err_count + 1
  -- 写 logs/error.log；失败绝不递归报错
  local line = os.date("%Y-%m-%d %H:%M:%S", now) .. " " .. util.strip_ctrl(text) .. "\n"
  fs.append(paths.error_log(), line)
end

return util
