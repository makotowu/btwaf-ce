--[[
  btwaf_ce / lib/json.lua
  纯 Lua JSON 编解码（Lua 5.1 / 5.4 公共子集）。
  - 不依赖 cjson / ffi / lfs，可在 OpenResty 与 wasmoon 测试环境运行。
  - 解码：null 解码为 nil（键被省略），数组带 json.array_mt 元表标记，
    以便空数组解码后仍能编码回 []（空表默认编码为 {}）。
  - 编码：兼容 ASCII 与 UTF-8；控制字符转义；拒绝 NaN/Inf（输出 null）。
  - 安全：限制最大嵌套深度，防止恶意 JSON 造成栈溢出。
]]

local json = {}

-- 数组标记元表：解码出的数组会带上该元表；编码时据此区分 [] 与 {}。
json.array_mt = {}
-- 空对象标记元表（可选，用于强制把空表编码为 {}，默认即如此）。
json.object_mt = {}

local MAX_DEPTH = 64

-- ---------------------------------------------------------------------------
-- UTF-8 编码辅助：把 Unicode 码点转成 UTF-8 字节串（纯算术，无 bit 库）
-- ---------------------------------------------------------------------------
local function utf8_char(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(
      0xC0 + math.floor(cp / 0x40),
      0x80 + (cp % 0x40)
    )
  elseif cp < 0x10000 then
    return string.char(
      0xE0 + math.floor(cp / 0x1000),
      0x80 + (math.floor(cp / 0x40) % 0x40),
      0x80 + (cp % 0x40)
    )
  elseif cp < 0x200000 then
    return string.char(
      0xF0 + math.floor(cp / 0x40000),
      0x80 + (math.floor(cp / 0x1000) % 0x40),
      0x80 + (math.floor(cp / 0x40) % 0x40),
      0x80 + (cp % 0x40)
    )
  end
  -- 非法码点按替换字符处理
  return "\239\191\189"
end

-- ---------------------------------------------------------------------------
-- 字符串编码
-- ---------------------------------------------------------------------------
local ESC_MAP = {
  ['"'] = '\\"',
  ["\\"] = "\\\\",
  ["\b"] = "\\b",
  ["\f"] = "\\f",
  ["\n"] = "\\n",
  ["\r"] = "\\r",
  ["\t"] = "\\t",
}

-- 转义字符串内容（不含两侧引号）；可被 util.escape_json 复用。
function json.escape_string(s)
  if type(s) ~= "string" then
    s = tostring(s)
  end
  -- 一次扫描替换：常见转义走查表，其余控制字符转 \u00XX
  local out = s:gsub('[%z\1-\31\\"]', function(c)
    local m = ESC_MAP[c]
    if m then
      return m
    end
    return string.format("\\u%04x", string.byte(c))
  end)
  return out
end

-- ---------------------------------------------------------------------------
-- 数字编码：整数不带小数点，浮点保留足够精度
-- ---------------------------------------------------------------------------
local function encode_number(n)
  if n ~= n then
    return "null" -- NaN
  end
  if n == math.huge or n == -math.huge then
    return "null"
  end
  local i = math.floor(n)
  -- 双精度整数安全范围 2^53，超出后用浮点格式
  if i == n and math.abs(n) < 9007199254740992 then
    if n == 0 then
      return "0"
    end
    return string.format("%d", n)
  end
  local s = string.format("%.14g", n)
  return s
end

-- ---------------------------------------------------------------------------
-- 编码
-- ---------------------------------------------------------------------------
local encode_value

-- 判断是否为连续数组（键 1..n）；空表返回 nil 交给调用方决定
local function is_array(t)
  local mt = getmetatable(t)
  if mt == json.array_mt then
    return true
  end
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" or k < 1 or k ~= math.floor(k) then
      return false
    end
    n = n + 1
    if k > n then
      -- 存在空洞或乱序，按对象处理（避免 # 结果不确定）
      return false
    end
  end
  return n > 0
end

-- 对象键排序，保证输出稳定（便于测试与 diff）
local function sorted_keys(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys, function(a, b)
    local ta, tb = type(a), type(b)
    if ta == tb then
      if ta == "number" then
        return a < b
      end
      return tostring(a) < tostring(b)
    end
    -- 数字键在前，字符串键在后
    return ta == "number"
  end)
  return keys
end

encode_value = function(v, buf, depth, seen)
  local tv = type(v)
  if tv == "nil" then
    buf[#buf + 1] = "null"
  elseif tv == "boolean" then
    buf[#buf + 1] = v and "true" or "false"
  elseif tv == "number" then
    buf[#buf + 1] = encode_number(v)
  elseif tv == "string" then
    buf[#buf + 1] = '"'
    buf[#buf + 1] = json.escape_string(v)
    buf[#buf + 1] = '"'
  elseif tv == "table" then
    if seen[v] then
      error("json.encode: 检测到循环引用")
    end
    if depth >= MAX_DEPTH then
      error("json.encode: 嵌套层级超过上限")
    end
    seen[v] = true
    if v == json.null then
      -- 显式 null 哨兵（解码不会产生，仅用于编码）
      buf[#buf + 1] = "null"
    elseif v == json.array_mt or is_array(v) then
      buf[#buf + 1] = "["
      local n = #v
      for i = 1, n do
        if i > 1 then
          buf[#buf + 1] = ","
        end
        encode_value(v[i], buf, depth + 1, seen)
      end
      buf[#buf + 1] = "]"
    else
      buf[#buf + 1] = "{"
      local keys = sorted_keys(v)
      local first = true
      for i = 1, #keys do
        local k = keys[i]
        if type(k) == "string" or type(k) == "number" then
          if not first then
            buf[#buf + 1] = ","
          end
          first = false
          buf[#buf + 1] = '"'
          buf[#buf + 1] = json.escape_string(tostring(k))
          buf[#buf + 1] = '":'
          encode_value(v[k], buf, depth + 1, seen)
        end
      end
      buf[#buf + 1] = "}"
    end
    seen[v] = nil
  else
    error("json.encode: 不支持的类型 " .. tv)
  end
end

-- 显式 null 哨兵（仅用于编码）
json.null = setmetatable({}, { __tostring = function() return "null" end })

function json.encode(tbl)
  local buf = {}
  local seen = {}
  local ok, err = pcall(encode_value, tbl, buf, 0, seen)
  if not ok then
    return nil, err
  end
  return table.concat(buf)
end

-- ---------------------------------------------------------------------------
-- 解码
-- ---------------------------------------------------------------------------
local decode_value

local function decode_error(pos, msg)
  error({ pos = pos, msg = msg })
end

local function skip_ws(s, pos)
  local _, e = s:find("^[ \t\r\n]+", pos)
  if e then
    return e + 1
  end
  return pos
end

local ESC_UNESCAPE = {
  ['"'] = '"',
  ["\\"] = "\\",
  ["/"] = "/",
  ["b"] = "\b",
  ["f"] = "\f",
  ["n"] = "\n",
  ["r"] = "\r",
  ["t"] = "\t",
}

local function decode_string(s, pos)
  -- pos 指向起始引号
  local buf = {}
  local i = pos + 1
  local len = #s
  while i <= len do
    local c = s:sub(i, i)
    if c == '"' then
      return table.concat(buf), i + 1
    elseif c == "\\" then
      local n = s:sub(i + 1, i + 1)
      if n == "u" then
        local hex = s:sub(i + 2, i + 5)
        if #hex < 4 or not hex:match("^%x%x%x%x$") then
          decode_error(i, "非法 \\u 转义")
        end
        local cp = tonumber(hex, 16)
        i = i + 6
        -- 代理对：高位 0xD800-0xDBFF + 低位 0xDC00-0xDFFF
        if cp >= 0xD800 and cp <= 0xDBFF then
          if s:sub(i, i + 1) == "\\u" then
            local hex2 = s:sub(i + 2, i + 5)
            if #hex2 == 4 and hex2:match("^%x%x%x%x$") then
              local lo = tonumber(hex2, 16)
              if lo >= 0xDC00 and lo <= 0xDFFF then
                cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
                i = i + 6
              end
            end
          end
        end
        buf[#buf + 1] = utf8_char(cp)
      else
        local u = ESC_UNESCAPE[n]
        if not u then
          decode_error(i, "非法转义字符 \\" .. tostring(n))
        end
        buf[#buf + 1] = u
        i = i + 2
      end
    else
      -- 普通字符段：一次取到下一个引号或反斜杠，减少逐字节开销
      local j = s:find('[\\"]', i)
      if not j then
        decode_error(i, "字符串未闭合")
      end
      buf[#buf + 1] = s:sub(i, j - 1)
      i = j
    end
  end
  decode_error(pos, "字符串未闭合")
end

local function decode_number(s, pos)
  local num_str = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
  if not num_str or num_str == "" then
    decode_error(pos, "非法数字")
  end
  local n = tonumber(num_str)
  if not n then
    decode_error(pos, "非法数字 " .. num_str)
  end
  return n, pos + #num_str
end

decode_value = function(s, pos, depth)
  if depth > MAX_DEPTH then
    decode_error(pos, "嵌套层级超过上限")
  end
  pos = skip_ws(s, pos)
  local c = s:sub(pos, pos)
  if c == '"' then
    return decode_string(s, pos)
  elseif c == "{" then
    local t = {}
    local mt = getmetatable(t)
    -- 空对象默认无元表；此处显式标记为对象（与空数组区分）
    setmetatable(t, json.object_mt)
    pos = skip_ws(s, pos + 1)
    if s:sub(pos, pos) == "}" then
      return t, pos + 1
    end
    while true do
      pos = skip_ws(s, pos)
      if s:sub(pos, pos) ~= '"' then
        decode_error(pos, "对象键必须是字符串")
      end
      local key
      key, pos = decode_string(s, pos)
      pos = skip_ws(s, pos)
      if s:sub(pos, pos) ~= ":" then
        decode_error(pos, "缺少冒号")
      end
      local val
      val, pos = decode_value(s, pos + 1, depth + 1)
      t[key] = val
      pos = skip_ws(s, pos)
      local d = s:sub(pos, pos)
      if d == "}" then
        return t, pos + 1
      elseif d == "," then
        pos = pos + 1
      else
        decode_error(pos, "对象缺少逗号或右花括号")
      end
    end
  elseif c == "[" then
    local t = setmetatable({}, json.array_mt)
    local idx = 0
    pos = skip_ws(s, pos + 1)
    if s:sub(pos, pos) == "]" then
      return t, pos + 1
    end
    while true do
      local val
      val, pos = decode_value(s, pos, depth + 1)
      idx = idx + 1
      if val == nil then
        -- JSON null：数组内保留占位（用哨兵，编码回 null）
        t[idx] = json.null
      else
        t[idx] = val
      end
      pos = skip_ws(s, pos)
      local d = s:sub(pos, pos)
      if d == "]" then
        return t, pos + 1
      elseif d == "," then
        pos = pos + 1
      else
        decode_error(pos, "数组缺少逗号或右方括号")
      end
    end
  elseif c == "t" then
    if s:sub(pos, pos + 3) == "true" then
      return true, pos + 4
    end
    decode_error(pos, "非法字面量")
  elseif c == "f" then
    if s:sub(pos, pos + 4) == "false" then
      return false, pos + 5
    end
    decode_error(pos, "非法字面量")
  elseif c == "n" then
    if s:sub(pos, pos + 3) == "null" then
      return nil, pos + 4
    end
    decode_error(pos, "非法字面量")
  else
    return decode_number(s, pos)
  end
end

function json.decode(str)
  if type(str) ~= "string" then
    return nil, "json.decode: 输入不是字符串"
  end
  if str == "" then
    return nil, "json.decode: 输入为空"
  end
  local ok, result, pos = pcall(decode_value, str, 1, 0)
  if not ok then
    local e = result
    if type(e) == "table" and e.msg then
      return nil, "json.decode: " .. e.msg .. "（位置 " .. tostring(e.pos) .. "）"
    end
    return nil, "json.decode: " .. tostring(e)
  end
  -- 检查末尾多余内容
  local tail = skip_ws(str, pos or 1)
  if tail <= #str then
    return nil, "json.decode: 末尾存在多余内容（位置 " .. tail .. "）"
  end
  return result
end

return json
