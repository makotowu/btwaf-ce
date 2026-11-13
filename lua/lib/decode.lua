--[[
  btwaf_ce / lib/decode.lua
  多层解码与规范化（contract §6.12）。
  纯 Lua 实现，不依赖 ngx（有 ngx 时仅为性能可选）；Lua 5.1/5.4 公共子集。
  所有函数对非字符串输入安全返回空串/原值，绝不抛异常。
]]

local decode = {}

-- UTF-8 码点编码（同 json.lua，独立实现避免跨模块耦合）
local function utf8_char(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + (cp % 0x40))
  elseif cp < 0x10000 then
    return string.char(
      0xE0 + math.floor(cp / 0x1000),
      0x80 + (math.floor(cp / 0x40) % 0x40),
      0x80 + (cp % 0x40)
    )
  end
  return string.char(
    0xF0 + math.floor(cp / 0x40000),
    0x80 + (math.floor(cp / 0x1000) % 0x40),
    0x80 + (math.floor(cp / 0x40) % 0x40),
    0x80 + (cp % 0x40)
  )
end

-- 单层 URL 解码：只处理合法的 %XX（非法序列原样保留）
local function url_once(s, plus)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  local out = s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
  if plus then
    out = out:gsub("%+", " ")
  end
  return out
end

decode.url_once = url_once

-- 多层 URL 解码（rounds 默认 1，最多 5 层，输入无变化提前结束）
function decode.url(s, rounds)
  if type(s) ~= "string" then
    return ""
  end
  rounds = tonumber(rounds) or 1
  if rounds < 1 then
    rounds = 1
  elseif rounds > 5 then
    rounds = 5
  end
  for _ = 1, rounds do
    local before = s
    s = url_once(s, false)
    if s == before then
      break
    end
  end
  return s
end

-- ---------------------------------------------------------------------------
-- Unicode 转义：\uXXXX 与 %uXXXX（含代理对）
-- ---------------------------------------------------------------------------
local function decode_unicode_escapes(s)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  -- 先处理 \uD8xx\uDCxx 代理对
  s = s:gsub("\\u([dD][89abAB]%x%x)\\u([dD][c-fC-F]%x%x)", function(hi, lo)
    local h = tonumber(hi, 16)
    local l = tonumber(lo, 16)
    return utf8_char(0x10000 + (h - 0xD800) * 0x400 + (l - 0xDC00))
  end)
  -- 再处理 %uD8xx%uDCxx 代理对
  s = s:gsub("%%u([dD][89abAB]%x%x)%%u([dD][c-fC-F]%x%x)", function(hi, lo)
    local h = tonumber(hi, 16)
    local l = tonumber(lo, 16)
    return utf8_char(0x10000 + (h - 0xD800) * 0x400 + (l - 0xDC00))
  end)
  -- 普通 \uXXXX / %uXXXX
  s = s:gsub("\\u(%x%x%x%x)", function(hex)
    return utf8_char(tonumber(hex, 16))
  end)
  s = s:gsub("%%u(%x%x%x%x)", function(hex)
    return utf8_char(tonumber(hex, 16))
  end)
  return s
end

function decode.unicode(s)
  if type(s) ~= "string" then
    return ""
  end
  return decode_unicode_escapes(s)
end

-- ---------------------------------------------------------------------------
-- HTML 实体
-- ---------------------------------------------------------------------------
local HTML_ENTITIES = {
  amp = "&", lt = "<", gt = ">", quot = '"', apos = "'", nbsp = " ",
  colon = ":", tab = "\t", newline = "\n", lpar = "(", rpar = ")",
  sol = "/", verbar = "|", comma = ",", period = ".", bsol = "\\",
  equals = "=", num = "#", dollar = "$", percnt = "%", plus = "+",
  semi = ";", excl = "!", quest = "?", commat = "@", ast = "*",
  grave = "`", lsqb = "[", rsqb = "]", lcub = "{", rcub = "}",
  sharp = "#", lowbar = "_", hyphen = "-", copy = "\194\169",
  reg = "\194\174", trade = "\226\132\162", hellip = "\226\128\166",
}

function decode.html_entities(s)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  s = s:gsub("&#[xX](%x+);?", function(hex)
    local cp = tonumber(hex, 16)
    if cp and cp > 0 and cp < 0x200000 then
      return utf8_char(cp)
    end
    return ""
  end)
  s = s:gsub("&#(%d+);?", function(dec)
    local cp = tonumber(dec)
    if cp and cp > 0 and cp < 0x200000 then
      return utf8_char(cp)
    end
    return ""
  end)
  s = s:gsub("&(%a+);", function(name)
    local v = HTML_ENTITIES[name:lower()]
    if v then
      return v
    end
    return "&" .. name .. ";"
  end)
  return s
end

-- ---------------------------------------------------------------------------
-- Base64
-- ---------------------------------------------------------------------------
local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_LOOKUP = {}
for i = 1, #B64_CHARS do
  B64_LOOKUP[B64_CHARS:sub(i, i)] = i - 1
end
B64_LOOKUP["-"] = 62
B64_LOOKUP["_"] = 63

function decode.base64(s)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  -- 去空白、URL-safe 兼容、去尾部 =
  local clean = s:gsub("[%s\r\n]", ""):gsub("-", "+"):gsub("_", "/"):gsub("=+$", "")
  if #clean == 0 or #clean % 4 == 1 then
    return nil
  end
  if clean:find("[^A-Za-z0-9+/]") then
    return nil
  end
  local out = {}
  local len = #clean
  local i = 1
  while i <= len do
    local c1 = B64_LOOKUP[clean:sub(i, i)]
    local c2 = B64_LOOKUP[clean:sub(i + 1, i + 1)]
    if not c1 or not c2 then
      return nil
    end
    local c3 = B64_LOOKUP[clean:sub(i + 2, i + 2)]
    local c4 = B64_LOOKUP[clean:sub(i + 3, i + 3)]
    out[#out + 1] = string.char(c1 * 4 + math.floor(c2 / 16))
    if c3 then
      out[#out + 1] = string.char((c2 % 16) * 16 + math.floor(c3 / 4))
      if c4 then
        out[#out + 1] = string.char((c3 % 4) * 64 + c4)
      end
    end
    i = i + 4
  end
  return table.concat(out)
end

-- 扫描场景的安全 Base64 解码（供 transform base64Decode 使用）：
-- 仅解码“短、纯文本、非 data: URI”的值；二进制展开会让正常内容误命中
-- rce/xss 规则（如 JSON 里的 data:image/png;base64,...），返回 nil 表示跳过。
function decode.base64_text(s, max_len)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  max_len = tonumber(max_len) or 2048
  if #s > max_len then
    return nil
  end
  local lower = s:lower()
  if lower:find("data:", 1, true) or lower:find(";base64", 1, true) then
    return nil
  end
  local decoded = decode.base64(s)
  if not decoded or decoded == "" then
    return nil
  end
  local bad = 0
  for i = 1, #decoded do
    local b = string.byte(decoded, i)
    if b == 0 then
      return nil
    end
    if (b < 0x20 and b ~= 9 and b ~= 10 and b ~= 13) or b == 0x7f then
      bad = bad + 1
    end
  end
  if bad / #decoded > 0.05 then
    return nil
  end
  return decoded
end

-- ---------------------------------------------------------------------------
-- 十六进制 / SQL hex / 转义序列
-- ---------------------------------------------------------------------------
-- 标准 hex 解码：41424344 -> ABCD（CRS t:hexDecode）
function decode.hex_str(s)
  if type(s) ~= "string" then
    return ""
  end
  local out = s:gsub("(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end)
  return out
end

-- SQL hex 解码：0x41424344 -> ABCD；也接受 X'4142' 形式
function decode.sql_hex(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("0[xX](%x+)", function(hex)
    if #hex % 2 == 1 then
      hex = "0" .. hex
    end
    return (hex:gsub("(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end))
  end):gsub("[xX]'([%x]+)'", function(hex)
    if #hex % 2 == 1 then
      hex = "0" .. hex
    end
    return (hex:gsub("(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end))
  end))
end

-- 转义序列：\xHH、\ooo 八进制、\n\r\t\b\f\v、\\ 、\"
-- 注意：Lua 模式不支持 | 交替，因此分多轮处理
function decode.escape_seq(s)
  if type(s) ~= "string" then
    return ""
  end
  local MAP = { n = "\n", r = "\r", t = "\t", b = "\b", f = "\f", v = "\v",
    ["\\"] = "\\", ["'"] = "'", ['"'] = '"', ["0"] = "\0" }
  -- 1) \xHH
  s = s:gsub("\\x(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
  -- 2) \ooo 八进制（1-3 位）
  s = s:gsub("\\(%d%d?%d?)", function(oct)
    local n = tonumber(oct, 8)
    if n and n < 256 then
      return string.char(n)
    end
    return "\\" .. oct
  end)
  -- 3) 其余单字符转义
  s = s:gsub("\\(.)", function(c)
    return MAP[c] or c
  end)
  return s
end

-- JS 解码：\uXXXX、\xHH、常见转义
function decode.js(s)
  if type(s) ~= "string" then
    return ""
  end
  s = decode_unicode_escapes(s)
  s = s:gsub("\\x(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
  return (s:gsub("\\([nrtbfv0\\\\/'\"]?)", function(c)
    local MAP = { n = "\n", r = "\r", t = "\t", b = "\b", f = "\f",
      v = "\v", ["0"] = "\0", ["\\"] = "\\", ["/"] = "/", ["'"] = "'", ['"'] = '"' }
    if c == "" then
      return "\\"
    end
    return MAP[c] or c
  end))
end

-- CSS 解码：\XXXXXX（1-6 位十六进制）或 \xHH
-- 说明：Lua 模式不支持 {n,m} 计数重复，逐字符解析
function decode.css(s)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  local out = {}
  local i = 1
  local len = #s
  while i <= len do
    local c = s:sub(i, i)
    if c == "\\" and i < len then
      local j = i + 1
      local hex = ""
      while j <= len and #hex < 6 and s:sub(j, j):match("^%x$") do
        hex = hex .. s:sub(j, j)
        j = j + 1
      end
      if hex ~= "" then
        local cp = tonumber(hex, 16)
        if cp and cp > 0 and cp < 0x200000 then
          out[#out + 1] = utf8_char(cp)
        end
        -- 可选地消费一个尾随空白（CSS 转义分隔符）
        if s:sub(j, j):match("^%s$") then
          j = j + 1
        end
        i = j
      else
        -- 非十六进制转义：\xHH 或直接输出下一个字符
        if s:sub(i + 1, i + 1) == "x" and s:sub(i + 2, i + 2):match("^%x$") then
          local h2 = s:sub(i + 2, i + 3)
          if h2:match("^%x%x$") then
            out[#out + 1] = string.char(tonumber(h2, 16))
            i = i + 4
          else
            out[#out + 1] = s:sub(i + 1, i + 1)
            i = i + 2
          end
        else
          out[#out + 1] = s:sub(i + 1, i + 1)
          i = i + 2
        end
      end
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return table.concat(out)
end

-- 命令行解码（对齐 ModSecurity t:cmdLine 语义）：
-- 转小写、去 ^ 转义、引号替换为空格、压缩空白，并移除 `(` 前的空白
-- （CRS 932140 期望 "in (set)" -> "in(set)"）。
-- 注意：**不能**把 `;`/`,` 当分隔符替换（ModSecurity 保留它们），
-- 否则会破坏依赖 `;` 的 CRS 规则（如 930110-12-1 路径遍历用例）。
function decode.cmd_line(s)
  if type(s) ~= "string" then
    return ""
  end
  s = s:lower()
  s = s:gsub("%^", "")
  s = s:gsub("[\"']", " ")
  s = s:gsub("%s+", " ")
  s = s:gsub("%s*%(", "(")
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- UTF-8 转 %uXXXX（CRS t:utf8ToUnicode 近似）
local function utf8_codepoint_at(s, i)
  local b = string.byte(s, i)
  if not b then
    return nil, 0
  end
  if b < 0x80 then
    return b, 1
  elseif b >= 0xC0 and b < 0xE0 then
    local b2 = string.byte(s, i + 1)
    if not b2 then
      return b, 1
    end
    return (b - 0xC0) * 0x40 + (b2 - 0x80), 2
  elseif b >= 0xE0 and b < 0xF0 then
    local b2, b3 = string.byte(s, i + 1), string.byte(s, i + 2)
    if not b2 or not b3 then
      return b, 1
    end
    return (b - 0xE0) * 0x1000 + (b2 - 0x80) * 0x40 + (b3 - 0x80), 3
  elseif b >= 0xF0 then
    local b2, b3, b4 = string.byte(s, i + 1), string.byte(s, i + 2), string.byte(s, i + 3)
    if not b2 or not b3 or not b4 then
      return b, 1
    end
    return (b - 0xF0) * 0x40000 + (b2 - 0x80) * 0x1000
      + (b3 - 0x80) * 0x40 + (b4 - 0x80), 4
  end
  return b, 1
end

function decode.utf8_to_unicode(s)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  local out = {}
  local i = 1
  local len = #s
  while i <= len do
    local cp, adv = utf8_codepoint_at(s, i)
    if not cp then
      break
    end
    if cp < 0x80 then
      out[#out + 1] = string.char(cp)
    elseif cp <= 0xFFFF then
      out[#out + 1] = string.format("%%u%04x", cp)
    else
      -- 补齐为 %uXXXX 形式（BMP 外码点用代理对表示，与 ModSecurity 近似）
      local v = cp - 0x10000
      local hi = 0xD800 + math.floor(v / 0x400)
      local lo = 0xDC00 + (v % 0x400)
      out[#out + 1] = string.format("%%u%04x%%u%04x", hi, lo)
    end
    i = i + adv
  end
  return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- 空字节 / 空白
-- ---------------------------------------------------------------------------
function decode.remove_nulls(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("%z", ""))
end

function decode.replace_nulls(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("%z", " "))
end

function decode.compress_whitespace(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("%s+", " "))
end

function decode.remove_whitespace(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("%s+", ""))
end

-- ---------------------------------------------------------------------------
-- 路径规范化
-- ---------------------------------------------------------------------------
-- 解析 /./ /../ // 等；可选把反斜杠视为分隔符（Windows）
function decode.normalize_path(s, win)
  if type(s) ~= "string" or s == "" then
    return s or ""
  end
  local path, query = s, ""
  local q = s:find("?", 1, true)
  if q then
    path = s:sub(1, q - 1)
    query = s:sub(q)
  end
  if win then
    path = path:gsub("\\", "/")
  end
  -- 先做 URL 解码，避免 %2e%2e 绕过（与 ModSecurity normalizePath 行为一致）
  path = decode.url(path, 4)
  local out = {}
  for seg in path:gmatch("[^/]+") do
    if seg == "." or seg == "" then
      -- 跳过 . 与空段
    elseif seg == ".." then
      -- 逐级回退；已在根目录则忽略（不越界）
      if #out > 0 then
        out[#out] = nil
      end
    else
      out[#out + 1] = seg
    end
  end
  local joined = "/" .. table.concat(out, "/")
  if path:sub(-1) == "/" and #joined > 1 then
    joined = joined .. "/"
  end
  return joined .. query
end

function decode.normalize_path_win(s)
  return decode.normalize_path(s, true)
end

-- ---------------------------------------------------------------------------
-- 多层变体：供 access 扫描使用
-- ---------------------------------------------------------------------------
-- 返回 {raw=原文, variants={最多 max 个不同解码变体}}
function decode.all_layers(s, max)
  if type(s) ~= "string" then
    return { raw = "", variants = {} }
  end
  max = tonumber(max) or 3
  if max < 1 then
    max = 1
  elseif max > 6 then
    max = 6
  end
  local result = { raw = s, variants = {} }
  local seen = { [s] = true }
  local function add(v)
    if type(v) == "string" and v ~= "" and not seen[v] then
      seen[v] = true
      result.variants[#result.variants + 1] = v
    end
  end
  local v1 = decode.url(s, 1)
  add(v1)
  local v2 = decode.url(s, 2)
  add(v2)
  add(decode.url_uni and decode.url_uni(s) or decode.url(s, 1))
  add(decode.html_entities(v1))
  add(decode.html_entities(decode.url(v1, 1)))
  add(decode.unicode(v1))
  add(decode.css(v1))
  add(decode.js(v1))
  -- 若变体过多按 max 截断
  while #result.variants > max do
    table.remove(result.variants)
  end
  return result
end

-- URL 解码 + %uXXXX（CRS t:urlDecodeUni）
function decode.url_uni(s)
  if type(s) ~= "string" then
    return ""
  end
  return decode.url(decode_unicode_escapes(s), 1)
end

return decode
