--[[
  btwaf_ce / lib/xss.lua
  v1 轻量 XSS 语义分析（contract §6.6）。
  独立实现：HTML5 粗解析（标签/属性/URL 协议/事件处理器）+ 特征打分，
  不复制 DOMPurify 等第三方代码。
  返回 {detected=bool, score=number, features={...}, name="XSS"}。
]]

local decode = require("lib.decode")

local xss = {}

-- 危险标签（可直接执行脚本或加载外部资源）
-- 注意：img/video/audio/source 等仅“存在标签”不算危险，必须配合事件处理器或
-- 危险 URL 协议才判定，避免把正常 HTML 片段（如 <IMG CLASS="...">）当 XSS。
local DANGEROUS_TAGS = {
  script = true, iframe = true, object = true, embed = true, applet = true,
  svg = true, math = true, link = true, style = true, meta = true,
  base = true, form = true, frameset = true, frame = true, body = true,
  template = true, marquee = true, details = true,
}

-- 危险 URL 协议
local DANGEROUS_SCHEMES = {
  "javascript:", "vbscript:", "data:text/html", "data:image/svg",
  "livescript:", "mocha:",
}

-- DOM 危险汇聚点
local DOM_SINKS = {
  "document.cookie", "document.write", "document.writeln", "innerhtml",
  "outerhtml", "eval(", "settimeout(", "setinterval(", "function(",
  "window.location", "location.href", "location.assign", "srcdoc",
}

local function add_feature(features, name, weight)
  features[#features + 1] = name
  return weight
end

-- 粗解析标签：返回 tag 名、属性串、标签数量
local function scan_tags(s)
  local tags = {}
  local count = 0
  local i = 1
  local len = #s
  while i <= len do
    local lt = s:find("<", i, true)
    if not lt then
      break
    end
    local gt = s:find(">", lt + 1, true)
    if not gt then
      break
    end
    local inner = s:sub(lt + 1, gt - 1)
    local tag = inner:match("^%s*/?%s*([%w:_%-]+)")
    if tag then
      tag = tag:lower()
      local attrs = inner:sub(#tag + 1)
      tags[#tags + 1] = { name = tag, attrs = attrs, raw = s:sub(lt, gt) }
      count = count + 1
    end
    i = gt + 1
  end
  return tags, count
end

-- 分析属性串中的事件处理器与危险协议
local function scan_attrs(attrs)
  local found = {}
  local lower = attrs:lower()
  -- 事件处理器：on\w+\s*=
  for name in lower:gmatch("([%w:_%-]*)%s*=") do
    if name ~= "" then
      found[#found + 1] = name
    end
  end
  return found, lower
end

-- 主分析函数：对原始串与解码变体分别分析，取最高分
function xss.analyse(str)
  local result = { detected = false, score = 0, features = {}, name = "XSS" }
  if type(str) ~= "string" or str == "" then
    return result
  end
  if #str > 16384 then
    str = str:sub(1, 16384)
  end

  local layers = decode.all_layers(str, 3)
  local candidates = { layers.raw }
  for i = 1, #layers.variants do
    candidates[#candidates + 1] = layers.variants[i]
  end

  local best_score = 0
  local best_features = {}
  local seen_candidate = {}

  for ci = 1, #candidates do
    local s = candidates[ci]
    if type(s) == "string" and s ~= "" and not seen_candidate[s] then
      seen_candidate[s] = true
      local score = 0
      local features = {}
      local lower = s:lower()

      local tags, tag_count = scan_tags(s)
      local has_tag = tag_count > 0

      -- 1) <script> 标签
      local has_script = false
      for i = 1, #tags do
        if tags[i].name == "script" then
          has_script = true
          break
        end
      end
      if has_script then
        score = score + add_feature(features, "script_tag", 6)
      end

      -- 2) 事件处理器 onXxx=
      local event_attr = false
      for i = 1, #tags do
        local attrs = tags[i].attrs:lower()
        if attrs:match("%f[%w]on[a-z]+%s*=") then
          event_attr = true
          break
        end
      end
      -- 任意位置出现 on*= 且带标签也计入（粗解析可能漏掉无闭合标签）
      if not event_attr and lower:match("%f[%w]on[a-z]+%s*=") and has_tag then
        event_attr = true
      end
      if event_attr then
        score = score + add_feature(features, "event_handler", 5)
      end

      -- 3) 危险协议
      local scheme_hit = false
      for i = 1, #DANGEROUS_SCHEMES do
        if lower:find(DANGEROUS_SCHEMES[i], 1, true) then
          scheme_hit = true
          break
        end
      end
      if scheme_hit then
        score = score + add_feature(features, "dangerous_scheme", 5)
      end

      -- 4) 危险标签（iframe/object/svg 等）
      local dangerous_tag = false
      for i = 1, #tags do
        if DANGEROUS_TAGS[tags[i].name] then
          dangerous_tag = true
          break
        end
      end
      if dangerous_tag then
        score = score + add_feature(features, "dangerous_tag", 3)
      end

      -- 5) 属性逃逸：引号未闭合/外部引号注入
      if has_tag then
        -- 标签内出现引号 + 事件/脚本关键字
        for i = 1, #tags do
          local raw = tags[i].raw
          if raw:find("['\"]") and (raw:lower():find("on") or raw:lower():find("script")) then
            score = score + add_feature(features, "attr_breakout", 3)
            break
          end
        end
      end

      -- 6) 实体/编码混淆（&lt;script 或 %3Cscript）
      if lower:find("&lt;script", 1, true) or lower:find("%3cscript", 1, true)
        or lower:find("&#x3c;", 1, true) or lower:find("&#60;", 1, true) then
        score = score + add_feature(features, "entity_obfuscation", 3)
      end
      -- 数字实体普遍出现（可能是正常内容），仅与标签关键字组合加重
      if lower:match("&#[xX]?%x+;") and (lower:find("script", 1, true) or lower:find("onerror", 1, true)) then
        score = score + add_feature(features, "numeric_entity", 2)
      end

      -- 7) CSS 表达式 / 行为
      if lower:match("expression%s*%(") or lower:find("behavior:", 1, true)
        or lower:find("-moz-binding", 1, true) then
        score = score + add_feature(features, "css_expression", 3)
      end

      -- 8) DOM 汇聚点
      local sink_hit = false
      for i = 1, #DOM_SINKS do
        if lower:find(DOM_SINKS[i], 1, true) then
          sink_hit = true
          break
        end
      end
      if sink_hit then
        score = score + add_feature(features, "dom_sink", 2)
      end

      -- 9) 空字节/控制字符混淆
      if s:find("%z") then
        score = score + add_feature(features, "null_byte", 2)
      end

      -- 10) 常见 XSS 片段（alert/prompt/confirm/document.cookie 组合）
      if lower:match("%f[%w]alert%s*%(") or lower:match("%f[%w]prompt%s*%(")
        or lower:match("%f[%w]confirm%s*%(") then
        score = score + add_feature(features, "alert_call", 2)
      end

      if score > best_score then
        best_score = score
        best_features = features
      end
    end
  end

  result.score = best_score
  result.features = best_features
  -- 判定：脚本标签/事件处理器/危险协议任一出现即判定；否则组合分 >= 5
  local detected = false
  for i = 1, #best_features do
    local f = best_features[i]
    if f == "script_tag" or f == "event_handler" or f == "dangerous_scheme" then
      detected = true
      break
    end
  end
  if not detected and best_score >= 5 then
    detected = true
  end
  result.detected = detected
  return result
end

return xss
