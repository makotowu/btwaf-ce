--[[
  btwaf_ce / lib/matcher.lua
  规则匹配引擎（contract §6.9 / §9）。
  支持：
    - chain（数组全部匹配才算命中，AND）
    - 变量定义（§9.1，由 pipeline.get_var 解析）
    - 变换（§9.2 全部）
    - 操作符（§6.13 全部）
    - negate / count
    - on_match 的 setvar（tx.anomaly_score 等）
    - @pm 走共享 AC 自动机（rules/ac.lua 的 lists[name]）
  容错：单条规则异常只跳过该规则并计数；不向调用方抛异常。
]]

local ngx = ngx
local util = require("lib.util")
local decode = require("lib.decode")
local pipeline = require("lib.pipeline")
local ac = require("lib.ac")
local sqli = require("lib.sqli")
local xss = require("lib.xss")
local tx = require("lib.tx")

local matcher = {}

-- ---------------------------------------------------------------------------
-- 内部状态
-- ---------------------------------------------------------------------------
local state = {
  rulesets = {},
  by_module = {},   -- module -> {{r=rule, src=...}, ...}
  ac_lists = {},    -- name -> automaton
  stats = {
    rules = 0,
    evaluations = 0,
    matches = 0,
    errors = 0,
    last_error = nil,
  },
}

-- ---------------------------------------------------------------------------
-- 变换（§9.2 全量）
-- ---------------------------------------------------------------------------
local function trim_left(s) return (s:gsub("^%s+", "")) end
local function trim_right(s) return (s:gsub("%s+$", "")) end

local TRANSFORMS = {
  none = function(s) return s end,
  lowercase = function(s) return s:lower() end,
  uppercase = function(s) return s:upper() end,
  urlDecode = function(s) return decode.url(s, 1) end,
  urlDecodeUni = function(s) return decode.url_uni(s) end,
  htmlEntityDecode = function(s) return decode.html_entities(s) end,
  jsDecode = function(s) return decode.js(s) end,
  cssDecode = function(s) return decode.css(s) end,
  removeNulls = function(s) return decode.remove_nulls(s) end,
  replaceNulls = function(s) return decode.replace_nulls(s) end,
  compressWhitespace = function(s) return decode.compress_whitespace(s) end,
  removeWhitespace = function(s) return decode.remove_whitespace(s) end,
  trim = function(s) return util.trim(s) end,
  trimLeft = trim_left,
  trimRight = trim_right,
  -- 安全 Base64 解码：data: URI / 超长 / 二进制结果保持原值（避免误报）
  base64Decode = function(s) return decode.base64_text(s) or s end,
  hexDecode = function(s) return decode.hex_str(s) end,
  normalizePath = function(s) return decode.normalize_path(s) end,
  normalizePathWin = function(s) return decode.normalize_path_win(s) end,
  cmdLine = function(s) return decode.cmd_line(s) end,
  length = function(s) return tostring(#s) end,
  utf8ToUnicode = function(s) return decode.utf8_to_unicode(s) end,
  escapeSeqDecode = function(s) return decode.escape_seq(s) end,
  sqlHexDecode = function(s) return decode.sql_hex(s) end,
}

matcher.TRANSFORMS = TRANSFORMS

-- 应用变换链；任一变换失败返回 nil（该条件不成立，并计入规则错误）
local function apply_transforms(s, transforms)
  if type(transforms) ~= "table" then
    return s
  end
  for i = 1, #transforms do
    local name = transforms[i]
    local fn = TRANSFORMS[name]
    if not fn then
      return nil, "不支持的变换: " .. tostring(name)
    end
    local ok, res = pcall(fn, s)
    if not ok or type(res) ~= "string" then
      return nil, "变换执行失败: " .. tostring(name) .. " (" .. tostring(res) .. ")"
    end
    s = res
  end
  return s
end

-- ---------------------------------------------------------------------------
-- 操作符（§6.13）
-- ---------------------------------------------------------------------------
local function regex_find(subject, pattern)
  local re = ngx and ngx.re
  if not re or not re.find then
    return nil, "ngx.re 不可用"
  end
  local ok, from, extra = pcall(re.find, subject, pattern, "jo")
  if not ok then
    return nil, "正则执行失败: " .. tostring(from)
  end
  if from == nil then
    if extra then
      return nil, "正则执行失败: " .. tostring(extra)
    end
    return false
  end
  return true
end

-- @pm 内联列表匹配（无自动机时）
local function pm_inline(value, words)
  if type(words) == "string" then
    return value:find(words, 1, true) ~= nil
  end
  for i = 1, #words do
    local w = words[i]
    if type(w) == "string" and w ~= "" then
      if value:find(w, 1, true) then
        return true
      end
    end
  end
  return false
end

-- 字节范围解析："1-255,9-10" -> 集合
local function parse_byte_ranges(spec)
  local allowed = {}
  if type(spec) ~= "string" or spec == "" then
    return nil
  end
  for part in spec:gmatch("[^,]+") do
    part = util.trim(part)
    local lo, hi = part:match("^(%d+)%-(%d+)$")
    if lo then
      lo, hi = tonumber(lo), tonumber(hi)
      if lo and hi and lo >= 0 and hi <= 255 and lo <= hi then
        for b = lo, hi do
          allowed[b] = true
        end
      end
    else
      local n = tonumber(part)
      if n and n >= 0 and n <= 255 then
        allowed[n] = true
      end
    end
  end
  return allowed
end

-- UTF-8 校验（返回合法布尔）
local function valid_utf8(s)
  local i = 1
  local len = #s
  while i <= len do
    local b = string.byte(s, i)
    local need = 0
    if b < 0x80 then
      need = 0
    elseif b >= 0xC2 and b <= 0xDF then
      need = 1
    elseif b >= 0xE0 and b <= 0xEF then
      need = 2
    elseif b >= 0xF0 and b <= 0xF4 then
      need = 3
    else
      return false
    end
    if i + need > len then
      return false
    end
    for k = 1, need do
      local cb = string.byte(s, i + k)
      if not cb or cb < 0x80 or cb > 0xBF then
        return false
      end
    end
    i = i + need + 1
  end
  return true
end

-- 校验 URL 编码：% 后必须是两位十六进制
local function valid_url_encoding(s)
  local i = 1
  local len = #s
  while i <= len do
    local c = s:sub(i, i)
    if c == "%" then
      local hex = s:sub(i + 1, i + 2)
      if #hex < 2 or not hex:match("^%x%x$") then
        return false
      end
      i = i + 3
    else
      i = i + 1
    end
  end
  return true
end

-- 执行操作符；返回 matched(bool), err
local function eval_operator(op, value, expected, ac_name)
  if op == "@rx" then
    if type(expected) ~= "string" then
      return false
    end
    return regex_find(value, expected)
  elseif op == "@pm" then
    if ac_name and state.ac_lists[ac_name] then
      local word = ac.match(state.ac_lists[ac_name], value)
      return word ~= nil
    end
    return pm_inline(value, expected)
  elseif op == "@contains" then
    return value:find(tostring(expected), 1, true) ~= nil
  elseif op == "@beginsWith" then
    local e = tostring(expected)
    return e ~= "" and value:sub(1, #e) == e
  elseif op == "@endsWith" then
    local e = tostring(expected)
    return e ~= "" and value:sub(-#e) == e
  elseif op == "@streq" or op == "@eq" then
    return value == tostring(expected)
  elseif op == "@ge" or op == "@gt" or op == "@le" or op == "@lt" then
    local a = tonumber(value)
    local b = tonumber(expected)
    if not a or not b then
      return false
    end
    if op == "@ge" then
      return a >= b
    elseif op == "@gt" then
      return a > b
    elseif op == "@le" then
      return a <= b
    end
    return a < b
  elseif op == "@within" then
    if type(expected) ~= "table" then
      return value == tostring(expected)
    end
    for i = 1, #expected do
      if value == tostring(expected[i]) then
        return true
      end
    end
    return false
  elseif op == "@unconditionalMatch" then
    return true
  elseif op == "@ipMatch" then
    local list = expected
    if type(list) == "string" then
      list = util.split(list, ",")
    end
    return util.ip_in_list(value, list)
  elseif op == "@validateByteRange" then
    -- ModSecurity 语义：发现“范围外”的字节才算命中（不是“全部合法”才命中）
    local allowed = parse_byte_ranges(expected)
    if not allowed then
      return false
    end
    for i = 1, #value do
      if not allowed[string.byte(value, i)] then
        return true
      end
    end
    return false
  elseif op == "@validateUrlEncoding" then
    -- ModSecurity 语义：编码非法时命中
    return not valid_url_encoding(value)
  elseif op == "@validateUtf8Encoding" then
    -- ModSecurity 语义：UTF-8 非法时命中
    return not valid_utf8(value)
  elseif op == "@detectSQLi" then
    local res = sqli.analyse(value)
    return res.detected == true
  elseif op == "@detectXSS" then
    local res = xss.analyse(value)
    return res.detected == true
  end
  return nil, "不支持的操作符: " .. tostring(op)
end

-- ---------------------------------------------------------------------------
-- 条件求值
-- ---------------------------------------------------------------------------
local function should_exclude_cond(value)
  return type(value) == "string" and value:sub(1, 1) == "!"
end

local function eval_condition(ctx, cond)
  if type(cond) ~= "table" then
    return false
  end
  local vars = cond.vars
  if type(vars) ~= "table" then
    return false
  end
  -- 兼容单个变量定义（非数组）
  if vars.type then
    vars = { vars }
  end

  -- 收集变量值（多个变量定义取并集）
  local values = {}
  local excludes = nil
  for i = 1, #vars do
    local vd = vars[i]
    if type(vd) == "string" then
      if should_exclude_cond(vd) then
        excludes = excludes or {}
        -- 形如 "!ARGS:foo"：按名字排除
        local name = vd:match("^![^:]+:(.+)$")
        if name then
          excludes[name] = true
        end
      else
        local vals = pipeline.get_var(ctx, vd)
        for k = 1, #vals do
          if not (excludes and excludes[k]) then
            values[#values + 1] = vals[k]
          end
        end
      end
    elseif type(vd) == "table" then
      local vals = pipeline.get_var(ctx, vd)
      for k = 1, #vals do
        values[#values + 1] = vals[k]
      end
    end
  end
  -- 按变量名排除（排除型变量会在变量定义阶段过滤；这里是兜底）
  if excludes and #values > 0 then
    local filtered = {}
    for i = 1, #values do
      if not excludes[values[i]] then
        filtered[#filtered + 1] = values[i]
      end
    end
    values = filtered
  end

  local negate = cond.negate == true
  if #values == 0 then
    -- 变量不存在：条件不成立（negate 也不成立，与 ModSecurity 行为一致）
    return false
  end

  local transforms = cond.transforms or {}
  local op = cond.op or "@rx"
  local expected = cond.value
  local ac_name = cond.ac_list

  local any = false
  for i = 1, #values do
    local transformed, terr = apply_transforms(values[i], transforms)
    if transformed == nil then
      return nil, terr
    end
    local matched, oerr = eval_operator(op, transformed, expected, ac_name)
    if matched == nil then
      return nil, oerr
    end
    if matched then
      any = true
      -- 记录首个命中值，供 access 写日志 snippet（不进入 hits 结构）
      if type(ctx) == "table" then
        ctx.last_match_value = transformed
      end
      break
    end
  end
  if negate then
    return not any
  end
  return any
end

-- ---------------------------------------------------------------------------
-- on_match 动作
-- ---------------------------------------------------------------------------
local ACTION_HANDLERS = {
  setvar = function(ctx, act)
    local scope = act.scope or "tx"
    if scope ~= "tx" then
      return
    end
    local key = act.key
    if type(key) ~= "string" or key == "" then
      return
    end
    if act.op == "inc" then
      tx.inc(ctx, key, tonumber(act.value) or 1)
    else
      tx.set(ctx, key, act.value)
    end
  end,
}

local function apply_on_match(ctx, actions)
  if type(actions) ~= "table" then
    return
  end
  for i = 1, #actions do
    local act = actions[i]
    if type(act) == "table" then
      local handler = ACTION_HANDLERS[act.action]
      if handler then
        local ok, err = pcall(handler, ctx, act)
        if not ok then
          state.stats.errors = state.stats.errors + 1
          state.stats.last_error = "on_match 执行失败: " .. tostring(err)
        end
      end
    end
  end
end

local function on_match_sets_anomaly(on_match)
  if type(on_match) ~= "table" then
    return false
  end
  for i = 1, #on_match do
    local act = on_match[i]
    if type(act) == "table" and act.action == "setvar" then
      local key = tostring(act.key or "")
      if key == "anomaly_score" or key == "TX:anomaly_score" then
        return true
      end
    end
  end
  return false
end

-- 严重级别 -> 默认分值（§6.13）
local SEVERITY_SCORE = {
  CRITICAL = 5,
  ERROR = 4,
  WARNING = 3,
  NOTICE = 2,
}

local function rule_score(rule)
  if type(rule.score) == "number" then
    return rule.score
  end
  if type(rule.severity) == "string" then
    return SEVERITY_SCORE[rule.severity:upper()] or 3
  end
  return 3
end

-- 单条规则求值；返回 matched(bool), err
local function eval_rule(ctx, rule)
  local chain = rule.chain
  if type(chain) ~= "table" or #chain == 0 then
    return false, "规则缺少 chain"
  end
  for i = 1, #chain do
    local ok, matched, err = pcall(eval_condition, ctx, chain[i])
    if not ok then
      return nil, tostring(matched)
    end
    if matched == nil then
      return nil, err
    end
    if not matched then
      return false
    end
  end
  return true
end

-- ---------------------------------------------------------------------------
-- 加载
-- ---------------------------------------------------------------------------
function matcher.load(rulesets, ac_lists)
  state.rulesets = {}
  state.by_module = {}
  state.ac_lists = ac_lists or {}
  state.stats.rules = 0
  state.stats.errors = 0
  state.stats.last_error = nil

  if type(rulesets) == "table" and rulesets.meta then
    rulesets = { rulesets }
  end
  if type(rulesets) ~= "table" then
    return 0
  end

  for i = 1, #rulesets do
    local rs = rulesets[i]
    if type(rs) == "table" and type(rs.rules) == "table" then
      local src = (type(rs.meta) == "table" and rs.meta.source) or "ce"
      local default_module = type(rs.meta) == "table" and rs.meta.module or nil
      for j = 1, #rs.rules do
        local r = rs.rules[j]
        if type(r) == "table" then
          local module = r.module or default_module or "unknown"
          local wrapper = { r = r, src = src, module = module }
          local list = state.by_module[module]
          if not list then
            list = {}
            state.by_module[module] = list
          end
          list[#list + 1] = wrapper
          state.stats.rules = state.stats.rules + 1
        end
      end
    end
  end
  return state.stats.rules
end

-- 测试用：注入 AC 自动机
function matcher.set_ac_lists(lists)
  state.ac_lists = lists or {}
end

function matcher.ac_lists()
  return state.ac_lists
end

-- ---------------------------------------------------------------------------
-- 评估
-- ---------------------------------------------------------------------------
local function build_exclude_sets(rule_exclude)
  if type(rule_exclude) ~= "table" then
    return nil
  end
  local out = {}
  local any = false
  for _, src in ipairs({ "crs", "ce" }) do
    local ids = rule_exclude[src]
    if type(ids) == "table" and #ids > 0 then
      local set = {}
      for i = 1, #ids do
        if type(ids[i]) == "string" then
          set[ids[i]] = true
        end
      end
      out[src] = set
      any = true
    end
  end
  if not any then
    return nil
  end
  return out
end

-- evaluate(ctx, module_cfg[, rule_exclude]) -> hits, total_score
function matcher.evaluate(ctx, module_cfg, rule_exclude)
  local hits = {}
  local total = 0
  if type(ctx) ~= "table" then
    return hits, total
  end
  if type(module_cfg) ~= "table" then
    module_cfg = (ctx.site and ctx.site.modules) or {}
  end
  if type(rule_exclude) ~= "table" then
    rule_exclude = ctx.site and ctx.site.rule_exclude or nil
  end
  local exclude = build_exclude_sets(rule_exclude)
  state.stats.evaluations = state.stats.evaluations + 1

  for module, cfgmod in pairs(module_cfg) do
    local list = state.by_module[module]
    if list and type(cfgmod) == "table" and cfgmod.open ~= false then
      local tier = tonumber(cfgmod.tier) or 1
      for i = 1, #list do
        local wrapper = list[i]
        local rule = wrapper.r
        local rule_tier = tonumber(rule.tier) or 1
        if rule_tier <= tier then
          local excluded = false
          if exclude then
            local set = exclude[wrapper.src]
            if set and rule.id and set[rule.id] then
              excluded = true
            end
            -- 兼容规则 id 缺失时按规则在集合中的 id 处理
          end
          if not excluded then
            local ok, matched, err = pcall(eval_rule, ctx, rule)
            if not ok then
              state.stats.errors = state.stats.errors + 1
              state.stats.last_error = "规则异常 '" .. tostring(rule.id) .. "': " .. tostring(matched)
              util.log_error(state.stats.last_error)
            elseif matched == nil then
              state.stats.errors = state.stats.errors + 1
              state.stats.last_error = "规则 '" .. tostring(rule.id) .. "' 执行失败: " .. tostring(err)
              util.log_error(state.stats.last_error)
            elseif matched then
              local score = rule_score(rule)
              local hit = {
                module = module,
                rule = tostring(rule.id or ""),
                name = tostring(rule.name or rule.msg or ""),
                score = score,
                tier = rule_tier,
                src = wrapper.src,
              }
              hits[#hits + 1] = hit
              total = total + score
              state.stats.matches = state.stats.matches + 1
              apply_on_match(ctx, rule.on_match)
              -- 未显式维护 anomaly_score 的规则自动累计（§9.4）
              if not on_match_sets_anomaly(rule.on_match) then
                tx.inc(ctx, "anomaly_score", score)
              end
            end
          end
        end
      end
    end
  end

  -- 若规则通过 on_match 显式设置了更高的 anomaly_score，以其为准
  local tx_anomaly = tonumber(tx.get(ctx, "anomaly_score"))
  if tx_anomaly and tx_anomaly > total then
    total = tx_anomaly
  end
  return hits, total
end

function matcher.stats()
  return state.stats
end

function matcher.rule_count()
  return state.stats.rules
end

function matcher.reset()
  state.rulesets = {}
  state.by_module = {}
  state.ac_lists = {}
  state.stats = { rules = 0, evaluations = 0, matches = 0, errors = 0, last_error = nil }
end

return matcher
