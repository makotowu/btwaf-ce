--[[
  btwaf_ce / lib/rules.lua
  规则集加载与自定义规则评估（contract §6.9 / §3 rule/custom.json）。
  说明：
  - 规则文件由 rules 组生成。由于编码规范禁用 lfs（无法遍历目录），
    加载顺序为：显式指定（测试/宿主）→ rules/manifest.lua → 内置 CE 模块名。
    rules 组需生成 rules/manifest.lua，返回模块名数组（或 {modules={...}}）。
  - 任何规则文件缺失/加载失败都只记录并跳过，不影响引擎启动。
  - 自定义规则不走 matcher 的 chain/transforms，直接按 field/operator 求值。
]]

local util = require("lib.util")
local decode = require("lib.decode")

local rules = {}

-- 内置自研规则模块名（rules 组按此命名生成；缺失时静默跳过）
local DEFAULT_CE_MODULES = {
  "rules.base",
  "rules.ce_sqli",
  "rules.ce_xss",
  "rules.ce_rce",
  "rules.ce_lfi",
  "rules.ce_php",
  "rules.ce_java",
  "rules.ce_scan",
  "rules.ce_crawler",
  "rules.ce_sensitive",
  "rules.ce_upload",
  "rules.ce_protocol",
  "rules.ce_nday",
}

rules.DEFAULT_CE_MODULES = DEFAULT_CE_MODULES

-- 取 manifest 中的模块名列表；无 manifest 返回 nil
local function manifest_modules()
  local override = rawget(_G, "BTWAF_CE_RULE_MODULES")
  if type(override) == "table" then
    return override, "override"
  end
  local ok, m = pcall(require, "rules.manifest")
  if ok and type(m) == "table" then
    if type(m.modules) == "table" then
      return m.modules, "manifest"
    end
    if #m > 0 then
      return m, "manifest"
    end
  end
  return nil, nil
end

-- 加载全部规则集。返回：
-- { rulesets = {规则集表...}, ac_lists = {}|nil, modules = {成功模块名},
--   failed = {{name=,err=}}, total_rules = n, source = "manifest"|"default"|"override" }
function rules.load(opts)
  opts = opts or {}
  local names, source = opts.modules, nil
  if type(names) ~= "table" then
    names, source = manifest_modules()
  else
    source = "explicit"
  end
  if type(names) ~= "table" then
    names = DEFAULT_CE_MODULES
    source = "default"
  end

  local rulesets = {}
  local loaded = {}
  local failed = {}
  local total = 0

  for i = 1, #names do
    local name = names[i]
    if type(name) == "string" and name ~= "" then
      local ok, mod = pcall(require, name)
      if ok and type(mod) == "table" and type(mod.rules) == "table" then
        rulesets[#rulesets + 1] = mod
        loaded[#loaded + 1] = name
        total = total + #mod.rules
      else
        failed[#failed + 1] = {
          name = name,
          err = ok and "缺少 rules 数组" or tostring(mod),
        }
      end
    end
  end

  -- AC 自动机（rules/ac.lua，格式 {lists={name=automaton}}；兼容直接返回 lists）
  local ac_lists = nil
  local ok_ac, ac_mod = pcall(require, "rules.ac")
  if ok_ac and type(ac_mod) == "table" then
    if type(ac_mod.lists) == "table" then
      ac_lists = ac_mod.lists
    else
      ac_lists = ac_mod
    end
  end

  return {
    rulesets = rulesets,
    ac_lists = ac_lists,
    modules = loaded,
    failed = failed,
    total_rules = total,
    source = source or "unknown",
  }
end

-- ---------------------------------------------------------------------------
-- 自定义规则（rule/custom.json）
-- ---------------------------------------------------------------------------
local function header_value(ctx, name)
  if type(name) ~= "string" or name == "" then
    return nil
  end
  return ctx.headers and ctx.headers[name:lower()] or nil
end

-- 提取自定义规则比较的目标值；返回字符串或 nil
local function field_value(ctx, rule)
  local field = rule.field
  if field == "uri" then
    return ctx.uri or ""
  elseif field == "query" then
    return ctx.query or ""
  elseif field == "body" then
    return ctx.body or ""
  elseif field == "header" then
    return header_value(ctx, rule.header)
  elseif field == "ua" then
    return ctx.headers and ctx.headers["user-agent"] or ""
  elseif field == "ip" then
    return ctx.ip or ""
  elseif field == "method" then
    return ctx.method or ""
  elseif field == "cookie" then
    local name = rule.header
    if type(name) == "string" and name ~= "" then
      return ctx.cookies and ctx.cookies[name:lower()] or nil
    end
    -- 未指定 cookie 名：拼接所有 cookie 值
    local parts = {}
    if ctx.cookies then
      for _, v in pairs(ctx.cookies) do
        parts[#parts + 1] = tostring(v)
      end
    end
    return table.concat(parts, ";")
  end
  return nil
end

-- 单个自定义规则求值：返回 matched(bool), err
function rules.eval_custom(ctx, rule)
  if type(rule) ~= "table" then
    return false, "规则不是 table"
  end
  if rule.open == false then
    return false
  end
  local field = rule.field
  if type(field) ~= "string" then
    return false, "缺少 field"
  end
  local raw = field_value(ctx, rule)
  if raw == nil then
    return false
  end
  local value = tostring(raw)
  local op = rule.operator or "contains"
  local pattern = tostring(rule.value or "")
  local matched = false
  local err = nil

  if op == "regexp" then
    -- 正则：优先大小写不敏感（自定义规则面向运维，(?i) 由 PCRE/mock 处理）
    local ngx = ngx
    if ngx and ngx.re and ngx.re.find then
      local ok, from, to = pcall(ngx.re.find, value, pattern, "jo")
      if ok then
        matched = from ~= nil
      else
        err = tostring(from)
      end
    else
      err = "ngx.re 不可用"
    end
  elseif op == "contains" then
    matched = value:find(pattern, 1, true) ~= nil
  elseif op == "eq" then
    matched = value == pattern
  elseif op == "prefix" then
    matched = pattern ~= "" and value:sub(1, #pattern) == pattern
  elseif op == "suffix" then
    matched = pattern ~= "" and value:sub(-#pattern) == pattern
  elseif op == "in" or op == "not_in" then
    local items = util.split(pattern, ",")
    local found = false
    for i = 1, #items do
      if util.trim(items[i]) == value then
        found = true
        break
      end
    end
    matched = (op == "in") and found or (not found)
  elseif op == "gt" or op == "lt" then
    local a = tonumber(value)
    local b = tonumber(pattern)
    if a and b then
      matched = (op == "gt") and (a > b) or (a < b)
    end
  else
    err = "未知 operator: " .. tostring(op)
  end

  return matched, err
end

-- 排序自定义规则：priority 数字小的先执行；无 priority 视为 10
function rules.sort_custom(list)
  local out = {}
  if type(list) ~= "table" then
    return out
  end
  for i = 1, #list do
    out[#out + 1] = list[i]
  end
  table.sort(out, function(a, b)
    local pa = tonumber(a.priority) or 10
    local pb = tonumber(b.priority) or 10
    if pa == pb then
      return tostring(a.id or "") < tostring(b.id or "")
    end
    return pa < pb
  end)
  return out
end

-- 判断自定义规则是否适用于某站点（scope/sites）
function rules.applies_to_site(rule, site_name)
  if type(rule) ~= "table" then
    return false
  end
  if rule.open == false then
    return false
  end
  if rule.scope == "site" then
    if type(rule.sites) ~= "table" or #rule.sites == 0 then
      return false
    end
    for i = 1, #rule.sites do
      if tostring(rule.sites[i]) == tostring(site_name) then
        return true
      end
    end
    return false
  end
  -- 默认 global
  return true
end

-- 解码字段值（自定义规则里 query/body 可能被编码）
function rules.decoded_field(ctx, rule)
  local v = field_value(ctx, rule)
  if v == nil then
    return nil
  end
  return decode.url(tostring(v), 2)
end

return rules
