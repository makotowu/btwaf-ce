--[[
  btwaf_ce / lib/geo.lua
  离线地区访问控制：当前内置数据只支持中国大陆/非中国大陆。

  数据文件：<LUA_DIR>/geo/cn.ranges
  格式：start_ip end_ip（每行一个 IPv4 范围，# 开头为注释）
  该文件由 tools/build_geoip.py 从 DB-IP Lite Country 生成。
]]--

local paths = require("lib.paths")
local fs = require("lib.fs")
local util = require("lib.util")

local geo = {}

local ranges = nil
local available = nil
local load_error_logged = false
local meta_cache = nil
local custom_cache = nil
local custom_error_logged = false

local PRIVATE_RANGES = {
  { 0, 16777215 },          -- 0.0.0.0/8
  { 167772160, 184549375 }, -- 10.0.0.0/8
  { 1681915904, 1686110207 }, -- 100.64.0.0/10
  { 2130706432, 2147483647 }, -- 127.0.0.0/8
  { 2851995648, 2852061183 }, -- 169.254.0.0/16
  { 2886729728, 2887778303 }, -- 172.16.0.0/12
  { 3221225472, 3221225727 }, -- 192.0.0.0/24
  { 3232235520, 3232301055 }, -- 192.168.0.0/16
  { 3323068416, 3323199487 }, -- 198.18.0.0/15
  { 3758096384, 4026531839 }, -- 224.0.0.0/4
  { 4026531840, 4294967295 }, -- 240.0.0.0/4
}

local function is_private(n)
  for i = 1, #PRIVATE_RANGES do
    local r = PRIVATE_RANGES[i]
    if n >= r[1] and n <= r[2] then
      return true
    end
  end
  return false
end

local function data_file()
  return paths.geo_file()
end

local function custom_file()
  return paths.geo_custom_file()
end

local function to_range(item)
  if type(item) ~= "table" then
    return nil
  end
  local first = item.start or item[1]
  local last = item["end"] or item[2]
  local a = util.ip_to_int(first)
  local b = util.ip_to_int(last)
  if a and b and a <= b then
    return { a, b }
  end
  return nil
end

local function load_custom()
  if custom_cache ~= nil then
    return custom_cache
  end
  custom_cache = { include = {}, exclude = {} }
  local path = custom_file()
  if not fs.exists(path) then
    return custom_cache
  end
  local ok, data = pcall(fs.read_json, path)
  if not ok or type(data) ~= "table" then
    if not custom_error_logged then
      util.log_error("自定义中国 IP 段无法解析: " .. path)
      custom_error_logged = true
    end
    return custom_cache
  end
  local ok_inc, include = pcall(function()
    local out = {}
    if type(data.include) == "table" then
      for i = 1, #data.include do
        local item = to_range(data.include[i])
        if item then out[#out + 1] = item end
      end
    end
    return out
  end)
  local ok_exc, exclude = pcall(function()
    local out = {}
    if type(data.exclude) == "table" then
      for i = 1, #data.exclude do
        local item = to_range(data.exclude[i])
        if item then out[#out + 1] = item end
      end
    end
    return out
  end)
  if ok_inc then custom_cache.include = include end
  if ok_exc then custom_cache.exclude = exclude end
  return custom_cache
end

local function merge_ranges(list)
  if type(list) ~= "table" or #list == 0 then
    return list or {}
  end
  table.sort(list, function(x, y)
    if x[1] == y[1] then return x[2] < y[2] end
    return x[1] < y[1]
  end)
  local out = {}
  for i = 1, #list do
    local item = list[i]
    if #out == 0 or item[1] > out[#out][2] + 1 then
      out[#out + 1] = { item[1], item[2] }
    elseif item[2] > out[#out][2] then
      out[#out][2] = item[2]
    end
  end
  return out
end

local function subtract_ranges(base, cuts)
  cuts = merge_ranges(cuts)
  local out = {}
  local j = 1
  for i = 1, #base do
    local start, finish = base[i][1], base[i][2]
    local cur = start
    while j <= #cuts and cuts[j][2] < cur do
      j = j + 1
    end
    local k = j
    while k <= #cuts and cuts[k][1] <= finish do
      if cuts[k][1] > cur then
        out[#out + 1] = { cur, math.min(finish, cuts[k][1] - 1) }
      end
      if cuts[k][2] >= cur then
        cur = cuts[k][2] + 1
      end
      if cur > finish then
        break
      end
      k = k + 1
    end
    if cur <= finish then
      out[#out + 1] = { cur, finish }
    end
  end
  return out
end

local function apply_custom(base)
  local custom = load_custom()
  local merged = {}
  for i = 1, #base do
    merged[#merged + 1] = { base[i][1], base[i][2] }
  end
  for i = 1, #custom.include do
    merged[#merged + 1] = { custom.include[i][1], custom.include[i][2] }
  end
  merged = merge_ranges(merged)
  if #custom.exclude > 0 then
    merged = subtract_ranges(merged, custom.exclude)
  end
  return merged
end

local function ensure()
  if ranges ~= nil then
    return available
  end
  ranges = {}
  available = false
  local text = fs.read(data_file())
  if type(text) ~= "string" or text == "" then
    if not load_error_logged then
      util.log_error("geo 数据缺失或不可读: " .. data_file())
      load_error_logged = true
    end
    return false
  end
  for line in text:gmatch("[^\r\n]+") do
    line = util.trim(line)
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local first, last = line:match("^(%d+%.%d+%.%d+%.%d+)%s+(%d+%.%d+%.%d+%.%d+)$")
      local a = first and util.ip_to_int(first) or nil
      local b = last and util.ip_to_int(last) or nil
      if a and b and a <= b then
        ranges[#ranges + 1] = { a, b }
      end
    end
  end
  if #ranges == 0 then
    if not load_error_logged then
      util.log_error("geo 数据为空: " .. data_file())
      load_error_logged = true
    end
    return false
  end
  ranges = apply_custom(ranges)
  table.sort(ranges, function(x, y) return x[1] < y[1] end)
  -- 内置数据存在即视为可用；即使自定义排除把范围减空，也应继续按 OTHER 处理。
  available = true
  return available
end

function geo.available()
  return ensure()
end

function geo.region(ip)
  if type(ip) ~= "string" or ip == "" or ip:find(":", 1, true) then
    return "UNKNOWN"
  end
  local n = util.ip_to_int(ip)
  if not n then
    return "UNKNOWN"
  end
  if is_private(n) then
    return "PRIVATE"
  end
  if not ensure() then
    return "UNKNOWN"
  end
  local lo, hi = 1, #ranges
  while lo <= hi do
    local mid = math.floor((lo + hi) / 2)
    local r = ranges[mid]
    if n < r[1] then
      hi = mid - 1
    elseif n > r[2] then
      lo = mid + 1
    else
      return "CN"
    end
  end
  return "OTHER"
end

local function blocked_reason(region, cfg)
  if cfg.mode == "block" then
    return "已禁止中国大陆访问"
  end
  if region == "PRIVATE" or region == "UNKNOWN" then
    return "无法识别 IP 地区，按未识别策略拦截"
  end
  return "仅允许中国大陆访问"
end

function geo.check(ip, cfg)
  if type(cfg) ~= "table" or cfg.open ~= true then
    return nil
  end
  if not ensure() then
    -- 数据不可用时放行，避免升级/数据损坏把站点锁死；诊断页会提示。
    return nil
  end
  local region = geo.region(ip)
  local blocked = false
  if region == "CN" then
    blocked = cfg.mode == "block"
  elseif region == "OTHER" then
    blocked = cfg.mode ~= "block"
  else
    blocked = cfg.unknown == "block"
  end
  if not blocked then
    return {
      blocked = false,
      country = region,
      geo_source = "builtin-cn",
      reason = "",
    }
  end
  return {
    blocked = true,
    country = region,
    geo_source = "builtin-cn",
    reason = blocked_reason(region, cfg),
  }
end

function geo.meta()
  if meta_cache ~= nil then
    return meta_cache
  end
  local ok, data = pcall(fs.read_json, paths.geo_meta_file())
  if ok and type(data) == "table" then
    meta_cache = data
  else
    meta_cache = {}
  end
  return meta_cache
end

function geo.reset()
  ranges = nil
  available = nil
  load_error_logged = false
  meta_cache = nil
  custom_cache = nil
  custom_error_logged = false
end

return geo
