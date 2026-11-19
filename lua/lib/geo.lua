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
  table.sort(ranges, function(x, y) return x[1] < y[1] end)
  available = #ranges > 0
  if not available and not load_error_logged then
    util.log_error("geo 数据为空: " .. data_file())
    load_error_logged = true
  end
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
end

return geo
