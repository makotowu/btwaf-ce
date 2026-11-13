--[[
  btwaf_ce / lib/cc.lua
  CC 限流与攻击计数（contract §6.10 / §5）。
  - 共享字典 btwaf_ce_cc：固定窗口计数（cycle 秒窗口，limit 次上限）；
  - 共享字典 btwaf_ce_block：临时封锁 key "b:<site>:<ip>"，TTL=block_time；
  - 攻击计数：attack_block 达到 limit 后封锁（reason=attack）。
  说明：契约描述为“滑动窗口”，v1 采用固定窗口（共享字典 incr + TTL 原子实现，
  无竞态、开销低）；窗口边界误差可接受，后续可平滑为双窗口。
  观察模式（observe）只计数/记录，不写封锁 key。
]]

local ngx = ngx
local storage = require("lib.storage")

local cc = {}

local CC_DICT = "btwaf_ce_cc"
local BLOCK_DICT = "btwaf_ce_block"

-- 静态资源后缀：skip_static 开启时不计 CC
local STATIC_EXT = {
  css = true, js = true, png = true, jpg = true, jpeg = true, gif = true,
  svg = true, ico = true, webp = true, avif = true, bmp = true,
  woff = true, woff2 = true, ttf = true, eot = true, otf = true,
  map = true, mp4 = true, webm = true, mp3 = true, wav = true,
  flv = true, m3u8 = true, ts = true, pdf = true,
}

local function cc_dict()
  if ngx and ngx.shared then
    return ngx.shared[CC_DICT]
  end
  return nil
end

local function block_dict()
  if ngx and ngx.shared then
    return ngx.shared[BLOCK_DICT]
  end
  return nil
end

-- 站点名（用于封锁 key；站点未匹配时用 host 兜底）
local function site_name(ctx)
  if ctx.site and ctx.site.site_name then
    return ctx.site.site_name
  end
  return ctx.host or ""
end

function cc.block_key(site, ip)
  return "b:" .. tostring(site) .. ":" .. tostring(ip)
end

-- 是否静态资源
function cc.is_static(uri)
  if type(uri) ~= "string" then
    return false
  end
  local ext = uri:match("%.([%w]+)%??$")
  if not ext then
    return false
  end
  return STATIC_EXT[ext:lower()] == true
end

-- 安全读取共享字典（pcall 包裹，字典异常不影响请求）
local function dict_get(d, key)
  if not d then
    return nil
  end
  local ok, v = pcall(d.get, d, key)
  if ok then
    return v
  end
  return nil
end

-- 原子自增：dict:incr(key, 1, 0, ttl)；失败时退化为 get/set
local function dict_incr(d, key, ttl)
  if not d then
    return 0
  end
  local ok, v = pcall(d.incr, d, key, 1, 0, ttl)
  if ok and type(v) == "number" then
    return v
  end
  -- 退化路径（老版本/测试 mock 不支持 init_ttl）
  local ok2, cur = pcall(d.get, d, key)
  if not ok2 then
    return 0
  end
  local nv = (tonumber(cur) or 0) + 1
  pcall(d.set, d, key, nv, ttl)
  return nv
end
cc.dict_incr = dict_incr

-- 查询是否已被临时封锁（用于面板/测试）
function cc.is_blocked(site, ip)
  local bd = block_dict()
  return dict_get(bd, cc.block_key(site, ip)) ~= nil
end

-- 清空某 IP 的计数（CC/攻击计数/URL-CC），保证解封后立即恢复访问
local function clear_counters(site, ip)
  local d = cc_dict()
  if not d or not d.get_keys then
    return 0
  end
  local ok, keys = pcall(d.get_keys, d, 4096)
  if not ok or type(keys) ~= "table" then
    return 0
  end
  local n = 0
  local prefix_c = "c:" .. tostring(site) .. ":" .. tostring(ip)
  local prefix_a = "a:" .. tostring(site) .. ":" .. tostring(ip)
  local suffix = ":" .. tostring(ip)
  for i = 1, #keys do
    local k = keys[i]
    if type(k) == "string" then
      local hit = (k == prefix_c or k == prefix_a)
        or (k:sub(1, #prefix_c) == prefix_c) or (k:sub(1, #prefix_a) == prefix_a)
      if not hit and tostring(site) == "" then
        -- site 为空（unban_all）：按 :<ip> 后缀匹配
        if k:sub(-#suffix) == suffix then
          hit = true
        end
      end
      if hit then
        pcall(d.delete, d, k)
        n = n + 1
      end
    end
  end
  return n
end

-- 解封：删除封锁 key，并清空该 IP 的窗口计数（否则解封后下一次请求会立刻重新触发）
function cc.unblock(site, ip)
  local bd = block_dict()
  local existed = false
  if bd then
    existed = dict_get(bd, cc.block_key(site, ip)) ~= nil
    if existed then
      pcall(bd.delete, bd, cc.block_key(site, ip))
    end
  end
  clear_counters(site, ip)
  return existed
end

-- CC 检查：返回 blocked(bool), counter(number)
-- 副作用：ctx.cc = {blocked=, counter=, exceeded=, reason=}，供 access 记录
function cc.check(ctx)
  ctx = ctx or {}
  ctx.cc = ctx.cc or {}
  local site = ctx.site
  local ccfg = (site and site.cc) or {}
  local ip = ctx.ip or ctx.remote_addr or ""
  local name = site_name(ctx)
  ctx.cc.counter = 0

  if ccfg.open == false then
    return false, 0
  end

  -- 已封锁：直接命中（不计数）
  local bd = block_dict()
  if dict_get(bd, cc.block_key(name, ip)) ~= nil then
    ctx.cc.blocked = true
    ctx.cc.exceeded = true
    return true, 0
  end

  -- 静态资源跳过
  if ccfg.skip_static ~= false and cc.is_static(ctx.uri) then
    return false, 0
  end

  local d = cc_dict()
  if not d then
    return false, 0
  end

  local cycle = tonumber(ccfg.cycle) or 60
  local limit = tonumber(ccfg.limit) or 120
  if cycle <= 0 or limit <= 0 then
    return false, 0
  end

  local key = "c:" .. name .. ":" .. ip
  if ccfg.url_cc == true then
    key = key .. ":" .. tostring(ctx.uri or "")
  end
  local counter = dict_incr(d, key, cycle)
  ctx.cc.counter = counter

  if counter > limit then
    ctx.cc.exceeded = true
    ctx.cc.reason = "cc"
    local observe = site and site.observe == true
    if observe then
      -- 观察模式：只记录，不封锁
      return false, counter
    end
    storage.add_block(ctx, "cc", tonumber(ccfg.block_time) or 300)
    ctx.cc.blocked = true
    return true, counter
  end
  return false, counter
end

-- 攻击计数：超限返回 true 并写封锁（reason=attack）
function cc.add_hit(ctx)
  ctx = ctx or {}
  local site = ctx.site
  local ab = (site and site.attack_block) or {}
  ctx.attack = ctx.attack or {}
  if ab.open == false then
    return false
  end
  local ip = ctx.ip or ctx.remote_addr or ""
  local name = site_name(ctx)
  local cycle = tonumber(ab.cycle) or 120
  local limit = tonumber(ab.limit) or 20
  if cycle <= 0 or limit <= 0 then
    return false
  end
  local d = cc_dict()
  if not d then
    return false
  end
  -- 同一 HTTP 请求只计一次：优先用 ngx.ctx（同一请求的多个 access 阶段共享），
  -- 其次用稳定 dedupe_id（request_id 或 connection:connection_requests）。
  if ctx.dedupe_id and ngx and ngx.ctx then
    if ngx.ctx.btwaf_ce_attack_counted then
      return false
    end
    ngx.ctx.btwaf_ce_attack_counted = true
  end
  local rid = ctx.dedupe_id or ctx.request_id or ctx.req_id
  if rid and tostring(rid) ~= "" then
    local dedupe_key = "d:" .. name .. ":" .. ip .. ":" .. tostring(rid)
    local ok_add, added = pcall(d.add, d, dedupe_key, 1, 5)
    if ok_add and added == false then
      return false
    end
  end
  local counter = dict_incr(d, "a:" .. name .. ":" .. ip, cycle)
  ctx.attack.counter = counter
  if counter >= limit then
    ctx.attack.exceeded = true
    local observe = site and site.observe == true
    if observe then
      return false
    end
    storage.add_block(ctx, "attack", tonumber(ab.block_time) or 86400)
    ctx.attack.blocked = true
    return true
  end
  return false
end

-- 测试/诊断用：清空计数
function cc.reset()
  local d = cc_dict()
  if d and d.flush_all then
    pcall(d.flush_all, d)
  end
  local bd = block_dict()
  if bd and bd.flush_all then
    pcall(bd.flush_all, bd)
  end
end

return cc
