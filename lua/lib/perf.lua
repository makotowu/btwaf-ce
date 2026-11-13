--[[
  btwaf_ce / lib/perf.lua
  性能计数器：写共享字典 btwaf_ce_cfg（跨 worker 汇总），由 init.lua 的
  worker 0 定时器读取快照写 data/perf.json（contract §2 / §6.11）。

  计数键：
    perf:req     总请求数
    perf:hits    有规则命中的请求数
    perf:blocked 实际拦截数
    perf:us      累计耗时（微秒；毫秒精度不够，avg_ms 由 µs 换算）
    perf:updated 最近更新时间
  兜底：共享字典不可用时退化为 worker 内计数（至少让 perf.json 有数据，
  不阻塞请求）。快照对两者取较大值，避免字典晚于请求创建时丢计数。
]]

local ngx = ngx

local perf = {}

local CFG_DICT = "btwaf_ce_cfg"

-- 兜底计数（共享字典不可用时）
local fallback = { req = 0, hits = 0, blocked = 0, us = 0, updated = 0 }

local function dict()
  if ngx and ngx.shared then
    return ngx.shared[CFG_DICT]
  end
  return nil
end

local function incr(d, key, value)
  if not d then
    return nil
  end
  local ok, res = pcall(d.incr, d, key, value, 0)
  if ok then
    return res
  end
  return nil
end

-- 记录一次请求（耗时毫秒，可为小数；内部换算为微秒累加）
function perf.record(elapsed_ms, hit, blocked)
  local us = math.floor((tonumber(elapsed_ms) or 0) * 1000 + 0.5)
  local d = dict()
  if d then
    incr(d, "perf:req", 1)
    if hit then
      incr(d, "perf:hits", 1)
    end
    if blocked then
      incr(d, "perf:blocked", 1)
    end
    if us > 0 then
      incr(d, "perf:us", us)
    end
    pcall(d.set, d, "perf:updated", os.time())
  end
  -- 兜底计数始终累加（同一 worker 内可见，供 snapshot 取较大值）
  fallback.req = fallback.req + 1
  if hit then
    fallback.hits = fallback.hits + 1
  end
  if blocked then
    fallback.blocked = fallback.blocked + 1
  end
  if us > 0 then
    fallback.us = fallback.us + us
  end
  fallback.updated = os.time()
end

-- 读取快照：{requests, hits, blocked, avg_ms, updated}
function perf.snapshot()
  local d = dict()
  local snap = { requests = 0, hits = 0, blocked = 0, avg_ms = 0, updated = 0 }
  if d then
    local function get(key, default)
      local ok, v = pcall(d.get, d, key)
      if ok and type(v) == "number" then
        return v
      end
      return default
    end
    snap.requests = get("perf:req", 0)
    snap.hits = get("perf:hits", 0)
    snap.blocked = get("perf:blocked", 0)
    snap.updated = get("perf:updated", 0)
    local us = get("perf:us", 0)
    snap.us = us
    if snap.requests == 0 and fallback.req > 0 then
      -- 字典计数为 0 但本 worker 有兜底计数：使用时序较新的兜底值
      snap.requests = fallback.req
      snap.hits = fallback.hits
      snap.blocked = fallback.blocked
      snap.us = fallback.us
      snap.updated = fallback.updated
    end
  elseif fallback.req > 0 then
    snap.requests = fallback.req
    snap.hits = fallback.hits
    snap.blocked = fallback.blocked
    snap.us = fallback.us
    snap.updated = fallback.updated
  end
  if snap.requests > 0 then
    snap.avg_ms = math.floor(((snap.us or 0) / snap.requests) / 1000 * 1000) / 1000
  end
  if not snap.updated or snap.updated == 0 then
    snap.updated = os.time()
  end
  return snap
end

-- 是否可用（测试/诊断）
function perf.available()
  return dict() ~= nil
end

-- 测试用：重置兜底计数
function perf.reset()
  fallback = { req = 0, hits = 0, blocked = 0, us = 0, updated = 0 }
end

return perf
