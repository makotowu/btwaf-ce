--[[
  btwaf_ce / lib/tx.lua
  事务变量（contract §6.8）。供规则 on_match 的 setvar/inc 与访问管线共享。
  ctx.tx 为普通 Lua 表，生命周期 = 单次请求。
]]

local tx = {}

function tx.new()
  return {}
end

function tx.ensure(ctx)
  if type(ctx) ~= "table" then
    return nil
  end
  if type(ctx.tx) ~= "table" then
    ctx.tx = {}
  end
  return ctx.tx
end

function tx.set(ctx, key, value)
  local t = tx.ensure(ctx)
  if not t or type(key) ~= "string" then
    return
  end
  t[key] = value
  return value
end

function tx.inc(ctx, key, n)
  local t = tx.ensure(ctx)
  if not t or type(key) ~= "string" then
    return nil
  end
  local delta = tonumber(n) or 1
  local cur = tonumber(t[key]) or 0
  t[key] = cur + delta
  return t[key]
end

function tx.get(ctx, key, default)
  if type(ctx) ~= "table" or type(ctx.tx) ~= "table" then
    return default
  end
  local v = ctx.tx[key]
  if v == nil then
    return default
  end
  return v
end

return tx
