--[[
  btwaf_ce / lib/storage.lua
  日志与数据落盘（contract §4 / §5 / §6.11）。
  - write_attack(ctx, decision)  追加 waf.log（JSONL，单行 ≤ 4KB，字段截断/控制字符清洗）
  - add_block(ctx, reason, t)    写共享字典封锁 key + 追加 data/block.log
  - rotate()                     waf.log 按大小轮转为 waf-YYYYMMDD.log，保留 retain_days 天
  - write_perf(snapshot)         写 data/perf.json
  说明：无 lfs（无法列目录），保留期清理通过“按日期推算文件名 + os.remove”实现。
]]

local ngx = ngx
local fs = require("lib.fs")
local json = require("lib.json")
local paths = require("lib.paths")
local util = require("lib.util")

local storage = {}

local MAX_LINE = 4096
local BLOCK_DICT = "btwaf_ce_block"

-- ---------------------------------------------------------------------------
-- 通用
-- ---------------------------------------------------------------------------
-- 请求 ID：优先 nginx 内置 request_id（nginx ≥1.11），否则自行生成
local req_seq = 0

function storage.new_req_id()
  if ngx and ngx.var then
    local ok, rid = pcall(function() return ngx.var.request_id end)
    if ok and type(rid) == "string" and rid ~= "" then
      return rid
    end
  end
  req_seq = req_seq + 1
  local pid = 0
  if ngx and ngx.worker and ngx.worker.pid then
    local ok, p = pcall(ngx.worker.pid)
    if ok and type(p) == "number" then
      pid = p
    end
  end
  return string.format("%d-%d-%d", util.now(), pid, req_seq)
end

-- 创建目录（真实部署由 install.sh 完成；测试后端支持 mkdir）
function storage.ensure_dirs()
  fs.mkdir(paths.LOG_DIR)
  fs.mkdir(paths.DATA_DIR)
  fs.mkdir(paths.DATA_DIR .. "/data")
  fs.mkdir(paths.DATA_DIR .. "/logs")
  fs.mkdir(paths.DATA_DIR .. "/rule")
end

-- ---------------------------------------------------------------------------
-- 攻击日志
-- ---------------------------------------------------------------------------
local function clean(v, limit)
  local s = util.strip_ctrl(tostring(v or ""))
  s = util.sanitize_utf8(s) -- 日志契约要求 UTF-8，非法字节替换为空格
  return util.truncate(s, limit)
end

-- 规范化 hits：只保留契约字段，避免任意字段污染日志
local function normalize_hits(hits, max_hits)
  local out = {}
  if type(hits) ~= "table" then
    return out
  end
  max_hits = max_hits or 20
  for i = 1, #hits do
    if i > max_hits then
      break
    end
    local h = hits[i]
    if type(h) == "table" then
      out[#out + 1] = {
        module = clean(h.module, 32),
        rule = clean(h.rule or h.id, 64),
        name = clean(h.name or h.msg, 128),
        score = tonumber(h.score) or 0,
        tier = tonumber(h.tier) or 1,
        src = clean(h.src or h.source, 16),
      }
    end
  end
  return out
end

-- 生成日志对象（供 write_attack 与测试复用）
function storage.build_attack_record(ctx, decision)
  decision = decision or {}
  ctx = ctx or {}
  local global = ctx.cfg or {}
  local snippet_limit = 512
  if type(global.log) == "table" and tonumber(global.log.snippet) then
    snippet_limit = math.max(0, tonumber(global.log.snippet))
  end
  local rec = {
    time = util.now(),
    site = clean(ctx.site and ctx.site.site_name or ctx.host, 128),
    host = clean(ctx.host, 128),
    ip = clean(ctx.ip or ctx.remote_addr, 64),
    method = clean(ctx.method, 16),
    uri = clean(ctx.uri_raw or ctx.uri, 512),
    query = clean(ctx.query, 512),
    status = tonumber(decision.status) or 403,
    action = clean(decision.action or "block", 16),
    score = tonumber(decision.score) or 0,
    sensitivity = tonumber(decision.sensitivity) or 2,
    hits = normalize_hits(decision.hits or ctx.hits),
    ua = clean(ctx.headers and ctx.headers["user-agent"], 256),
    referer = clean(ctx.headers and ctx.headers["referer"], 256),
    ctype = clean(ctx.headers and ctx.headers["content-type"], 128),
    body_len = tonumber(ctx.body_len) or 0,
    snippet = clean(decision.snippet or ctx.snippet, snippet_limit),
    block_time = tonumber(decision.block_time) or 0,
    rule_source = clean(decision.rule_source, 16),
    req_id = clean(ctx.req_id or decision.req_id, 64),
  }
  return rec
end

-- 追加攻击日志；返回写入行（供测试/自测）
function storage.write_attack(ctx, decision)
  -- log.enabled=false 时不落盘（性能/关闭日志场景，如语料跑批）
  local cfg = ctx.cfg
  if type(cfg) == "table" and type(cfg.log) == "table" and cfg.log.enabled == false then
    return nil
  end
  local rec = storage.build_attack_record(ctx, decision)
  local line = json.encode(rec)
  if type(line) ~= "string" then
    util.log_error("waf.log 编码失败: " .. tostring(rec.req_id))
    return nil
  end
  -- 单行 ≤ 4KB：逐级收缩可选字段
  if #line > MAX_LINE then
    rec.snippet = ""
    line = json.encode(rec)
  end
  if #line > MAX_LINE then
    rec.ua = util.truncate(rec.ua, 64)
    rec.referer = util.truncate(rec.referer, 64)
    rec.uri = util.truncate(rec.uri, 256)
    rec.query = util.truncate(rec.query, 256)
    line = json.encode(rec)
  end
  if #line > MAX_LINE then
    rec.hits = normalize_hits(rec.hits, 3)
    line = json.encode(rec)
  end
  local ok, err = fs.append(paths.waf_log(), line .. "\n")
  if not ok then
    util.log_error("waf.log 写入失败: " .. tostring(err))
    return nil
  end
  return line
end

-- ---------------------------------------------------------------------------
-- 临时封锁
-- ---------------------------------------------------------------------------
-- 写共享字典封锁 key + data/block.log；返回 expire 时间戳
function storage.add_block(ctx, reason, block_time)
  ctx = ctx or {}
  local ip = ctx.ip or ctx.remote_addr or ""
  local site = ctx.site and ctx.site.site_name or ctx.host or ""
  local t = tonumber(block_time) or 300
  if t <= 0 then
    return nil
  end
  local now = util.now()
  local expire = now + t
  local key = "b:" .. site .. ":" .. ip

  -- 1) 共享字典（TTL 自动过期）
  local bd = ngx and ngx.shared and ngx.shared[BLOCK_DICT]
  if bd then
    local ok = pcall(bd.set, bd, key, 1, t)
    if not ok then
      util.log_error("封锁 key 写入失败: " .. key)
    end
  end

  -- 2) block.log 追加（Python 读末尾推导当前封锁）
  local rec = {
    time = now,
    ip = util.strip_ctrl(ip),
    site = util.strip_ctrl(site),
    reason = util.strip_ctrl(reason or "attack"),
    expire = expire,
    block_time = t,
  }
  local line = json.encode(rec)
  if line then
    local ok2, err = fs.append(paths.block_log(), line .. "\n")
    if not ok2 then
      util.log_error("block.log 写入失败: " .. tostring(err))
    end
  end
  return expire
end

-- ---------------------------------------------------------------------------
-- 日志轮转与保留期
-- ---------------------------------------------------------------------------
-- 记录上次保留期清理日期，避免定时器每 3 秒都尝试删除
local last_retention_day = nil

local function rotated_name(now)
  local date = os.date("%Y%m%d", now)
  local path = paths.rotated_log(date)
  if fs.exists(path) then
    -- 同一天多次轮转：加时间后缀避免覆盖
    path = paths.LOG_DIR .. "/waf-" .. date .. "-" .. os.date("%H%M%S", now) .. ".log"
  end
  return path
end

-- 清理保留期外的历史日志（按日期推算文件名）
local function cleanup_retention(retain_days, now)
  local today = os.date("%Y%m%d", now)
  if last_retention_day == today then
    return
  end
  last_retention_day = today
  if retain_days <= 0 then
    return
  end
  -- 多清 7 天余量（防止跨天/漏清理）
  for d = retain_days + 1, retain_days + 8 do
    local date = os.date("%Y%m%d", now - d * 86400)
    fs.remove(paths.rotated_log(date))
  end
end

-- 轮转（worker 0 定时器调用）：size 超过 rotate_size 时改名；每天做一次保留期清理
function storage.rotate(global_cfg)
  local logcfg = (global_cfg and global_cfg.log) or {}
  local now = util.now()
  local retain_days = tonumber(logcfg.retain_days) or 30
  local rotate_size = tonumber(logcfg.rotate_size) or 52428800
  local path = paths.waf_log()

  local size = fs.size(path)
  if size and rotate_size > 0 and size >= rotate_size then
    local target = rotated_name(now)
    local ok = fs.rename(path, target)
    if ok then
      -- 轮转后重建空日志（后续 append 会创建）
      fs.write(path, "")
    else
      util.log_error("waf.log 轮转失败: " .. tostring(target))
    end
  end
  cleanup_retention(retain_days, now)
end

-- ---------------------------------------------------------------------------
-- 性能快照
-- ---------------------------------------------------------------------------
local function snapshot_time(snapshot)
  local t = tonumber(snapshot and snapshot.updated)
  if t and t > 0 then
    return t
  end
  return util.now()
end

function storage.write_perf(snapshot)
  if type(snapshot) ~= "table" then
    return nil, "snapshot 不是 table"
  end
  local data = {
    requests = tonumber(snapshot.requests) or 0,
    hits = tonumber(snapshot.hits) or 0,
    blocked = tonumber(snapshot.blocked) or 0,
    avg_ms = tonumber(snapshot.avg_ms) or 0,
    updated = snapshot_time(snapshot),
  }
  local line = json.encode(data)
  if not line then
    return nil, "perf 编码失败"
  end
  return fs.write(paths.perf_file(), line)
end

-- ---------------------------------------------------------------------------
-- 自定义拦截页（缓存读取，每 30 秒最多读一次文件）
-- ---------------------------------------------------------------------------
local page_cache = { content = nil, loaded_at = 0, tried = false }

function storage.block_page()
  local now = util.now()
  if page_cache.tried and (now - page_cache.loaded_at) < 30 then
    return page_cache.content
  end
  page_cache.tried = true
  page_cache.loaded_at = now
  local data = fs.read(paths.block_page())
  if type(data) == "string" and data ~= "" then
    page_cache.content = data
  else
    page_cache.content = nil
  end
  return page_cache.content
end

function storage.reset_cache()
  page_cache.content = nil
  page_cache.loaded_at = 0
  page_cache.tried = false
  last_retention_day = nil
end

return storage
