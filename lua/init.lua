--[[
  btwaf_ce / init.lua
  init_worker_by_lua_file 入口（contract §2）：
    1) 设置 package.path（真实部署 /www/server/btwaf_ce/lua，测试环境用全局覆盖）；
    2) 加载配置 + 规则（lib/bootstrap）；
    3) 启动 2–3 秒定时器：
       - 配置热更新（config.json/site.json/hosts.json/rule/custom.json 指纹变化才重载）
       - unban.log 增量应用（按 data/state.json 的 unban_offset）
       - worker 0：waf.log 轮转/保留期清理 + perf.json 落盘
  所有步骤 pcall 包裹，失败只记录（util.log_error，60 秒去重），不影响 nginx。
]]

-- ---------------------------------------------------------------------------
-- 路径引导（必须在 require("lib.*") 之前执行）
-- ---------------------------------------------------------------------------
local function setup_package_path()
  local roots = {}
  -- 测试/宿主可覆盖
  local override = rawget(_G, "BTWAF_CE_LUA_DIR")
  if type(override) == "string" and override ~= "" then
    roots[#roots + 1] = override
  end
  -- 真实部署路径（install.sh 将 lua/ 复制到数据目录）
  roots[#roots + 1] = "/www/server/btwaf_ce/lua"
  local parts = {}
  for i = 1, #roots do
    parts[#parts + 1] = roots[i] .. "/?.lua"
    parts[#parts + 1] = roots[i] .. "/lib/?.lua"
  end
  package.path = table.concat(parts, ";") .. ";" .. package.path
end

setup_package_path()

local ngx = ngx

-- 业务模块
local bootstrap = require("lib.bootstrap")
local util = require("lib.util")
local cfg = require("lib.config")
local storage = require("lib.storage")
local perf = require("lib.perf")
local fs = require("lib.fs")
local paths = require("lib.paths")
local json = require("lib.json")
local cc = require("lib.cc")

-- ---------------------------------------------------------------------------
-- unban 增量应用（contract §5）
-- ---------------------------------------------------------------------------
-- 读取 data/unban.log 从 unban_offset 开始的新增记录，删除对应封锁 key，
-- 并把新 offset 写回 data/state.json（保留其它字段）。
local function unban_increment()
  local path = paths.unban_log()
  local size = fs.size(path)
  if not size or size <= 0 then
    return 0
  end
  local state = fs.read_json(paths.state_file())
  if type(state) ~= "table" then
    state = {}
  end
  local offset = tonumber(state.unban_offset) or 0
  if offset < 0 then
    offset = 0
  end
  if size < offset then
    -- 文件被截断/重建：从头重读
    offset = 0
  end
  if size == offset then
    return 0
  end
  local data = fs.read(path)
  if type(data) ~= "string" then
    return 0
  end
  local chunk = data:sub(offset + 1)
  -- 只处理完整行（以 \n 结尾），尾部残行留到下一轮，避免 JSON 解析半行
  local cut = chunk:match(".*()\n")
  if not cut then
    return 0
  end
  local complete = chunk:sub(1, cut)
  local consumed = #complete
  if consumed == 0 then
    return 0
  end

  local applied = 0
  local function unban_all_for_ip(ip)
    local bd = ngx and ngx.shared and ngx.shared["btwaf_ce_block"]
    if not bd or not bd.get_keys then
      return 0
    end
    local n = 0
    local ok, keys = pcall(bd.get_keys, bd, 4096)
    if not ok or type(keys) ~= "table" then
      return 0
    end
    local suffix = ":" .. ip
    for i = 1, #keys do
      local k = keys[i]
      if type(k) == "string" and k:sub(1, 2) == "b:" and k:sub(-#suffix) == suffix then
        pcall(bd.delete, bd, k)
        n = n + 1
      end
    end
    return n
  end

  for line in complete:gmatch("[^\n]+") do
    local ok, rec = pcall(json.decode, line)
    if ok and type(rec) == "table" and type(rec.ip) == "string" and rec.ip ~= "" then
      local site = rec.site
      if type(site) == "string" and site ~= "" then
        pcall(cc.unblock, site, rec.ip)
        applied = applied + 1
      else
        -- site 为空：解封该 IP 在所有站点的封锁
        applied = applied + unban_all_for_ip(rec.ip)
      end
    end
  end

  -- 写回 state.json（保留 Python 写入的其它字段）
  local new_state = {}
  for k, v in pairs(state) do
    new_state[k] = v
  end
  new_state.unban_offset = offset + consumed
  new_state.unban_applied_at = util.now()
  local ok_w = pcall(fs.write, paths.state_file(), json.encode(new_state))
  if not ok_w then
    util.log_error("state.json 写入失败（unban_offset 未能持久化）")
  end
  return applied
end

-- ---------------------------------------------------------------------------
-- 定时器
-- ---------------------------------------------------------------------------
local TIMER_INTERVAL = 3 -- 秒（契约要求 2–3s）

-- 当前 worker 是否为 worker 0（日志轮转/perf 落盘只在一个 worker 做）
local function is_worker_zero()
  if not ngx or not ngx.worker or not ngx.worker.id then
    return true
  end
  local ok, id = pcall(ngx.worker.id)
  if ok and type(id) == "number" then
    return id == 0
  end
  return true
end

-- 单次 tick：每一步独立 pcall，互不影响
local function tick()
  -- 1) 配置热更新（所有 worker 都重载各自内存配置）
  local ok_cfg, changed = pcall(bootstrap.reload_config)
  if not ok_cfg then
    util.log_error("配置热更新异常: " .. tostring(changed))
  end

  -- 2) worker 0：日志轮转 / 保留期 / perf / unban
  if is_worker_zero() then
    local global_cfg = nil
    if cfg.ready() then
      global_cfg = cfg.global()
    end

    local ok_rot, err_rot = pcall(storage.rotate, global_cfg)
    if not ok_rot then
      util.log_error("日志轮转异常: " .. tostring(err_rot))
    end

    -- perf.json：无论配置是否 ready 都写（概览页依赖它；写失败必须暴露出来）
    local ok_snap, snap = pcall(perf.snapshot)
    if not ok_snap then
      util.log_error("perf 快照异常: " .. tostring(snap))
    elseif snap then
      local ok_perf, res, werr = pcall(storage.write_perf, snap)
      if not ok_perf then
        util.log_error("perf.json 写入异常: " .. tostring(res))
      elseif not res then
        util.log_error("perf.json 写入失败: " .. tostring(werr) ..
          " (requests=" .. tostring(snap.requests) .. ")")
      end
    end

    local ok_unban, err_unban = pcall(unban_increment)
    if not ok_unban then
      util.log_error("unban 增量应用异常: " .. tostring(err_unban))
    end
  end
end

-- 启动定时器（每个 worker 一个）
local function setup_timer()
  if not ngx or not ngx.timer or not ngx.timer.every then
    return false
  end
  local ok, err = pcall(ngx.timer.every, TIMER_INTERVAL, function(premature)
    if premature then
      return
    end
    local ok_tick, terr = pcall(tick)
    if not ok_tick then
      util.log_error("定时器执行异常: " .. tostring(terr))
    end
  end)
  if not ok then
    util.log_error("定时器启动失败: " .. tostring(err))
    return false
  end
  return true
end

-- ---------------------------------------------------------------------------
-- 入口
-- ---------------------------------------------------------------------------
local function main()
  local ok, err = pcall(bootstrap.init)
  if not ok then
    util.log_error("引擎初始化失败: " .. tostring(err))
  end
  -- 规则统计（方便 nginx error.log 诊断；不含请求数据）
  local stats = bootstrap.stats and bootstrap.stats() or nil
  if ngx and ngx.log and stats and stats.rules then
    local r = stats.rules
    pcall(ngx.log, ngx.NOTICE or 5, string.format(
      "btwaf_ce: 规则加载完成 total=%d modules=%d failed=%d source=%s",
      tonumber(r.total_rules) or 0, tonumber(r.module_count) or 0,
      tonumber(r.failed_count) or 0, tostring(r.source)))
  end
  setup_timer()
end

local ok_main, err_main = pcall(main)
if not ok_main then
  util.log_error("init.lua 顶层异常: " .. tostring(err_main))
end

-- 供测试/自测调用
rawset(_G, "btwaf_ce_init", main)
rawset(_G, "btwaf_ce_unban_increment", unban_increment)

return main
