--[[
  btwaf_ce / lib/bootstrap.lua
  引擎一次性初始化（配置 + 规则 + matcher），供 init.lua（init_worker）与
  access.lua（懒初始化兜底）共用。

  路径引导不在这里做：init.lua / access.lua 顶部的 setup_package_path() 负责
  先把 lua 根目录加入 package.path，之后才能 require("lib.bootstrap")。
]]

local bootstrap = {
  initialized = false,
  init_ok = false,
  init_error = nil,
  rule_stats = nil,
}

-- 加载全部规则并交给 matcher；返回统计
function bootstrap.load_rules()
  local rules = require("lib.rules")
  local matcher = require("lib.matcher")
  local ok, res = pcall(rules.load)
  if not ok or type(res) ~= "table" then
    bootstrap.init_error = "规则加载失败: " .. tostring(res)
    return nil
  end
  local ok2, err2 = pcall(matcher.load, res.rulesets, res.ac_lists)
  if not ok2 then
    bootstrap.init_error = "matcher.load 失败: " .. tostring(err2)
    return nil
  end
  local ac_count = 0
  if type(res.ac_lists) == "table" then
    for _ in pairs(res.ac_lists) do
      ac_count = ac_count + 1
    end
  end
  bootstrap.rule_stats = {
    total_rules = res.total_rules or 0,
    modules = res.modules or {},
    module_count = #(res.modules or {}),
    failed = res.failed or {},
    failed_count = #(res.failed or {}),
    source = res.source,
    ac_lists = ac_count,
  }
  return bootstrap.rule_stats
end

-- 完整初始化（幂等）
function bootstrap.init()
  local cfg = require("lib.config")
  local storage = require("lib.storage")

  pcall(storage.ensure_dirs)

  local ok1, res1 = pcall(cfg.init)
  local config_ok = ok1 and res1 ~= false
  if not config_ok then
    -- cfg.init 内部已兜底默认配置，这里只记录
    bootstrap.init_error = "配置初始化异常: " .. tostring(res1)
  end

  bootstrap.load_rules()

  bootstrap.initialized = true
  bootstrap.init_ok = config_ok
  return bootstrap.init_ok
end

-- 每请求调用：已初始化时只是一个布尔判断
function bootstrap.ensure()
  if bootstrap.initialized then
    return true
  end
  return bootstrap.init()
end

-- 配置热更新：只重载配置（规则为代码文件，不随配置热更）
function bootstrap.reload_config()
  local cfg = require("lib.config")
  local ok, res = pcall(cfg.reload_if_changed)
  if not ok then
    bootstrap.init_error = "配置热更新失败: " .. tostring(res)
    return false
  end
  return res == true
end

-- 诊断信息
function bootstrap.stats()
  return {
    initialized = bootstrap.initialized,
    init_ok = bootstrap.init_ok,
    init_error = bootstrap.init_error,
    rules = bootstrap.rule_stats,
  }
end

-- 测试用：重置
function bootstrap.reset()
  bootstrap.initialized = false
  bootstrap.init_ok = false
  bootstrap.init_error = nil
  bootstrap.rule_stats = nil
end

return bootstrap
