--[[
  btwaf_ce / lib/paths.lua
  统一解析运行期路径。真实部署根目录固定为 /www/server/btwaf_ce（contract §2/§10），
  测试环境通过全局变量覆盖（run.mjs 注入），避免测试依赖固定 Windows 路径。

  可覆盖全局变量：
    BTWAF_CE_DATA_DIR  数据目录（默认 /www/server/btwaf_ce）
    BTWAF_CE_LOG_DIR   日志目录（默认 /www/wwwlogs/btwaf_ce）
    BTWAF_CE_LUA_DIR   Lua 根目录（默认 <DATA_DIR>/lua）
]]

local P = {}

local function get_str(name, default)
  local v = rawget(_G, name)
  if type(v) == "string" and v ~= "" then
    return v
  end
  return default
end

P.DATA_DIR = get_str("BTWAF_CE_DATA_DIR", "/www/server/btwaf_ce")
P.LOG_DIR = get_str("BTWAF_CE_LOG_DIR", "/www/wwwlogs/btwaf_ce")
P.LUA_DIR = get_str("BTWAF_CE_LUA_DIR", P.DATA_DIR .. "/lua")

function P.config_file()
  return P.DATA_DIR .. "/config.json"
end

function P.site_file()
  return P.DATA_DIR .. "/site.json"
end

function P.hosts_file()
  return P.DATA_DIR .. "/hosts.json"
end

function P.custom_rule_file()
  return P.DATA_DIR .. "/rule/custom.json"
end

function P.state_file()
  return P.DATA_DIR .. "/data/state.json"
end

function P.perf_file()
  return P.DATA_DIR .. "/data/perf.json"
end

function P.block_log()
  return P.DATA_DIR .. "/data/block.log"
end

function P.unban_log()
  return P.DATA_DIR .. "/data/unban.log"
end

function P.block_page()
  return P.DATA_DIR .. "/data/blockpage.html"
end

function P.waf_log()
  return P.LOG_DIR .. "/waf.log"
end

function P.error_log()
  return P.DATA_DIR .. "/logs/error.log"
end

-- 按日期轮转后的历史日志文件名（waf-YYYYMMDD.log）
function P.rotated_log(date_str)
  return P.LOG_DIR .. "/waf-" .. date_str .. ".log"
end

return P
