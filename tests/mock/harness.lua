--[[
  tests/mock/harness.lua
  测试引导（由 run.mjs 通过 doString 加载，早于任何业务模块）：
    1) 把 JS 桥（Node 文件系统 / 正则）包装为 __BTWAF_FS；
    2) 安装 require 自定义 searcher（从真实 lua 目录与 tests/mock 目录读取文件，
       使 wasmoon 内的 require("lib.json") 等能加载仓库真实代码）；
    3) 加载 ngx 垫片（tests/mock/ngx.lua）；
    4) 提供 __reset_suite(name) 供每个 suite 重置状态。
]]

-- ---------------------------------------------------------------------------
-- 1) 文件系统后端（注入给 lib/fs.lua 的 __BTWAF_FS）
-- ---------------------------------------------------------------------------
local FS = {}

FS.read = function(path)
  local res = __BTWAF_FS_READ(path)
  if res == false or res == nil then
    return nil, "读文件失败"
  end
  return res
end

FS.write = function(path, data)
  local ok = __BTWAF_FS_WRITE(path, data)
  if ok == false or ok == nil then
    return nil, "写文件失败"
  end
  return true
end

FS.append = function(path, data)
  local ok = __BTWAF_FS_APPEND(path, data)
  if ok == false or ok == nil then
    return nil, "追加失败"
  end
  return true
end

FS.exists = function(path)
  return __BTWAF_FS_EXISTS(path) == true
end

FS.remove = function(path)
  __BTWAF_FS_REMOVE(path)
  return true
end

FS.rename = function(from, to)
  local ok = __BTWAF_FS_RENAME(from, to)
  if ok == false or ok == nil then
    return nil, "重命名失败"
  end
  return true
end

FS.size = function(path)
  local n = __BTWAF_FS_SIZE(path)
  if type(n) ~= "number" or n < 0 then
    return nil
  end
  return n
end

FS.mtime = function(path)
  local n = __BTWAF_FS_MTIME(path)
  if type(n) ~= "number" or n < 0 then
    return nil
  end
  return n
end

FS.mkdir = function(path)
  __BTWAF_FS_MKDIR(path)
  return true
end

_G.__BTWAF_FS = FS

-- ---------------------------------------------------------------------------
-- 2) require 加载器（真实业务代码 + mock 模块都可 require）
-- ---------------------------------------------------------------------------
local LUA_ROOT = __LUA_ROOT
local MOCK_ROOT = __MOCK_ROOT

local function resolve(name)
  local rel = name:gsub("%.", "/") .. ".lua"
  local candidates = {
    LUA_ROOT .. "/" .. rel,
    MOCK_ROOT .. "/" .. rel,
  }
  for i = 1, #candidates do
    if __BTWAF_FS_EXISTS(candidates[i]) then
      return candidates[i]
    end
  end
  return nil
end

local function mock_searcher(name)
  local path = resolve(name)
  if not path then
    return "\n\tno file '" .. name .. "'（mock searcher）"
  end
  local src = __BTWAF_FS_READ(path)
  if not src then
    return "\n\tno file '" .. name .. "'（mock searcher 读取失败）"
  end
  local chunk, err = load(src, "@" .. path)
  if not chunk then
    error("加载模块失败: " .. name .. " (" .. path .. "): " .. tostring(err), 0)
  end
  return chunk, path
end

-- 插到标准 searcher 之前（标准 searcher 无法访问宿主机文件系统）
table.insert(package.searchers, 2, mock_searcher)

-- ---------------------------------------------------------------------------
-- 3) ngx 垫片
-- ---------------------------------------------------------------------------
local mock = require("mock.ngx")
_G.mock = mock

-- ---------------------------------------------------------------------------
-- 4) suite 生命周期
-- ---------------------------------------------------------------------------
function _G.__reset_suite(name)
  mock.reset_all()
  local framework = require("mock.framework")
  framework.reset(name)
  -- 重置业务模块内存状态（每个 suite 使用新 Lua 引擎，这里是双保险）
  local ok_cfg, config = pcall(require, "lib.config")
  if ok_cfg then
    config.reset()
  end
  local ok_m, matcher = pcall(require, "lib.matcher")
  if ok_m then
    matcher.reset()
  end
  local ok_b, bootstrap = pcall(require, "lib.bootstrap")
  if ok_b then
    bootstrap.reset()
  end
  local ok_u, util = pcall(require, "lib.util")
  if ok_u then
    util.reset_error_log()
  end
  local ok_s, storage = pcall(require, "lib.storage")
  if ok_s then
    storage.reset_cache()
  end
end

-- 兼容 Lua 5.1 习惯
if not unpack then
  unpack = table.unpack
end

return true
