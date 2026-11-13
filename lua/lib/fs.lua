--[[
  btwaf_ce / lib/fs.lua
  文件读写薄封装。真实部署走标准 Lua io/os（OpenResty 允许阻塞式 io，仅用于
  init/定时器等低频路径）；测试环境由 tests/mock/ngx.lua 注入纯 Lua 内存/JS 后端，
  通过全局 `__BTWAF_FS` 覆盖，从而让同一份 Lua 代码可在 wasmoon 中运行。

  约定：所有函数失败均返回 nil, err，不抛异常（调用方决定是否记日志）。
  注意：契约要求禁止 lfs/ffi，因此没有真正的 stat(2)。配置热更新用
  fingerprint()（size + 内容哈希，优先使用后端提供的 mtime）判断变化。
]]

local fs = {}

-- 测试/宿主注入的后端（可选）：需实现 read/write/append/exists/remove/rename/size
local function injected()
  return rawget(_G, "__BTWAF_FS")
end

-- ---------------------------------------------------------------------------
-- 默认后端（标准 Lua io/os）
-- ---------------------------------------------------------------------------
local function io_read(path)
  local f, err = io.open(path, "rb")
  if not f then
    return nil, err
  end
  local data = f:read("*a")
  f:close()
  if not data then
    return nil, "读取失败"
  end
  return data
end

local function io_write(path, data)
  local f, err = io.open(path, "wb")
  if not f then
    return nil, err
  end
  local ok, werr = f:write(data)
  f:close()
  if not ok then
    return nil, werr
  end
  return true
end

local function io_append(path, data)
  local f, err = io.open(path, "ab")
  if not f then
    return nil, err
  end
  local ok, werr = f:write(data)
  f:close()
  if not ok then
    return nil, werr
  end
  return true
end

local function io_exists(path)
  local f = io.open(path, "rb")
  if f then
    f:close()
    return true
  end
  return false
end

local function io_remove(path)
  local ok = os.remove(path)
  return ok and true or nil, "删除失败: " .. tostring(path)
end

local function io_rename(from, to)
  local ok, err = os.rename(from, to)
  if not ok then
    return nil, err
  end
  return true
end

local function io_size(path)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local size = f:seek("end")
  f:close()
  return size
end

-- 默认后端表
local DEFAULT = {
  read = io_read,
  write = io_write,
  append = io_append,
  exists = io_exists,
  remove = io_remove,
  rename = io_rename,
  size = io_size,
}

-- 返回实际使用的后端（注入优先）
local function be()
  local inj = injected()
  if type(inj) == "table" then
    return inj
  end
  return DEFAULT
end

-- ---------------------------------------------------------------------------
-- 公共接口
-- ---------------------------------------------------------------------------
function fs.backend_name()
  return injected() and "injected" or "io"
end

function fs.read(path)
  local b = be()
  if type(b.read) ~= "function" then
    return nil, "后端不支持 read"
  end
  return b.read(path)
end

function fs.write(path, data)
  local b = be()
  if type(b.write) ~= "function" then
    return nil, "后端不支持 write"
  end
  return b.write(path, data)
end

function fs.append(path, data)
  local b = be()
  if type(b.append) ~= "function" then
    return nil, "后端不支持 append"
  end
  return b.append(path, data)
end

function fs.exists(path)
  local b = be()
  if type(b.exists) == "function" then
    return b.exists(path) and true or false
  end
  return false
end

function fs.remove(path)
  local b = be()
  if type(b.remove) ~= "function" then
    return nil, "后端不支持 remove"
  end
  return b.remove(path)
end

function fs.rename(from, to)
  local b = be()
  if type(b.rename) ~= "function" then
    return nil, "后端不支持 rename"
  end
  return b.rename(from, to)
end

function fs.size(path)
  local b = be()
  if type(b.size) == "function" then
    return b.size(path)
  end
  return nil
end

-- 目录创建（默认后端无法创建，真实部署由 install.sh 建目录；测试后端可提供）
function fs.mkdir(path)
  local b = be()
  if type(b.mkdir) == "function" then
    return b.mkdir(path)
  end
  return false
end

-- ---------------------------------------------------------------------------
-- 指纹：配置热更新判断
-- ---------------------------------------------------------------------------
-- djb2 字符串哈希（无 bit 库依赖，结果取模到 2^32）
function fs.hash(s)
  local h = 5381
  local len = #s
  for i = 1, len, 1 do
    h = (h * 33 + string.byte(s, i)) % 4294967296
  end
  return h
end

-- 优先使用后端 mtime（测试后端有），否则用 size+hash；文件不存在返回 nil
function fs.fingerprint(path)
  local b = be()
  if type(b.mtime) == "function" then
    local mt = b.mtime(path)
    if mt then
      local size = fs.size(path)
      return tostring(mt) .. ":" .. tostring(size)
    end
  end
  local data, err = fs.read(path)
  if not data then
    return nil, err
  end
  return tostring(#data) .. ":" .. fs.hash(data)
end

function fs.read_json(path)
  local data = fs.read(path)
  if not data then
    return nil, "无法读取 " .. tostring(path)
  end
  local json = require("lib.json")
  local obj, err = json.decode(data)
  if not obj then
    return nil, "JSON 解析失败（" .. tostring(path) .. "）: " .. tostring(err)
  end
  return obj
end

return fs
