--[[
  btwaf_ce / lib/ip.lua
  客户端真实 IP 解析（contract §6.4）。
  - 默认取 remote_addr。
  - 站点开启 CDN 时，按 cdn.headers 顺序取代理头；cdn.trusted 非空时要求
    remote_addr 属于受信代理，避免伪造头。
  - 全局 trusted_proxies 同理（用于反向代理场景）。
  - 只返回合法 IP；绝不因头部为空/非法而返回空串。
]]

local util = require("lib.util")
local fs = require("lib.fs")

local ip = {}
local PANEL_CDN_GLOBAL = "/www/server/panel/vhost/nginx/real_cdn_ip.conf"
local PANEL_CDN_EXT = "/www/server/panel/vhost/nginx/extension/%s/proxy_real_ip.conf"
local panel_cdn_cache = {}

local function panel_realip(path)
  local text = fs.read(path)
  if type(text) ~= "string" or text == "" then
    return false, ""
  end
  local has_from = false
  local header = ""
  for line in text:gmatch("[^\r\n]+") do
    line = util.trim(line)
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local name, value = line:match("^(%S+)%s+(.+)$")
      if name == "set_real_ip_from" then
        has_from = true
      elseif name == "real_ip_header" then
        header = value:gsub(";", "")
      end
    end
  end
  return has_from and header ~= "", header
end

-- 面板 CDN/真实 IP 已由 Nginx 提前改写 remote_addr；插件不能再解析 Header。
local function panel_cdn(site_name)
  local key = type(site_name) == "string" and site_name or ""
  if panel_cdn_cache[key] ~= nil then
    return panel_cdn_cache[key]
  end
  local result = { open = false, scope = "" }
  local global_open = panel_realip(PANEL_CDN_GLOBAL)
  if global_open then
    result.open = true
    result.scope = "global"
  end
  if key ~= "" and not key:find("[/\\]") and not key:find("%.%.") then
    local site_open = panel_realip(string.format(PANEL_CDN_EXT, key))
    if site_open then
      result.open = true
      result.scope = "site"
    end
  end
  panel_cdn_cache[key] = result
  return result
end
ip.panel_cdn = panel_cdn

-- 大小写不敏感取 header（headers 约定为小写键，但测试/调用方可能传原始大小写）
local function header_get(headers, name)
  if type(headers) ~= "table" then
    return nil
  end
  local v = headers[name]
  if v then
    return v
  end
  local target = name:lower()
  for k, val in pairs(headers) do
    if type(k) == "string" and k:lower() == target then
      return val
    end
  end
  return nil
end
ip.header_get = header_get

-- 从 "1.2.3.4, 5.6.7.8" 这类头部里取第一个合法 IP（可指定跳过列表）
local function first_valid(value, skip)
  if type(value) ~= "string" then
    return nil
  end
  for candidate in value:gmatch("[^,%s]+") do
    candidate = util.trim(candidate)
    if candidate ~= "" and util.is_ip(candidate) then
      if not skip or candidate ~= skip then
        return candidate
      end
    end
  end
  return nil
end
ip.first_valid = first_valid

-- 受信代理判断：trusted 为空视为不校验（站点显式开启 CDN 场景）
local function trusted_ok(remote_addr, trusted)
  if type(trusted) ~= "table" or #trusted == 0 then
    return true
  end
  return util.ip_in_list(remote_addr, trusted)
end

-- 返回 ip, via（via 用于日志/诊断，例如 "remote"/"cdn:cf-connecting-ip"）
function ip.client_ip(headers, remote_addr, site_cfg)
  remote_addr = util.trim(remote_addr or "")
  local global = nil
  local cdn = nil
  if type(site_cfg) == "table" then
    cdn = site_cfg.cdn
    global = site_cfg.global_proxy_trusted
  end

  -- 面板 CDN 已由 Nginx real_ip 模块处理时，realip_remote_addr 与原地址不同；
  -- 这种情况下不能再从 Header 解析，否则会重复处理或绕过面板的 trusted 链。
  local realip = nil
  if ngx and ngx.var then
    realip = ngx.var.realip_remote_addr
  end
  if type(realip) == "string" and realip ~= "" and realip ~= remote_addr then
    return remote_addr, "panel-cdn:realip"
  end

  -- 面板全局/站点 CDN 已由 Nginx real_ip 模块处理，直接使用 remote_addr。
  local panel = panel_cdn(type(site_cfg) == "table" and site_cfg.site_name or nil)
  if panel.open then
    return remote_addr, "panel-cdn:" .. panel.scope
  end

  -- 1) 站点 CDN 开启
  if type(cdn) == "table" and cdn.open == true then
    if not trusted_ok(remote_addr, cdn.trusted) then
      return remote_addr, "remote"
    end
    local hdrs = cdn.headers
    if type(hdrs) == "table" then
      for i = 1, #hdrs do
        local name = hdrs[i]
        if type(name) == "string" then
          local value = header_get(headers, name:lower())
          local found = first_valid(value, remote_addr)
          if found then
            return found, "cdn:" .. name:lower()
          end
        end
      end
    end
    return remote_addr, "remote"
  end

  -- 2) 全局受信代理（反向代理链）
  if type(global) == "table" and global.open == true then
    if not trusted_ok(remote_addr, global.trusted) then
      return remote_addr, "remote"
    end
    local hdrs = global.headers or { "x-forwarded-for", "x-real-ip", "cf-connecting-ip" }
    for i = 1, #hdrs do
      local name = hdrs[i]
      if type(name) == "string" then
        local value = header_get(headers, name:lower())
        local found = first_valid(value, remote_addr)
        if found then
          return found, "proxy:" .. name:lower()
        end
      end
    end
  end

  return remote_addr, "remote"
end

return ip
