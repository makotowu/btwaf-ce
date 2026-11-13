--[[
  btwaf_ce / lib/config.lua
  读取并合并全局/站点配置（contract §3 / §6.2），支持热更新。
  数据来源（Python 写、Lua 读）：
    config.json            全局配置
    site.json              站点配置（key=面板站点名）
    hosts.json             host -> 站点名
    rule/custom.json       自定义规则
  继承规则（与 UI 文案一致）：
    - 站点 0 / null / "" / 空数组 = 继承或空；
    - lists / rule_exclude = 全局 ∪ 站点；
    - sensitivity=0、tier=0、cc/attack_block 数值 0 = 继承全局；
    - observe/open 为 null 时继承全局。
  热更新：契约建议按 mtime 判断；编码规范禁用 lfs/ffi，改用文件内容指纹
  （size+hash，测试后端提供 mtime 时优先 mtime），行为等价且无需额外依赖。
]]

local fs = require("lib.fs")
local paths = require("lib.paths")
local util = require("lib.util")
local rules_mod = require("lib.rules")

local config = {}

-- ---------------------------------------------------------------------------
-- 默认全局配置（contract §3 原样内嵌，任何字段缺失时兜底）
-- ---------------------------------------------------------------------------
local DEFAULT_GLOBAL = {
  schema = 1,
  version = "0.1.0",
  enabled = true,
  observe = false,
  sensitivity = 2,
  block = { status = 403, use_custom = false, page = "" },
  scan = {
    body_limit = 1048576,
    arg_limit = 8192,
    header_limit = 8192,
    upload_scan_limit = 20971520,
    max_args = 200,
  },
  log = { enabled = true, retain_days = 30, rotate_size = 52428800, snippet = 512 },
  cc = {
    open = true,
    cycle = 60,
    limit = 120,
    block_time = 300,
    status = 444,
    url_cc = false,
    skip_static = true,
  },
  attack_block = { open = true, cycle = 120, limit = 20, block_time = 1800 },
  modules = {
    sqli = { open = true, tier = 1 },
    xss = { open = true, tier = 1 },
    rce = { open = true, tier = 1 },
    lfi = { open = true, tier = 1 },
    php = { open = true, tier = 1 },
    java = { open = true, tier = 1 },
    scan = { open = true, tier = 1 },
    crawler = { open = true, tier = 1 },
    sensitive = { open = true, tier = 1 },
    upload = { open = true, tier = 1 },
    protocol = { open = true, tier = 1 },
    custom = { open = true, tier = 1 },
  },
  lists = {
    ip_black = {},
    ip_white = {},
    url_black = {},
    url_white = {},
    ua_black = {},
    ua_white = {},
    param_white = {},
  },
  rule_exclude = { crs = {}, ce = {} },
  trusted_proxies = {},
  crawler = {
    allow = {
      "baiduspider", "googlebot", "bingbot", "bytespider", "sogou",
      "360spider", "yandex", "duckduckbot", "applebot",
    },
    block_fake = true,
  },
  fail_open = true,
  whitelist_first = true,
  update_time = 0,
}

config.DEFAULT_GLOBAL = DEFAULT_GLOBAL

-- 站点默认值（schema 中站点字段）
local DEFAULT_SITE = {
  open = true,
  sensitivity = 0,
  observe = nil,
  modules = {},
  cc = { open = nil, cycle = 0, limit = 0, block_time = 0, status = 0, url_cc = nil },
  attack_block = { open = nil, cycle = 0, limit = 0, block_time = 0 },
  cdn = { open = false, headers = { "cf-connecting-ip", "x-real-ip", "x-forwarded-for" }, trusted = {} },
  lists = { ip_black = {}, ip_white = {}, url_black = {}, url_white = {}, ua_black = {}, ua_white = {}, param_white = {} },
  rule_exclude = { crs = {}, ce = {} },
  disable_php_path = { "^/cache/", "^/config/", "^/runtime/", "^/application/", "^/logs/" },
  disable_ext = { "sql", "bak", "swp", "git", "env" },
  upload_ext = { "php", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "exe", "sh" },
  custom_rules = {},
  update_time = 0,
}

config.DEFAULT_SITE = DEFAULT_SITE

-- ---------------------------------------------------------------------------
-- 工具
-- ---------------------------------------------------------------------------
local function is_array(t)
  if type(t) ~= "table" then
    return false
  end
  local mt = getmetatable(t)
  if mt and mt.__btwaf_array then
    return true
  end
  if next(t) == nil then
    return false
  end
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" or k < 1 or k ~= math.floor(k) then
      return false
    end
    n = n + 1
  end
  return n == #t
end

config.is_array = is_array

local function copy(v)
  return util.deep_copy(v)
end

-- 深度合并：用户配置覆盖默认；数组整体替换（除非默认是数组且用户为空）
local function deep_merge(default, user)
  if type(default) ~= "table" or type(user) ~= "table" then
    if user == nil then
      return copy(default)
    end
    return copy(user)
  end
  if is_array(default) or is_array(user) then
    if #user > 0 then
      return copy(user)
    end
    return copy(default)
  end
  local out = {}
  for k, v in pairs(default) do
    out[k] = deep_merge(v, user[k])
  end
  for k, v in pairs(user) do
    if out[k] == nil then
      out[k] = copy(v)
    end
  end
  return out
end

local function as_array(v)
  if type(v) == "table" then
    return copy(v)
  end
  return {}
end

-- 站点数值：0 视为继承
local function pick_num(site_v, global_v)
  if type(site_v) == "number" and site_v ~= 0 then
    return site_v
  end
  return global_v
end

-- 站点布尔：nil 视为继承
local function pick_bool(site_v, global_v)
  if type(site_v) == "boolean" then
    return site_v
  end
  return global_v
end

-- 字符串：空串视为继承
local function pick_str(site_v, global_v)
  if type(site_v) == "string" and site_v ~= "" then
    return site_v
  end
  return global_v
end

-- 数组合并（去重保序）
local function union_list(a, b)
  local out = {}
  local seen = {}
  local function add(list)
    if type(list) ~= "table" then
      return
    end
    for i = 1, #list do
      local item = list[i]
      if type(item) == "string" then
        local key = item
        if not seen[key] then
          seen[key] = true
          out[#out + 1] = item
        end
      end
    end
  end
  add(a)
  add(b)
  return out
end

local LIST_KEYS = {
  "ip_black", "ip_white", "url_black", "url_white", "ua_black", "ua_white", "param_white",
}
local EXCLUDE_KEYS = { "crs", "ce" }
local MODULE_NAMES = {
  "sqli", "xss", "rce", "lfi", "php", "java", "scan",
  "crawler", "sensitive", "upload", "protocol", "custom",
}

local function merge_modules(global_modules, site_modules)
  local out = {}
  for i = 1, #MODULE_NAMES do
    local name = MODULE_NAMES[i]
    local gm = type(global_modules) == "table" and global_modules[name] or nil
    local sm = type(site_modules) == "table" and site_modules[name] or nil
    -- 全局模块默认开启（仅显式 false 才关闭）
    local g_open = true
    if gm and gm.open == false then
      g_open = false
    end
    local g_tier = gm and tonumber(gm.tier) or 1
    out[name] = {
      open = pick_bool(sm and sm.open, g_open),
      tier = pick_num(sm and tonumber(sm.tier), g_tier),
    }
  end
  -- 保留自定义模块（扩展用）
  if type(global_modules) == "table" then
    for name, gm in pairs(global_modules) do
      if out[name] == nil and not gm.__btwaf_array then
        out[name] = { open = gm.open ~= false, tier = tonumber(gm.tier) or 1 }
      end
    end
  end
  return out
end

local function merge_lists(global_lists, site_lists)
  local out = {}
  for i = 1, #LIST_KEYS do
    local key = LIST_KEYS[i]
    out[key] = union_list(
      global_lists and global_lists[key],
      site_lists and site_lists[key]
    )
  end
  return out
end

local function merge_exclude(global_ex, site_ex)
  local out = {}
  for i = 1, #EXCLUDE_KEYS do
    local key = EXCLUDE_KEYS[i]
    out[key] = union_list(
      global_ex and global_ex[key],
      site_ex and site_ex[key]
    )
  end
  return out
end

local function merge_cc(global_cc, site_cc)
  site_cc = site_cc or {}
  return {
    open = pick_bool(site_cc.open, global_cc.open),
    cycle = pick_num(site_cc.cycle, global_cc.cycle),
    limit = pick_num(site_cc.limit, global_cc.limit),
    block_time = pick_num(site_cc.block_time, global_cc.block_time),
    status = pick_num(site_cc.status, global_cc.status),
    url_cc = pick_bool(site_cc.url_cc, global_cc.url_cc),
    skip_static = pick_bool(site_cc.skip_static, global_cc.skip_static),
  }
end

local function merge_attack_block(global_ab, site_ab)
  site_ab = site_ab or {}
  return {
    open = pick_bool(site_ab.open, global_ab.open),
    cycle = pick_num(site_ab.cycle, global_ab.cycle),
    limit = pick_num(site_ab.limit, global_ab.limit),
    block_time = pick_num(site_ab.block_time, global_ab.block_time),
  }
end

local function merge_cdn(site_cdn)
  local out = {
    open = false,
    headers = copy(DEFAULT_SITE.cdn.headers),
    trusted = {},
  }
  if type(site_cdn) == "table" then
    if type(site_cdn.open) == "boolean" then
      out.open = site_cdn.open
    end
    if type(site_cdn.headers) == "table" and #site_cdn.headers > 0 then
      out.headers = copy(site_cdn.headers)
    end
    if type(site_cdn.trusted) == "table" then
      out.trusted = copy(site_cdn.trusted)
    end
  end
  return out
end

-- ---------------------------------------------------------------------------
-- 内部状态
-- ---------------------------------------------------------------------------
local state = {
  ready = false,
  global = nil,     -- 合并默认值后的全局配置
  sites_raw = {},   -- site.json 原始
  hosts = {},       -- host(lower) -> site name
  custom_raw = {},  -- custom.json 原始（{rules={...}}）
  merged_cache = {}, -- site name -> 合并结果
  fp = nil,         -- 文件指纹快照
  last_error = nil,
  loaded_at = 0,
  reload_count = 0,
  tier_override = nil, -- 测试/宿主 tier 覆盖
}

-- 文件指纹：固定四个键，缺失记为 "missing"，保证可比较
local function fingerprint_all()
  return {
    config = fs.fingerprint(paths.config_file()) or "missing",
    site = fs.fingerprint(paths.site_file()) or "missing",
    hosts = fs.fingerprint(paths.hosts_file()) or "missing",
    custom = fs.fingerprint(paths.custom_rule_file()) or "missing",
  }
end

local function fp_equal(a, b)
  if type(a) ~= "table" or type(b) ~= "table" then
    return false
  end
  return a.config == b.config and a.site == b.site
    and a.hosts == b.hosts and a.custom == b.custom
end

-- 构建全局配置（默认值 + 用户值）
local function build_global(raw)
  local merged = deep_merge(DEFAULT_GLOBAL, raw or {})
  -- 数值/类型兜底
  merged.sensitivity = tonumber(merged.sensitivity) or 2
  if merged.sensitivity < 1 then
    merged.sensitivity = 1
  elseif merged.sensitivity > 3 then
    merged.sensitivity = 3
  end
  merged.enabled = merged.enabled ~= false
  merged.observe = merged.observe == true
  merged.fail_open = merged.fail_open ~= false
  merged.whitelist_first = merged.whitelist_first ~= false
  return merged
end

-- 构建 hosts 映射（全部小写）
local function build_hosts(raw)
  local out = {}
  if type(raw) ~= "table" then
    return out
  end
  for host, site_name in pairs(raw) do
    if type(host) == "string" and type(site_name) == "string" then
      out[host:lower()] = site_name
    end
  end
  return out
end

-- 站点原始配置归一（缺失字段补默认，但保留 null/0 语义）
local function normalize_site_raw(raw)
  if type(raw) ~= "table" then
    return {}
  end
  local out = deep_merge(DEFAULT_SITE, raw)
  -- deep_merge 会把 null 视为缺失；这里显式保留 open/observe 的布尔语义即可
  return out
end

-- 站点自定义规则：全局 custom.json + 站点内联 custom_rules
local function collect_custom_rules(site_name, site_raw)
  local out = {}
  local by_id = {}

  -- 1) custom.json 中适用该站点的规则
  local global_rules = type(state.custom_raw) == "table" and state.custom_raw.rules or nil
  if type(global_rules) == "table" then
    for i = 1, #global_rules do
      local r = global_rules[i]
      if type(r) == "table" and rules_mod.applies_to_site(r, site_name) then
        local item = copy(r)
        item.src = "custom"
        local id = tostring(item.id or ("custom-json-" .. i))
        item.id = id
        if by_id[id] then
          out[by_id[id]] = item
        else
          by_id[id] = #out + 1
          out[#out + 1] = item
        end
      end
    end
  end

  -- 2) site.json 内联 custom_rules（站点级，优先生效）
  local inline = site_raw and site_raw.custom_rules
  if type(inline) == "table" then
    for i = 1, #inline do
      local r = inline[i]
      if type(r) == "table" then
        local item = copy(r)
        item.src = "custom"
        local id = tostring(item.id or ("custom-site-" .. i))
        item.id = id
        if by_id[id] then
          out[by_id[id]] = item
        else
          by_id[id] = #out + 1
          out[#out + 1] = item
        end
      end
    end
  end

  return rules_mod.sort_custom(out)
end

-- 模块 tier 覆盖（测试/宿主用）：设置后所有模块 tier 强制为该值；nil 取消覆盖。
-- 用于语料分档跑批（恶意 tier=3 / 良性 tier=1），避免依赖对合并表的引用修改。
function config.set_module_tier_override(tier)
  if tier == nil then
    state.tier_override = nil
  else
    tier = tonumber(tier)
    if not tier or tier < 0 then
      return false, "tier 非法"
    end
    state.tier_override = tier
  end
  -- 已合并缓存失效，下一次 site() 重新合并并应用覆盖
  state.merged_cache = {}
  return true
end

function config.module_tier_override()
  return state.tier_override
end

-- 合并单个站点配置（结果缓存）
local function merge_site(site_name)
  local cached = state.merged_cache[site_name]
  if cached then
    return cached
  end
  local global = state.global or build_global({})
  local raw = normalize_site_raw(state.sites_raw[site_name])
  local merged = {}
  merged.site_name = site_name
  merged.raw = raw
  merged.enabled = global.enabled
  merged.open = pick_bool(raw.open, global.enabled)
  merged.observe = pick_bool(raw.observe, global.observe)
  merged.sensitivity = pick_num(raw.sensitivity, global.sensitivity)
  merged.modules = merge_modules(global.modules, raw.modules)
  -- 测试/宿主 tier 覆盖（语料分档）：所有模块统一为指定 tier
  if state.tier_override ~= nil then
    for _, m in pairs(merged.modules) do
      m.tier = state.tier_override
    end
  end
  merged.cc = merge_cc(global.cc, raw.cc)
  merged.attack_block = merge_attack_block(global.attack_block, raw.attack_block)
  merged.cdn = merge_cdn(raw.cdn)
  merged.lists = merge_lists(global.lists, raw.lists)
  merged.rule_exclude = merge_exclude(global.rule_exclude, raw.rule_exclude)
  merged.disable_php_path = as_array(raw.disable_php_path)
  merged.disable_ext = as_array(raw.disable_ext)
  merged.upload_ext = as_array(raw.upload_ext)
  merged.custom_rules = collect_custom_rules(site_name, raw)
  -- 全局共享项（站点级无对应字段）
  merged.block = global.block
  merged.scan = global.scan
  merged.log = global.log
  merged.crawler = global.crawler
  merged.fail_open = global.fail_open
  merged.whitelist_first = global.whitelist_first
  merged.global_proxy_trusted = {
    open = type(global.trusted_proxies) == "table" and #global.trusted_proxies > 0,
    headers = { "x-forwarded-for", "x-real-ip" },
    trusted = global.trusted_proxies,
  }
  state.merged_cache[site_name] = merged
  return merged
end

-- ---------------------------------------------------------------------------
-- 加载
-- ---------------------------------------------------------------------------
local function load_all(global_raw, sites_raw, hosts_raw, custom_raw)
  local errors = {}
  local g = build_global(global_raw)
  state.global = g
  state.sites_raw = type(sites_raw) == "table" and sites_raw or {}
  state.hosts = build_hosts(hosts_raw)
  state.custom_raw = type(custom_raw) == "table" and custom_raw or {}
  state.merged_cache = {}
  state.ready = true
  state.loaded_at = util.now()
  if #errors > 0 then
    state.last_error = errors[1]
  else
    state.last_error = nil
  end
  return true
end

-- 从数据目录读取并加载；任何文件缺失/损坏都降级为默认值 + 记录错误
function config.init()
  local errors = {}
  local global_raw = nil
  local sites_raw = nil
  local hosts_raw = nil
  local custom_raw = nil

  local ok1, g, e1 = pcall(fs.read_json, paths.config_file())
  if ok1 and g then
    global_raw = g
  else
    errors[#errors + 1] = "config.json: " .. tostring(e1 or g)
  end

  local ok2, s, e2 = pcall(fs.read_json, paths.site_file())
  if ok2 and s then
    sites_raw = s
  else
    errors[#errors + 1] = "site.json: " .. tostring(e2 or s)
  end

  local ok3, h, e3 = pcall(fs.read_json, paths.hosts_file())
  if ok3 and h then
    hosts_raw = h
  else
    errors[#errors + 1] = "hosts.json: " .. tostring(e3 or h)
  end

  local ok4, c, e4 = pcall(fs.read_json, paths.custom_rule_file())
  if ok4 and c then
    custom_raw = c
  else
    errors[#errors + 1] = "rule/custom.json: " .. tostring(e4 or c)
  end

  local ok, err = pcall(load_all, global_raw, sites_raw, hosts_raw, custom_raw)
  if not ok then
    -- 极端情况：使用纯默认配置，保证引擎可用
    pcall(load_all, nil, {}, {}, {})
    state.last_error = "配置加载异常: " .. tostring(err)
    util.log_error(state.last_error)
    return false
  end

  state.fp = fingerprint_all()
  state.reload_count = state.reload_count + 1
  if #errors > 0 then
    state.last_error = errors[1]
    -- 缺失文件是常态（未同步站点时），仅记录一次（去重）
    util.log_error("配置加载告警: " .. table.concat(errors, "; "))
  end
  return true
end

-- 测试/宿主直接注入配置表（不读文件）
function config.load_from_tables(global_raw, sites_raw, hosts_raw, custom_raw)
  local ok, err = pcall(load_all, global_raw, sites_raw, hosts_raw, custom_raw)
  if not ok then
    state.last_error = "注入配置异常: " .. tostring(err)
    return false
  end
  -- 建立基线指纹，避免下一次定时器立刻重新读文件覆盖注入配置
  state.fp = fingerprint_all()
  return true
end

-- 定时器调用：文件指纹变化才重载
function config.reload_if_changed()
  if not state.ready then
    return config.init()
  end
  local fresh = fingerprint_all()
  if fp_equal(state.fp, fresh) then
    return false
  end
  local ok = config.init()
  if ok then
    state.reload_count = state.reload_count + 1
  end
  return ok
end

-- 强制重载
function config.reload()
  local ok = config.init()
  return ok
end

-- ---------------------------------------------------------------------------
-- 查询接口
-- ---------------------------------------------------------------------------
function config.ready()
  return state.ready
end

function config.global()
  return state.global
end

-- host -> 站点名（兼容端口、末尾点）
function config.site_name_for_host(host)
  if type(host) ~= "string" or host == "" then
    return nil
  end
  host = host:lower()
  host = host:gsub(":%d+$", "")
  host = host:gsub("%.$", "")
  local name = state.hosts[host]
  if name then
    return name
  end
  -- hosts.json 缺失时，站点名本身可能就是域名
  if state.sites_raw[host] ~= nil then
    return host
  end
  return nil
end

-- 返回合并后的站点配置；未匹配返回 nil
function config.site(host)
  local name = config.site_name_for_host(host)
  if not name then
    return nil
  end
  if state.sites_raw[name] == nil then
    return nil
  end
  return merge_site(name)
end

-- 按站点名取合并配置（面板/自测用）
function config.site_by_name(site_name)
  if type(site_name) ~= "string" or state.sites_raw[site_name] == nil then
    return nil
  end
  return merge_site(site_name)
end

-- 合并后的模块表；site 可为合并配置、站点名或 nil（全局）
function config.modules(site)
  if type(site) == "table" and site.modules then
    return site.modules
  end
  if type(site) == "string" then
    local s = config.site_by_name(site)
    if s then
      return s.modules
    end
  end
  local g = state.global
  if not g then
    g = build_global({})
  end
  return merge_modules(g.modules, nil)
end

-- 适用站点的自定义规则；site 为合并配置（含 custom_rules）或 nil
function config.custom_rules(site)
  if type(site) == "table" then
    return site.custom_rules or {}
  end
  if type(site) == "string" then
    local s = config.site_by_name(site)
    if s then
      return s.custom_rules
    end
    return {}
  end
  -- 全局：仅 custom.json 中 scope=global 的规则
  local out = {}
  local global_rules = type(state.custom_raw) == "table" and state.custom_raw.rules or nil
  if type(global_rules) == "table" then
    for i = 1, #global_rules do
      local r = global_rules[i]
      if type(r) == "table" and rules_mod.applies_to_site(r, "") then
        local item = copy(r)
        item.src = "custom"
        out[#out + 1] = item
      end
    end
  end
  return rules_mod.sort_custom(out)
end

function config.last_error()
  return state.last_error
end

-- 诊断信息（面板/测试用）
function config.stats()
  local site_count = 0
  for _ in pairs(state.sites_raw) do
    site_count = site_count + 1
  end
  local host_count = 0
  for _ in pairs(state.hosts) do
    host_count = host_count + 1
  end
  local custom_count = 0
  if type(state.custom_raw) == "table" and type(state.custom_raw.rules) == "table" then
    custom_count = #state.custom_raw.rules
  end
  return {
    ready = state.ready,
    sites = site_count,
    hosts = host_count,
    custom_rules = custom_count,
    loaded_at = state.loaded_at,
    reload_count = state.reload_count,
    last_error = state.last_error,
    fingerprint = state.fp,
  }
end

-- 测试用：清空状态
function config.reset()
  state.ready = false
  state.global = nil
  state.sites_raw = {}
  state.hosts = {}
  state.custom_raw = {}
  state.merged_cache = {}
  state.fp = nil
  state.last_error = nil
  state.loaded_at = 0
  state.reload_count = 0
  state.tier_override = nil
end

return config
