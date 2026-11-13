--[[
  btwaf_ce / access.lua
  access_by_lua_file 入口：单请求检测管线（contract §9）。
  阶段顺序：
    站点匹配 → IP 名单 → CC → URL/UA 名单 → protocol 配置检查 → 取参
    → 上传检查 → 规则匹配（matcher，含 transforms/解码）→ 自定义规则
    → 攻击计数 → 决策 → 响应 → 写日志
  性能：
    - 正常 GET 不读 body（pipeline.want_body 判断）；
    - 规则按 module/tier 过滤后再匹配（matcher 内部）；
    - 耗时写共享字典（lib/perf），定时器落盘 perf.json。
  容错：顶层 pcall；fail_open=true（默认）时异常放行，false 时返回 403。
  测试：设置全局 BTWAF_CE_ACCESS_AUTORUN=false 后加载本文件，可手动调用
        _G.btwaf_ce_access()。
]]

-- ---------------------------------------------------------------------------
-- 路径引导（必须在 require("lib.*") 之前）
-- ---------------------------------------------------------------------------
local function setup_package_path()
  local roots = {}
  local override = rawget(_G, "BTWAF_CE_LUA_DIR")
  if type(override) == "string" and override ~= "" then
    roots[#roots + 1] = override
  end
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

-- 安全 require：核心模块加载失败时 fail_open（放行），不抛 500
local function safe_require(name)
  local ok, mod = pcall(require, name)
  if not ok then
    if ngx and ngx.log then
      pcall(ngx.log, ngx.ERR or 4, "btwaf_ce: require " .. name .. " 失败: " .. tostring(mod))
    end
    return nil, tostring(mod)
  end
  return mod
end

local bootstrap = safe_require("lib.bootstrap")
local config = safe_require("lib.config")
local util = safe_require("lib.util")
local pipeline = safe_require("lib.pipeline")
local ipmod = safe_require("lib.ip")
local cc = safe_require("lib.cc")
local matcher = safe_require("lib.matcher")
local rules_mod = safe_require("lib.rules")
local storage = safe_require("lib.storage")
local perf = safe_require("lib.perf")

local CORE_OK = bootstrap and config and util and pipeline and ipmod
  and cc and matcher and rules_mod and storage and perf

if not CORE_OK and ngx and ngx.log then
  pcall(ngx.log, ngx.ERR or 4, "btwaf_ce: 核心模块加载不完整，本次请求放行（fail_open）")
end

-- ---------------------------------------------------------------------------
-- 常量
-- ---------------------------------------------------------------------------
-- sensitivity -> 拦截阈值（§9.4）
local THRESHOLD = { [1] = 10, [2] = 5, [3] = 3 }

-- 允许的 HTTP 方法（其余视为非法请求）
local ALLOWED_METHODS = {
  GET = true, POST = true, HEAD = true, PUT = true,
  DELETE = true, OPTIONS = true, PATCH = true,
}

local DEFAULT_BLOCK_PAGE = [[
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>请求被拦截</title>
<style>body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f7f8fa;color:#222;text-align:center;padding:80px 20px}h1{font-size:28px;margin-bottom:12px}p{color:#666;font-size:14px;line-height:1.8}</style>
</head>
<body><h1>请求被拦截</h1>
<p>您的请求包含不安全的内容，已被安全策略拦截。</p>
<p>如属误拦截，请联系网站管理员。</p>
</body></html>
]]

-- ---------------------------------------------------------------------------
-- 工具
-- ---------------------------------------------------------------------------
local function header_ua(ctx)
  return ctx.headers and ctx.headers["user-agent"] or ""
end

-- 正则匹配（禁用 php 路径等配置项）：优先 PCRE，退化前缀/子串
local function regex_match(text, pattern)
  if type(text) ~= "string" or type(pattern) ~= "string" or pattern == "" then
    return false
  end
  local re = ngx and ngx.re
  if re and re.find then
    local ok, from = pcall(re.find, text, pattern, "jo")
    if ok then
      return from ~= nil
    end
  end
  if pattern:sub(1, 1) == "^" then
    local prefix = pattern:sub(2)
    return prefix ~= "" and text:sub(1, #prefix) == prefix
  end
  return text:find(pattern, 1, true) ~= nil
end

-- URL 名单：~ 开头为正则，^ 开头为前缀，其余为精确或路径前缀
local function match_url_list(uri, list)
  if type(list) ~= "table" or type(uri) ~= "string" then
    return nil
  end
  for i = 1, #list do
    local pat = list[i]
    if type(pat) == "string" and pat ~= "" then
      if pat:sub(1, 1) == "~" then
        if regex_match(uri, pat:sub(2)) then
          return pat
        end
      elseif pat:sub(1, 1) == "^" then
        local prefix = pat:sub(2)
        if prefix ~= "" and uri:sub(1, #prefix) == prefix then
          return pat
        end
      else
        if uri == pat then
          return pat
        end
        if pat:sub(1, 1) == "/" and uri:sub(1, #pat) == pat then
          return pat
        end
      end
    end
  end
  return nil
end

-- UA 名单：大小写不敏感子串
local function match_ua_list(ua, list)
  if type(list) ~= "table" or type(ua) ~= "string" or ua == "" then
    return nil
  end
  local lower_ua = ua:lower()
  for i = 1, #list do
    local pat = list[i]
    if type(pat) == "string" and pat ~= "" then
      if lower_ua:find(pat:lower(), 1, true) then
        return pat
      end
    end
  end
  return nil
end

-- 生成配置类命中（protocol/upload 等非规则文件检测）
local function config_hit(module, rule, name, score)
  return {
    module = module,
    rule = rule,
    name = name,
    score = score or 5,
    tier = 1,
    src = "ce",
  }
end

-- 命中来源：crs > custom > ce
local function rule_source(hits)
  local has_crs = false
  local has_custom = false
  for i = 1, #hits do
    local src = hits[i].src
    if src == "crs" then
      has_crs = true
    elseif src == "custom" then
      has_custom = true
    end
  end
  if has_crs then
    return "crs"
  elseif has_custom then
    return "custom"
  end
  return "ce"
end

-- 从命中/请求中提取 payload 片段（日志 snippet）
local function pick_snippet(ctx)
  if type(ctx.last_match_value) == "string" and ctx.last_match_value ~= "" then
    return util.truncate(util.strip_ctrl(ctx.last_match_value), 512)
  end
  if #ctx.args > 0 then
    return util.truncate(util.strip_ctrl(tostring(ctx.args[1].value or "")), 512)
  end
  return util.truncate(util.strip_ctrl(ctx.query or ""), 512)
end

-- 过滤 param_white 参数（白名单参数不参与规则扫描）
local function filter_param_white(ctx, param_white)
  if type(param_white) ~= "table" or #param_white == 0 or #ctx.args == 0 then
    return
  end
  local white = {}
  for i = 1, #param_white do
    if type(param_white[i]) == "string" then
      white[param_white[i]] = true
    end
  end
  local kept = {}
  for i = 1, #ctx.args do
    local a = ctx.args[i]
    if not white[a.name] then
      kept[#kept + 1] = a
    end
  end
  ctx.args = kept
end

-- ---------------------------------------------------------------------------
-- 决策构造
-- ---------------------------------------------------------------------------
local function make_decision(ctx, opts)
  opts = opts or {}
  return {
    action = opts.action or "block",
    status = tonumber(opts.status) or 403,
    hits = opts.hits or {},
    score = tonumber(opts.score) or 0,
    block_time = tonumber(opts.block_time) or 0,
    rule_source = opts.rule_source or rule_source(opts.hits or {}),
    sensitivity = tonumber(opts.sensitivity) or
      (ctx.site and ctx.site.sensitivity) or 2,
    snippet = opts.snippet or pick_snippet(ctx),
    log = opts.log ~= false,
  }
end

-- ---------------------------------------------------------------------------
-- 主检测逻辑：返回 decision（nil=放行且不记录）
-- ---------------------------------------------------------------------------
local function evaluate(ctx)
  local global = ctx.cfg
  local site = ctx.site
  local lists = site.lists or {}
  local observe = site.observe == true
  local whitelist_first = site.whitelist_first ~= false
  local sensitivity = tonumber(site.sensitivity) or 2
  if sensitivity < 1 then
    sensitivity = 1
  elseif sensitivity > 3 then
    sensitivity = 3
  end
  local block_cfg = site.block or {}
  local status_block = tonumber(block_cfg.status) or 403

  -- 0) 站点开关
  if site.open == false or site.enabled == false then
    return nil
  end

  -- 1) IP 名单（白名单优先可配）
  local ip = ctx.ip
  local remote = ctx.remote_addr
  local ip_white = util.ip_in_list(ip, lists.ip_white)
    or util.ip_in_list(remote, lists.ip_white)
  local ip_black = util.ip_in_list(ip, lists.ip_black)
    or util.ip_in_list(remote, lists.ip_black)
  if whitelist_first and ip_white then
    return nil
  end
  if ip_black then
    if observe then
      return make_decision(ctx, {
        action = "allow", status = 200, hits = {}, score = 0,
        block_time = 0, rule_source = "ce", sensitivity = sensitivity,
        snippet = "",
      })
    end
    return make_decision(ctx, {
      action = "blacklist", status = status_block, hits = {}, score = 0,
      block_time = 0, rule_source = "ce", sensitivity = sensitivity,
    })
  end
  if not whitelist_first and ip_white then
    return nil
  end

  -- 2) CC 限流
  local cc_blocked = cc.check(ctx)
  if cc_blocked and not observe then
    local ccfg = site.cc or {}
    return make_decision(ctx, {
      action = "cc",
      status = tonumber(ccfg.status) or 444,
      hits = {},
      score = 0,
      block_time = tonumber(ccfg.block_time) or 300,
      rule_source = "ce",
      sensitivity = sensitivity,
      snippet = "",
    })
  end

  -- 3) URL / UA 名单
  local ua = header_ua(ctx)
  local url_white = match_url_list(ctx.uri, lists.url_white)
  local url_black = match_url_list(ctx.uri, lists.url_black)
  local ua_white = match_ua_list(ua, lists.ua_white)
  local ua_black = match_ua_list(ua, lists.ua_black)
  if whitelist_first and (url_white or ua_white) then
    return nil
  end
  if url_black or ua_black then
    if observe then
      return make_decision(ctx, {
        action = "allow", status = 200, hits = {}, score = 0,
        block_time = 0, rule_source = "ce", sensitivity = sensitivity,
        snippet = "",
      })
    end
    return make_decision(ctx, {
      action = "blacklist", status = status_block, hits = {}, score = 0,
      block_time = 0, rule_source = "ce", sensitivity = sensitivity,
    })
  end
  if not whitelist_first and (url_white or ua_white) then
    return nil
  end

  -- 4) protocol 配置检查（方法/高危路径/敏感后缀）
  local hits = {}
  local extra_score = 0
  local mods = site.modules or {}
  local protocol_open = mods.protocol == nil or mods.protocol.open ~= false
  if protocol_open then
    local method = (ctx.method or "GET"):upper()
    if not ALLOWED_METHODS[method] then
      hits[#hits + 1] = config_hit("protocol", "ce-config-method", "非法请求方法", 5)
      extra_score = extra_score + 5
    end
    local uri = ctx.uri or "/"
    -- 高危目录（schema: disable_php_path）
    local php_paths = site.disable_php_path or {}
    for i = 1, #php_paths do
      if regex_match(uri, php_paths[i]) then
        hits[#hits + 1] = config_hit("protocol", "ce-config-php-path", "禁止访问的高危目录", 5)
        extra_score = extra_score + 5
        break
      end
    end
    -- 敏感后缀（schema: disable_ext）
    local ext = uri:match("%.([%w]+)$")
    if ext then
      ext = ext:lower()
      local bad_exts = site.disable_ext or {}
      for i = 1, #bad_exts do
        if type(bad_exts[i]) == "string" and bad_exts[i]:lower() == ext then
          hits[#hits + 1] = config_hit("protocol", "ce-config-ext", "禁止访问的文件类型", 5)
          extra_score = extra_score + 5
          break
        end
      end
    end
  end

  -- 5) 取参（按需读 body；GET 无 body 时不读）
  pipeline.collect(ctx, site, { want_body = nil })
  filter_param_white(ctx, lists.param_white)

  -- 6) 上传检查（multipart 文件后缀，schema: upload_ext）
  local upload_open = mods.upload == nil or mods.upload.open ~= false
  if upload_open and #ctx.files > 0 then
    local upload_ext = site.upload_ext or {}
    for i = 1, #ctx.files do
      local fext = ctx.files[i].ext or ""
      for j = 1, #upload_ext do
        if type(upload_ext[j]) == "string" and upload_ext[j]:lower() == fext then
          hits[#hits + 1] = config_hit("upload", "ce-config-upload", "危险文件上传", 5)
          extra_score = extra_score + 5
          break
        end
      end
    end
  end

  -- 7) 规则匹配（module/tier 过滤在 matcher 内完成；transforms 在条件内解码）
  local rule_hits, total = matcher.evaluate(ctx, mods, site.rule_exclude)
  for i = 1, #rule_hits do
    hits[#hits + 1] = rule_hits[i]
  end
  total = (tonumber(total) or 0) + extra_score

  -- 8) 自定义规则（custom.json + 站点内联）
  local forced = nil
  local custom_allow = false
  local custom_rules = site.custom_rules or {}
  for i = 1, #custom_rules do
    local rule = custom_rules[i]
    local ok, matched, err = pcall(rules_mod.eval_custom, ctx, rule)
    if not ok then
      util.log_error("自定义规则执行异常 " .. tostring(rule.id) .. ": " .. tostring(matched))
    elseif err then
      util.log_error("自定义规则配置异常 " .. tostring(rule.id) .. ": " .. tostring(err))
    elseif matched then
      local score = tonumber(rule.score) or 5
      local action = rule.action or "block"
      if action == "allow" then
        custom_allow = true
        break
      end
      local hit = {
        module = "custom",
        rule = tostring(rule.id or ""),
        name = tostring(rule.name or ""),
        score = score,
        tier = 1,
        src = "custom",
      }
      hits[#hits + 1] = hit
      total = total + score
      if action == "block" then
        forced = { status = tonumber(rule.status) or status_block, rule = hit.rule }
      end
    end
  end
  if custom_allow then
    -- 自定义 allow 规则：显式白名单放行
    return nil
  end

  -- 9) 决策：只有“确实要拦截”的攻击请求才累计攻击次数
  --    低分命中但放行的请求（例如数值 IP Host 920350）不计入，避免正常用户被误封。
  local has_hits = #hits > 0
  local threshold = THRESHOLD[sensitivity] or 5
  local rule_block = forced ~= nil or (has_hits and total >= threshold)
  local attack_blocked = false
  if not observe and rule_block then
    local ok, blocked = pcall(cc.add_hit, ctx)
    if ok and blocked then
      attack_blocked = true
    end
  end

  -- 10) 处置
  if observe then
    -- 观察模式：只记录不拦截，也不累计攻击次数
    if has_hits or (ctx.cc and ctx.cc.exceeded) then
      return make_decision(ctx, {
        action = "allow", status = 200, hits = hits, score = total,
        block_time = 0, rule_source = rule_source(hits), sensitivity = sensitivity,
      })
    end
    return nil
  end

  local should_block = rule_block or attack_blocked
  if not should_block then
    if has_hits then
      -- 未达阈值但有命中：记录 allow（§4 action 语义）
      return make_decision(ctx, {
        action = "allow", status = 200, hits = hits, score = total,
        block_time = 0, rule_source = rule_source(hits), sensitivity = sensitivity,
      })
    end
    return nil
  end

  local status = status_block
  local block_time = 0
  if forced then
    status = forced.status
  end
  if attack_blocked then
    block_time = tonumber(site.attack_block and site.attack_block.block_time) or 86400
  end
  return make_decision(ctx, {
    action = "block", status = status, hits = hits, score = total,
    block_time = block_time, rule_source = rule_source(hits), sensitivity = sensitivity,
  })
end

-- ---------------------------------------------------------------------------
-- 响应
-- ---------------------------------------------------------------------------
local function respond(ctx, decision)
  local global = ctx.cfg or {}
  -- 先写日志（ngx.exit 之后 Lua 代码不再执行）
  if decision.log then
    local ok, err = pcall(storage.write_attack, ctx, decision)
    if not ok then
      util.log_error("攻击日志写入异常: " .. tostring(err))
    end
  end

  local action = decision.action
  if action == "block" or action == "cc" or action == "blacklist" then
    local status = tonumber(decision.status) or 403
    if status == 444 then
      -- 444：nginx 直接断开连接，无响应体
      ngx.status = 444
      if ngx.exit then
        pcall(ngx.exit, 444)
      end
      return
    end
    local page = nil
    local block_cfg = global.block or {}
    if block_cfg.use_custom == true then
      page = storage.block_page()
    end
    if type(page) ~= "string" or page == "" then
      page = DEFAULT_BLOCK_PAGE
    end
    ngx.status = status
    if ngx.header then
      ngx.header["Content-Type"] = "text/html; charset=utf-8"
      ngx.header["X-BtWaf-Blocked"] = "1"
    end
    if ngx.say then
      pcall(ngx.say, page)
    end
    if ngx.exit then
      pcall(ngx.exit, status)
    end
  end
end

-- ---------------------------------------------------------------------------
-- 单请求入口
-- ---------------------------------------------------------------------------
local function run()
  if not ngx then
    return
  end
  if not CORE_OK then
    return -- 模块缺失：放行
  end

  -- 引擎初始化（init_worker 已初始化时只是一个布尔判断）
  bootstrap.ensure()

  local global = config.global()
  if not global or global.enabled == false then
    return
  end

  local started = util.now_ms()
  local ctx = pipeline.new(ngx.var, { cfg = global })
  ctx.cfg = global
  -- 使用稳定的请求标识做攻击计数去重：
  -- 1) nginx $request_id（若可用）；2) $connection + $connection_requests（同一请求的
  --    多个 access 阶段相同，下一条请求会递增）；3) 最后才生成随机 ID。
  local request_id = ngx.var and ngx.var.request_id or ""
  local dedupe_id = request_id
  if type(dedupe_id) ~= "string" or dedupe_id == "" then
    local conn = ngx.var and ngx.var.connection or ""
    local conn_req = ngx.var and ngx.var.connection_requests or ""
    if type(conn) == "string" and conn ~= "" and type(conn_req) == "string" and conn_req ~= "" then
      dedupe_id = conn .. ":" .. conn_req
    else
      dedupe_id = storage.new_req_id()
    end
  end
  if type(request_id) ~= "string" or request_id == "" then
    request_id = storage.new_req_id()
  end
  ctx.req_id = request_id
  ctx.dedupe_id = dedupe_id

  local site = config.site(ctx.host)
  ctx.site = site
  local remote = ctx.remote_addr or ""

  -- 未匹配站点：仅全局 IP 黑名单作为安全网，其它一律放行
  if not site then
    ctx.ip = remote
    local lists = global.lists or {}
    local blocked = util.ip_in_list(remote, lists.ip_black)
    if blocked then
      local observe = global.observe == true
      local decision = make_decision(ctx, {
        action = observe and "allow" or "blacklist",
        status = observe and 200 or (tonumber(global.block and global.block.status) or 403),
        hits = {}, score = 0, block_time = 0, rule_source = "ce",
        sensitivity = global.sensitivity or 2, snippet = "",
      })
      -- 性能计数必须在 respond 之前：ngx.exit 之后 Lua 代码不再执行
      pcall(perf.record, util.now_ms() - started, true, not observe)
      respond(ctx, decision)
      return
    end
    pcall(perf.record, util.now_ms() - started, false, false)
    return
  end

  -- 客户端真实 IP（CDN/代理头）
  local client_ip = ipmod.client_ip(ctx.headers, remote, site)
  if type(client_ip) == "string" and client_ip ~= "" then
    ctx.ip = client_ip
  else
    ctx.ip = remote
  end

  -- 主检测
  local decision = evaluate(ctx)

  -- 测试/诊断钩子：仅在显式设置全局表时记录本次决策（生产环境零开销，不改变行为）
  local dbg = rawget(_G, "BTWAF_CE_DEBUG_LAST")
  if type(dbg) == "table" then
    dbg.decision = decision
    dbg.status = decision and decision.status or (ngx.status or 200)
    dbg.action = decision and decision.action or "pass"
    dbg.hits = decision and decision.hits or {}
    dbg.score = decision and decision.score or 0
  end

  -- 性能计数（共享字典；定时器写 perf.json）
  -- 注意：必须放在 respond 之前，否则 ngx.exit 会中止后续 Lua 代码，
  -- 导致 blocked/req 计数永远不更新（真机 perf.json 长时间不刷新的根因）。
  local blocked = decision ~= nil and
    (decision.action == "block" or decision.action == "cc" or decision.action == "blacklist")
  pcall(perf.record, util.now_ms() - started, decision ~= nil, blocked)

  -- 响应 + 日志
  if decision then
    respond(ctx, decision)
  end
end

-- 顶层容错：fail_open 可配
local function safe_run()
  if not CORE_OK then
    return
  end
  local ok, err = pcall(run)
  if ok then
    return
  end
  util.log_error("access 执行异常: " .. tostring(err))
  local global = config.global()
  local fail_open = not (global and global.fail_open == false)
  if not fail_open and ngx then
    -- 失败关闭：返回 403（仅当请求尚未响应）
    local sent = ngx.headers_sent == true
    if not sent then
      pcall(function()
        ngx.status = 403
        if ngx.header then
          ngx.header["Content-Type"] = "text/html; charset=utf-8"
        end
        if ngx.say then
          ngx.say(DEFAULT_BLOCK_PAGE)
        end
        if ngx.exit then
          ngx.exit(403)
        end
      end)
    end
  end
end

-- 暴露给测试/自测；nginx 模式下加载即执行
-- 测试调用入口与 nginx 执行路径保持一致（都经过 safe_run，覆盖 fail_open 语义）
rawset(_G, "btwaf_ce_access", safe_run)
rawset(_G, "btwaf_ce_access_run", run)
rawset(_G, "btwaf_ce_access_evaluate", evaluate)

if rawget(_G, "BTWAF_CE_ACCESS_AUTORUN") ~= false then
  safe_run()
end

return safe_run
