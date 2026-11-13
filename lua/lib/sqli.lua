--[[
  btwaf_ce / lib/sqli.lua
  v1 轻量 SQL 注入语义分析（contract §6.6）。
  独立实现：SQL 词法切分 + 结构化特征打分，不复制任何第三方检测器代码。
  返回 {detected=bool, score=number, features={...}, name="SQL注入"}。

  设计原则（v1.1，按 libinjection 误报集调优）：
    - 只在出现“结构化信号”时判定：联合查询/时间盲注/强堆叠语句/
      信息探测函数/引号+关键字（或引号+注释+关键字）/带引号的布尔比较；
    - 不靠单词/特殊字符裸计数；普通文本里的引号+井号、英文里的 "; exec ..."
      等不再判定；
    - 多个弱特征累加达到阈值（默认 5）才判定。
]]

local decode = require("lib.decode")

local sqli = {}

-- 强 SQL 关键字（用于“引号+关键字”结构信号；避免 or/and 这类英文常用词）
local DETECT_KEYWORDS = {
  select = true, union = true, insert = true, update = true, delete = true,
  drop = true, create = true, alter = true, truncate = true, declare = true,
  exec = true, execute = true, sleep = true, benchmark = true, pg_sleep = true,
  waitfor = true, load_file = true, outfile = true, dumpfile = true,
  information_schema = true, xp_cmdshell = true, extractvalue = true,
  updatexml = true, geometrycollection = true, version = true, concat = true,
  unhex = true, char = true, ascii = true,
}

-- 词法密度统计用关键字（含常见 SQL 词，仅作为弱特征）
local ALL_KEYWORDS = {
  select = true, union = true, insert = true, update = true, delete = true,
  drop = true, create = true, alter = true, truncate = true, exec = true,
  execute = true, declare = true, from = true, where = true, having = true,
  order = true, group = true, limit = true, offset = true, into = true,
  values = true, set = true, table = true, database = true, schema = true,
  information_schema = true, sleep = true, benchmark = true, waitfor = true,
  delay = true, pg_sleep = true, load_file = true, outfile = true,
  concat = true, char = true, ascii = true, substring = true, mid = true,
  version = true, user = true, current_user = true, xor = true, like = true,
}

-- 堆叠语句：分号后必须跟“SQL 语句形态”（关键字+上下文），避免英文分号误报
local STACK_KEYWORDS = {
  "select", "insert", "update", "delete", "drop", "create",
  "alter", "truncate", "declare", "union", "exec", "execute",
}
local SQL_CONTEXT_WORDS = {
  "table", "from", "into", "where", "values", "set", "database",
  "users", "information_schema", "columns", "passwords", "admin",
}

-- 简单词法切分：返回 token 列表（小写）+ 是否出现注释替代空格的混淆
local function tokenize(s)
  local tokens = {}
  local suspicious_gap = false
  local i = 1
  local len = #s
  while i <= len do
    local c = s:sub(i, i)
    if c:match("[%w_]") then
      local j = i
      while j <= len and s:sub(j, j):match("[%w_]") do
        j = j + 1
      end
      tokens[#tokens + 1] = s:sub(i, j - 1):lower()
      i = j
    elseif c == " " or c == "\t" or c == "\n" or c == "\r" then
      i = i + 1
    elseif c == "/" and s:sub(i + 1, i + 1) == "*" then
      local e = s:find("*/", i + 2, true)
      if e then
        i = e + 2
        suspicious_gap = true
      else
        break
      end
    elseif c == "-" and s:sub(i + 1, i + 1) == "-" then
      local e = s:find("\n", i + 2, true)
      suspicious_gap = true
      i = e and (e + 1) or (len + 1)
    elseif c == "#" then
      local e = s:find("\n", i + 1, true)
      suspicious_gap = true
      i = e and (e + 1) or (len + 1)
    else
      tokens[#tokens + 1] = c
      i = i + 1
    end
  end
  return tokens, suspicious_gap
end

-- 统计关键字（去重）
local function keyword_info(tokens, dict)
  local seen = {}
  local count = 0
  for i = 1, #tokens do
    local t = tokens[i]
    if dict[t] and not seen[t] then
      seen[t] = true
      count = count + 1
    end
  end
  return count, seen
end

local function add_feature(features, name, weight)
  features[#features + 1] = name
  return weight
end

local function has_quote(s)
  return s:find("'", 1, true) ~= nil or s:find('"', 1, true) ~= nil
end

-- 注释标记：-- 、# 、/* */
local function has_comment(lower)
  return lower:find("--", 1, true) ~= nil
    or lower:find("#", 1, true) ~= nil
    or lower:find("/*", 1, true) ~= nil
end

-- 注释规范化（参考 CRS/Coraza 的 replaceComments 思路）：
-- 仅用于 SQL 结构判断，不改变日志/原始请求；/*...*/、-- 行注释、# 行注释
-- 统一替换为空格，避免 "1/**/OR/**/1=1" 被拆成无法匹配的原始串。
local function strip_sql_comments(s)
  local out = {}
  local i = 1
  local len = #s
  while i <= len do
    local c = s:sub(i, i)
    if c == "/" and s:sub(i + 1, i + 1) == "*" then
      local e = s:find("*/", i + 2, true)
      if not e then
        out[#out + 1] = " "
        break
      end
      -- MySQL 可执行注释 /*!50000 ... */：保留内部 SQL，去掉版本号
      if s:sub(i + 2, i + 2) == "!" then
        local inner = s:sub(i + 3, e - 1):gsub("^%d+", "")
        out[#out + 1] = " " .. inner .. " "
      else
        out[#out + 1] = " "
      end
      i = e + 2
    elseif c == "-" and s:sub(i + 1, i + 1) == "-" then
      local nxt = s:sub(i + 2, i + 2)
      -- "1--2" 视为减法；"-- " / "--" / "--\n" 才按行注释处理
      if nxt == "" or nxt:match("%s") or nxt == "-" then
        out[#out + 1] = " "
        local e = s:find("\n", i + 2, true)
        if not e then
          break
        end
        i = e + 1
      else
        out[#out + 1] = c
        i = i + 1
      end
    elseif c == "#" then
      out[#out + 1] = " "
      local e = s:find("\n", i + 1, true)
      if not e then
        break
      end
      i = e + 1
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return (table.concat(out):gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", ""))
end

-- 强堆叠语句：分号 + SQL 语句关键字 + SQL 上下文（表名/括号/引号）
local function stacked_strong(lower)
  for ki = 1, #STACK_KEYWORDS do
    local kw = STACK_KEYWORDS[ki]
    if lower:match(";%s*%f[%w]" .. kw .. "%f[^%w]%s*%(") then
      return true
    end
    if lower:match(";%s*%f[%w]" .. kw .. "%f[^%w]%s*['\"]") then
      return true
    end
    for ci = 1, #SQL_CONTEXT_WORDS do
      local ctxw = SQL_CONTEXT_WORDS[ci]
      if lower:match(";%s*%f[%w]" .. kw .. "%f[^%w]%s+%f[%w]" .. ctxw .. "%f[^%w]") then
        return true
      end
    end
  end
  return false
end

-- 闭合引号后接 SQL 结构（引号前必须是标识符/数字/右括号）：
-- 只认可识别的语句形态，避免书名/产品描述里的 "UNION"、18'; 等误判：
--   1' union [all] select ... / 1' insert into ... / 1' exec( / 1'(
local QUOTE_STMT_KEYWORDS = {
  "insert", "update", "delete", "drop", "exec", "execute", "declare",
}
local QUOTE_STMT_CONTEXT = {
  "table", "into", "from", "where", "set", "values", "database", "users",
}

-- 闭合引号 + union ... select（有界窗口搜索，避免 .- 在长串上回溯）
local function closed_quote_union_select(lower)
  local init = 1
  local count = 0
  while count < 40 do
    local from, to = lower:find("[%w%)]['\"]", init)
    if not from then
      return false
    end
    init = to + 1
    count = count + 1
    local window = lower:sub(to + 1, math.min(#lower, to + 60))
    if window:match("^%s*union%f[^%w]") and window:match("%f[%w]select%f[^%w]") then
      return true
    end
  end
  return false
end

local function quote_keyword_strong(lower)
  -- 闭合引号 + union ... select（两者都是独立词）
  if closed_quote_union_select(lower) then
    return true
  end
  -- 闭合引号 + 语句关键字 + SQL 上下文
  for i = 1, #QUOTE_STMT_KEYWORDS do
    local kw = QUOTE_STMT_KEYWORDS[i]
    local prefix = "[%w%)]['\"]%s*" .. kw .. "%f[^%w]"
    if lower:match(prefix .. "%s*%(") then
      return true
    end
    for ci = 1, #QUOTE_STMT_CONTEXT do
      local ctxw = QUOTE_STMT_CONTEXT[ci]
      if lower:match(prefix .. ".%f[%w]" .. ctxw .. "%f[^%w]") then
        return true
      end
    end
  end
  return false
end

-- 布尔比较：带引号的 ' or '1'='1；无引号但形态明确的 1234 OR 1=1
local function boolean_hit(lower, hasq)
  local ops = { "or", "and" }
  for i = 1, #ops do
    local op = ops[i]
    if hasq then
      if lower:match("%f[%w]" .. op .. "%f[^%w]%s*['\"]?%d+['\"]?%s*=%s*['\"]?%d+") then
        return true
      end
      if lower:match("%f[%w]" .. op .. "%f[^%w]%s+['\"]%w+['\"]%s*=%s*['\"]%w+['\"]") then
        return true
      end
    else
      -- 无引号的恒真比较（CRS 回放语料常见 "1234 OR 1=1"）
      if lower:match("%f[%w]" .. op .. "%f[^%w]%s+%d+%s*=%s*%d+") then
        return true
      end
    end
  end
  return false
end

-- 主分析函数：对原始串与解码变体分别分析，取最高分
function sqli.analyse(str)
  local result = { detected = false, score = 0, features = {}, name = "SQL注入" }
  if type(str) ~= "string" or str == "" then
    return result
  end
  if #str > 8192 then
    str = str:sub(1, 8192)
  end

  -- 长串只分析原文（跳过多层解码变体），控制单请求 CPU
  local candidates
  if #str > 4096 then
    candidates = { str }
  else
    local layers = decode.all_layers(str, 3)
    candidates = { layers.raw }
    for i = 1, #layers.variants do
      candidates[#candidates + 1] = layers.variants[i]
    end
  end

  local best_score = 0
  local best_features = {}
  local seen_candidate = {}

  for ci = 1, #candidates do
    local s = candidates[ci]
    if type(s) == "string" and s ~= "" and not seen_candidate[s] then
      seen_candidate[s] = true
      local score = 0
      local features = {}
      local strong = false
      local lower = s:lower()
      -- 结构判断使用注释规范化后的串；原始 lower 仅保留给 quote_comment 特征
      local norm = strip_sql_comments(lower)
      local tokens = tokenize(s)
      local kw_n = keyword_info(tokens, ALL_KEYWORDS)
      local det_n, det_seen = keyword_info(tokens, DETECT_KEYWORDS)
      local q = has_quote(s)
      local comment = has_comment(lower)

      -- 1) 联合查询：union + select（词边界，忽略混淆空白/注释）
      if norm:match("%f[%w]union%f[^%w]") and norm:match("%f[%w]select%f[^%w]") then
        score = score + add_feature(features, "union_select", 5)
        strong = true
      end

      -- 2) 时间盲注
      if norm:match("%f[%w]sleep%s*%(") or norm:match("%f[%w]benchmark%s*%(")
        or norm:match("%f[%w]pg_sleep%s*%(") or norm:match("waitfor%s+delay") then
        score = score + add_feature(features, "time_based", 5)
        strong = true
      end

      -- 3) 堆叠语句（严格要求 SQL 语句形态）
      if stacked_strong(norm) then
        score = score + add_feature(features, "stacked", 5)
        strong = true
      end

      -- 4) 信息探测 / 报错注入函数
      if norm:find("information_schema", 1, true) or norm:find("@@version", 1, true)
        or norm:find("@@datadir", 1, true) or norm:find("load_file", 1, true)
        or norm:find("into outfile", 1, true) or norm:find("into dumpfile", 1, true)
        or norm:find("xp_cmdshell", 1, true) or norm:find("extractvalue", 1, true)
        or norm:find("updatexml", 1, true) or norm:find("geometrycollection", 1, true)
        or norm:match("%f[%w]version%s*%(%s*%)") then
        score = score + add_feature(features, "info_schema", 4)
        strong = true
      end

      -- 5) 带引号/明确形态的布尔比较
      if boolean_hit(norm, q) then
        score = score + add_feature(features, "boolean_based", 5)
        strong = true
      end

      -- 6) 闭合引号 + SQL 结构（普通英文/书名不含此形态）
      if q and quote_keyword_strong(norm) then
        score = score + add_feature(features, "quote_keyword", 5)
        strong = true
      end

      -- 7) 引号 + 注释：只有同时出现强关键字才算强信号；
      --    否则只是弱信号（普通文本中的 " # 等不判定）
      if q and comment then
        if det_n > 0 then
          score = score + add_feature(features, "quote_comment", 5)
          strong = true
        elseif lower:match("['\"]%s*[-#]%s*$") then
          score = score + add_feature(features, "quote_comment", 3)
        else
          score = score + add_feature(features, "quote_comment", 2)
        end
      end

      -- 8) 裸数字引号注释（短串如 1'-- / 1'#，避免长文本误报）
      if #s <= 16 and lower:match("^%s*%d+%s*['\"]%s*[-#]") then
        score = score + add_feature(features, "quote_comment_bare", 5)
        strong = true
      end

      -- 9) 编码/函数混淆
      if lower:match("0x%x%x%x%x%x%x") or lower:match("char%s*%(%s*%d+%s*,%s*%d+")
        or lower:match("unhex%s*%(") or lower:match("concat%s*%(") then
        score = score + add_feature(features, "encoding_fn", 3)
      end

      -- 10) 注释混淆（MySQL /*! 版本注释 / 成对块注释）
      if lower:find("/*!", 1, true)
        or (lower:find("/*", 1, true) and lower:find("*/", 1, true)) then
        score = score + add_feature(features, "comment_evasion", 2)
      end

      -- 11) 引号不平衡（弱信号，仅用于累加）
      local single, double = 0, 0
      for si = 1, #s do
        local c = s:sub(si, si)
        if c == "'" then
          single = single + 1
        elseif c == '"' then
          double = double + 1
        end
      end
      if single % 2 == 1 or double % 2 == 1 then
        score = score + add_feature(features, "quote_imbalance", 1)
      end

      -- 12) 关键字密度（弱信号：需要标点/引号上下文）
      local has_punct = s:find("'", 1, true) or s:find('"', 1, true)
        or s:find(";", 1, true) or s:find("(", 1, true)
      if kw_n >= 3 and has_punct then
        score = score + add_feature(features, "keyword_density", 3)
      elseif kw_n >= 5 then
        score = score + add_feature(features, "keyword_density", 1)
      end

      -- 13) 参数逃逸（id=1'）
      if lower:match("=%s*%d+['\"]") then
        score = score + add_feature(features, "param_escape", 2)
      end

      if strong then
        score = math.max(score, 5)
      end
      if score > best_score then
        best_score = score
        best_features = features
      end
    end
  end

  result.score = best_score
  result.features = best_features
  result.detected = best_score >= 5
  return result
end

return sqli
