--[[
  tests/mock/framework.lua
  极简 Lua 测试框架：test/ok/eq/... + JSON 结果报告（由 run.mjs 解析）。
  失败断言通过 error(msg) 中止当前用例，由框架记录。
]]

local json = require("lib.json")

local framework = {
  name = "",
  cases = {},
  suite_error = nil,
}

-- 设置当前套件名（用例文件顶部调用：t.suite("01-json")）
function framework.suite(name)
  framework.name = tostring(name or "")
end

function framework.reset(name)
  framework.name = tostring(name or "")
  framework.cases = {}
  framework.suite_error = nil
end

function framework.test(name, fn)
  framework.cases[#framework.cases + 1] = { name = tostring(name), fn = fn }
end

-- ---------------------------------------------------------------------------
-- 断言
-- ---------------------------------------------------------------------------
local function serialize(v, depth)
  depth = depth or 0
  if depth > 3 then
    return tostring(v)
  end
  local tv = type(v)
  if tv == "string" then
    return string.format("%q", v)
  elseif tv == "table" then
    local ok, s = pcall(json.encode, v)
    if ok and s and #s <= 400 then
      return s
    end
    return tostring(v)
  end
  return tostring(v)
end
framework.serialize = serialize

function framework.fail(msg)
  error(tostring(msg), 0)
end

function framework.ok(cond, msg)
  if not cond then
    error("断言失败: " .. tostring(msg or "期望为真"), 0)
  end
end

function framework.not_ok(cond, msg)
  if cond then
    error("断言失败: " .. tostring(msg or "期望为假"), 0)
  end
end

local function deep_equal(a, b, depth)
  depth = depth or 0
  if depth > 8 then
    return false
  end
  if type(a) ~= type(b) then
    return false
  end
  if type(a) ~= "table" then
    return a == b
  end
  local na, nb = 0, 0
  for _ in pairs(a) do na = na + 1 end
  for _ in pairs(b) do nb = nb + 1 end
  if na ~= nb then
    return false
  end
  for k, v in pairs(a) do
    if not deep_equal(v, b[k], depth + 1) then
      return false
    end
  end
  return true
end

framework.deep_equal = deep_equal

function framework.eq(a, b, msg)
  if not deep_equal(a, b) then
    error((msg or "值不相等") .. ": 实际=" .. serialize(a) .. " 期望=" .. serialize(b), 0)
  end
end

function framework.ne(a, b, msg)
  if deep_equal(a, b) then
    error((msg or "值不应相等") .. ": " .. serialize(a), 0)
  end
end

function framework.contains(haystack, needle, msg)
  if type(haystack) ~= "string" or not haystack:find(needle, 1, true) then
    error((msg or "不包含子串") .. ": 期望包含 " .. serialize(needle) ..
      "，实际=" .. serialize(haystack), 0)
  end
end

function framework.not_contains(haystack, needle, msg)
  if type(haystack) == "string" and haystack:find(needle, 1, true) then
    error((msg or "不应包含子串") .. ": " .. serialize(needle), 0)
  end
end

function framework.near(actual, expected, tolerance, msg)
  tolerance = tolerance or 1e-6
  if type(actual) ~= "number" then
    error((msg or "不是数字") .. ": " .. serialize(actual), 0)
  end
  if math.abs(actual - expected) > tolerance then
    error((msg or "数值超出容差") .. ": 实际=" .. actual .. " 期望=" .. expected, 0)
  end
end

-- ---------------------------------------------------------------------------
-- 执行与报告
-- ---------------------------------------------------------------------------
function framework.run()
  local passed, failed = 0, 0
  local failures = {}
  for i = 1, #framework.cases do
    local case = framework.cases[i]
    local ok, err = pcall(case.fn)
    if ok then
      passed = passed + 1
    else
      failed = failed + 1
      failures[#failures + 1] = {
        name = case.name,
        error = tostring(err),
      }
    end
  end
  -- failures 必须编码为 JSON 数组（空数组也输出 []）
  setmetatable(failures, json.array_mt)
  framework.last = {
    suite = framework.name,
    passed = passed,
    failed = failed,
    total = passed + failed,
    failures = failures,
    suite_error = framework.suite_error,
  }
  return framework.last
end

function framework.report_json()
  local report = framework.last
  if not report then
    report = framework.run()
  end
  local ok, s = pcall(json.encode, report)
  if not ok or type(s) ~= "string" then
    return '{"suite":"' .. framework.name .. '","passed":0,"failed":1,"total":1,"failures":[{"name":"report","error":"报告编码失败"}]}'
  end
  return s
end

function framework.set_suite_error(err)
  framework.suite_error = tostring(err)
end

return framework
