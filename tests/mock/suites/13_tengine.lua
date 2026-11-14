-- 13-tengine：旧 Lua 模块的 ngx.timer.at 重排与失败/退出处理
local t = require("mock.framework")
t.suite("13-tengine")

local mock = require("mock.ngx")
local json = require("lib.json")
local paths = require("lib.paths")
local config = require("lib.config")
local bootstrap = require("lib.bootstrap")
local util = require("lib.util")

local function with_timer(overrides, fn)
  local original = ngx.timer
  local original_exiting = ngx.worker.exiting
  mock.timers = {}
  mock.clear_logs()
  mock.file_write(paths.error_log(), "")
  util.reset_error_log()
  config.reset()
  bootstrap.reset()
  mock.file_write(paths.config_file(), json.encode({
    enabled = true, sensitivity = 2, cc = { open = false }, attack_block = { open = false },
  }))
  mock.file_write(paths.site_file(), "{}")
  mock.file_write(paths.hosts_file(), "{}")
  mock.file_write(paths.custom_rule_file(), '{"rules":[]}')
  ngx.timer = overrides
  local ok, err = pcall(function()
    assert(load(mock.file_read(paths.LUA_DIR .. "/init.lua"), "@init.lua"))()
    fn()
  end)
  ngx.timer = original
  ngx.worker.exiting = original_exiting
  mock.timers = {}
  t.ok(ok, tostring(err))
end

local timer_at = ngx.timer.at

local function logged(text)
  local data = mock.file_read(paths.error_log())
  return type(data) == "string" and data:find(text, 1, true) ~= nil
end

t.test("没有 every 时注册 at，连续 tick 仍热更新并只保留一个任务", function()
  with_timer({ at = timer_at }, function()
    t.eq(mock.timer_count(), 1)
    t.eq(mock.timers[1].kind, "at")
    t.eq(mock.timers[1].delay, 3)
    mock.file_write(paths.config_file(), json.encode({ enabled = false, sensitivity = 3 }))
    mock.run_timers()
    t.eq(config.global().enabled, false)
    t.eq(config.global().sensitivity, 3)
    t.eq(mock.timer_count(), 1)
    mock.file_write(paths.config_file(), json.encode({ enabled = true, sensitivity = 1 }))
    mock.run_timers()
    t.eq(config.global().enabled, true)
    t.eq(config.global().sensitivity, 1)
    t.eq(mock.timer_count(), 1)
    t.ok(mock.file_exists(paths.perf_file()))
  end)
end)

t.test("every 返回 nil,error 时不能误判成功，应降级到 at", function()
  with_timer({
    every = function() return nil, "no memory" end,
    at = timer_at,
  }, function()
    t.eq(mock.timer_count(), 1)
    t.eq(mock.timers[1].kind, "at")
    t.ok(logged("no memory"))
  end)
end)

t.test("every 抛异常时 at 仍运行", function()
  with_timer({
    every = function() error("every unavailable") end,
    at = timer_at,
  }, function()
    t.eq(mock.timer_count(), 1)
    t.ok(logged("every unavailable"))
    mock.run_timers()
    t.eq(mock.timer_count(), 1)
  end)
end)

t.test("at 排程失败暴露错误，不崩溃也不注册幽灵任务", function()
  with_timer({ at = function() return nil, "process exiting" end }, function()
    t.eq(mock.timer_count(), 0)
    t.ok(logged("定时器排程失败"))
    t.ok(logged("process exiting"))
  end)
end)

t.test("at 重新排程失败会记录错误并停止", function()
  local calls = 0
  with_timer({ at = function(delay, fn)
    calls = calls + 1
    if calls == 1 then
      return timer_at(delay, fn)
    end
    return nil, "too many pending timers"
  end }, function()
    mock.run_timers()
    t.eq(mock.timer_count(), 0)
    t.ok(logged("too many pending timers"))
  end)
end)

t.test("premature 回调不执行 tick，也不重新排程", function()
  with_timer({ at = timer_at }, function()
    mock.file_write(paths.config_file(), json.encode({ enabled = false }))
    mock.run_timers(true)
    t.eq(config.global().enabled, true)
    t.eq(mock.timer_count(), 0)
  end)
end)

t.test("worker 正在退出时不再安排下一个 at", function()
  with_timer({ at = timer_at }, function()
    ngx.worker.exiting = function() return true end
    mock.run_timers()
    t.eq(mock.timer_count(), 0)
  end)
end)

t.test("旧模块缺失或异常的 worker.exiting 不打断 at 重排", function()
  for _, value in ipairs({ false, true, function() error("unsupported") end }) do
    with_timer({ at = timer_at }, function()
      ngx.worker.exiting = value
      mock.run_timers()
      t.eq(mock.timer_count(), 1)
    end)
  end
end)

t.test("没有任何定时器 API 时给出明确错误", function()
  with_timer({}, function()
    t.eq(mock.timer_count(), 0)
    t.ok(logged("定时器 API 不可用"))
  end)
end)
