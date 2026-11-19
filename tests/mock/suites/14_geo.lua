-- 14-geo：离线地区匹配、配置与失败降级
local t = require("mock.framework")
t.suite("14-geo")

local mock = require("mock.ngx")
local paths = require("lib.paths")
local geo = require("lib.geo")
local config = require("lib.config")
local json = require("lib.json")

local function write_ranges()
  mock.file_write(paths.geo_file(), table.concat({
    "# test fixture",
    "1.2.3.0 1.2.3.255",
    "114.114.114.0 114.114.114.255",
  }, "\n") .. "\n")
  mock.file_write(paths.geo_meta_file(), '{"source":"fixture","records":2}')
  __BTWAF_FS_REMOVE(paths.geo_custom_file())
  geo.reset()
end

local function write_custom(include, exclude)
  mock.file_write(paths.geo_custom_file(), json.encode({
    version = 1,
    include = include or {},
    exclude = exclude or {},
  }))
  geo.reset()
end

t.test("CN/OTHER/PRIVATE/UNKNOWN 分类", function()
  write_ranges()
  t.eq(geo.region("1.2.3.4"), "CN")
  t.eq(geo.region("114.114.114.114"), "CN")
  t.eq(geo.region("8.8.8.8"), "OTHER")
  t.eq(geo.region("10.1.2.3"), "PRIVATE")
  t.eq(geo.region("127.0.0.1"), "PRIVATE")
  t.eq(geo.region("2001:db8::1"), "UNKNOWN")
  t.eq(geo.region("bad"), "UNKNOWN")
end)

t.test("allow/block 模式与 unknown 策略", function()
  write_ranges()
  local allow = { open = true, mode = "allow", regions = { "CN" }, unknown = "allow" }
  local block = { open = true, mode = "block", regions = { "CN" }, unknown = "allow" }
  t.eq(geo.check("1.2.3.4", allow).blocked, false)
  t.eq(geo.check("8.8.8.8", allow).blocked, true)
  t.eq(geo.check("10.1.2.3", allow).blocked, false)
  allow.unknown = "block"
  t.eq(geo.check("10.1.2.3", allow).blocked, true)
  t.eq(geo.check("1.2.3.4", block).blocked, true)
  t.eq(geo.check("8.8.8.8", block).blocked, false)
  t.eq(geo.check("1.2.3.4", { open = false, mode = "allow" }), nil)
end)

t.test("数据缺失时 fail-open", function()
  __BTWAF_FS_REMOVE(paths.geo_file())
  geo.reset()
  t.eq(geo.available(), false)
  t.eq(geo.check("1.2.3.4", { open = true, mode = "allow", unknown = "allow" }), nil)
end)

t.test("站点 geo 继承和覆盖", function()
  config.load_from_tables(
    { enabled = true, geo = { open = true, mode = "allow", regions = { "CN" }, unknown = "allow", status = 403 } },
    { ["www.example.com"] = { open = true, geo = { mode = "block", status = 404 } } },
    { ["www.example.com"] = "www.example.com" },
    { rules = {} }
  )
  local site = config.site("www.example.com")
  t.eq(site.geo.open, true)
  t.eq(site.geo.mode, "block")
  t.eq(site.geo.status, 404)

  config.load_from_tables(
    { enabled = true, geo = { open = true, mode = "allow", regions = { "CN" }, unknown = "allow", status = 403 } },
    { ["www.example.com"] = { open = true, geo = { open = false } } },
    { ["www.example.com"] = "www.example.com" },
    { rules = {} }
  )
  t.eq(config.site("www.example.com").geo.open, false)
end)

t.test("自定义中国 IP 段：补充与排除", function()
  write_ranges()
  write_custom(
    { { ["start"] = "8.8.8.0", ["end"] = "8.8.8.255" } },
    { { ["start"] = "1.2.3.128", ["end"] = "1.2.3.255" } }
  )
  t.eq(geo.region("8.8.8.8"), "CN")
  t.eq(geo.region("1.2.3.4"), "CN")
  t.eq(geo.region("1.2.3.200"), "OTHER")
  t.eq(geo.region("114.114.114.114"), "CN")
end)

t.test("自定义中国 IP 段：排除优先", function()
  write_ranges()
  write_custom(
    { { ["start"] = "1.2.3.0", ["end"] = "1.2.3.255" } },
    { { ["start"] = "1.2.3.0", ["end"] = "1.2.3.255" } }
  )
  t.eq(geo.region("1.2.3.4"), "OTHER")
end)

t.test("自定义中国 IP 段：文件损坏回退内置数据", function()
  write_ranges()
  mock.file_write(paths.geo_custom_file(), "{bad json")
  geo.reset()
  t.eq(geo.region("1.2.3.4"), "CN")
  t.eq(geo.region("8.8.8.8"), "OTHER")
end)
