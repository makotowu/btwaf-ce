--[[
  btwaf_ce / rules/base.lua -- 基础协议卫生规则（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：只保留 CRS 未覆盖或语义不同的“请求行/方法/Host/超长”类基础检查。
  规则格式见 docs/CONTRACT.md §6.13。
]]

return {
  meta = { module = "protocol", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-base-001", module = "protocol", tier = 1, score = 5,
      name = "请求方法包含非法字符",
      tags = { "protocol", "ce", "base" },
      chain = {
        {
          vars = { { type = "REQUEST_METHOD" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "[^a-z0-9-]",
          negate = false,
        },
      },
      msg = "HTTP 方法包含非字母/连字符字符",
    },
    {
      id = "ce-base-002", module = "protocol", tier = 1, score = 5,
      name = "请求行包含控制字符",
      tags = { "protocol", "ce", "base" },
      chain = {
        {
          vars = { { type = "REQUEST_LINE" } },
          transforms = {},
          op = "@rx",
          value = "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]",
          negate = false,
        },
      },
      msg = "请求行包含控制字符（可能的请求走私/注入）",
    },
    {
      id = "ce-base-003", module = "protocol", tier = 1, score = 5,
      name = "URI 包含裸换行或空字节",
      tags = { "protocol", "ce", "base" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = {},
          op = "@rx",
          value = "[\\r\\n\\x00]",
          negate = false,
        },
      },
      msg = "URI 包含裸 CR/LF/NULL",
    },
    {
      id = "ce-base-004", module = "protocol", tier = 1, score = 4,
      name = "Host 头包含非法字符",
      tags = { "protocol", "ce", "base" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "host" } },
          transforms = {},
          op = "@rx",
          value = "[\\s\\r\\n,;<>\"']",
          negate = false,
        },
      },
      msg = "Host 头包含空白/分隔符等非法字符",
    },
    {
      id = "ce-base-005", module = "protocol", tier = 2, score = 3,
      name = "URI 长度超过 2048",
      tags = { "protocol", "ce", "base", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "length" },
          op = "@gt",
          value = "2048",
          negate = false,
        },
      },
      msg = "URI 超长（>2048）",
    },
    {
      id = "ce-base-006", module = "protocol", tier = 2, score = 3,
      name = "参数名长度超过 512",
      tags = { "protocol", "ce", "base", "anomaly" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" } },
          transforms = { "length" },
          op = "@gt",
          value = "512",
          negate = false,
        },
      },
      msg = "参数名超长（>512）",
    },
    {
      id = "ce-base-008", module = "protocol", tier = 2, score = 2,
      name = "请求头名称数量异常",
      tags = { "protocol", "ce", "base", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS_NAMES", count = true } },
          transforms = {},
          op = "@gt",
          value = "64",
          negate = false,
        },
      },
      msg = "请求头数量超过 64",
    },
  },
}
