--[[
  btwaf_ce / rules/ce_protocol.lua -- 协议层异常（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：只补充 CRS 已导入规则未覆盖的编码/头部/走私类检查。
]]

return {
  meta = { module = "protocol", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-protocol-001", module = "protocol", tier = 1, score = 4,
      name = "IIS %uXXXX Unicode 编码规避",
      tags = { "protocol", "ce", "evasion" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "%u[0-9a-f]{4}",
          negate = false,
        },
      },
      msg = "参数或 URI 使用 IIS %uXXXX Unicode 编码",
    },
    {
      id = "ce-protocol-002", module = "protocol", tier = 1, score = 5,
      name = "Overlong UTF-8 编码绕过",
      tags = { "protocol", "ce", "evasion" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "%(?:c0%ae|c0%af|c1%9c|c0%2e|c0%2f)",
          negate = false,
        },
      },
      msg = "检测到 Overlong UTF-8 编码（路径穿越绕过）",
    },
    {
      id = "ce-protocol-003", module = "protocol", tier = 1, score = 4,
      name = "双重 URL 编码路径穿越",
      tags = { "protocol", "ce", "evasion" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "%2(?:e%2e|5c%2e|e2e%2f|e2e%5c)|%252e%252e",
          negate = false,
        },
      },
      msg = "检测到双重 URL 编码的 ../ 路径穿越",
    },
    {
      id = "ce-protocol-004", module = "protocol", tier = 1, score = 5,
      name = "请求头值包含裸 CR/LF",
      tags = { "protocol", "ce", "header-injection" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS" } },
          transforms = {},
          op = "@rx",
          value = "[\\r\\n]",
          negate = false,
        },
      },
      msg = "请求头值包含裸 CR/LF（响应拆分/头注入）",
    },
    {
      id = "ce-protocol-005", module = "protocol", tier = 1, score = 4,
      name = "请求头名称含非法字符",
      tags = { "protocol", "ce", "header-injection" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS_NAMES" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "[^a-z0-9!#$&'*+.^_`|~-]",
          negate = false,
        },
      },
      msg = "请求头名称包含非法字符",
    },
    {
      id = "ce-protocol-006", module = "protocol", tier = 2, score = 4,
      name = "非法 HTTP 协议版本",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_LINE" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "http/(?:0\\.[0-8]|1\\.[2-9]|[2-9]\\.)",
          negate = false,
        },
      },
      msg = "HTTP 协议版本异常",
    },
    {
      id = "ce-protocol-007", module = "protocol", tier = 1, score = 5,
      name = "同时存在 Content-Length 与 Transfer-Encoding",
      tags = { "protocol", "ce", "smuggling" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "transfer-encoding" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "chunked",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_HEADERS", key = "content-length" } },
          transforms = {},
          op = "@rx",
          value = "^[0-9]+$",
          negate = false,
        },
      },
      msg = "同时存在 Transfer-Encoding 与 Content-Length（请求走私）",
    },
    {
      id = "ce-protocol-008", module = "protocol", tier = 2, score = 3,
      name = "multipart/form-data 缺少 boundary",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "content-type" } },
          transforms = { "lowercase", "trim" },
          op = "@streq",
          value = "multipart/form-data",
          negate = false,
        },
      },
      msg = "multipart/form-data 缺少 boundary 参数",
    },
    {
      id = "ce-protocol-009", module = "protocol", tier = 2, score = 3,
      name = "URI 以 // 开头（协议相对跳转探测）",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = {},
          op = "@rx",
          value = "^//",
          negate = false,
        },
      },
      msg = "URI 以 // 开头",
    },
    {
      id = "ce-protocol-010", module = "protocol", tier = 1, score = 4,
      name = "参数包含 %00 空字节",
      tags = { "protocol", "ce", "evasion" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = {},
          op = "@rx",
          value = "%00|\\x00",
          negate = false,
        },
      },
      msg = "参数包含空字节（截断/绕过）",
    },
    {
      id = "ce-protocol-011", module = "protocol", tier = 2, score = 4,
      name = "Cookie 值包含控制字符",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES" } },
          transforms = {},
          op = "@rx",
          value = "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]",
          negate = false,
        },
      },
      msg = "Cookie 值包含控制字符",
    },
    {
      id = "ce-protocol-012", module = "protocol", tier = 2, score = 3,
      name = "X-Forwarded-For 包含注入字符",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "x-forwarded-for" } },
          transforms = {},
          op = "@rx",
          value = "['\"<>;{}]",
          negate = false,
        },
      },
      msg = "X-Forwarded-For 包含非法字符",
    },
    {
      id = "ce-protocol-013", module = "protocol", tier = 2, score = 3,
      name = "Cookie 数量异常",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES_NAMES", count = true } },
          transforms = {},
          op = "@gt",
          value = "64",
          negate = false,
        },
      },
      msg = "Cookie 数量超过 64",
    },
    {
      id = "ce-protocol-014", module = "protocol", tier = 2, score = 3,
      name = "请求体 Content-Type 携带多个 charset",
      tags = { "protocol", "ce", "anomaly" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "content-type" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "charset=[^;]*;.*charset=",
          negate = false,
        },
      },
      msg = "Content-Type 声明多个 charset",
    },
  },
}
