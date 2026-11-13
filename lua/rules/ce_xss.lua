--[[
  btwaf_ce / rules/ce_xss.lua -- XSS 补充（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 941xxx 覆盖 <script>/onerror/javascript: 等通用向量；
  本文件补充新事件属性、编码绕过、DOM 上下文与模板上下文向量。
]]

return {
  meta = { module = "xss", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-xss-001", module = "xss", tier = 1, score = 4,
      name = "指针类事件属性注入",
      tags = { "xss", "ce", "event-handler" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "\\bon(?:pointerenter|pointerleave|pointerdown|pointerup|pointerover|pointerout|gotpointercapture|lostpointercapture|beforetoggle|toggle|contentvisibilityautostatechange)\\s*=",
          negate = false,
        },
      },
      msg = "检测到指针/新特性事件属性注入",
    },
    {
      id = "ce-xss-002", module = "xss", tier = 1, score = 4,
      name = "base 标签劫持",
      tags = { "xss", "ce", "tag" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "<base\\s[^>]*href\\s*=",
          negate = false,
        },
      },
      msg = "检测到 <base href> 标签注入（base 劫持）",
    },
    {
      id = "ce-xss-003", module = "xss", tier = 1, score = 5,
      name = "iframe srcdoc 注入脚本",
      tags = { "xss", "ce", "tag" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "<iframe[^>]*srcdoc\\s*=[^>]*(?:<script|onerror|onload|javascript:)",
          negate = false,
        },
      },
      msg = "检测到 iframe srcdoc 内嵌脚本",
    },
    {
      id = "ce-xss-004", module = "xss", tier = 1, score = 4,
      name = "meta refresh 跳转 javascript",
      tags = { "xss", "ce", "tag" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "<meta[^>]*http-equiv\\s*=\\s*[\"']?refresh[^>]*javascript:",
          negate = false,
        },
      },
      msg = "检测到 meta refresh 跳转到 javascript:",
    },
    {
      id = "ce-xss-005", module = "xss", tier = 1, score = 4,
      name = "xlink:href javascript 注入",
      tags = { "xss", "ce", "svg" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "xlink:href\\s*=\\s*[\"']?\\s*javascript:",
          negate = false,
        },
      },
      msg = "检测到 xlink:href=javascript: 注入",
    },
    {
      id = "ce-xss-006", module = "xss", tier = 1, score = 5,
      name = "data:text/html 脚本载荷",
      tags = { "xss", "ce", "uri" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "data:text/html\\s*;?[^,]*,",
          negate = false,
        },
      },
      msg = "检测到 data:text/html 内联脚本载荷",
    },
    {
      id = "ce-xss-007", module = "xss", tier = 1, score = 4,
      name = "旧版浏览器 moz-binding 注入",
      tags = { "xss", "ce", "css" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@contains",
          value = "-moz-binding:",
          negate = false,
        },
      },
      msg = "检测到 -moz-binding CSS 注入",
    },
    {
      id = "ce-xss-008", module = "xss", tier = 1, score = 4,
      name = "vbscript 协议注入",
      tags = { "xss", "ce", "protocol" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "[\\s\"'=(]vbscript\\s*:",
          negate = false,
        },
      },
      msg = "检测到 vbscript: 协议注入",
    },
    {
      id = "ce-xss-009", module = "xss", tier = 1, score = 4,
      name = "实体编码 javascript: 绕过",
      tags = { "xss", "ce", "encoding" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "javascript\\s*(?:&colon;|&#(?:0*58|0*x*3a);|&#x3a;)",
          negate = false,
        },
      },
      msg = "检测到实体编码的 javascript: 伪协议",
    },
    {
      id = "ce-xss-010", module = "xss", tier = 1, score = 4,
      name = "Angular 模板注入",
      tags = { "xss", "ce", "csti" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\{\\{[^}]{0,80}(?:constructor|__proto__|\\$eval|\\$apply|ng-|\\[\\\"\\$)",
          negate = false,
        },
      },
      msg = "检测到 AngularJS 客户端模板注入（CSTI）",
    },
    {
      id = "ce-xss-011", module = "xss", tier = 1, score = 4,
      name = "Vue 模板注入",
      tags = { "xss", "ce", "csti" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\{\\{[^}]{0,80}(?:_c\\.|\\$options|\\$el\\.|\\$createelement)",
          negate = false,
        },
      },
      msg = "检测到 Vue 客户端模板注入（CSTI）",
    },
    {
      id = "ce-xss-012", module = "xss", tier = 1, score = 4,
      name = "javascript 伪协议位于属性值",
      tags = { "xss", "ce", "protocol" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "\\b(?:href|src|action|formaction|location|url)\\s*=\\s*[\"']?\\s*javascript:",
          negate = false,
        },
      },
      msg = "检测到属性值中的 javascript: 伪协议",
    },
    {
      id = "ce-xss-013", module = "xss", tier = 1, score = 4,
      name = "expression CSS 注入",
      tags = { "xss", "ce", "css" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "expression\\s*\\(\\s*[^)]*(?:alert|eval|document|window)",
          negate = false,
        },
      },
      msg = "检测到 CSS expression 脚本注入",
    },
    {
      id = "ce-xss-014", module = "xss", tier = 1, score = 5,
      name = "SVG animate 事件注入",
      tags = { "xss", "ce", "svg" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "<(?:animate|set)\\b[^>]*\\bon(?:begin|end|repeat|load)\\s*=",
          negate = false,
        },
      },
      msg = "检测到 SVG animate 事件属性注入",
    },
    {
      id = "ce-xss-015", module = "xss", tier = 1, score = 4,
      name = "form action javascript 注入",
      tags = { "xss", "ce", "tag" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "<form[^>]*\\baction\\s*=\\s*[\"']?\\s*javascript:",
          negate = false,
        },
      },
      msg = "检测到 form action=javascript:",
    },
    {
      id = "ce-xss-016", module = "xss", tier = 1, score = 5,
      name = "DOM 数据外带 sink 组合",
      tags = { "xss", "ce", "dom" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "(?:document\\.(?:cookie|domain|location)|localstorage|sessionstorage)[^\\n]{0,80}(?:fetch|xmlhttprequest|new\\s+image|location\\s*=)",
          negate = false,
        },
      },
      msg = "检测到 DOM 数据外带脚本组合",
    },
    {
      id = "ce-xss-017", module = "xss", tier = 2, score = 3,
      name = "alert/confirm/prompt 弹窗探测",
      tags = { "xss", "ce", "probe" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:alert|confirm|prompt)\\s*\\(\\s*(?:1|\"1\"|'1'|document\\.cookie|window\\.)",
          negate = false,
        },
      },
      msg = "检测到 XSS 弹窗探测代码",
    },
    {
      id = "ce-xss-018", module = "xss", tier = 1, score = 4,
      name = "SVG/MathML 标签注入脚本",
      tags = { "xss", "ce", "svg" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "<(?:svg|math)[^>]*(?:onload|onerror|onbegin|href\\s*=\\s*[\"']?javascript:)",
          negate = false,
        },
      },
      msg = "检测到 SVG/MathML 标签内联脚本",
    },
    {
      id = "ce-xss-019", module = "xss", tier = 1, score = 4,
      name = "Unicode/UTF-7 编码脚本注入",
      tags = { "xss", "ce", "encoding" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:\\+adw-|<\\s*script|%uff1cscript)",
          negate = false,
        },
      },
      msg = "检测到 UTF-7/全角编码的 <script 注入",
    },
    {
      id = "ce-xss-020", module = "xss", tier = 2, score = 3,
      name = "脚本标签拼接绕过",
      tags = { "xss", "ce", "obfuscation" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "removeNulls", "lowercase" },
          op = "@rx",
          value = "<\\s*scr(?:i)?pt[\\s>]|<\\s*/\\s*scr(?:i)?pt",
          negate = false,
        },
      },
      msg = "检测到拆分/空字节混淆的 script 标签",
    },
  },
}
