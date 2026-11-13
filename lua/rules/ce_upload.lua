--[[
  btwaf_ce / rules/ce_upload.lua -- 恶意文件上传（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 933xxx 扫描上传文件内容与 PHP 标签；
  本文件聚焦 multipart 文件名/扩展名策略与图片内嵌脚本等上传语义。
]]

return {
  meta = { module = "upload", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-upload-001", module = "upload", tier = 1, score = 5,
      name = "上传可执行脚本扩展名",
      tags = { "upload", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*\\.(?:php\\d?|pht|phps|phar|phtm|phtml|jsp|jspx|jspf|asp|aspx|asa|asax|cer|cdx|exe|sh|pl|cgi)\"",
          negate = false,
        },
      },
      msg = "上传文件名使用可执行脚本扩展名",
    },
    {
      id = "ce-upload-002", module = "upload", tier = 1, score = 5,
      name = "图片扩展名 + 脚本双扩展名",
      tags = { "upload", "ce", "bypass" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*\\.(?:jpg|jpeg|png|gif|bmp|webp|txt|pdf)\\.(?:php\\d?|phtml|jsp|asp|aspx|sh)\"",
          negate = false,
        },
      },
      msg = "检测到双扩展名上传绕过",
    },
    {
      id = "ce-upload-003", module = "upload", tier = 1, score = 5,
      name = "上传 .htaccess 配置文件",
      tags = { "upload", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*(?:\\.htaccess|\\.htpasswd)\"",
          negate = false,
        },
      },
      msg = "上传 .htaccess/.htpasswd（可改写服务器配置）",
    },
    {
      id = "ce-upload-004", module = "upload", tier = 1, score = 5,
      name = "上传 .user.ini 配置",
      tags = { "upload", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "filename=\".user.ini\"",
          negate = false,
        },
      },
      msg = "上传 .user.ini（可设置 auto_prepend_file）",
    },
    {
      id = "ce-upload-005", module = "upload", tier = 1, score = 4,
      name = "上传 web.config",
      tags = { "upload", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*web\\.config\"",
          negate = false,
        },
      },
      msg = "上传 IIS web.config",
    },
    {
      id = "ce-upload-006", module = "upload", tier = 1, score = 5,
      name = "上传文件名包含路径穿越",
      tags = { "upload", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*(?:\\.\\./|\\.\\.\\\\|/etc/|/var/www/)",
          negate = false,
        },
      },
      msg = "上传文件名包含路径穿越",
    },
    {
      id = "ce-upload-007", module = "upload", tier = 1, score = 5,
      name = "上传文件名空字节截断",
      tags = { "upload", "ce", "evasion" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*(?:%00|%2500|\\\\x00)",
          negate = false,
        },
      },
      msg = "上传文件名使用空字节截断",
    },
    {
      id = "ce-upload-008", module = "upload", tier = 1, score = 5,
      name = "图片上传内嵌 PHP 代码",
      tags = { "upload", "ce", "polyglot" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*\\.(?:jpg|jpeg|png|gif|webp|bmp)\"",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "<?php",
          negate = false,
        },
      },
      msg = "图片上传内容中内嵌 PHP 代码（图片马）",
    },
    {
      id = "ce-upload-009", module = "upload", tier = 1, score = 4,
      name = "SVG 上传内嵌脚本",
      tags = { "upload", "ce", "xss" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*\\.svg\"",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "<script|onload\\s*=|javascript:",
          negate = false,
        },
      },
      msg = "SVG 上传内容包含脚本（存储型 XSS）",
    },
    {
      id = "ce-upload-010", module = "upload", tier = 1, score = 4,
      name = "RFC5987 filename* 可疑扩展名",
      tags = { "upload", "ce", "bypass" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\*\\s*=\\s*(?:utf-8|iso-8859-1)''[^\\r\\n]*\\.(?:php\\d?|phtml|jsp|asp|aspx|sh)",
          negate = false,
        },
      },
      msg = "filename* 编码的文件名包含脚本扩展名",
    },
    {
      id = "ce-upload-011", module = "upload", tier = 1, score = 4,
      name = "IIS 特殊脚本扩展名上传",
      tags = { "upload", "ce", "iis" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"[^\"]*\\.(?:asa|cer|cdx|apl|hxt|stm|shtml)\"",
          negate = false,
        },
      },
      msg = "上传 IIS 可执行扩展名文件",
    },
    {
      id = "ce-upload-012", module = "upload", tier = 2, score = 3,
      name = "上传文件名以点开头（隐藏执行文件）",
      tags = { "upload", "ce", "bypass" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "filename\\s*=\\s*\"\\.(?:php|htaccess|user\\.ini|env)",
          negate = false,
        },
      },
      msg = "上传以点开头的隐藏执行文件",
    },
  },
}
