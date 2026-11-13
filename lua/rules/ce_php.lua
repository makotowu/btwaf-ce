--[[
  btwaf_ce / rules/ce_php.lua -- PHP 代码注入/WebShell（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 933xxx 已覆盖 php-errors/php-function-names 词表与 <?php 标签；
  本文件补充“危险函数 + 用户输入变量”组合、混淆 WebShell 与对象注入。
]]

return {
  meta = { module = "php", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-php-001", module = "php", tier = 1, score = 5,
      name = "eval 执行用户输入",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\beval\\s*\\(\\s*\\$_(?:post|get|request|cookie|server|session|files)",
          negate = false,
        },
      },
      msg = "检测到 eval($_POST) 型 WebShell 代码",
    },
    {
      id = "ce-php-002", module = "php", tier = 1, score = 5,
      name = "assert 执行用户输入",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\bassert\\s*\\(\\s*\\$_(?:post|get|request|cookie|server)",
          negate = false,
        },
      },
      msg = "检测到 assert($_POST) 型 WebShell 代码",
    },
    {
      id = "ce-php-003", module = "php", tier = 1, score = 4,
      name = "preg_replace /e 修饰符执行",
      tags = { "php", "ce", "rce" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "preg_replace\\s*\\(\\s*['\"][^'\"]*/[a-z]*e[a-z]*['\"]",
          negate = false,
        },
      },
      msg = "检测到 preg_replace /e 修饰符（代码执行）",
    },
    {
      id = "ce-php-004", module = "php", tier = 1, score = 4,
      name = "create_function 动态函数",
      tags = { "php", "ce", "obfuscation" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@contains",
          value = "create_function(",
          negate = false,
        },
      },
      msg = "检测到 create_function 动态函数（代码执行）",
    },
    {
      id = "ce-php-005", module = "php", tier = 1, score = 4,
      name = "call_user_func 回连用户输入",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\bcall_user_func(?:_array)?\\s*\\(\\s*\\$_(?:post|get|request|cookie|server)",
          negate = false,
        },
      },
      msg = "检测到 call_user_func($_POST) 动态调用",
    },
    {
      id = "ce-php-006", module = "php", tier = 1, score = 5,
      name = "base64 混淆 + eval 组合",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\beval\\s*\\(\\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 base64/gzinflate + eval 混淆 WebShell",
    },
    {
      id = "ce-php-007", module = "php", tier = 1, score = 5,
      name = "危险函数直接读取超全局变量",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\b(?:system|exec|shell_exec|passthru|popen|proc_open)\\s*\\(\\s*\\$_(?:post|get|request|cookie|server)",
          negate = false,
        },
      },
      msg = "检测到 system/exec 等读取用户输入的 WebShell",
    },
    {
      id = "ce-php-008", module = "php", tier = 1, score = 5,
      name = "include/require 包含用户输入",
      tags = { "php", "ce", "lfi" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\b(?:include|include_once|require|require_once)\\s*\\(?\\s*\\$_(?:post|get|request|cookie|server)",
          negate = false,
        },
      },
      msg = "检测到 include/require 包含用户输入（LFI/RCE）",
    },
    {
      id = "ce-php-009", module = "php", tier = 1, score = 5,
      name = "file_put_contents 写入用户输入",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\bfile_put_contents\\s*\\([^)]*\\$_(?:post|get|request|cookie)",
          negate = false,
        },
      },
      msg = "检测到 file_put_contents 写入用户输入",
    },
    {
      id = "ce-php-010", module = "php", tier = 1, score = 4,
      name = "move_uploaded_file 移动上传",
      tags = { "php", "ce", "upload" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bmove_uploaded_file\\s*\\(\\s*\\$_files",
          negate = false,
        },
      },
      msg = "检测到 move_uploaded_file 上传落盘代码",
    },
    {
      id = "ce-php-011", module = "php", tier = 2, score = 3,
      name = "phpinfo 探测调用",
      tags = { "php", "ce", "probe" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bphpinfo\\s*\\(\\s*\\)",
          negate = false,
        },
      },
      msg = "检测到 phpinfo() 调用探测",
    },
    {
      id = "ce-php-012", module = "php", tier = 1, score = 4,
      name = "反序列化用户输入",
      tags = { "php", "ce", "deserialization" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\bunserialize\\s*\\(\\s*\\$_(?:post|get|request|cookie)",
          negate = false,
        },
      },
      msg = "检测到 unserialize 用户输入（对象注入）",
    },
    {
      id = "ce-php-013", module = "php", tier = 1, score = 4,
      name = "变量覆盖/参数解析注入",
      tags = { "php", "ce", "variable-overwrite" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\b(?:extract|parse_str|import_request_variables)\\s*\\(\\s*\\$_(?:post|get|request)",
          negate = false,
        },
      },
      msg = "检测到变量覆盖（extract/parse_str）",
    },
    {
      id = "ce-php-014", module = "php", tier = 1, score = 4,
      name = "array_map 调用 assert/eval",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\barray_(?:map|filter|reduce)\\s*\\(\\s*['\"](?:assert|eval|system|exec|create_function)['\"]",
          negate = false,
        },
      },
      msg = "检测到 array_map 回调危险函数",
    },
    {
      id = "ce-php-015", module = "php", tier = 1, score = 5,
      name = "PHP 免杀 WebShell 特征",
      tags = { "php", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "\\$_(?:post|get|request)\\s*\\[\\s*['\"][a-z0-9_]{1,8}['\"]\\s*\\]\\s*\\(|\\b(?:preg_replace|assert)\\s*\\(\\s*base64_decode",
          negate = false,
        },
      },
      msg = "检测到免杀 WebShell 调用特征",
    },
  },
}
