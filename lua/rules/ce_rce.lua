--[[
  btwaf_ce / rules/ce_rce.lua -- 命令执行/模板注入补充（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 932xxx 已覆盖 unix-shell 词表与常见命令拼接；
  本文件补充 JNDI/Log4j、Windows 命令、SSTI 探测、原型链等精确特征。
]]

return {
  meta = { module = "rce", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-rce-001", module = "rce", tier = 1, score = 5,
      name = "JNDI/Log4j2 注入",
      tags = { "rce", "ce", "jndi" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\$\\{\\s*jndi\\s*:\\s*(?:ldaps?|rmi|dns|iiop|corba|nds|http)://",
          negate = false,
        },
      },
      msg = "检测到 JNDI 注入（Log4j2 CVE-2021-44228）",
    },
    {
      id = "ce-rce-002", module = "rce", tier = 1, score = 5,
      name = "JNDI 关键词变体",
      tags = { "rce", "ce", "jndi" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "jndi\\s*:\\s*(?:ldaps?|rmi|dns)://",
          negate = false,
        },
      },
      msg = "检测到 jndi:ldap/rmi/dns 协议载荷",
    },
    {
      id = "ce-rce-003", module = "rce", tier = 1, score = 5,
      name = "SSTI 算术探针",
      tags = { "rce", "ce", "ssti" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "\\{\\{\\s*[0-9]{1,3}\\s*[\\*\\+\\-]\\s*[0-9]{1,3}\\s*\\}\\}|\\$\\{\\s*[0-9]{1,3}\\s*[\\*\\+\\-]\\s*[0-9]{1,3}\\s*\\}|<%=\\s*[0-9]{1,3}\\s*[\\*\\+\\-]\\s*[0-9]{1,3}",
          negate = false,
        },
      },
      msg = "检测到模板引擎算术探针（SSTI）",
    },
    {
      id = "ce-rce-004", module = "rce", tier = 1, score = 5,
      name = "FreeMarker 模板指令注入",
      tags = { "rce", "ce", "ssti" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "<#(?:assign|import|include|list|macro)\\b|\\?new\\s*\\(|\\?api\\b",
          negate = false,
        },
      },
      msg = "检测到 FreeMarker 模板指令注入",
    },
    {
      id = "ce-rce-005", module = "rce", tier = 1, score = 4,
      name = "Windows PowerShell 编码执行",
      tags = { "rce", "ce", "windows" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "powershell(?:\\.exe)?\\s+[^|;\\n]{0,80}(?:-enc|-encodedcommand|-e\\s+[a-z0-9+/=]{20,})|\\b(?:iex|invoke-expression)\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 PowerShell 编码命令执行",
    },
    {
      id = "ce-rce-006", module = "rce", tier = 1, score = 4,
      name = "Windows LOLBin 下载执行",
      tags = { "rce", "ce", "windows" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:certutil\\s+-urlcache|bitsadmin\\s+/transfer|mshta\\s+https?:|regsvr32\\s+/s\\s+/u|rundll32\\s+javascript:)",
          negate = false,
        },
      },
      msg = "检测到 Windows LOLBin 下载执行",
    },
    {
      id = "ce-rce-007", module = "rce", tier = 1, score = 5,
      name = "反弹 Shell 载荷",
      tags = { "rce", "ce", "shell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:/dev/tcp/|bash\\s+-i\\s+>&|nc(?:at)?\\s+-[a-z]*e\\s+/bin/(?:sh|bash)|socat\\s+exec:|mkfifo\\s+/tmp/)",
          negate = false,
        },
      },
      msg = "检测到反弹 Shell 载荷",
    },
    {
      id = "ce-rce-008", module = "rce", tier = 1, score = 4,
      name = "LD_PRELOAD 劫持",
      tags = { "rce", "ce", "privilege" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bld_preload\\s*=|/etc/ld\\.so\\.preload",
          negate = false,
        },
      },
      msg = "检测到 LD_PRELOAD 劫持",
    },
    {
      id = "ce-rce-009", module = "rce", tier = 1, score = 4,
      name = "命令替换符内嵌命令",
      tags = { "rce", "ce", "shell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\$\\(\\s*(?:id|whoami|cat|ls|uname|curl|wget|bash|sh|nc|python|perl)\\b|`\\s*(?:id|whoami|cat|ls|uname|curl|wget)\\b",
          negate = false,
        },
      },
      msg = "检测到命令替换符内嵌系统命令",
    },
    {
      id = "ce-rce-010", module = "rce", tier = 1, score = 5,
      name = "危险文件删除/破坏命令",
      tags = { "rce", "ce", "destructive" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\brm\\s+-[a-z]*r[a-z]*f?\\s+(?:/|\\*|\\.\\.)|\\bmkfs(?:\\.|\\s)|\\bdd\\s+if=/dev/zero\\b",
          negate = false,
        },
      },
      msg = "检测到危险文件删除/破坏命令",
    },
    {
      id = "ce-rce-011", module = "rce", tier = 1, score = 4,
      name = "Node.js child_process 注入",
      tags = { "rce", "ce", "nodejs" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "require\\s*\\(\\s*['\"]child_process['\"]|child_process\\s*\\.\\s*(?:exec|spawn|execSync)",
          negate = false,
        },
      },
      msg = "检测到 Node.js child_process 注入",
    },
    {
      id = "ce-rce-012", module = "rce", tier = 1, score = 4,
      name = "原型链污染",
      tags = { "rce", "ce", "prototype" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" }, { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\"__proto__\"\\s*:|constructor\\s*\"?\\s*:\\s*\\{[^}]*prototype|\\b__proto__\\[",
          negate = false,
        },
      },
      msg = "检测到 JavaScript 原型链污染载荷",
    },
    {
      id = "ce-rce-013", module = "rce", tier = 1, score = 4,
      name = "Python 命令执行注入",
      tags = { "rce", "ce", "python" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:os\\.system|subprocess\\.(?:popen|call|run|check_output)|__import__\\s*\\(\\s*['\"]os)\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 Python 命令执行注入",
    },
    {
      id = "ce-rce-014", module = "rce", tier = 1, score = 4,
      name = "Perl/Ruby 单行命令执行",
      tags = { "rce", "ce", "shell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bperl\\s+-e\\s|\\bruby\\s+-e\\s|\\bpython[0-9.]*\\s+-c\\s",
          negate = false,
        },
      },
      msg = "检测到 Perl/Ruby/Python 单行命令执行",
    },
    {
      id = "ce-rce-015", module = "rce", tier = 1, score = 5,
      name = "Fastjson @type 反序列化",
      tags = { "rce", "ce", "java" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" }, { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\"@type\"\\s*:\\s*\"(?:java\\.|com\\.sun\\.|org\\.apache\\.|javax\\.)",
          negate = false,
        },
      },
      msg = "检测到 Fastjson @type 反序列化载荷",
    },
    {
      id = "ce-rce-016", module = "rce", tier = 1, score = 4,
      name = "Shellshock 环境变量载荷",
      tags = { "rce", "ce", "shellshock" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS" } },
          transforms = {},
          op = "@rx",
          value = "\\(\\)\\s*\\{\\s*:\\s*;\\s*\\}",
          negate = false,
        },
      },
      msg = "检测到 Shellshock（CVE-2014-6271）函数载荷",
    },
    {
      id = "ce-rce-017", module = "rce", tier = 1, score = 4,
      name = "命令拼接执行特征",
      tags = { "rce", "ce", "shell" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:;|\\||&&|%0a)\\s*(?:cat\\s+/etc/|id\\s*;|whoami|uname\\s+-a|curl\\s+http|wget\\s+http)",
          negate = false,
        },
      },
      msg = "检测到命令拼接执行特征",
    },
    {
      id = "ce-rce-018", module = "rce", tier = 2, score = 3,
      name = "环境变量命令分隔绕过",
      tags = { "rce", "ce", "obfuscation" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\$\\{?ifs\\}?|\\$\\{?path\\}?\\s*:",
          negate = false,
        },
      },
      msg = "检测到 $IFS/$PATH 命令分隔绕过",
    },
    {
      id = "ce-rce-019", module = "rce", tier = 1, score = 5,
      name = "Shell 命令分隔符 + 短命令",
      tags = { "rce", "ce", "shell", "cmdi" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:;|\\||&&|%0a|\\n)\\s*(?:id|whoami|uname|pwd|cat|ls|curl|wget|nc|ncat|bash|sh|python|perl|php|sleep|ping|nslookup|dig)(?:[\\s;&|]|$)",
          negate = false,
        },
      },
      msg = "检测到分隔符拼接的短命令执行特征",
    },
  },
}
