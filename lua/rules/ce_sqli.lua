--[[
  btwaf_ce / rules/ce_sqli.lua -- SQL/NoSQL/LDAP 注入补充（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 942xxx 已覆盖通用 UNION/SELECT、引号闭合、注释等模式，
  本文件补充数据库函数族、时间盲注、堆叠语句、NoSQL/LDAP 注入等精确规则。
]]

return {
  meta = { module = "sqli", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-sqli-001", module = "sqli", tier = 1, score = 5,
      name = "时间盲注 sleep/benchmark",
      tags = { "sqli", "ce", "time-based" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" }, { type = "REQUEST_COOKIES" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:sleep|benchmark)\\s*\\(\\s*[0-9]",
          negate = false,
        },
      },
      msg = "检测到 SQL 时间盲注（sleep/benchmark）",
    },
    {
      id = "ce-sqli-002", module = "sqli", tier = 1, score = 5,
      name = "PostgreSQL 时间盲注 pg_sleep",
      tags = { "sqli", "ce", "time-based" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bpg_sleep\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 PostgreSQL pg_sleep 时间盲注",
    },
    {
      id = "ce-sqli-003", module = "sqli", tier = 1, score = 5,
      name = "MSSQL 时间盲注 waitfor delay",
      tags = { "sqli", "ce", "time-based" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bwaitfor\\s+delay\\b",
          negate = false,
        },
      },
      msg = "检测到 MSSQL waitfor delay 时间盲注",
    },
    {
      id = "ce-sqli-004", module = "sqli", tier = 1, score = 4,
      name = "MySQL 报错注入函数 extractvalue/updatexml",
      tags = { "sqli", "ce", "error-based" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:extractvalue|updatexml)\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 MySQL 报错注入函数 usage",
    },
    {
      id = "ce-sqli-005", module = "sqli", tier = 2, score = 3,
      name = "探测 information_schema 元数据",
      tags = { "sqli", "ce", "enumeration" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\binformation_schema\\b",
          negate = false,
        },
      },
      msg = "尝试查询 information_schema 元数据",
    },
    {
      id = "ce-sqli-006", module = "sqli", tier = 1, score = 4,
      name = "数据库版本变量探测",
      tags = { "sqli", "ce", "enumeration" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "@@(?:version|datadir|hostname|servername)",
          negate = false,
        },
      },
      msg = "探测 @@version 等数据库变量",
    },
    {
      id = "ce-sqli-007", module = "sqli", tier = 1, score = 5,
      name = "文件读写注入 load_file/outfile",
      tags = { "sqli", "ce", "file" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bload_file\\s*\\(|\\binto\\s+(?:out|dump)file\\b",
          negate = false,
        },
      },
      msg = "检测到 SQL 文件读写（load_file / INTO OUTFILE）",
    },
    {
      id = "ce-sqli-008", module = "sqli", tier = 2, score = 4,
      name = "堆叠 DDL/DML 注入",
      tags = { "sqli", "ce", "stacked" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = ";\\s*(?:drop|truncate|alter)\\s+(?:table|database)|;\\s*delete\\s+from\\b|;\\s*insert\\s+into\\b",
          negate = false,
        },
      },
      msg = "检测到堆叠 SQL 语句",
    },
    {
      id = "ce-sqli-009", module = "sqli", tier = 1, score = 5,
      name = "MSSQL 命令执行 xp_cmdshell",
      tags = { "sqli", "ce", "rce" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\bxp_cmdshell\\b|\\bsp_executesql\\b|\\bexecute\\s+master\\.",
          negate = false,
        },
      },
      msg = "检测到 MSSQL 命令执行（xp_cmdshell 等）",
    },
    {
      id = "ce-sqli-010", module = "sqli", tier = 2, score = 4,
      name = "char 编码绕过注入",
      tags = { "sqli", "ce", "obfuscation" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:char|chr|ascii|substr|substring)\\s*\\(\\s*[0-9]+\\s*,\\s*[0-9]+",
          negate = false,
        },
      },
      msg = "检测到 char/chr/substr 编码绕过",
    },
    {
      id = "ce-sqli-011", module = "sqli", tier = 1, score = 5,
      name = "NoSQL 注入运算符",
      tags = { "sqli", "ce", "nosql" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "[\"']?\\$(?:where|ne|gt|gte|lt|lte|regex|in|nin|or|and|exists|type)[\"']?\\s*:",
          negate = false,
        },
      },
      msg = "检测到 MongoDB 风格 NoSQL 注入运算符",
    },
    {
      id = "ce-sqli-012", module = "sqli", tier = 1, score = 4,
      name = "MySQL 版本注释绕过",
      tags = { "sqli", "ce", "obfuscation" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "/\\*![0-9]{0,6}",
          negate = false,
        },
      },
      msg = "检测到 MySQL /*! 版本注释",
    },
    {
      id = "ce-sqli-013", module = "sqli", tier = 1, score = 5,
      name = "Oracle 网络/管道函数",
      tags = { "sqli", "ce", "oracle" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:utl_http|utl_inaddr|dbms_pipe|dbms_lock)\\b",
          negate = false,
        },
      },
      msg = "检测到 Oracle 网络/管道函数注入",
    },
    {
      id = "ce-sqli-014", module = "sqli", tier = 1, score = 4,
      name = "数据库敏感函数探测",
      tags = { "sqli", "ce", "enumeration" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:current_user|current_database|system_user|user_name|database)\\s*\\(",
          negate = false,
        },
      },
      msg = "探测数据库当前用户/库名函数",
    },
    {
      id = "ce-sqli-015", module = "sqli", tier = 2, score = 3,
      name = "group_concat/concat 聚合探测",
      tags = { "sqli", "ce", "enumeration" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:group_concat|concat_ws)\\s*\\(|\\bconcat\\s*\\(\\s*(?:0x|[0-9]|char\\s*\\()",
          negate = false,
        },
      },
      msg = "检测到 group_concat/concat 聚合注入",
    },
    {
      id = "ce-sqli-016", module = "sqli", tier = 1, score = 4,
      name = "LDAP 过滤器注入",
      tags = { "sqli", "ce", "ldap" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "\\)\\s*\\(\\s*[|&]\\s*\\(|\\(\\s*[|&]\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 LDAP 过滤器注入模式",
    },
    {
      id = "ce-sqli-017", module = "sqli", tier = 1, score = 5,
      name = "SQL 注入闭合加注释结尾",
      tags = { "sqli", "ce", "termination" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "['\"]\\s*(?:\\)|\\s)*(?:or|and)\\s+['\"]?[0-9]+['\"]?\\s*=\\s*['\"]?[0-9]+",
          negate = false,
        },
      },
      msg = "检测到引号闭合的布尔注入",
    },
    {
      id = "ce-sqli-018", module = "sqli", tier = 2, score = 3,
      name = "SQL 注释截断 payload",
      tags = { "sqli", "ce", "termination" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "['\"]\\s*(?:--|/\\*)\\s*$",
          negate = false,
        },
      },
      msg = "检测到引号后注释截断",
    },
    {
      id = "ce-sqli-019", module = "sqli", tier = 2, score = 3,
      name = "SQL 十六进制/二进制字面量注入",
      tags = { "sqli", "ce", "obfuscation" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:0x[0-9a-f]{16,}|\\bx'[0-9a-f]{16,}'|\\bb'[01]{16,}')",
          negate = false,
        },
      },
      msg = "检测到长十六进制/二进制字面量",
    },
    {
      id = "ce-sqli-020", module = "sqli", tier = 1, score = 4,
      name = "SQL 注入分隔符 + 语句关键字",
      tags = { "sqli", "ce", "stacked" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "[;'\"%]\\s*(?:union\\s+(?:all\\s+)?select\\b|select\\b.{0,40}\\bfrom\\b|update\\s+\\S+\\s+set\\b|insert\\s+into\\s+\\S+|delete\\s+from\\s+\\S+|drop\\s+(?:table|database)\\b)",
          negate = false,
        },
      },
      msg = "检测到分隔符后的 SQL 语句关键字",
    },
    {
      id = "ce-sqli-021", module = "sqli", tier = 1, score = 5,
      name = "SQL 注入专用探测函数组合",
      tags = { "sqli", "ce", "scan" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\b(?:if|case)\\s*\\(.*\\b(?:sleep|benchmark|pg_sleep|waitfor)\\b",
          negate = false,
        },
      },
      msg = "检测到条件时间盲注函数组合",
    },
    {
      id = "ce-sqli-022", module = "sqli", tier = 2, score = 3,
      name = "JSON 体中的数据库报错探测",
      tags = { "sqli", "ce", "json" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "\"(?:\\$)?(?:sql|query|where|filter)\"\\s*:\\s*\"[^\"]*(?:select|union|sleep|benchmark)",
          negate = false,
        },
      },
      msg = "JSON 参数中出现 SQL 关键字",
    },
  },
}
