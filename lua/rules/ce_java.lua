--[[
  btwaf_ce / rules/ce_java.lua -- Java 反序列化/表达式注入（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 944100 已覆盖 java.lang.runtime/processbuilder 与常见 base64 魔数；
  本文件补充 gadget 类名、JNDI Lookup、脚本引擎与 SpEL/OGNL 特征。
]]

return {
  meta = { module = "java", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-java-001", module = "java", tier = 1, score = 5,
      name = "ScriptEngineManager 脚本执行",
      tags = { "java", "ce", "rce" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@contains",
          value = "scriptenginemanager",
          negate = false,
        },
      },
      msg = "检测到 ScriptEngineManager 脚本执行",
    },
    {
      id = "ce-java-002", module = "java", tier = 1, score = 4,
      name = "Class.forName 动态加载类",
      tags = { "java", "ce", "gadget" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "class\\s*\\.\\s*forname\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 Class.forName 动态类加载",
    },
    {
      id = "ce-java-003", module = "java", tier = 1, score = 5,
      name = "Fastjson/Jackson gadget 类名",
      tags = { "java", "ce", "gadget" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "com\\.sun\\.rowset\\.jdbcrowsetimpl|templatesimpl|badattributevalueexp|invokertransformer|chainedtransformer|transformer\\s*\\[",
          negate = false,
        },
      },
      msg = "检测到 Java 反序列化 gadget 类名",
    },
    {
      id = "ce-java-004", module = "java", tier = 1, score = 5,
      name = "Spring 上下文加载 gadget",
      tags = { "java", "ce", "gadget" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@contains",
          value = "filesystemxmlapplicationcontext",
          negate = false,
        },
      },
      msg = "检测到 Spring FileSystemXmlApplicationContext gadget",
    },
    {
      id = "ce-java-005", module = "java", tier = 1, score = 4,
      name = "JNDI InitialContext lookup",
      tags = { "java", "ce", "jndi" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "initialcontext\\s*\\(|\\blookup\\s*\\(\\s*[\"'](?:ldap|rmi|dns)://",
          negate = false,
        },
      },
      msg = "检测到 JNDI InitialContext.lookup",
    },
    {
      id = "ce-java-006", module = "java", tier = 1, score = 4,
      name = "URLClassLoader 远程类加载",
      tags = { "java", "ce", "remote-load" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@contains",
          value = "urlclassloader",
          negate = false,
        },
      },
      msg = "检测到 URLClassLoader 远程类加载",
    },
    {
      id = "ce-java-007", module = "java", tier = 1, score = 4,
      name = "Java 文件读取类调用",
      tags = { "java", "ce", "lfi" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase", "removeWhitespace" },
          op = "@rx",
          value = "java\\.io\\.fileinputstream|files\\.readallbytes|new\\s+java\\.io\\.file\\s*\\(",
          negate = false,
        },
      },
      msg = "检测到 Java 文件读取类调用",
    },
    {
      id = "ce-java-008", module = "java", tier = 1, score = 4,
      name = "SnakeYAML 反序列化",
      tags = { "java", "ce", "deserialization" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" }, { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "!!javax\\.script|!!com\\.sun\\.|snakeyaml",
          negate = false,
        },
      },
      msg = "检测到 SnakeYAML 反序列化载荷",
    },
    {
      id = "ce-java-009", module = "java", tier = 1, score = 5,
      name = "ysoserial/JRMP 利用特征",
      tags = { "java", "ce", "deserialization" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "ysoserial|jrmpclient|jrmplistener|\\bgadget[s]?:",
          negate = false,
        },
      },
      msg = "检测到 ysoserial/JRMP 利用特征",
    },
    {
      id = "ce-java-010", module = "java", tier = 1, score = 4,
      name = "SpEL/OGNL 表达式注入",
      tags = { "java", "ce", "expression" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:t\\(java\\.lang\\.(?:runtime|processbuilder)\\)|new\\s+java\\.lang\\.processbuilder|#context\\[|%\\{[^}]{0,120}(?:runtime|getclass|processbuilder))",
          negate = false,
        },
      },
      msg = "检测到 SpEL/OGNL 表达式注入",
    },
  },
}
