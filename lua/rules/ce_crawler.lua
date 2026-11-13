--[[
  btwaf_ce / rules/ce_crawler.lua -- 伪装爬虫（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 只按 UA 词表拦扫描器，不区分搜索引擎爬虫；
  本文件对“声称是搜索引擎爬虫却请求攻击路径/漏洞文件/非 GET”的行为做组合判定。
]]

return {
  meta = { module = "crawler", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-crawler-001", module = "crawler", tier = 1, score = 5,
      name = "伪装百度爬虫访问敏感文件",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "baiduspider",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:\\.git/|\\.env|\\.svn/|wp-admin/|phpmyadmin|adminer|dede/|web-inf/)|(?:^|[/.])(?:backup|www|db|database|dump)[a-z0-9_.-]*\\.(?:zip|rar|sql|tar|gz|bak)$",
          negate = false,
        },
      },
      msg = "伪装百度爬虫访问敏感文件/后台",
    },
    {
      id = "ce-crawler-002", module = "crawler", tier = 1, score = 5,
      name = "伪装搜索引擎爬虫执行攻击",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "baiduspider", "googlebot", "bingbot", "bytespider", "sogou",
            "360spider", "yandex", "duckduckbot", "applebot",
          },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" }, { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "%27|%22|\\b(?:union|select|sleep|benchmark|waitfor)\\b|<\\s*script|\\.\\./|etc/passwd|\\$\\{jndi",
          negate = false,
        },
      },
      msg = "伪装搜索引擎爬虫的请求携带攻击载荷",
    },
    {
      id = "ce-crawler-003", module = "crawler", tier = 1, score = 5,
      name = "伪装爬虫访问后台登录",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "baiduspider", "googlebot", "bingbot", "bytespider", "sogou", "360spider" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:wp-login\\.php|wp-admin/|administrator/|dede/login\\.php|admin/login\\.php|user/login|login\\.php$)",
          negate = false,
        },
      },
      msg = "伪装搜索引擎爬虫请求后台登录页",
    },
    {
      id = "ce-crawler-004", module = "crawler", tier = 2, score = 4,
      name = "伪装爬虫发起非 GET 请求",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "baiduspider", "googlebot", "bingbot", "bytespider", "sogou", "360spider" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_METHOD" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "^(?:post|put|delete|patch)$",
          negate = false,
        },
      },
      msg = "搜索引擎爬虫发起写请求（疑似伪装）",
    },
    {
      id = "ce-crawler-005", module = "crawler", tier = 1, score = 4,
      name = "伪装爬虫探测上传漏洞",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "baiduspider", "googlebot", "bingbot", "bytespider" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:upload|file|attach|editor|ueditor|kindeditor)/",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_METHOD" } },
          transforms = { "lowercase" },
          op = "@streq",
          value = "post",
          negate = false,
        },
      },
      msg = "伪装爬虫向上传接口发起 POST",
    },
    {
      id = "ce-crawler-006", module = "crawler", tier = 2, score = 4,
      name = "伪装爬虫探目录遍历",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "baiduspider", "googlebot", "bingbot", "bytespider", "sogou", "360spider", "yandex" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "normalizePath", "lowercase" },
          op = "@contains",
          value = "../",
          negate = false,
        },
      },
      msg = "伪装搜索引擎爬虫请求路径含 ../",
    },
    {
      id = "ce-crawler-007", module = "crawler", tier = 1, score = 4,
      name = "伪装爬虫请求站点地图探测",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "baiduspider", "googlebot", "bingbot" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:wp-json/wp/v2/users|xmlrpc\\.php|wp-config|setup\\.php)",
          negate = false,
        },
      },
      msg = "伪装爬虫探测 WordPress 敏感接口",
    },
    {
      id = "ce-crawler-008", module = "crawler", tier = 2, score = 3,
      name = "伪装爬虫空 Referer 高频探测",
      tags = { "crawler", "ce", "spoof" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "bytespider", "petalbot", "yisouspider" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:\\.php\\?|\\.asp\\?|\\.jsp\\?|/api/|/admin)",
          negate = false,
        },
      },
      msg = "字节/花瓣等爬虫请求动态接口（疑似采集或探测）",
    },
  },
}
