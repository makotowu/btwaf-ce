--[[
  btwaf_ce / rules/ce_lfi.lua -- 路径穿越/本地文件包含（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 930100/930110/930120 基于通用穿越正则与 lfi-os-files 词表，
  本文件补充参数语义组合、PHP 包装器协议、XXE 与日志投毒等高置信规则。
]]

return {
  meta = { module = "lfi", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-lfi-001", module = "lfi", tier = 1, score = 5,
      name = "读取 Linux 账号文件",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" }, { type = "REQUEST_HEADERS" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:etc/(?:passwd|shadow|group|gshadow|sudoers)|proc/self/(?:environ|cmdline|fd/))",
          negate = false,
        },
      },
      msg = "尝试读取 /etc/passwd、/proc/self 等系统文件",
    },
    {
      id = "ce-lfi-002", module = "lfi", tier = 1, score = 5,
      name = "读取 Windows 系统文件",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" }, { type = "REQUEST_HEADERS" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:windows\\\\|win\\.ini|boot\\.ini|system32|drivers/etc/hosts)",
          negate = false,
        },
      },
      msg = "尝试读取 Windows 系统敏感文件",
    },
    {
      id = "ce-lfi-003", module = "lfi", tier = 1, score = 5,
      name = "PHP 流包装器协议",
      tags = { "lfi", "ce", "wrapper" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:php://(?:filter|input|stdin|memory)|data://(?:text|application)|expect://|phar://|zip://|compress\\.zlib://)",
          negate = false,
        },
      },
      msg = "使用 PHP 流包装器协议（文件包含/命令执行）",
    },
    {
      id = "ce-lfi-004", module = "lfi", tier = 1, score = 4,
      name = "文件类参数名 + 路径穿越组合",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "file", "path", "filename", "download", "template", "include",
            "page", "doc", "load", "read", "url", "dir", "folder", "src",
          },
          negate = false,
        },
        {
          vars = { { type = "ARGS" } },
          transforms = {},
          op = "@contains",
          value = "../",
          negate = false,
        },
      },
      msg = "文件读取类参数携带 ../ 路径穿越",
    },
    {
      id = "ce-lfi-005", module = "lfi", tier = 1, score = 4,
      name = "反斜杠路径穿越",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = {},
          op = "@contains",
          value = "..\\",
          negate = false,
        },
      },
      msg = "使用 Windows 反斜杠路径穿越",
    },
    {
      id = "ce-lfi-006", module = "lfi", tier = 2, score = 3,
      name = "多层路径穿越",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "normalizePathWin", "lowercase" },
          op = "@rx",
          value = "(?:\\.\\./){3,}",
          negate = false,
        },
      },
      msg = "出现三层以上路径穿越",
    },
    {
      id = "ce-lfi-007", module = "lfi", tier = 1, score = 4,
      name = "包含 Web 服务器/应用日志",
      tags = { "lfi", "ce", "log-poisoning" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:var/log/|wwwlogs/|access\\.log|error\\.log|nginx\\.log|apache2?/)",
          negate = false,
        },
      },
      msg = "尝试包含 Web/系统日志（日志投毒）",
    },
    {
      id = "ce-lfi-008", module = "lfi", tier = 1, score = 4,
      name = "包含临时目录/会话文件",
      tags = { "lfi", "ce", "session" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:/tmp/sess_|/tmp/upload|/var/tmp/|/dev/shm/|php\\.ini)",
          negate = false,
        },
      },
      msg = "尝试包含 /tmp 会话或上传临时文件",
    },
    {
      id = "ce-lfi-009", module = "lfi", tier = 1, score = 5,
      name = "XML 外部实体（XXE）声明",
      tags = { "lfi", "ce", "xxe" },
      chain = {
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "<!entity",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_BODY" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "system",
          negate = false,
        },
      },
      msg = "请求体包含 XML 外部实体声明（XXE）",
    },
    {
      id = "ce-lfi-010", module = "lfi", tier = 1, score = 4,
      name = "请求读取 /etc 系统配置",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:etc/(?:hosts|hostname|resolv\\.conf|issue|motd|crontab|fstab|nginx/|apache2?/))",
          negate = false,
        },
      },
      msg = "尝试读取 /etc 下的系统配置文件",
    },
    {
      id = "ce-lfi-011", module = "lfi", tier = 2, score = 4,
      name = "参数值包含绝对路径敏感目录",
      tags = { "lfi", "ce", "traversal" },
      chain = {
        {
          vars = { { type = "ARGS" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:^|[/\"'=])(?:/root/|/home/[^/\"]+/|/var/www/|/www/wwwroot/|/data/|/usr/local/)",
          negate = false,
        },
      },
      msg = "参数值包含服务器绝对路径",
    },
    {
      id = "ce-lfi-012", module = "lfi", tier = 1, score = 4,
      name = "引用 PHP 配置文件读取",
      tags = { "lfi", "ce", "config" },
      chain = {
        {
          vars = { { type = "ARGS" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:config/(?:database|config|db|app)\\.php|wp-config\\.php|\\.env|application/config)",
          negate = false,
        },
        {
          vars = { { type = "ARGS" } },
          transforms = {},
          op = "@rx",
          value = "\\.\\./|\\.\\.\\\\|/etc/|/var/",
          negate = false,
        },
      },
      msg = "带穿越路径读取应用配置文件",
    },
  },
}
