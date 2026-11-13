--[[
  btwaf_ce / rules/ce_sensitive.lua -- 敏感文件/宝塔场景（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 930120/930130 基于 lfi-os-files/restricted-files 词表，
  本文件补充 .git/.env/备份文件/IDE 配置/面板场景等带路径语义的高置信规则。
]]

return {
  meta = { module = "sensitive", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-sensitive-001", module = "sensitive", tier = 1, score = 5,
      name = "访问 .git 仓库文件",
      tags = { "sensitive", "ce", "scm" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:\\.git/(?:config|head|index|logs|refs|objects|packed-refs)|\\.git$)",
          negate = false,
        },
      },
      msg = "尝试访问 .git 仓库文件",
    },
    {
      id = "ce-sensitive-002", module = "sensitive", tier = 1, score = 5,
      name = "访问 .svn/.hg 版本库文件",
      tags = { "sensitive", "ce", "scm" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:\\.svn/(?:entries|wc\\.db|format)|\\.hg/|\\.bzr/)",
          negate = false,
        },
      },
      msg = "尝试访问 .svn/.hg/.bzr 版本库文件",
    },
    {
      id = "ce-sensitive-003", module = "sensitive", tier = 1, score = 5,
      name = "访问 .env 环境变量文件",
      tags = { "sensitive", "ce", "credential" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:\\.env(?:\\.[a-z0-9_-]+)?(?:$|[/?]))",
          negate = false,
        },
      },
      msg = "尝试访问 .env 环境变量文件",
    },
    {
      id = "ce-sensitive-004", module = "sensitive", tier = 1, score = 4,
      name = "访问系统/IDE 隐藏文件",
      tags = { "sensitive", "ce", "scm" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:\\.ds_store|thumbs\\.db|desktop\\.ini|\\.idea/|\\.vscode/|\\.project$|\\.classpath$)",
          negate = false,
        },
      },
      msg = "尝试访问系统/IDE 隐藏文件",
    },
    {
      id = "ce-sensitive-005", module = "sensitive", tier = 1, score = 5,
      name = "访问编辑器备份/临时文件",
      tags = { "sensitive", "ce", "backup" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "\\.(?:php|jsp|asp|aspx|html?|config|ini|inc|sql|js|css)(?:~|\\.swp|\\.swo|\\.bak|\\.old|\\.orig|\\.save|\\.tmp|\\.copy)$",
          negate = false,
        },
      },
      msg = "尝试访问源码备份/临时文件",
    },
    {
      id = "ce-sensitive-006", module = "sensitive", tier = 1, score = 5,
      name = "下载网站备份压缩包",
      tags = { "sensitive", "ce", "backup" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:www|web|site|html|wwwroot|backup|bak|db|database|dump|data|sql|upload|temp|files)[a-z0-9_.-]*\\.(?:zip|rar|7z|tar\\.gz|tgz|tar|gz|sql|bak|mdb)$",
          negate = false,
        },
      },
      msg = "尝试下载网站备份压缩包/数据库导出文件",
    },
    {
      id = "ce-sensitive-007", module = "sensitive", tier = 2, score = 4,
      name = "访问 SQL 导出文件",
      tags = { "sensitive", "ce", "backup" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "\\.(?:sql|mdb|sqlite|sqlite3)$",
          negate = false,
        },
      },
      msg = "尝试访问数据库导出文件",
    },
    {
      id = "ce-sensitive-008", module = "sensitive", tier = 1, score = 5,
      name = "访问 SSH/云凭证文件",
      tags = { "sensitive", "ce", "credential" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:\\.ssh/|\\.aws/credentials|\\.kube/config|\\.docker/config\\.json|\\.npmrc$|\\.git-credentials$)",
          negate = false,
        },
      },
      msg = "尝试访问 SSH/云平台凭证文件",
    },
    {
      id = "ce-sensitive-009", module = "sensitive", tier = 2, score = 4,
      name = "访问私钥/证书文件",
      tags = { "sensitive", "ce", "credential" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|[a-z0-9_-]+\\.(?:pem|key|p12|pfx))$",
          negate = false,
        },
      },
      msg = "尝试下载私钥/证书文件",
    },
    {
      id = "ce-sensitive-010", module = "sensitive", tier = 1, score = 5,
      name = "访问框架配置文件",
      tags = { "sensitive", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:web\\.config|\\.htaccess|\\.user\\.ini|web\\.xml|app\\.config|php\\.ini)$",
          negate = false,
        },
      },
      msg = "尝试访问框架/服务器配置文件",
    },
    {
      id = "ce-sensitive-011", module = "sensitive", tier = 2, score = 4,
      name = "访问容器/编排配置文件",
      tags = { "sensitive", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:docker-compose\\.ya?ml|dockerfile|compose\\.ya?ml|\\.dockerignore)$",
          negate = false,
        },
      },
      msg = "尝试访问容器/编排配置文件",
    },
    {
      id = "ce-sensitive-012", module = "sensitive", tier = 2, score = 3,
      name = "访问服务器状态页",
      tags = { "sensitive", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:server-status|server-info|nginx_status)$",
          negate = false,
        },
      },
      msg = "尝试访问 Web 服务器状态页",
    },
    {
      id = "ce-sensitive-013", module = "sensitive", tier = 2, score = 3,
      name = "访问 IDE/构建产物目录",
      tags = { "sensitive", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:node_modules/|vendor/|target/classes/|[a-z0-9_-]+\\.iml$|package-lock\\.json$)",
          negate = false,
        },
      },
      msg = "尝试访问依赖/构建产物目录",
    },
    {
      id = "ce-sensitive-014", module = "sensitive", tier = 2, score = 3,
      name = "访问宝塔/面板常见数据文件",
      tags = { "sensitive", "ce", "baota" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "/www/server/", "/www/wwwroot/", "/www/wwwlogs/", "/etc/passwd",
            "/etc/shadow", "/root/.bash_history", "/proc/self/environ",
          },
          negate = false,
        },
      },
      msg = "尝试访问宝塔/服务器本地路径",
    },
    {
      id = "ce-sensitive-015", module = "sensitive", tier = 2, score = 3,
      name = "访问日志文件",
      tags = { "sensitive", "ce", "log" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:access|error|debug|install|mysql|php|slow)\\.log(?:\\.\\d+)?$",
          negate = false,
        },
      },
      msg = "尝试下载服务器/应用日志",
    },
    {
      id = "ce-sensitive-016", module = "sensitive", tier = 1, score = 4,
      name = "访问 WordPress 备份/配置残留",
      tags = { "sensitive", "ce", "wordpress" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:wp-config\\.php\\.(?:bak|old|save|txt|swp)|wp-config\\.php~|\\.maintenance$)",
          negate = false,
        },
      },
      msg = "尝试访问 WordPress 配置备份/维护文件",
    },
    {
      id = "ce-sensitive-017", module = "sensitive", tier = 2, score = 3,
      name = "访问常见数据库管理入口",
      tags = { "sensitive", "ce", "baota" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:mysqladmin/|myadmin/|dbadmin/|adminer\\.php\\?.*(?:server|username)=)",
          negate = false,
        },
      },
      msg = "访问数据库管理工具入口",
    },
    {
      id = "ce-sensitive-018", module = "sensitive", tier = 1, score = 4,
      name = "访问 composer/依赖锁文件泄露",
      tags = { "sensitive", "ce", "config" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:composer\\.(?:json|lock)|yarn\\.lock|package\\.json|requirements\\.txt)$",
          negate = false,
        },
        {
          vars = { { type = "REQUEST_METHOD" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "get", "head" },
          negate = false,
        },
      },
      msg = "公开读取依赖锁文件（信息泄露）",
    },
    {
      id = "ce-sensitive-019", module = "sensitive", tier = 2, score = 4,
      name = "访问 Spring/Druid 监控台",
      tags = { "sensitive", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:druid/index\\.html|druid/sql\\.html|actuator/mappings|actuator/beans|actuator/configprops)",
          negate = false,
        },
      },
      msg = "访问 Spring/Druid 监控台（信息泄露）",
    },
    {
      id = "ce-sensitive-020", module = "sensitive", tier = 1, score = 4,
      name = "访问 PHPUnit eval-stdin 后门路径",
      tags = { "sensitive", "ce", "nday" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "/vendor/phpunit/phpunit/src/util/php/eval-stdin.php",
          negate = false,
        },
      },
      msg = "访问 PHPUnit CVE-2017-9841 后门路径",
    },
    {
      id = "ce-sensitive-021", module = "sensitive", tier = 1, score = 5,
      name = "访问网站备份/导出文件",
      tags = { "sensitive", "ce", "backup", "wordpress" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:[^/]*(?:backup|bak|dump|export|db|database)[^/]*\\.(?:zip|rar|7z|tar\\.gz|tgz|tar|gz|bz2|sql|mdb|bak|old|orig|save|wpress)|(?:ai1wm-backups|updraft|backups?|wp-content/uploads)/[^?]*\\.(?:zip|rar|7z|tar\\.gz|tgz|gz|bz2|sql|bak|old|orig|save|wpress))(?:\\?|$)",
          negate = false,
        },
      },
      msg = "尝试下载网站备份/数据库导出文件",
    },
  },
}
