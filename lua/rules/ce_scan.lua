--[[
  btwaf_ce / rules/ce_scan.lua -- 扫描器探测（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 913100（scanners-user-agents.data）去重：只补充国内常用扫描器、
  扫描器探针路径与 WVS/Acunetix 专用标记。
]]

return {
  meta = { module = "scan", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-scan-001", module = "scan", tier = 1, score = 5,
      name = "国内常用扫描器 User-Agent",
      tags = { "scan", "ce", "scanner-ua" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "fscan", "goby", "xray", "vulmap", "pocsuite", "dirsearch",
            "yakit", "zaproxy", "owasp zap", "ffuf", "xray/", "xray ",
            "goby/", "fscan/", "webscan", "lazyxss", "sqlscan", "zmeu",
          },
          negate = false,
        },
      },
      msg = "User-Agent 命中国内常用安全扫描器",
    },
    {
      id = "ce-scan-002", module = "scan", tier = 1, score = 5,
      name = "Acunetix 专用请求头",
      tags = { "scan", "ce", "scanner-fingerprint" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS_NAMES" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "acunetix-aspect", "acunetix-aspect-queries", "acunetix-scan" },
          negate = false,
        },
      },
      msg = "出现 Acunetix 扫描器专用请求头",
    },
    {
      id = "ce-scan-003", module = "scan", tier = 1, score = 5,
      name = "Acunetix WVS 探测路径",
      tags = { "scan", "ce", "scanner-fingerprint" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "acunetix-wvs-test-for-some-inexistent-file",
          negate = false,
        },
      },
      msg = "请求 Acunetix WVS 特征探测路径",
    },
    {
      id = "ce-scan-004", module = "scan", tier = 1, score = 4,
      name = "PHP easter egg 哈希探测",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" }, { type = "ARGS" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "phpe9568f34", "phpe9568f35", "phpe9568f36" },
          negate = false,
        },
      },
      msg = "请求 PHP easter egg 哈希（版本探测扫描）",
    },
    {
      id = "ce-scan-005", module = "scan", tier = 1, score = 4,
      name = "嵌入式设备/路由器扫描探针",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:hnap1|currentsetting\\.htm|setup\\.cgi|boaform/|goform/|gponform/)",
          negate = false,
        },
      },
      msg = "请求嵌入式设备扫描探针路径",
    },
    {
      id = "ce-scan-006", module = "scan", tier = 1, score = 5,
      name = "常见 WebShell 落地路径探测",
      tags = { "scan", "ce", "webshell" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "/shell.php", "/cmd.php", "/c99.php", "/r57.php", "/webshell.php",
            "/1.php", "/x.php", "/muieblackcat", "/backdoor.php",
          },
          negate = false,
        },
      },
      msg = "请求常见 WebShell 文件名",
    },
    {
      id = "ce-scan-007", module = "scan", tier = 1, score = 4,
      name = "Java 中间件管理端点扫描（JMX/WebLogic）",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:jmx-console|wls-wsat|web-console/|invoker/jmxinvokerservlet)",
          negate = false,
        },
      },
      msg = "访问 JBoss/WebLogic 高危管理端点",
    },
    {
      id = "ce-scan-008", module = "scan", tier = 1, score = 4,
      name = "中间件/搜索引擎管理接口探测",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:solr/admin|_cat/indices|_cluster/health|nacos/v1/auth|actuator/(?:env|heapdump|gateway|refresh|shutdown))",
          negate = false,
        },
      },
      msg = "探测中间件/搜索服务管理接口",
    },
    {
      id = "ce-scan-009", module = "scan", tier = 1, score = 4,
      name = "phpMyAdmin 安装目录探测",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "scripts/setup.php",
          negate = false,
        },
      },
      msg = "访问 phpMyAdmin setup 脚本（安装后应删除）",
    },
    {
      id = "ce-scan-010", module = "scan", tier = 2, score = 3,
      name = "通用扫描器标识请求头",
      tags = { "scan", "ce", "scanner-fingerprint" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS_NAMES" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "x-scanner", "x-scan", "x-scan-memo", "x-hacker" },
          negate = false,
        },
      },
      msg = "出现扫描器标识请求头",
    },
    {
      id = "ce-scan-011", module = "scan", tier = 2, score = 4,
      name = "扫描器高频探测文件（WEB-INF/META-INF）",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:web-inf/|meta-inf/)",
          negate = false,
        },
      },
      msg = "尝试读取 WEB-INF/META-INF 受保护元数据",
    },
    {
      id = "ce-scan-012", module = "scan", tier = 1, score = 5,
      name = "漏洞扫描器常见回连标记",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "dnslog.cn", "ceye.io", "burpcollaborator", "interact.sh", "oast.", "dnslog/" },
          negate = false,
        },
      },
      msg = "请求包含扫描器/漏洞验证平台回连域名",
    },
    {
      id = "ce-scan-013", module = "scan", tier = 3, score = 3,
      name = "Tomcat 管理台外部访问",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:manager/html|host-manager/html)",
          negate = false,
        },
      },
      msg = "外部访问 Tomcat manager/host-manager",
    },
    {
      id = "ce-scan-014", module = "scan", tier = 2, score = 4,
      name = "探测 PHP 版本/配置泄露文件",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "/phpinfo.php", "/info.php", "/i.php", "/p.php", "/test.php", "/php_info.php" },
          negate = false,
        },
      },
      msg = "探测 phpinfo 等版本/配置泄露文件",
    },
    {
      id = "ce-scan-015", module = "scan", tier = 1, score = 4,
      name = "扫描器批量探测路径特征（连续 404 目录）",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "/admin.php", "/admin/login.php", "/login.php", "/manager.php",
            "/phpmyadmin/", "/pma/", "/adminer.php", "/mysql/", "/dbadmin/",
          },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_METHOD" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "options", "trace" },
          negate = false,
        },
      },
      msg = "OPTIONS/TRACE 探测管理后台路径",
    },
    {
      id = "ce-scan-016", module = "scan", tier = 1, score = 5,
      name = "扫描器探测 Windows 敏感路径",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:c:\\\\windows\\\\|c:/windows/|win\\.ini|boot\\.ini|system32/)",
          negate = false,
        },
      },
      msg = "探测 Windows 系统敏感文件",
    },
    {
      id = "ce-scan-017", module = "scan", tier = 1, score = 4,
      name = "扫描器常见编码探测参数",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "xss", "sqli", "cmd", "exec", "shell", "upload", "file" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "/test", "/tmp", "/demo", "/example", "/debug" },
          negate = false,
        },
      },
      msg = "测试/演示路径上的攻击类参数名组合",
    },
    {
      id = "ce-scan-018", module = "scan", tier = 2, score = 3,
      name = "扫描器探测 spring/actuator 根路径",
      tags = { "scan", "ce", "probe" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "^/actuator(?:/)?$",
          negate = false,
        },
      },
      msg = "探测 Spring Boot actuator 根路径",
    },
    {
      id = "ce-scan-019", module = "scan", tier = 1, score = 5,
      name = "漏洞扫描器特征查询参数",
      tags = { "scan", "ce", "scanner-fingerprint" },
      chain = {
        {
          vars = { { type = "QUERY_STRING" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "=etc/passwd", "=../../", "=%27", "=1%27", "=1%20or%201=1",
            "=<script>", "=alert(", "=phpinfo(",
          },
          negate = false,
        },
      },
      msg = "查询串包含扫描器批量化攻击探测特征",
    },
    {
      id = "ce-scan-020", module = "scan", tier = 1, score = 4,
      name = "扫描器 UA 与空 Host 组合",
      tags = { "scan", "ce", "scanner-ua" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = { "fscan", "goby", "xray", "vulmap", "pocsuite", "dirsearch", "yakit" },
          negate = false,
        },
        {
          vars = { { type = "REQUEST_HEADERS", key = "host" } },
          transforms = { "trim" },
          op = "@streq",
          value = "",
          negate = false,
        },
      },
      msg = "扫描器 UA 且缺少 Host 头",
    },
  },
}
