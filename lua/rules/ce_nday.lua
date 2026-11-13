--[[
  btwaf_ce / rules/ce_nday.lua -- 国内常见 CMS/OA/框架 Nday（自研，本项目 AGPL-3.0）
  origin=btwaf_ce 自研规则
  与 OWASP CRS 去重：CRS 932xxx/933xxx 覆盖通用命令与 PHP 代码注入，
  本文件以“漏洞入口路径 + 利用参数”组合特征识别 ThinkPHP/DedeCMS/PHPCMS/
  泛微/致远/通达/用友/若依/Shiro/Struts2 等 Nday 攻击。
  tags 中的 nday 标记便于按需关闭误报规则。
]]

return {
  meta = { module = "rce", source = "ce", version = "2026.11" },
  rules = {
    {
      id = "ce-nday-001", module = "rce", tier = 1, score = 5,
      name = "ThinkPHP invokefunction 远程执行",
      tags = { "nday", "ce", "thinkphp" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" }, { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "invokefunction|call_user_func_array[^\\n]{0,40}vars\\[",
          negate = false,
        },
      },
      msg = "ThinkPHP invokefunction/call_user_func_array 利用",
    },
    {
      id = "ce-nday-002", module = "rce", tier = 1, score = 5,
      name = "ThinkPHP 5.0.23 _method=__construct",
      tags = { "nday", "ce", "thinkphp" },
      chain = {
        {
          vars = { { type = "QUERY_STRING" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "_method=__construct",
          negate = false,
        },
      },
      msg = "ThinkPHP 5.0.23 _method=__construct 利用",
    },
    {
      id = "ce-nday-003", module = "rce", tier = 1, score = 5,
      name = "ThinkPHP filter 参数注入",
      tags = { "nday", "ce", "thinkphp" },
      chain = {
        {
          vars = { { type = "QUERY_STRING" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "filter(?:\\[[^\\]]*\\])?=(?:system|exec|phpinfo|call_user_func|assert|base64_decode)",
          negate = false,
        },
      },
      msg = "ThinkPHP filter=system 等函数注入",
    },
    {
      id = "ce-nday-004", module = "rce", tier = 1, score = 5,
      name = "ThinkPHP 命名空间路径穿越",
      tags = { "nday", "ce", "thinkphp" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" }, { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "\\\\think\\\\|/think\\\\|think\\\\app|think\\\\request",
          negate = false,
        },
      },
      msg = "URI/参数包含 ThinkPHP 命名空间路径",
    },
    {
      id = "ce-nday-005", module = "rce", tier = 1, score = 5,
      name = "ThinkPHP vars 变量覆盖",
      tags = { "nday", "ce", "thinkphp" },
      chain = {
        {
          vars = { { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "vars\\[\\d+\\]\\s*=",
          negate = false,
        },
      },
      msg = "ThinkPHP vars[N]= 变量覆盖利用",
    },
    {
      id = "ce-nday-006", module = "rce", tier = 1, score = 5,
      name = "DedeCMS recommend.php 任意文件上传",
      tags = { "nday", "ce", "dedecms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "/plus/recommend.php",
          negate = false,
        },
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@contains",
          value = "_files[",
          negate = false,
        },
      },
      msg = "DedeCMS recommend.php 任意文件上传",
    },
    {
      id = "ce-nday-007", module = "rce", tier = 1, score = 5,
      name = "DedeCMS dedesql 类直接访问",
      tags = { "nday", "ce", "dedecms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "/include/dedesql.class.php",
          negate = false,
        },
      },
      msg = "直接访问 DedeCMS dedesql.class.php",
    },
    {
      id = "ce-nday-008", module = "rce", tier = 1, score = 5,
      name = "DedeCMS download.php SSRF/文件读取",
      tags = { "nday", "ce", "dedecms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "plus/download\\.php\\?[^\\n]{0,80}(?:open=1|link=(?:https?|file|ftp|php)://)",
          negate = false,
        },
      },
      msg = "DedeCMS download.php SSRF/文件读取利用",
    },
    {
      id = "ce-nday-009", module = "sqli", tier = 1, score = 5,
      name = "PHPCMS get_menu 后台接口利用",
      tags = { "nday", "ce", "phpcms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "op=get_menu",
          negate = false,
        },
        {
          vars = { { type = "ARGS" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "admin_username",
          negate = false,
        },
      },
      msg = "PHPCMS api.php get_menu 后台越权利用",
    },
    {
      id = "ce-nday-010", module = "sqli", tier = 1, score = 4,
      name = "PHPCMS 参数注入特征",
      tags = { "nday", "ce", "phpcms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "phpcms[/_]|/phpsso_server/|m=member&c=index&a=register[^\\n]{0,80}(?:siteid|modelid)=\\d+['\"]",
          negate = false,
        },
      },
      msg = "PHPCMS 模块路径/参数注入特征",
    },
    {
      id = "ce-nday-011", module = "rce", tier = 1, score = 5,
      name = "PHPCMS v9 后台 getshell 入口",
      tags = { "nday", "ce", "phpcms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:index\\.php\\?m=content&c=create_html&a=public_index|api\\.php\\?op=get_menu)",
          negate = false,
        },
      },
      msg = "PHPCMS 后台 getshell 入口路径",
    },
    {
      id = "ce-nday-012", module = "rce", tier = 1, score = 5,
      name = "用友 NC NCFindWeb 任意文件读取",
      tags = { "nday", "ce", "yonyou" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "ncfindweb|/servlet/~ic/|/uapws/",
          negate = false,
        },
      },
      msg = "用友 NC NCFindWeb/ufida 接口利用",
    },
    {
      id = "ce-nday-013", module = "rce", tier = 1, score = 5,
      name = "泛微 e-cology BeanShell 执行",
      tags = { "nday", "ce", "weaver" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "bsh\\.servlet\\.bshservlet|/weaver/bsh|xmlrpcservlet|/weaver/org\\.apache",
          negate = false,
        },
      },
      msg = "泛微 e-cology BeanShell/XMLRPC 执行",
    },
    {
      id = "ce-nday-014", module = "rce", tier = 1, score = 5,
      name = "泛微 OA 文件上传/SSRF 接口",
      tags = { "nday", "ce", "weaver" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:weaver/|wui/)?(?:getdata\\.jsp|fileupload|ln\\.filedownload|ec/dev/app/getappfile)",
          negate = false,
        },
      },
      msg = "泛微 OA 文件上传/下载接口利用",
    },
    {
      id = "ce-nday-015", module = "rce", tier = 1, score = 5,
      name = "致远 OA htmlofficeservlet 执行",
      tags = { "nday", "ce", "seeyon" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "htmlofficeservlet|autoinstall\\.do\\.css|/seeyon/thirdpartycontroller\\.do|/seeyon/getajaxdata",
          negate = false,
        },
      },
      msg = "致远 OA htmlofficeservlet/autoinstall 利用",
    },
    {
      id = "ce-nday-016", module = "rce", tier = 1, score = 5,
      name = "通达 OA 上传/包含利用",
      tags = { "nday", "ce", "tongda" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:ispirit/im/upload\\.php|mac/gateway\\.php|general/document/index\\.php/|module/appbuilder/)",
          negate = false,
        },
      },
      msg = "通达 OA 上传/包含入口利用",
    },
    {
      id = "ce-nday-017", module = "lfi", tier = 1, score = 5,
      name = "若依 RuoYi 任意文件下载",
      tags = { "nday", "ce", "ruoyi" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "common/download/resource",
          negate = false,
        },
        {
          vars = { { type = "ARGS" }, { type = "REQUEST_URI" } },
          transforms = { "urlDecodeUni" },
          op = "@contains",
          value = "../",
          negate = false,
        },
      },
      msg = "若依 RuoYi 任意文件下载（路径穿越）",
    },
    {
      id = "ce-nday-018", module = "rce", tier = 1, score = 5,
      name = "Laravel Ignition 远程执行",
      tags = { "nday", "ce", "laravel" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "_ignition/execute-solution",
          negate = false,
        },
      },
      msg = "Laravel Ignition CVE-2021-3129 利用",
    },
    {
      id = "ce-nday-019", module = "rce", tier = 1, score = 5,
      name = "Jenkins /script Groovy 执行",
      tags = { "nday", "ce", "jenkins" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "^(?:/jenkins)?/script(?:/)?$",
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
      msg = "访问 Jenkins /script 并提交 POST",
    },
    {
      id = "ce-nday-020", module = "rce", tier = 1, score = 4,
      name = "Struts2 OGNL 表达式利用",
      tags = { "nday", "ce", "struts2" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = ".action",
          negate = false,
        },
        {
          vars = { { type = "ARGS" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "(?:redirect:|%\\{|\\$\\{)",
          negate = false,
        },
      },
      msg = "Struts2 .action 携带 OGNL 表达式",
    },
    {
      id = "ce-nday-021", module = "java", tier = 1, score = 5,
      name = "Shiro rememberMe 反序列化",
      tags = { "nday", "ce", "shiro" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", key = "rememberme" } },
          transforms = { "base64Decode", "lowercase" },
          op = "@rx",
          value = "commons-(?:collections|beanutils|logging)|c3p0|ysoserial|jndi|dnslog|templatesimpl|clonetransformer",
          negate = false,
        },
      },
      msg = "Shiro rememberMe Cookie 反序列化利用",
    },
    {
      id = "ce-nday-022", module = "lfi", tier = 1, score = 5,
      name = "WordPress RevSlider 任意文件读取",
      tags = { "nday", "ce", "wordpress" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "revslider_show_image",
          negate = false,
        },
      },
      msg = "WordPress RevSlider 任意文件读取利用",
    },
    {
      id = "ce-nday-023", module = "rce", tier = 1, score = 5,
      name = "WordPress wp-file-manager 上传执行",
      tags = { "nday", "ce", "wordpress" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@contains",
          value = "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
          negate = false,
        },
      },
      msg = "wp-file-manager CVE-2020-25213 任意文件上传",
    },
    {
      id = "ce-nday-024", module = "rce", tier = 1, score = 5,
      name = "Confluence OGNL 注入",
      tags = { "nday", "ce", "confluence" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/(?:pages/createpage-entervariables|pages/doenterpagevariables|pages/createpage-entervariables)\\.action",
          negate = false,
        },
      },
      msg = "Confluence OGNL 表达式注入（CVE-2021-26084）",
    },
    {
      id = "ce-nday-025", module = "php", tier = 1, score = 5,
      name = "帝国 CMS 后台 getshell 参数",
      tags = { "nday", "ce", "empirecms" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "/e/admin/(?:setpage|editinfo|file)?[a-z]*\\.php[^\\n]{0,80}(?:file=|path=|doecms)",
          negate = false,
        },
      },
      msg = "帝国 CMS 后台文件写入参数",
    },
  },
}
