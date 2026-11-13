-- origin=OWASP CRS v4.30.0 https://github.com/coreruleset/coreruleset (Apache-2.0)
-- generated_by=tools/import_crs.py from REQUEST-944-APPLICATION-ATTACK-JAVA.conf  DO NOT EDIT
-- module=java  rules=11

return {
  meta = {
    module = "java",
    source = "crs",
    crs_version = "4.30.0",
    file = "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
    generated_by = "tools/import_crs.py",
  },
  rules = {
    {
      id = "crs-944100", module = "java", tier = 1, score = 5, src = "crs",
      name = "Remote Command Execution: Suspicious Java class detected",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/137/6" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "java\\.lang\\.(?:runtime|processbuilder)",
          negate = false,
        },
      },
      status = 403,
      msg = "Remote Command Execution: Suspicious Java class detected",
    },
    {
      id = "crs-944130", module = "java", tier = 1, score = 5, src = "crs",
      name = "Suspicious Java class detected",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_FILENAME" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "classloader", "com.opensymphony.xwork2", "com.sun.org.apache", "declaredclass", "freemarker.core", "freemarker.ext.rhino",
            "freemarker.template", "java.beans.xmldecode", "java.io.bufferedinputstream", "java.io.bufferedreader", "java.io.bytearrayinputstream", "java.io.bytearrayoutputstream",
            "java.io.chararrayreader", "java.io.datainputstream", "java.io.file", "java.io.fileoutputstream", "java.io.filepermission", "java.io.filewriter",
            "java.io.filterinputstream", "java.io.filteroutputstream", "java.io.filterreader", "java.io.inputstream", "java.io.ioexception", "java.io.linenumberreader",
            "java.io.objectinputstream", "java.io.objectoutputstream", "java.io.outputstream", "java.io.pipedoutputstream", "java.io.pipedreader", "java.io.printstream",
            "java.io.pushbackinputstream", "java.io.reader", "java.io.stringreader", "java.lang.class", "java.lang.enum", "java.lang.integer",
            "java.lang.number", "java.lang.object", "java.lang.process", "java.lang.processbuilder", "java.lang.reflect", "java.lang.runtime",
            "java.lang.string", "java.lang.system", "java.net.datagramsocket", "java.net.httpurlconnection", "java.net.jarurlconnection", "java.net.multicastsocket",
            "java.net.serversocket", "java.net.socket", "java.net.url", "java.nio.file", "javassist", "javax.naming.initialcontext",
            "javax.script.scriptenginemanager", "javax.xml.parsers", "javax.xml.stream", "ognlcontext", "ognlutil", "org.apache.commons",
            "org.apache.struts", "org.apache.struts2", "org.dom4j.io.saxreader", "org.jdom2.input.saxbuilder", "org.omg.corba", "org.xml.sax",
            "propertyutilsbean", "sun.reflect",
          },
          ac_list = "java-classes",
          negate = false,
        },
      },
      status = 403,
      msg = "Suspicious Java class detected",
    },
    {
      id = "crs-944140", module = "java", tier = 1, score = 5, src = "crs",
      name = "Java Injection Attack: Java Script File Upload Found",
      tags = { "application-multi", "language-java", "platform-multi", "attack-injection-java", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "FILES", parse = { "all" } }, { type = "REQUEST_HEADERS", parse = { "all" }, key = "x-filename" }, { type = "REQUEST_HEADERS", parse = { "all" }, key = "x_filename" }, { type = "REQUEST_HEADERS", parse = { "all" }, key = "x.filename" }, { type = "REQUEST_HEADERS", parse = { "all" }, key = "x-file-name" } },
          transforms = { "lowercase", "removeWhitespace" },
          op = "@rx",
          value = ".*\\.(?:jsp|jspx)[./]*$",
          negate = false,
        },
      },
      status = 403,
      msg = "Java Injection Attack: Java Script File Upload Found",
    },
    {
      id = "crs-944150", module = "java", tier = 1, score = 5, src = "crs",
      name = "Potential Remote Command Execution: Log4j / Log4shell",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/137/6" },
      chain = {
        {
          vars = { { type = "REQUEST_LINE" }, { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "urlDecodeUni", "jsDecode", "htmlEntityDecode" },
          op = "@rx",
          value = "(?i)(?:\\$|&dollar;?)(?:\\{|&l(?:brace|cub);?)(?:[^\\}]{0,15}(?:\\$|&dollar;?)(?:\\{|&l(?:brace|cub);?)|jndi|ctx)",
          negate = false,
        },
      },
      status = 403,
      msg = "Potential Remote Command Execution: Log4j / Log4shell",
    },
    {
      id = "crs-944151", module = "java", tier = 2, score = 5, src = "crs",
      name = "Potential Remote Command Execution: Log4j / Log4shell",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/137/6" },
      chain = {
        {
          vars = { { type = "REQUEST_LINE" }, { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "urlDecodeUni", "jsDecode", "htmlEntityDecode" },
          op = "@rx",
          value = "(?i)(?:\\$|&dollar;?)(?:\\{|&l(?:brace|cub);?)(?:[^\\}]*(?:\\$|&dollar;?)(?:\\{|&l(?:brace|cub);?)|jndi|ctx)",
          negate = false,
        },
      },
      status = 403,
      msg = "Potential Remote Command Execution: Log4j / Log4shell",
    },
    {
      id = "crs-944200", module = "java", tier = 2, score = 5, src = "crs",
      name = "Magic bytes Detected, probable java serialization in use",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "\\xac\\xed\\x00\\x05",
          negate = false,
        },
      },
      status = 403,
      msg = "Magic bytes Detected, probable java serialization in use",
    },
    {
      id = "crs-944210", module = "java", tier = 2, score = 5, src = "crs",
      name = "Magic bytes Detected Base64 Encoded, probable java serialization in use",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "(?:rO0ABQ|KztAAU|Cs7QAF)",
          negate = false,
        },
      },
      status = 403,
      msg = "Magic bytes Detected Base64 Encoded, probable java serialization in use",
    },
    {
      id = "crs-944240", module = "java", tier = 2, score = 5, src = "crs",
      name = "Remote Command Execution: Java serialization (CVE-2015-4852)",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "(?:clonetransform|xmldecod)er|f(?:orclosure|ilewriter)|in(?:stantiate(?:factory|transformer)|vokertransformer)|(?:prototype(?:clone|serialization)factor|getpropert)y|whileclosure",
          negate = false,
        },
      },
      status = 403,
      msg = "Remote Command Execution: Java serialization (CVE-2015-4852)",
    },
    {
      id = "crs-944250", module = "java", tier = 2, score = 5, src = "crs",
      name = "Remote Command Execution: Suspicious Java method detected",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "java\\b.+(?:runtime|processbuilder)",
          negate = false,
        },
      },
      status = 403,
      msg = "Remote Command Execution: Suspicious Java method detected",
    },
    {
      id = "crs-944260", module = "java", tier = 2, score = 5, src = "crs",
      name = "Remote Command Execution: Malicious class-loading payload",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "class\\.module\\.classLoader\\.resources\\.context\\.parent\\.pipeline|springframework\\.context\\.support\\.FileSystemXmlApplicationContext",
          negate = false,
        },
      },
      status = 403,
      msg = "Remote Command Execution: Malicious class-loading payload",
    },
    {
      id = "crs-944300", module = "java", tier = 3, score = 5, src = "crs",
      name = "Base64 encoded string matched suspicious keyword",
      tags = { "application-multi", "language-java", "platform-multi", "attack-rce", "paranoia-level/3", "OWASP_CRS", "OWASP_CRS/ATTACK-JAVA", "capec/1000/152/248" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } }, { type = "ARGS_NAMES" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_BODY" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "c(?:nVudGltZQ|HJv(?:Y2Vzc2J1aWxkZXI|dG90eXBl(?:Y2xvbmVmYWN0b3J5|c2VyaWFsaXphdGlvbmZhY3Rvcnk)))|H(?:J1bnRpbWU|Byb(?:2Nlc3NidWlsZGVy|3RvdHlwZ(?:WNsb25lZmFjdG9yeQ|XNlcmlhbGl6YXRpb25mYWN0b3J5))|doaWxlY2xvc3VyZQ)|B(?:(?:ydW50aW1|mb3JjbG9zdXJ)l|wcm9(?:jZXNzYnVpbGRlcg|0b3R5cGV(?:jbG9uZWZhY3Rvcnk|zZXJpYWxpemF0aW9uZmFjdG9yeQ))|jbG9uZXRyYW5zZm9ybWVy|pbn(?:N0YW50aWF0Z(?:WZhY3Rvcnk|XRyYW5zZm9ybWVy)|Zva2VydHJhbnNmb3JtZXI)|3aGlsZWNsb3N1cmU)|Y2xvbmV0cmFuc2Zvcm1lcg|G(?:Nsb25ldHJhbnNmb3JtZXI|ZvcmNsb3N1cmU|lu(?:c3RhbnRpYXRl(?:ZmFjdG9yeQ|dHJhbnNmb3JtZXI)|dm9rZXJ0cmFuc2Zvcm1lcg))|Zm9yY2xvc3VyZQ|aW5(?:zdGFudGlhdGV(?:mYWN0b3J5|0cmFuc2Zvcm1lcg)|2b2tlcnRyYW5zZm9ybWVy)|d2hpbGVjbG9zdXJl",
          negate = false,
        },
      },
      status = 403,
      msg = "Base64 encoded string matched suspicious keyword",
    },
  },
}
