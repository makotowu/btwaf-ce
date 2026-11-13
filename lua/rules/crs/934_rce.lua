-- origin=OWASP CRS v4.30.0 https://github.com/coreruleset/coreruleset (Apache-2.0)
-- generated_by=tools/import_crs.py from REQUEST-934-APPLICATION-ATTACK-GENERIC.conf  DO NOT EDIT
-- module=rce  rules=13

return {
  meta = {
    module = "rce",
    source = "crs",
    crs_version = "4.30.0",
    file = "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
    generated_by = "tools/import_crs.py",
  },
  rules = {
    {
      id = "crs-934100", module = "rce", tier = 1, score = 5, src = "crs",
      name = "Node.js Injection Attack 1/2",
      tags = { "application-multi", "language-javascript", "platform-multi", "platform-nodejs", "attack-rce", "attack-injection-generic", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_FILENAME" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "urlDecodeUni", "jsDecode", "removeWhitespace", "base64Decode" },
          op = "@rx",
          value = "_(?:\\$\\$ND_FUNC\\$\\$_|_js_function)|(?:\\beval|new[\\s\\x0b]+Function[\\s\\x0b]*)\\(|(?:String\\.fromCharCod|Module:prototyp)e|function\\(\\)\\{|this\\.constructor|module\\.exports=|\\([\\s\\x0b]*[^0-9A-Z_a-z]child_process[^0-9A-Z_a-z][\\s\\x0b]*\\)|cons(?:tructor:constructor|ole(?:\\.(?:(?:debu|lo)g|error|info|trace|warn)(?:\\.call)?\\(|\\[[\"'`](?:(?:debu|lo)g|error|info|trace|warn)[\"'`]\\]))|process(?:\\.(?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?(?:\\.call)?\\(|binding|constructor|env|global|main(?:Module)?|process|require)|\\[[\"'`](?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?|binding|constructor|env|global|main(?:Module)?|process|require)[\"'`]\\])|(?:binding|constructor|env|global|main(?:Module)?|process|require)\\[|require(?:\\.(?:resolve(?:\\.call)?\\(|main|extensions|cache)|\\[[\"'`](?:(?:resolv|cach)e|main|extensions)[\"'`]\\])",
          negate = false,
        },
      },
      status = 403,
      msg = "Node.js Injection Attack 1/2",
    },
    {
      id = "crs-934101", module = "rce", tier = 2, score = 5, src = "crs",
      name = "Node.js Injection Attack 2/2",
      tags = { "application-multi", "language-javascript", "platform-nodejs", "attack-rce", "attack-injection-generic", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_FILENAME" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "urlDecodeUni", "jsDecode", "base64Decode" },
          op = "@rx",
          value = "(?:close|exists|fork|(?:ope|spaw)n|re(?:ad|quire)|w(?:atch|rite))[\\s\\x0b]*\\(",
          negate = false,
        },
      },
      status = 403,
      msg = "Node.js Injection Attack 2/2",
    },
    {
      id = "crs-934110", module = "rce", tier = 1, score = 5, src = "crs",
      name = "Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-ssrf", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/225/664" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_FILENAME" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "gopher://127.0.0.1", "gopher://localhost", "gopher://metadata.google.internal", "http://0.0.0.0", "http://0/", "http://0177.0.0.1/",
            "http://017700000001:2375/", "http://0251.0376.0251.0376/computemetadata/v1/", "http://0251.0376.0251.0376/latest/", "http://0251.0376.0251.0376/metadata/v1/", "http://0251.254.169.254/computemetadata/v1/", "http://0251.254.169.254/latest/",
            "http://0251.254.169.254/metadata/v1/", "http://025177524776/computemetadata/v1/", "http://025177524776/latest/", "http://025177524776/metadata/v1/", "http://0x7f000001:2375/", "http://0xa9.0xfe.0xa9.0xfe/computemetadata/v1/",
            "http://0xa9.0xfe.0xa9.0xfe/latest/", "http://0xa9.0xfe.0xa9.0xfe/metadata/v1/", "http://0xa9fea9fe/computemetadata/v1/", "http://0xa9fea9fe/latest/", "http://0xa9fea9fe/metadata/v1/", "http://0xc0a80014:2375/",
            "http://100.100.100.200/latest/meta-data/", "http://127.0.0.0", "http://127.0.0.1", "http://127.0.0.1.nip.io", "http://127.0.0.1:2375", "http://127.0.0.1:2379",
            "http://127.0.1", "http://127.0.1.12", "http://127.1", "http://127.127.127.127", "http://169.254.169.254.nip.io/computemetadata/v1/", "http://169.254.169.254.nip.io/latest/",
            "http://169.254.169.254.nip.io/metadata/v1/", "http://169.254.169.254/2009-04-04/meta-data/", "http://169.254.169.254/computemetadata/v1/", "http://169.254.169.254/latest/", "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipaddress/0/publicipaddress?api-version=2017-04-02&format=text", "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
            "http://169.254.169.254/metadata/v1.json", "http://169.254.169.254/metadata/v1/", "http://169.254.169.254/openstack", "http://169.254.170.2/v2", "http://169。254。169。254", "http://169｡254｡169｡254",
            "http://192.0.0.192/latest/", "http://2130706433/", "http://2130706433:2375/", "http://2852039166/", "http://2852039166/computemetadata/v1/", "http://2852039166/latest/",
            "http://2852039166/metadata/v1/", "http://3232235521/", "http://3232235777/", "http://[0000::1]", "http://[0000::1]:2375/", "http://[0:0:0:0:0:ffff:127.0.0.1]",
            "http://[0:0:0:0:0:ffff:127.0.0.1]:2375/", "http://[0:0:0:0:0:ffff:169.254.169.254]/computemetadata/v1/", "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/", "http://[0:0:0:0:0:ffff:169.254.169.254]/metadata/v1/", "http://[0:0:0:0:0:ffff:a9fe:a9fe]/computemetadata/v1/", "http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/",
            "http://[0:0:0:0:0:ffff:a9fe:a9fe]/metadata/v1/", "http://[::1]", "http://[::]:", "http://[::]:2375/", "http://[::ffff:127.0.0.1]", "http://[::ffff:a9fe:a9fe]/computemetadata/v1/",
            "http://[::ffff:a9fe:a9fe]/latest/", "http://[::ffff:a9fe:a9fe]/metadata/v1/", "http://[::①⑥⑨｡②⑤④｡⑯⑨｡②⑤④]", "http://[::ⓕⓕⓕⓕ:①⑥⑨。②⑤④。⑯⑨。②⑤④]", "http://instance-data/latest/", "http://localhost",
            "http://localhost:9001/2018-06-01/runtime/", "http://localtest.me", "http://metadata.google.internal/computemetadata/v1/", "http://metadata.google.internal/computemetadata/v1/instance/disks/?recursive=true", "http://metadata.google.internal/computemetadata/v1beta1/", "http://metadata/computemetadata/v1/",
            "http://nicob.net/redir-http-169.254.169.254:80-", "http://rancher-metadata/", "http://②⑧⑤②⓪③⑨①⑥⑥", "http://④②⑤｡⑤①⓪｡④②⑤｡⑤①⓪", "http://⑯⑨。②⑤④。⑯⑨｡②⑤④", "http://⓪②⑤①。⓪③⑦⑥。⓪②⑤①。⓪③⑦⑥",
            "http://⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ", "http://⓪ⓧⓐ⑨。⓪③⑦⑥。④③⑤①⑧", "http://⓪ⓧⓐ⑨｡⑯⑥⑧⑨⑥⑥②", "http://⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ", "http://⓪⓪②⑤①。⑯⑥⑧⑨⑥⑥②", "http://⓪⓪②⑤①｡⓪ⓧⓕⓔ｡④③⑤①⑧",
            "http://⓪⓪②⑤①｡⓪⓪⓪③⑦⑥｡⓪⓪⓪⓪②⑤①｡⓪⓪⓪⓪⓪③⑦⑥", "http:127.0.0.1", "https://metadata.packet.net/userdata", "jar:ftp://127.0.0.1!/", "jar:http://127.0.0.1!/", "jar:https://127.0.0.1!/",
          },
          ac_list = "ssrf",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter",
    },
    {
      id = "crs-934120", module = "rce", tier = 2, score = 5, src = "crs",
      name = "Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-ssrf", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/225/664" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_FILENAME" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "(?i)(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip):/?/?(?:[0-9]{7,10}|(?:0x[0-9a-f]{2}\\.){3}0x[0-9a-f]{2}|0x(?:[0-9a-f]{8}|[0-9a-f]{16})|(?:0{1,4}[0-9]{1,3}\\.){3}0{1,4}[0-9]{1,3}|[0-9]{1,3}\\.(?:[0-9]{1,3}\\.[0-9]{5}|[0-9]{8})|(?:\\x5c\\x5c[\\-0-9a-z]\\.?_?)+|\\[[0-:a-f]+(?:[\\.0-9]+|%[0-9A-Z_a-z]+)?\\]|[a-z][\\-\\.0-9A-Z_a-z]{1,255}:[0-9]{1,5}(?:#?[\\s\\x0b]*&?@(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}|[a-z][\\-\\.0-9A-Z_a-z]{1,255}):[0-9]{1,5}/?)+|[\\.0-9]{0,11}(?:\\x{e2}(?:\\x91[\\xa0-\\x{bf}]|\\x92[\\x80-\\x{bf}]|\\x93[\\x80-\\x{a9}\\x{ab}-\\x{bf}])|\\x{e3}\\x80\\x82)+)",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address",
    },
    {
      id = "crs-934130", module = "rce", tier = 1, score = 5, src = "crs",
      name = "JavaScript Prototype Pollution",
      tags = { "application-multi", "language-javascript", "platform-multi", "attack-rce", "attack-injection-generic", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1/180/77" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "urlDecodeUni", "jsDecode" },
          op = "@rx",
          value = "__proto__|constructor[\\s\\x0b]*(?:\\.|\\]?\\[)[\\s\\x0b]*prototype",
          negate = false,
        },
      },
      status = 403,
      msg = "JavaScript Prototype Pollution",
    },
    {
      id = "crs-934140", module = "rce", tier = 2, score = 5, src = "crs",
      name = "Perl Injection Attack",
      tags = { "application-multi", "language-perl", "platform-multi", "attack-rce", "attack-injection-generic", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "@+\\{[\\s\\x0b]*\\[",
          negate = false,
        },
      },
      status = 403,
      msg = "Perl Injection Attack",
    },
    {
      id = "crs-934150", module = "rce", tier = 1, score = 5, src = "crs",
      name = "Ruby Injection Attack",
      tags = { "application-multi", "language-ruby", "platform-multi", "attack-rce", "attack-injection-generic", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "Process[\\s\\x0b]*\\.[\\s\\x0b]*spawn[\\s\\x0b]*\\(",
          negate = false,
        },
      },
      status = 403,
      msg = "Ruby Injection Attack",
    },
    {
      id = "crs-934170", module = "rce", tier = 1, score = 5, src = "crs",
      name = "PHP data scheme attack",
      tags = { "application-multi", "language-php", "platform-multi", "attack-ssrf", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_FILENAME" }, { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "^(?:json\\.)?data:(?:(?:\\*|[^!\"\\(\\),/:-\\?\\[-\\]\\{\\}]+)/(?:\\*|[^!\"\\(\\),/:-\\?\\[-\\]\\{\\}]+)|\\*)(?:[\\s\\x0b]*;[\\s\\x0b]*(?:charset[\\s\\x0b]*=[\\s\\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\\b\"?|(?:[^\\s\\x0b-\"\\(\\),/:-\\?\\[-\\]c\\{\\}]|c(?:[^!\"\\(\\),/:-\\?\\[-\\]h\\{\\}]|h(?:[^!\"\\(\\),/:-\\?\\[-\\]a\\{\\}]|a(?:[^!\"\\(\\),/:-\\?\\[-\\]r\\{\\}]|r(?:[^!\"\\(\\),/:-\\?\\[-\\]s\\{\\}]|s(?:[^!\"\\(\\),/:-\\?\\[-\\]e\\{\\}]|e[^!\"\\(\\),/:-\\?\\[-\\]t\\{\\}]))))))[^!\"\\(\\),/:-\\?\\[-\\]\\{\\}]*[\\s\\x0b]*=[\\s\\x0b]*[^!\\(\\),/:-\\?\\[-\\]\\{\\}]+);?)*(?:[\\s\\x0b]*,[\\s\\x0b]*(?:(?:\\*|[^!\"\\(\\),/:-\\?\\[-\\]\\{\\}]+)/(?:\\*|[^!\"\\(\\),/:-\\?\\[-\\]\\{\\}]+)|\\*)(?:[\\s\\x0b]*;[\\s\\x0b]*(?:charset[\\s\\x0b]*=[\\s\\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\\b\"?|(?:[^\\s\\x0b-\"\\(\\),/:-\\?\\[-\\]c\\{\\}]|c(?:[^!\"\\(\\),/:-\\?\\[-\\]h\\{\\}]|h(?:[^!\"\\(\\),/:-\\?\\[-\\]a\\{\\}]|a(?:[^!\"\\(\\),/:-\\?\\[-\\]r\\{\\}]|r(?:[^!\"\\(\\),/:-\\?\\[-\\]s\\{\\}]|s(?:[^!\"\\(\\),/:-\\?\\[-\\]e\\{\\}]|e[^!\"\\(\\),/:-\\?\\[-\\]t\\{\\}]))))))[^!\"\\(\\),/:-\\?\\[-\\]\\{\\}]*[\\s\\x0b]*=[\\s\\x0b]*[^!\\(\\),/:-\\?\\[-\\]\\{\\}]+);?)*)*",
          negate = false,
        },
      },
      status = 403,
      msg = "PHP data scheme attack",
    },
    {
      id = "crs-934180", module = "rce", tier = 2, score = 5, src = "crs",
      name = "SSTI Attack",
      tags = { "application-multi", "platform-multi", "attack-ssti", "attack-injection-generic", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "(?:\\{%[^%}]*%}|<%=?[^%>]*%>)",
          negate = false,
        },
      },
      status = 403,
      msg = "SSTI Attack",
    },
    {
      id = "crs-934190", module = "rce", tier = 1, score = 5, src = "crs",
      name = "Possible Server Side Request Forgery (SSRF) Attack: Scheme-less localhost or internal hostname detected",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-ssrf", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/225/664" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "REQUEST_FILENAME" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "gateway.docker.internal/", "host.containers.internal/", "host.docker.internal/", "ip6-loopback/", "ipv6-localhost/", "kubernetes.default.svc.cluster.local/",
            "kubernetes.docker.internal/", "localhost.localdomain/", "localhost/", "localhost4.localdomain4/", "localhost4/", "localtest.me/",
            "lvh.me/",
          },
          ac_list = "ssrf-no-scheme",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Server Side Request Forgery (SSRF) Attack: Scheme-less localhost or internal hostname detected",
    },
    {
      id = "crs-934200", module = "rce", tier = 1, score = 5, src = "crs",
      name = "Server-Side Template Injection (SSTI) Attack",
      tags = { "application-multi", "platform-multi", "attack-ssti", "attack-injection-generic", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/242" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "\\{\\{[^\\}]*?(?:[\\(\\*]|__)[^\\}]*?\\}\\}|#(?:\\{[^\\}]*?(?:[\\(\\*]|__)[^\\}]*?\\}|[0-9A-Z_a-z]+[\\s\\x0b]*\\([\\s\\x0b]*\\$[^\\)]*?(?:[\\(\\*]|__)[^\\)]*?\\))|<(?:%=?[\\s\\x0b]*[^%]*?(?:[\\(\\*]|__)[^%]*?%|[#@][0-9A-Z_a-z]+[^>]*?(?:[\\(\\*]|__)[^>]*?)>",
          negate = false,
        },
      },
      status = 403,
      msg = "Server-Side Template Injection (SSTI) Attack",
    },
    {
      id = "crs-934210", module = "rce", tier = 3, score = 5, src = "crs",
      name = "ORM Lookup Operator Injection",
      tags = { "application-multi", "platform-multi", "attack-injection-generic", "paranoia-level/3", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/248/66/109" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "__(?:i?(?:startswith|e(?:ndswith|xact)|contains|regex)|i(?:snull|n)|range|[gl]te?|has_(?:keys?|any_keys)|contained_by)(?:$|\"[\\s\\x0b]*:)",
          negate = false,
        },
      },
      status = 403,
      msg = "ORM Lookup Operator Injection",
    },
    {
      id = "crs-934220", module = "rce", tier = 2, score = 5, src = "crs",
      name = "ORM Lookup Operator Injection via Nested Traversal",
      tags = { "application-multi", "platform-multi", "attack-injection-generic", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-GENERIC", "capec/1000/152/248/66/109" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "__[^\"&=]*__(?:i?(?:startswith|e(?:ndswith|xact)|contains|regex)|i(?:snull|n)|range|[gl]te?|has_(?:keys?|any_keys)|contained_by)(?:$|\"[\\s\\x0b]*:)",
          negate = false,
        },
      },
      status = 403,
      msg = "ORM Lookup Operator Injection via Nested Traversal",
    },
  },
}
