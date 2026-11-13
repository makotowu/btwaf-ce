-- origin=OWASP CRS v4.30.0 https://github.com/coreruleset/coreruleset (Apache-2.0)
-- generated_by=tools/import_crs.py from REQUEST-921-PROTOCOL-ATTACK.conf  DO NOT EDIT
-- module=protocol  rules=13

return {
  meta = {
    module = "protocol",
    source = "crs",
    crs_version = "4.30.0",
    file = "REQUEST-921-PROTOCOL-ATTACK.conf",
    generated_by = "tools/import_crs.py",
  },
  rules = {
    {
      id = "crs-921110", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "HTTP Request Smuggling Attack",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/33" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } }, { type = "REQUEST_BODY" } },
          transforms = { "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "(?:get|p(?:(?:os|u)t|atch|rop(?:find|atch))|head|options|co(?:nnect|py)|delete|trac[ek]|m(?:kcol|ove)|(?:un)?lock)[\\s\\x0b]+[^\\s\\x0b]+[\\s\\x0b]+http/[0-9]",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Request Smuggling Attack",
    },
    {
      id = "crs-921120", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "HTTP Response Splitting Attack",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/34" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "[\\n\\r][^0-9A-Z_a-z]*?(?:content-(?:type|length)|set-cookie|location):[\\s\\x0b]*[0-9A-Z_a-z]",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Response Splitting Attack",
    },
    {
      id = "crs-921130", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "HTTP Response Splitting Attack",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/34" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "htmlEntityDecode", "lowercase" },
          op = "@rx",
          value = "(?:\\bhttp/\\d|<(?:html|meta)\\b)",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Response Splitting Attack",
    },
    {
      id = "crs-921140", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "HTTP Header Injection Attack via headers",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/273" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS_NAMES" }, { type = "REQUEST_HEADERS", parse = { "all" } } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "[\\n\\r]",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Header Injection Attack via headers",
    },
    {
      id = "crs-921150", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "HTTP Header Injection Attack via payload (CR/LF detected)",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/33" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" } },
          transforms = {  },
          op = "@rx",
          value = "[\\n\\r]",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Header Injection Attack via payload (CR/LF detected)",
    },
    {
      id = "crs-921151", module = "protocol", tier = 2, score = 5, src = "crs",
      name = "HTTP Header Injection Attack via payload (CR/LF detected)",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/33" },
      chain = {
        {
          vars = { { type = "ARGS_GET", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "[\\n\\r]",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Header Injection Attack via payload (CR/LF detected)",
    },
    {
      id = "crs-921190", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "HTTP Splitting (CR/LF in request filename detected)",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/34" },
      chain = {
        {
          vars = { { type = "REQUEST_FILENAME" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "[\\n\\r]",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Splitting (CR/LF in request filename detected)",
    },
    {
      id = "crs-921200", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "LDAP Injection Attack",
      tags = { "application-multi", "language-ldap", "platform-multi", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/152/248/136" },
      chain = {
        {
          vars = { { type = "REQUEST_COOKIES", parse = { "all" } }, { type = "REQUEST_COOKIES_NAMES" }, { type = "ARGS_NAMES" }, { type = "ARGS", parse = { "all" } } },
          transforms = { "htmlEntityDecode" },
          op = "@rx",
          value = "^[^!&\\(\\):<>\\|~]*\\)[\\s\\x0b]*(?:\\((?:[^!&\\(\\),<->\\|~]+[<>~]?=|[\\s\\x0b]*[!&\\|][\\s\\x0b]*[\\(\\)]?[\\s\\x0b]*)|\\)[\\s\\x0b]*\\([\\s\\x0b]*[!&\\|][\\s\\x0b]*|[!&\\|][\\s\\x0b]*\\([^!&\\(\\),<->\\|~]+[<>~]?=[^!&\\(\\):<>\\|~]*)",
          negate = false,
        },
      },
      status = 403,
      msg = "LDAP Injection Attack",
    },
    {
      id = "crs-921210", module = "protocol", tier = 3, score = 5, src = "crs",
      name = "HTTP Parameter Pollution after detecting bogus char after parameter array",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/3", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/152/137/15/460" },
      chain = {
        {
          vars = { { type = "ARGS_NAMES" } },
          transforms = {  },
          op = "@rx",
          value = "(][^\\]]+$|][^\\]]+\\[)",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Parameter Pollution after detecting bogus char after parameter array",
    },
    {
      id = "crs-921230", module = "protocol", tier = 3, score = 5, src = "crs",
      name = "HTTP Range Header detected",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/3", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", parse = { "all" }, key = "range", count = true } },
          transforms = {  },
          op = "@gt",
          value = "0",
          negate = false,
        },
      },
      status = 403,
      msg = "HTTP Range Header detected",
    },
    {
      id = "crs-921240", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "mod_proxy attack attempt detected",
      tags = { "application-multi", "language-multi", "platform-apache", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/210/272/220/33" },
      chain = {
        {
          vars = { { type = "REQUEST_URI" } },
          transforms = { "urlDecodeUni", "lowercase" },
          op = "@rx",
          value = "unix:[^|]*\\|",
          negate = false,
        },
      },
      status = 403,
      msg = "mod_proxy attack attempt detected",
    },
    {
      id = "crs-921421", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "Content-Type header: Dangerous content type outside the mime type declaration",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/255/153" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", parse = { "all" }, key = "content-type" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "^[^\\s\\x0b,;]+[\\s\\x0b,;].*?(?:application/(?:.+\\+)?json|(?:application/(?:soap\\+)?|text/)xml)",
          negate = false,
        },
      },
      status = 403,
      msg = "Content-Type header: Dangerous content type outside the mime type declaration",
    },
    {
      id = "crs-921422", module = "protocol", tier = 2, score = 5, src = "crs",
      name = "Content-Type header: Dangerous content type outside the mime type declaration",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-protocol", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/PROTOCOL-ATTACK", "capec/1000/255/153" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", parse = { "all" }, key = "content-type" } },
          transforms = { "lowercase" },
          op = "@rx",
          value = "^[^\\s\\x0b,;]+[\\s\\x0b,;].*?\\b(?:((?:tex|multipar)t|application)|((?:audi|vide)o|image|cs[sv]|(?:vn|relate)d|p(?:df|lain)|json|(?:soa|cs)p|x(?:ml|-www-form-urlencoded)|form-data|x-amf|(?:octe|repor)t|stream)|([\\+/]))\\b",
          negate = false,
        },
      },
      status = 403,
      msg = "Content-Type header: Dangerous content type outside the mime type declaration",
    },
  },
}
