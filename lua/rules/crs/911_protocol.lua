-- origin=OWASP CRS v4.30.0 https://github.com/coreruleset/coreruleset (Apache-2.0)
-- generated_by=tools/import_crs.py from REQUEST-911-METHOD-ENFORCEMENT.conf  DO NOT EDIT
-- module=protocol  rules=1

return {
  meta = {
    module = "protocol",
    source = "crs",
    crs_version = "4.30.0",
    file = "REQUEST-911-METHOD-ENFORCEMENT.conf",
    generated_by = "tools/import_crs.py",
  },
  rules = {
    {
      id = "crs-911100", module = "protocol", tier = 1, score = 5, src = "crs",
      name = "Method is not allowed by policy",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-generic", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/METHOD-ENFORCEMENT", "capec/1000/210/272/220/274" },
      chain = {
        {
          vars = { { type = "REQUEST_METHOD" } },
          transforms = {  },
          op = "@within",
          value = {
            "GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH",
            "DELETE",
          },
          negate = true,
        },
      },
      status = 403,
      msg = "Method is not allowed by policy",
    },
  },
}
