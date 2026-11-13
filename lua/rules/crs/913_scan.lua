-- origin=OWASP CRS v4.30.0 https://github.com/coreruleset/coreruleset (Apache-2.0)
-- generated_by=tools/import_crs.py from REQUEST-913-SCANNER-DETECTION.conf  DO NOT EDIT
-- module=scan  rules=1

return {
  meta = {
    module = "scan",
    source = "crs",
    crs_version = "4.30.0",
    file = "REQUEST-913-SCANNER-DETECTION.conf",
    generated_by = "tools/import_crs.py",
  },
  rules = {
    {
      id = "crs-913100", module = "scan", tier = 1, score = 5, src = "crs",
      name = "Found User-Agent associated with security scanner",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-reputation-scanner", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/SCANNER-DETECTION", "capec/1000/118/224/541/310" },
      chain = {
        {
          vars = { { type = "REQUEST_HEADERS", parse = { "all" }, key = "user-agent" } },
          transforms = { "lowercase" },
          op = "@pm",
          value = {
            "acunetix", "appspider", "arachni", "betabot", "bewica-security-scan", "bfac",
            "cmsmap", "commix", "detectify", "dirbuster", "dotdotpwn", "droopescan",
            "feroxbuster", "fimap", "fuzz faster", "ghauri", "gobuster", "graphql-cop",
            "graphw00f", "havij", "hexometer", "ironwasp", "jbrofuzz", "joomscan",
            "jorgee", "jsql", "kadimus", "l9explore", "l9tcpid", "lfimap",
            "lfisuite", "libwhisker", "masscan", "morfeus", "mozilla/4.0 (hydra)", "mozilla/5.0 (compatible; appscan;",
            "mozilla/5.0 (compatible; panoptic", "mozilla/5.g", "mozilla/6.0", "mozlila", "n-stalker", "nessus",
            "netlab360", "netsparker", "nettacker", "nikto", "nmap", "noseyparker",
            "nuclei", "openvas", "qualysguard", "securityagent", "shortscan", "sitelockspider",
            "skipfish", "sqlmap", "sqlninja", "sstimap", "sysscan", "tinja",
            "tplmap", "trufflehog", "tsunamisecurityscanner", "vega/", "w3af.org", "wapiti",
            "webbandit", "webshag", "wfuzz", "whatwaf", "whatweb", "wpprobe",
            "wprecon", "wpscan", "xsser", "xsstrike", "yeswehack-hunter", "zgrab",
            "zmeu",
          },
          ac_list = "scanners-user-agents",
          negate = false,
        },
      },
      status = 403,
      msg = "Found User-Agent associated with security scanner",
    },
  },
}
