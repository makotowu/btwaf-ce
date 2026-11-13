-- origin=OWASP CRS v4.30.0 https://github.com/coreruleset/coreruleset (Apache-2.0)
-- generated_by=tools/import_crs.py from REQUEST-931-APPLICATION-ATTACK-RFI.conf  DO NOT EDIT
-- module=lfi  rules=4

return {
  meta = {
    module = "lfi",
    source = "crs",
    crs_version = "4.30.0",
    file = "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    generated_by = "tools/import_crs.py",
  },
  rules = {
    {
      id = "crs-931100", module = "lfi", tier = 1, score = 5, src = "crs",
      name = "Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-rfi", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-RFI", "capec/1000/152/175/253" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "(?i)^(f(?:ile|tps?)|https?|ssh)://(?:\\[?[0-9a-f]+:[0-:a-f]+\\]?|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address",
    },
    {
      id = "crs-931110", module = "lfi", tier = 1, score = 5, src = "crs",
      name = "Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-rfi", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-RFI", "capec/1000/152/175/253" },
      chain = {
        {
          vars = { { type = "QUERY_STRING" }, { type = "REQUEST_BODY" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "(?i)(?:\\binclude[\\s\\x0b]*\\([^\\)]*|mosConfig_absolute_path|(?:_(?:CONF\\[path|SERVER\\[DOCUMENT_ROOT)|path\\[docroot|config\\[root_dir)\\]|GALLERY_BASEDIR|appserv_root)=(?:f(?:ile|tps?)|https?)://",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload",
    },
    {
      id = "crs-931120", module = "lfi", tier = 1, score = 5, src = "crs",
      name = "Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-rfi", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-RFI", "capec/1000/152/175/253" },
      chain = {
        {
          vars = { { type = "ARGS", parse = { "all" } } },
          transforms = {  },
          op = "@rx",
          value = "^(?i:file|ftps?|https?).*?\\?+$",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)",
    },
    {
      id = "crs-931131", module = "lfi", tier = 2, score = 5, src = "crs",
      name = "Possible Remote File Inclusion (RFI) Attack",
      tags = { "application-multi", "language-multi", "platform-multi", "attack-rfi", "paranoia-level/2", "OWASP_CRS", "OWASP_CRS/ATTACK-RFI", "capec/1000/152/175/253" },
      chain = {
        {
          vars = { { type = "REQUEST_FILENAME" } },
          transforms = { "urlDecodeUni" },
          op = "@rx",
          value = "(?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)",
          negate = false,
        },
      },
      status = 403,
      msg = "Possible Remote File Inclusion (RFI) Attack",
    },
  },
}
