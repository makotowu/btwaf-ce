import io,os,sys,re
root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
paths=os.path.join(root,"wafcore","paths.py")
version=re.search(r'VERSION = "([^"]+)"',io.open(paths,encoding="utf-8").read()).group(1)
problems=[]
def read(p):
    return io.open(os.path.join(root,p),encoding="utf-8").read()
def line_count(p):
    return len(io.open(os.path.join(root,p),encoding="utf-8").read().splitlines())
# 所有前端 JS 源文件；模板/方法/核心分包后仍按整体做标记检查
_js_parts = ["static/js/app.js"]
_waf_dir = os.path.join(root, "static/js/waf")
for _dirpath, _dirnames, _filenames in os.walk(_waf_dir):
    for _name in sorted(_filenames):
        if _name.endswith(".js"):
            _js_parts.append(os.path.relpath(os.path.join(_dirpath, _name), root).replace("\\", "/"))
_js_parts = sorted(set(_js_parts))
for _p in _js_parts:
    if not os.path.isfile(os.path.join(root, _p)):
        problems.append("missing frontend source: " + _p)
appjs = "\n".join(read(p) for p in _js_parts)
# version.json
vj=read("static/version.json")
try:
    import json; v=json.loads(vj).get("version")
    if v!=version: problems.append("static/version.json=%s != paths.VERSION=%s"%(v,version))
except Exception as e: problems.append("static/version.json invalid: %s"%e)
# index markers and versioned loader
idx=read("index.html")
for marker in ["AUTO DARK THEME","static/version.json","__BTWAF_ASSET_VERSION","layui-layer-page"]:
    if marker not in idx: problems.append("index.html missing marker: "+marker)
if "http://" in idx or "https://" in idx: problems.append("index.html contains external URL")
charts=read("static/js/charts.js")
if "echarts" not in charts: problems.append("charts.js missing echarts runtime")
# theme follow / locale / contrast regressions
for marker in ["btp-primary","panelDocument","month11","--btn"]:
    pass
# 产品名统一为「宝塔WAF社区版」（技术名 btwaf_ce 保留）
try:
    import json as _json
    info = _json.loads(read("info.json"))
    if info.get("title") != "宝塔WAF社区版": problems.append("info.json title is not 宝塔WAF社区版")
except Exception as e:
    problems.append("info.json unreadable: %s" % e)
for p in ["static/js/app.js","index.html","preview.html","install.sh","wafcore/paths.py","btwaf_ce_main.py"]:
    _s=read(p)
    for bad in ["btwaf CE","WAF 社区版","堡塔 WAF","宝塔 WAF"]:
        if bad in _s: problems.append("%s still contains old name: %s" % (p,bad))
for p in ["static/js/waf/templates/monitor.js","index.html","info.json"]:
    if "宝塔WAF社区版" not in read(p): problems.append("%s missing canonical name" % p)
if "btp-primary" not in appjs: problems.append("app.js missing panel theme follower")
if "month11" not in appjs: problems.append("app.js datepicker locale incomplete")
if "state.applied" not in appjs: problems.append("app.js theme apply loop missing guard")
if "state.color = ''" in appjs: problems.append("app.js forces theme refresh on every poll")
if "未移植 / 跳过规则清单" in appjs or "waf-skips" in appjs: problems.append("app.js still shows dev-only skipped rule panel")
if "网站防护" not in appjs: problems.append("app.js missing 网站防护 label")
if "oplogs" not in appjs or "set_rule_status" not in appjs: problems.append("app.js missing P0 operation/rule status UI")
if "CDN_PRESETS" not in appjs or "panelCdnOpen" not in appjs: problems.append("app.js missing CDN presets/panel CDN warning")
if "IP 范围" not in appjs: problems.append("app.js missing IP range hint")
if "geoModeOptions" not in appjs or "地区访问" not in appjs or "countryLabel" not in appjs:
    problems.append("app.js missing geo access UI")
if "waf-grid-3" not in appjs: problems.append("app.js missing top sites grid")
if "get_system_firewall" not in appjs or "unban_system_ip" not in appjs:
    problems.append("app.js missing system firewall UI")
if "showConfirmWithOption" not in appjs or "blockSystem" not in appjs:
    problems.append("app.js missing system firewall confirm state")
if "import_lists" not in appjs or "onImportGlobalList" not in appjs or "exportGlobalList" not in appjs:
    problems.append("app.js missing IP list import/export UI")
if "logRows: 10" not in appjs or "siteRows: 10" not in appjs: problems.append("table default rows not 10")
if "page-sizes=\"[10, 20, 50, 100]\"" not in appjs: problems.append("page size options missing 10")
if line_count("static/js/app.js") > 600:
    problems.append("app.js is too large; move view code into static/js/waf")
for _p in _js_parts:
    if _p.startswith("static/js/waf/") and line_count(_p) > 800:
        problems.append("frontend module too large: %s" % _p)
for _p in ("static/js/waf/core.js", "static/js/waf/templates/monitor.js",
           "static/js/waf/methods/common.js"):
    if _p not in read("index.html") or _p not in read("preview.html"):
        problems.append("frontend loader missing: " + _p)
if read("index.html").find("static/js/waf/core.js") > read("index.html").find("static/js/app.js"):
    problems.append("app.js must load after waf modules")
css=read("static/css/app.css")
for marker in ["--btp-primary","waf-dark","el-select__popper","el-upload__input","el-input-number__increase"]:
    if marker not in css: problems.append("app.css missing "+marker)
# no legacy hardcoded Element defaults in our css/js
for p in ["static/css/app.css","static/js/charts.js","static/js/app.js"]:
    s=read(p)
    for bad in ["#409eff","#409EFF","#67c23a","#e6a23c","#f56c6c"]:
        if bad in s: problems.append("%s contains Element default color %s"%(p,bad))
# version consistency in frontend source
for p in ["static/js/app.js","index.html"]:
    if "1.0.0" in read(p): problems.append("%s still contains 1.0.0"%p)
print("check_frontend: version",version,"problems",len(problems))
for x in problems: print(" -",x)
sys.exit(1 if problems else 0)
