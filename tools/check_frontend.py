import io,os,sys,re
root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
paths=os.path.join(root,"wafcore","paths.py")
version=re.search(r'VERSION = "([^"]+)"',io.open(paths,encoding="utf-8").read()).group(1)
problems=[]
def read(p):
    return io.open(os.path.join(root,p),encoding="utf-8").read()
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
appjs=read("static/js/app.js")
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
for p in ["static/js/app.js","index.html","info.json"]:
    if "宝塔WAF社区版" not in read(p): problems.append("%s missing canonical name" % p)
if "btp-primary" not in appjs: problems.append("app.js missing panel theme follower")
if "month11" not in appjs: problems.append("app.js datepicker locale incomplete")
if "state.applied" not in appjs: problems.append("app.js theme apply loop missing guard")
if "state.color = ''" in appjs: problems.append("app.js forces theme refresh on every poll")
if "未移植 / 跳过规则清单" in appjs or "waf-skips" in appjs: problems.append("app.js still shows dev-only skipped rule panel")
if "网站防护" not in appjs: problems.append("app.js missing 网站防护 label")
if "waf-grid-3" not in appjs: problems.append("app.js missing top sites grid")
if "logRows: 10" not in appjs or "siteRows: 10" not in appjs: problems.append("table default rows not 10")
if "page-sizes=\"[10, 20, 50, 100]\"" not in appjs: problems.append("page size options missing 10")
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
