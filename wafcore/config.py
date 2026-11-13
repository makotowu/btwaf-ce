# coding: utf-8
"""全局/站点配置、hosts、自定义规则。"""
import copy
import json
import os

from . import paths, util

MODULES = [
    ("sqli", "SQL 注入"),
    ("xss", "XSS 跨站"),
    ("rce", "命令执行"),
    ("lfi", "文件包含/遍历"),
    ("php", "PHP 代码注入"),
    ("java", "Java 注入/反序列化"),
    ("scan", "扫描器"),
    ("crawler", "恶意爬虫"),
    ("sensitive", "敏感文件"),
    ("upload", "恶意上传"),
    ("protocol", "协议异常"),
    ("custom", "自定义规则"),
]
MODULE_KEYS = [m[0] for m in MODULES]

DEFAULT_GLOBAL = {
    "schema": 1,
    "version": paths.VERSION,
    "enabled": True,
    "observe": False,
    "sensitivity": 2,
    "block": {"status": 403, "use_custom": False, "page": ""},
    "scan": {
        "body_limit": 1048576,
        "arg_limit": 8192,
        "header_limit": 8192,
        "upload_scan_limit": 20971520,
        "max_args": 200,
    },
    "log": {"enabled": True, "retain_days": 30, "rotate_size": 52428800, "snippet": 512},
    "cc": {
        "open": True,
        "cycle": 60,
        "limit": 120,
        "block_time": 300,
        "status": 444,
        "url_cc": False,
        "skip_static": True,
    },
    "attack_block": {"open": True, "cycle": 120, "limit": 20, "block_time": 1800},
    "modules": dict([(k, {"open": True, "tier": 1}) for k in MODULE_KEYS]),
    "lists": {
        "ip_black": [],
        "ip_white": [],
        "url_black": [],
        "url_white": [],
        "ua_black": [],
        "ua_white": [],
        "param_white": [],
    },
    "rule_exclude": {"crs": [], "ce": []},
    "trusted_proxies": [],
    "crawler": {
        "allow": [
            "baiduspider",
            "googlebot",
            "bingbot",
            "bytespider",
            "sogou",
            "360spider",
            "yandex",
            "duckduckbot",
            "applebot",
        ],
        "block_fake": True,
    },
    "fail_open": True,
    "whitelist_first": True,
    "update_time": 0,
}

DEFAULT_CDN = {
    "open": False,
    "headers": ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"],
    "trusted": [],
}


def default_site_entry():
    entry = {
        "open": True,
        "sensitivity": 0,
        "observe": None,
        "modules": dict([(k, {"open": True, "tier": 0}) for k in MODULE_KEYS]),
        "cc": {
            "open": None,
            "cycle": 0,
            "limit": 0,
            "block_time": 0,
            "status": 0,
            "url_cc": None,
        },
        "attack_block": {"open": None, "cycle": 0, "limit": 0, "block_time": 0},
        "cdn": copy.deepcopy(DEFAULT_CDN),
        "lists": copy.deepcopy(DEFAULT_GLOBAL["lists"]),
        "rule_exclude": {"crs": [], "ce": []},
        "disable_php_path": ["^/cache/", "^/config/", "^/runtime/", "^/application/", "^/logs/"],
        "disable_ext": ["sql", "bak", "swp", "git", "env"],
        "upload_ext": ["php", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "exe", "sh"],
        "custom_rules": [],
        "update_time": 0,
    }
    return entry


# ---------------- 深合并 / 清理 ----------------
def _as_dict(v):
    """损坏的配置（非 dict）一律回退为空 dict，保证 fail-open 可自救。"""
    return v if isinstance(v, dict) else {}


def deep_merge(base, override):
    """override 覆盖 base；dict 递归，list 直接替换（None 视为不覆盖）。"""
    if not isinstance(base, dict):
        base = {}
    out = copy.deepcopy(base)
    if not isinstance(override, dict):
        return out
    for k, v in override.items():
        if v is None:
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _bool(v, default):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(v, (int, float)):
        return bool(v)
    return default


def _clean_bool_maybe(v):
    if v is None:
        return None
    return _bool(v, False)


def clean_global(data):
    """合并默认值并做范围校验，返回 (cfg, warnings)。"""
    warnings = []
    cfg = deep_merge(DEFAULT_GLOBAL, data or {})
    cfg["enabled"] = _bool(cfg.get("enabled"), True)
    cfg["observe"] = _bool(cfg.get("observe"), False)
    cfg["fail_open"] = _bool(cfg.get("fail_open"), True)
    cfg["whitelist_first"] = _bool(cfg.get("whitelist_first"), True)
    cfg["sensitivity"] = util.safe_int(cfg.get("sensitivity"), 2, 1, 3)

    blk = _as_dict(cfg.get("block"))
    status = util.safe_int(blk.get("status"), 403)
    if status not in (403, 404, 444, 429, 503):
        warnings.append("拦截状态码不支持，已回退 403")
        status = 403
    page = blk.get("page") or ""
    if page:
        page, removed = util.sanitize_block_page(page)
        if removed:
            warnings.append("自定义拦截页包含被移除的危险内容")
    cfg["block"] = {
        "status": status,
        "use_custom": _bool(blk.get("use_custom"), False),
        "page": page,
    }

    scan = _as_dict(cfg.get("scan"))
    cfg["scan"] = {
        "body_limit": util.safe_int(scan.get("body_limit"), 1048576, 0, 52428800),
        "arg_limit": util.safe_int(scan.get("arg_limit"), 8192, 256, 1048576),
        "header_limit": util.safe_int(scan.get("header_limit"), 8192, 256, 1048576),
        "upload_scan_limit": util.safe_int(scan.get("upload_scan_limit"), 20971520, 0, 104857600),
        "max_args": util.safe_int(scan.get("max_args"), 200, 1, 5000),
    }

    log = _as_dict(cfg.get("log"))
    cfg["log"] = {
        "enabled": _bool(log.get("enabled"), True),
        "retain_days": util.safe_int(log.get("retain_days"), 30, 1, 365),
        "rotate_size": util.safe_int(log.get("rotate_size"), 52428800, 1048576, 1073741824),
        "snippet": util.safe_int(log.get("snippet"), 512, 0, 4096),
    }

    cc = _as_dict(cfg.get("cc"))
    cc_status = util.safe_int(cc.get("status"), 444)
    if cc_status not in (403, 404, 444, 429, 503):
        cc_status = 444
    cfg["cc"] = {
        "open": _bool(cc.get("open"), True),
        "cycle": util.safe_int(cc.get("cycle"), 60, 10, 3600),
        "limit": util.safe_int(cc.get("limit"), 120, 2, 100000),
        "block_time": util.safe_int(cc.get("block_time"), 300, 10, 86400 * 30),
        "status": cc_status,
        "url_cc": _bool(cc.get("url_cc"), False),
        "skip_static": _bool(cc.get("skip_static"), True),
    }

    ab = _as_dict(cfg.get("attack_block"))
    cfg["attack_block"] = {
        "open": _bool(ab.get("open"), True),
        "cycle": util.safe_int(ab.get("cycle"), 120, 10, 86400),
        "limit": util.safe_int(ab.get("limit"), 20, 1, 100000),
        "block_time": util.safe_int(ab.get("block_time"), 86400, 10, 86400 * 30),
    }

    mods = _as_dict(cfg.get("modules"))
    clean_mods = {}
    for k in MODULE_KEYS:
        item = _as_dict(mods.get(k))
        clean_mods[k] = {
            "open": _bool(item.get("open"), True),
            "tier": util.safe_int(item.get("tier"), 1, 1, 3),
        }
    cfg["modules"] = clean_mods

    cfg["lists"] = clean_lists(cfg.get("lists") or {})
    cfg["rule_exclude"] = clean_rule_exclude(cfg.get("rule_exclude") or {})
    cfg["trusted_proxies"] = clean_trusted(cfg.get("trusted_proxies") or [])

    crawler = _as_dict(cfg.get("crawler"))
    allow = crawler.get("allow")
    if not isinstance(allow, list):
        allow = DEFAULT_GLOBAL["crawler"]["allow"]
    allow = [str(x).strip() for x in allow if str(x).strip()][:200]
    cfg["crawler"] = {"allow": allow, "block_fake": _bool(crawler.get("block_fake"), True)}
    cfg["update_time"] = util.safe_int(cfg.get("update_time"), 0)
    return cfg, warnings


def clean_lists(lists):
    out = {}
    for key in DEFAULT_GLOBAL["lists"].keys():
        items = lists.get(key) if isinstance(lists, dict) else None
        if not isinstance(items, list):
            items = []
        clean = []
        for item in items:
            if not isinstance(item, str):
                item = str(item)
            item = item.strip()
            if not item or item in clean:
                continue
            if key.startswith("ip_"):
                if "/" in item and not util.valid_cidr(item):
                    continue
                if "/" not in item and not util.valid_ip(item):
                    continue
            if key.startswith("url_"):
                probe = item[1:] if item.startswith("~") else item
                if len(probe) > 512:
                    continue
            if len(item) > 1024:
                continue
            clean.append(item)
        out[key] = clean[:2000]
    return out


def clean_trusted(items):
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if isinstance(item, str) and util.valid_ip_or_cidr(item.strip()):
            out.append(item.strip())
    return out[:200]


def clean_rule_exclude(obj):
    out = {"crs": [], "ce": []}
    if not isinstance(obj, dict):
        return out
    for key in ("crs", "ce"):
        items = obj.get(key)
        if not isinstance(items, list):
            continue
        clean = []
        for item in items:
            if isinstance(item, str) and item.strip() and len(item) <= 64:
                clean.append(item.strip())
        out[key] = clean[:2000]
    return out


def clean_site(data):
    entry = deep_merge(default_site_entry(), data or {})
    entry["open"] = _bool(entry.get("open"), True)
    entry["sensitivity"] = util.safe_int(entry.get("sensitivity"), 0, 0, 3)
    if entry.get("observe") is None:
        entry["observe"] = None
    else:
        entry["observe"] = _bool(entry.get("observe"), False)

    mods = _as_dict(entry.get("modules"))
    clean_mods = {}
    for k in MODULE_KEYS:
        item = _as_dict(mods.get(k))
        clean_mods[k] = {
            "open": _bool(item.get("open"), True),
            "tier": util.safe_int(item.get("tier"), 0, 0, 3),
        }
    entry["modules"] = clean_mods

    cc = _as_dict(entry.get("cc"))
    entry["cc"] = {
        "open": _clean_bool_maybe(cc.get("open")),
        "cycle": util.safe_int(cc.get("cycle"), 0, 0, 3600),
        "limit": util.safe_int(cc.get("limit"), 0, 0, 100000),
        "block_time": util.safe_int(cc.get("block_time"), 0, 0, 86400 * 30),
        "status": util.safe_int(cc.get("status"), 0, 0, 503),
        "url_cc": _clean_bool_maybe(cc.get("url_cc")),
    }
    ab = _as_dict(entry.get("attack_block"))
    entry["attack_block"] = {
        "open": _clean_bool_maybe(ab.get("open")),
        "cycle": util.safe_int(ab.get("cycle"), 0, 0, 86400),
        "limit": util.safe_int(ab.get("limit"), 0, 0, 100000),
        "block_time": util.safe_int(ab.get("block_time"), 0, 0, 86400 * 30),
    }

    cdn = _as_dict(entry.get("cdn"))
    headers = cdn.get("headers")
    if not isinstance(headers, list):
        headers = list(DEFAULT_CDN["headers"])
    entry["cdn"] = {
        "open": _bool(cdn.get("open"), False),
        "headers": [str(h).strip().lower() for h in headers if str(h).strip()][:20],
        "trusted": clean_trusted(cdn.get("trusted") or []),
    }

    entry["lists"] = clean_lists(entry.get("lists") or {})
    entry["rule_exclude"] = clean_rule_exclude(entry.get("rule_exclude") or {})
    for key, default in (
        ("disable_php_path", []),
        ("disable_ext", []),
        ("upload_ext", []),
    ):
        items = entry.get(key)
        if not isinstance(items, list):
            items = default
        entry[key] = [str(x).strip() for x in items if str(x).strip()][:200]
    rules = entry.get("custom_rules")
    if not isinstance(rules, list):
        rules = []
    entry["custom_rules"] = [str(x) for x in rules][:200]
    entry["update_time"] = util.safe_int(entry.get("update_time"), 0)
    return entry


# ---------------- 读写 ----------------
def load_global():
    data = util.read_json(paths.GLOBAL_CONFIG, None)
    if data is None and os.path.isfile(paths.default_file("config.json")):
        data = util.read_json(paths.default_file("config.json"), None)
    try:
        cfg, _ = clean_global(data or {})
    except Exception:
        # 配置损坏时回退默认值，保证诊断页仍可用（fail-open）
        cfg, _ = clean_global({})
    return cfg


def save_global(cfg):
    clean, warnings = clean_global(cfg or {})
    clean["update_time"] = util.now()
    util.write_json(paths.GLOBAL_CONFIG, clean)
    return clean, warnings


def load_sites():
    data = util.read_json(paths.SITE_CONFIG, {})
    if not isinstance(data, dict):
        data = {}
    out = {}
    for name, entry in data.items():
        if not isinstance(name, str) or not name.strip():
            continue
        try:
            out[name.strip()] = clean_site(entry)
        except Exception:
            out[name.strip()] = default_site_entry()
    return out


def save_sites(sites):
    util.write_json(paths.SITE_CONFIG, sites or {})


def load_hosts():
    data = util.read_json(paths.HOSTS_CONFIG, {})
    if not isinstance(data, dict):
        return {}
    out = {}
    for host, site in data.items():
        if isinstance(host, str) and isinstance(site, str) and host.strip() and site.strip():
            out[host.strip().lower()] = site.strip()
    return out


def save_hosts(hosts):
    util.write_json(paths.HOSTS_CONFIG, hosts or {})


def load_custom():
    data = util.read_json(paths.CUSTOM_RULES, {"rules": []})
    if isinstance(data, list):
        data = {"rules": data}
    if not isinstance(data, dict):
        data = {"rules": []}
    rules = data.get("rules")
    if not isinstance(rules, list):
        rules = []
    data["rules"] = [clean_custom_rule(r) for r in rules if isinstance(r, dict)]
    return data


def save_custom(data):
    util.write_json(paths.CUSTOM_RULES, data or {"rules": []})


CUSTOM_FIELDS = ("uri", "query", "body", "header", "ua", "ip", "method", "cookie")
CUSTOM_OPS = ("regexp", "contains", "eq", "prefix", "suffix", "in", "not_in", "gt", "lt")
CUSTOM_ACTIONS = ("block", "allow", "log")


def clean_custom_rule(rule):
    rid = str(rule.get("id") or "").strip()
    out = {
        "id": rid,
        "name": util.truncate(rule.get("name") or "自定义规则", 64),
        "open": _bool(rule.get("open"), True),
        "priority": util.safe_int(rule.get("priority"), 10, 0, 1000),
        "scope": "site" if str(rule.get("scope")) == "site" else "global",
        "field": str(rule.get("field") or "uri").strip().lower(),
        "operator": str(rule.get("operator") or "contains").strip().lower(),
        "value": util.truncate(rule.get("value") or "", 2048),
        "action": str(rule.get("action") or "block").strip().lower(),
        "status": util.safe_int(rule.get("status"), 403, 100, 599),
        "score": util.safe_int(rule.get("score"), 5, 1, 100),
        "note": util.truncate(rule.get("note") or "", 256),
        "sites": [],
        "hits": util.safe_int(rule.get("hits"), 0, 0),
    }
    if out["field"] == "header":
        out["header"] = util.truncate(rule.get("header") or "user-agent", 64).lower()
    if out["field"] not in CUSTOM_FIELDS:
        out["field"] = "uri"
    if out["operator"] not in CUSTOM_OPS:
        out["operator"] = "contains"
    if out["action"] not in CUSTOM_ACTIONS:
        out["action"] = "block"
    sites = rule.get("sites")
    if isinstance(sites, list):
        out["sites"] = [str(s).strip() for s in sites if str(s).strip()][:100]
    return out


def valid_custom_rule(rule):
    """返回 (ok, msg)。"""
    if not isinstance(rule, dict):
        return False, "规则格式错误"
    if not str(rule.get("value") or "").strip():
        return False, "匹配内容不能为空"
    op = str(rule.get("operator") or "")
    if op == "regexp" and not util.valid_regex(rule.get("value")):
        return False, "正则表达式无法编译"
    if op in ("gt", "lt"):
        try:
            float(rule.get("value"))
        except Exception:
            return False, "数值比较的匹配内容必须是数字"
    if str(rule.get("field")) == "ip":
        val = str(rule.get("value") or "").strip()
        parts = [p for p in val.split(",") if p.strip()]
        for p in parts:
            if not util.valid_ip_or_cidr(p.strip()):
                return False, "IP 格式错误：%s" % p
    return True, ""


def next_custom_id(rules):
    used = set()
    for r in rules:
        rid = str(r.get("id") or "")
        if rid.startswith("custom-"):
            try:
                used.add(int(rid.split("-", 1)[1]))
            except Exception:
                pass
    i = 1
    while i in used:
        i += 1
    return "custom-%d" % i


# ---------------- 生效配置合并（后端视角，便于 UI/测试） ----------------
def effective_site(global_cfg, site_cfg):
    g = _as_dict(global_cfg)
    s = _as_dict(site_cfg)
    out = deep_merge(g, {})
    out.pop("module", None)
    out["sensitivity"] = s.get("sensitivity") or g.get("sensitivity", 2)
    if s.get("observe") is not None:
        out["observe"] = s.get("observe")
    out["modules"] = {}
    gmods = _as_dict(g.get("modules"))
    smods = _as_dict(s.get("modules"))
    for k in MODULE_KEYS:
        gm = gmods.get(k) or {"open": True, "tier": 1}
        sm = smods.get(k) or {}
        tier = sm.get("tier") or gm.get("tier", 1)
        out["modules"][k] = {"open": _bool(sm.get("open"), gm.get("open", True)), "tier": tier}
    # 站点覆盖 cc / attack_block
    for key in ("cc", "attack_block"):
        gc = dict(_as_dict(g.get(key)))
        sc = _as_dict(s.get(key))
        for k, v in sc.items():
            if v is None or v == 0 or v == "":
                continue
            gc[k] = v
        out[key] = gc
    out["lists"] = {}
    for key in _as_dict(g.get("lists")).keys():
        merged = list(g.get("lists", {}).get(key) or [])
        for item in _as_dict(s.get("lists")).get(key) or []:
            if item not in merged:
                merged.append(item)
        out["lists"][key] = merged
    out["rule_exclude"] = {
        "crs": list(_as_dict(g.get("rule_exclude")).get("crs") or [])
        + list(_as_dict(s.get("rule_exclude")).get("crs") or []),
        "ce": list(_as_dict(g.get("rule_exclude")).get("ce") or [])
        + list(_as_dict(s.get("rule_exclude")).get("ce") or []),
    }
    for key in ("disable_php_path", "disable_ext", "upload_ext"):
        if s.get(key):
            out[key] = list(s.get(key))
    return out
