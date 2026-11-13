# coding: utf-8
"""规则清单（读取 index.json，缺失时回退扫描 Lua）与规则排除。"""
import os
import re

from . import config as C
from . import paths, state, util

ID_RE = re.compile(r'id\s*=\s*"([^"]+)"')
MODULE_RE = re.compile(r'module\s*=\s*"([^"]+)"')
TIER_RE = re.compile(r"tier\s*=\s*(\d+)")
SCORE_RE = re.compile(r"score\s*=\s*(\d+)")
NAME_RE = re.compile(r'name\s*=\s*"((?:[^"\\]|\\.)*)"')


def _index_paths():
    return [
        paths.RULES_INDEX,
        os.path.join(paths.PLUGIN_DIR, "lua", "rules", "index.json"),
    ]


def load_index():
    for p in _index_paths():
        data = util.read_json(p, None)
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            return data
    return {"rules": [], "crs_version": "", "skipped": [], "_fallback": True}


def _scan_lua_rules(root):
    """从 Lua 规则文件粗略提取元数据（index.json 缺失时兜底）。"""
    out = []
    if not os.path.isdir(root):
        return out
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith(".lua"):
                continue
            if name in ("ac.lua", "version.lua", "crs_meta.lua", "index.lua"):
                continue
            path = os.path.join(dirpath, name)
            text = util.read_text(path, "")
            segments = []
            matches = list(ID_RE.finditer(text))
            for i, m in enumerate(matches):
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                segments.append(text[m.start() : end])
            for seg in segments:
                rid = ID_RE.search(seg)
                if not rid:
                    continue
                module = MODULE_RE.search(seg)
                tier = TIER_RE.search(seg)
                score = SCORE_RE.search(seg)
                nm = NAME_RE.search(seg)
                out.append(
                    {
                        "id": rid.group(1),
                        "module": module.group(1) if module else "protocol",
                        "name": nm.group(1) if nm else "",
                        "tier": util.safe_int(tier.group(1) if tier else 1, 1),
                        "score": util.safe_int(score.group(1) if score else 5, 5),
                        "src": "ce" if rid.group(1).startswith("ce-") else "crs",
                    }
                )
    return out


def all_rules():
    index = load_index()
    rules = index.get("rules") or []
    if not rules:
        runtime = os.path.join(paths.runtime_lua_dir(), "rules")
        plugin = os.path.join(paths.PLUGIN_DIR, "lua", "rules")
        rules = _scan_lua_rules(runtime) or _scan_lua_rules(plugin)
    custom = C.load_custom().get("rules") or []
    merged = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        merged.append(
            {
                "id": str(r.get("id") or ""),
                "module": str(r.get("module") or ""),
                "name": str(r.get("name") or ""),
                "tier": util.safe_int(r.get("tier"), 1, 1, 3),
                "score": util.safe_int(r.get("score"), 5, 0, 100),
                "src": str(r.get("src") or ("ce" if str(r.get("id", "")).startswith("ce-") else "crs")),
            }
        )
    for r in custom:
        merged.append(
            {
                "id": r.get("id", ""),
                "module": "custom",
                "name": r.get("name", ""),
                "tier": 1,
                "score": util.safe_int(r.get("score"), 5),
                "src": "custom",
            }
        )
    return merged


def _is_enabled(rule, cfg, site_cfg=None):
    sensitivity = cfg.get("sensitivity", 2)
    excludes = set((cfg.get("rule_exclude") or {}).get(rule["src"], []) or [])
    if site_cfg:
        sensitivity = site_cfg.get("sensitivity") or sensitivity
        for key in ("crs", "ce"):
            excludes.update((site_cfg.get("rule_exclude") or {}).get(key, []) or [])
    modules = cfg.get("modules") or {}
    mod = modules.get(rule["module"]) or {}
    if not mod.get("open", True):
        return False
    if util.safe_int(rule["tier"], 1) > util.safe_int(sensitivity, 2):
        return False
    if rule["id"] in excludes:
        return False
    return True


def get_rules(params=None):
    params = params or {}
    module = (params.get("module") or "").strip().lower()
    source = (params.get("source") or "").strip().lower()
    keyword = (params.get("keyword") or "").strip().lower()
    status = (params.get("status") or "").strip().lower()
    page = util.safe_int(params.get("p"), 1, 1)
    rows = util.safe_int(params.get("rows"), 50, 1, 500)
    cfg = C.load_global()
    rules = all_rules()
    out = []
    for r in rules:
        if module and r["module"] != module:
            continue
        if source and r["src"] != source:
            continue
        if keyword and keyword not in (r["id"] + " " + r["name"]).lower():
            continue
        r = dict(r)
        r["enabled"] = _is_enabled(r, cfg)
        if status == "enabled" and not r["enabled"]:
            continue
        if status in ("disabled", "excluded") and r["enabled"]:
            continue
        out.append(r)
    out.sort(key=lambda x: (x["module"], x["src"], x["id"]))
    total = len(out)
    start = (page - 1) * rows
    page_list = out[start : start + rows]
    try:
        from . import logs as _logs

        hits = _logs.rule_hits_for([r["id"] for r in page_list])
    except Exception:
        hits = {}
    for r in page_list:
        r["hits"] = util.safe_int(hits.get(r["id"]), 0)
    index = load_index()
    return {
        "list": page_list,
        "total": total,
        "page": page,
        "rows": rows,
        "skipped": index.get("skipped") or [],
        "crs_version": index.get("crs_version") or "",
    }


def modules_meta(params=None):
    cfg = C.load_global()
    rules = all_rules()
    out = {}
    for key, _name in C.MODULES:
        items = [r for r in rules if r["module"] == key]
        enabled = [r for r in items if _is_enabled(r, cfg)]
        mod = (cfg.get("modules") or {}).get(key) or {}
        out[key] = {
            "open": bool(mod.get("open", True)),
            "tier": util.safe_int(mod.get("tier"), 1, 1, 3),
            "total": len(items),
            "enabled": len(enabled),
        }
    return out


def set_rule_exclude(scope, site_name, type_key, ids, db=None):
    type_key = (type_key or "").strip().lower()
    if type_key not in ("crs", "ce"):
        raise ValueError("规则类型只支持 crs / ce")
    if not isinstance(ids, list):
        raise ValueError("ids 必须是数组")
    clean = []
    for item in ids:
        item = str(item).strip()
        if item and len(item) <= 64 and item not in clean:
            clean.append(item)
    if scope == "site":
        if not site_name:
            raise ValueError("缺少站点名")
        sites_cfg = C.load_sites()
        if site_name not in sites_cfg:
            raise ValueError("站点不存在：%s" % site_name)
        entry = sites_cfg[site_name]
        entry.setdefault("rule_exclude", {"crs": [], "ce": []})
        entry["rule_exclude"][type_key] = clean
        entry["update_time"] = util.now()
        C.save_sites(sites_cfg)
    else:
        cfg = C.load_global()
        cfg.setdefault("rule_exclude", {"crs": [], "ce": []})
        cfg["rule_exclude"][type_key] = clean
        C.save_global(cfg)
    state.mark_config_applied("rule_exclude")
    state.append_plugin_log("更新规则排除：%s/%s，%d 条" % (scope or "global", type_key, len(clean)))
    return {"saved": True, "count": len(clean)}


def version_info():
    index = load_index()
    return {
        "crs_version": index.get("crs_version") or "",
        "generated_at": util.safe_int(index.get("generated_at"), 0),
        "skipped": index.get("skipped") or [],
        "fallback_scan": bool(index.get("_fallback")),
        "total": len(all_rules()),
    }
