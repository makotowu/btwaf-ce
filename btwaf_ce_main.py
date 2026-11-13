#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔WAF社区版（btwaf_ce）—— 面板控制器
# | 入口：POST /plugin?action=a&name=btwaf_ce&s=<method>
# +-------------------------------------------------------------------
import json
import os
import re
import sys
import time

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

# 面板公共库（非命令行模式下由面板注入会话）
sys.path.append("/www/server/panel/class")
try:
    import public  # noqa: F401
except Exception:
    public = None

from wafcore import config as C
from wafcore import engine as E
from wafcore import logs as L
from wafcore import paths
from wafcore import rules as R
from wafcore import sites as S
from wafcore import state
from wafcore import util

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SITE_RE = re.compile(r"^[A-Za-z0-9\.\-_\*\u4e00-\u9fa5]+$")


def _api(fn):
    """统一包装：返回值放入 data；异常转 status=false。"""

    def wrapper(self, get=None):
        try:
            self._init_dirs()
            data = fn(self, get)
            return {"status": True, "msg": "", "data": data}
        except ValueError as e:
            return {"status": False, "msg": str(e), "data": None}
        except Exception as e:  # 兜底，避免面板层返回 500
            try:
                state.append_plugin_log("API 异常 %s: %s" % (fn.__name__, e))
            except Exception:
                pass
            return {"status": False, "msg": "内部错误：%s" % str(e)[:300], "data": None}

    wrapper.__name__ = fn.__name__
    return wrapper


class btwaf_ce_main(object):
    def __init__(self):
        self.public = public

    # ---------------- 基础辅助 ----------------
    def _init_dirs(self):
        try:
            # 幂等：确保运行期目录/默认文件存在（安装脚本已建时开销仅几次 stat）
            S.default_data_files()
        except Exception:
            pass

    def _p(self, get, key, default=None):
        if get is None:
            return default
        if isinstance(get, dict):
            return get.get(key, default)
        try:
            return getattr(get, key)
        except Exception:
            return default

    def _obj_param(self, get, key, default=None):
        raw = self._p(get, key, None)
        if raw is None or raw == "":
            return default
        if isinstance(raw, (dict, list)):
            return raw
        try:
            return json.loads(raw)
        except Exception:
            raise ValueError("参数 %s 不是合法 JSON" % key)

    def _site_name(self, get, key="site_name"):
        name = str(self._p(get, key, "") or "").strip()
        if not name:
            raise ValueError("缺少站点名")
        if len(name) > 253 or not SITE_RE.match(name):
            raise ValueError("站点名格式不正确")
        return name

    def _check_site_exists(self, name):
        db = getattr(self.public, "M", None) if self.public else None
        if not callable(db):
            return True
        try:
            names = S.site_names(db)
        except Exception:
            return True
        if names and name not in names:
            raise ValueError("站点不存在：%s" % name)
        return True

    def _area_lookup(self):
        if self.public is None:
            return None
        fn = getattr(self.public, "get_ip_location", None)
        return fn if callable(fn) else None

    def _db(self):
        db = getattr(self.public, "M", None) if self.public else None
        if not callable(db):
            raise ValueError("无法访问面板数据库（public.M 不可用）")
        return db

    def _date(self, get, key="date"):
        d = str(self._p(get, key, "") or "").strip()
        if not d:
            return util.date_str()
        if not DATE_RE.match(d):
            raise ValueError("日期格式应为 YYYY-MM-DD")
        return d

    def _audit(self, msg):
        try:
            if self.public is not None and hasattr(self.public, "WriteLog"):
                self.public.WriteLog("宝塔WAF社区版", msg)
        except Exception:
            pass
        try:
            state.append_plugin_log(msg)
        except Exception:
            pass

    def _reload_if_needed(self):
        try:
            res = E.ensure_conf(force=False)
            if res.get("changed"):
                E.reload_nginx()
        except Exception:
            pass

    # ---------------- 系统 / 状态 ----------------
    @_api
    def get_engine_status(self, get):
        return E.status()

    @_api
    def check_env(self, get):
        return E.check_env()

    @_api
    def repair_env(self, get):
        res = E.repair_env()
        self._audit("一键修复：" + "；".join(res.get("actions") or []))
        return res

    @_api
    def get_overview(self, get):
        date = self._date(get)
        cfg = C.load_global()
        st = E.status()
        db = getattr(self.public, "M", None) if self.public else None
        sites_total = 0
        sites_open = 0
        try:
            if callable(db):
                rows = S.list_sites(db)
                sites_total = len(rows)
                cfg_sites = C.load_sites()
                sites_open = len([1 for r in rows if (cfg_sites.get(r["site_name"]) or {}).get("open", True)])
        except Exception:
            pass
        stat_data = L.stat_for_date(date, None)
        hits, last_hits = L.site_hit_counts(date)
        return {
            "date": date,
            "stats": {
                "blocks": stat_data.get("blocks", stat_data["total"]),
                "allowed": stat_data.get("allowed", 0),
                "cc_blocks": stat_data["cc"],
                "attack_ips": len(stat_data["ips"]),
                "sites_total": sites_total,
                "sites_open": sites_open,
                "requests": (st.get("perf") or {}).get("requests"),
            },
            "trend": L.trend(7),
            "types": stat_data["types"],
            "top_ips": L.top_ips(date, 10, self._area_lookup()),
            "top_urls": L.top_urls(date, 10),
            "recent": L.recent(10),
            "engine": {
                "ready": st.get("ready"),
                "enabled": cfg.get("enabled"),
                "observe": cfg.get("observe"),
                "sensitivity": cfg.get("sensitivity"),
            },
            "hits_by_site": hits,
        }

    @_api
    def get_logs(self, get):
        p = util.safe_int(self._p(get, "p"), 1, 1)
        rows = util.safe_int(self._p(get, "rows"), 50, 1, 200)
        lines = state.read_plugin_log()
        lines = list(reversed(lines))
        total = len(lines)
        start = (p - 1) * rows
        items = []
        for line in lines[start : start + rows]:
            content = line.strip()
            ts = 0
            m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", content)
            if m:
                try:
                    ts = int(time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")))
                except Exception:
                    ts = 0
            items.append({"time": ts, "content": content})
        return {"list": items, "total": total, "page": p, "rows": rows}

    @_api
    def clear_logs(self, get):
        state.clear_plugin_log()
        self._audit("清空插件操作日志")
        return {"cleared": True}

    # ---------------- 全局配置 ----------------
    @_api
    def get_plugin_config(self, get):
        return C.load_global()

    @_api
    def save_plugin_config(self, get):
        payload = self._obj_param(get, "config", None)
        if not isinstance(payload, dict):
            raise ValueError("config 参数必须是对象")
        cur = C.load_global()
        merged = C.deep_merge(cur, payload)
        saved, warnings = C.save_global(merged)
        if saved.get("block", {}).get("page"):
            util.write_text(paths.BLOCK_PAGE, saved["block"]["page"], 0o644)
        res, apply_at = E.apply_config("save_plugin_config")
        self._audit("更新全局配置")
        return {"saved": True, "apply_at": apply_at, "warnings": warnings, "conf_restored": bool(res.get("changed"))}

    @_api
    def get_modules(self, get):
        return {
            "modules": R.modules_meta(),
            "sensitivity_options": [
                {"value": 1, "label": "宽松（阈值 10，仅 PL1）"},
                {"value": 2, "label": "标准（阈值 5，PL1+部分 PL2）"},
                {"value": 3, "label": "严格（阈值 3，PL1–PL3）"},
            ],
        }

    @_api
    def save_modules(self, get):
        payload = self._obj_param(get, "modules", None)
        if not isinstance(payload, dict):
            raise ValueError("modules 参数必须是对象")
        cfg = C.load_global()
        for key, item in payload.items():
            if key not in C.MODULE_KEYS:
                continue
            if not isinstance(item, dict):
                continue
            cur = cfg["modules"].get(key) or {"open": True, "tier": 1}
            if "open" in item:
                cur["open"] = bool(item.get("open"))
            if "tier" in item:
                cur["tier"] = util.safe_int(item.get("tier"), 1, 1, 3)
            cfg["modules"][key] = cur
        C.save_global(cfg)
        E.apply_config("save_modules")
        self._audit("更新模块开关")
        return {"saved": True}

    @_api
    def get_rules(self, get):
        return R.get_rules(
            {
                "module": self._p(get, "module", ""),
                "source": self._p(get, "source", ""),
                "keyword": self._p(get, "keyword", ""),
                "status": self._p(get, "status", ""),
                "p": self._p(get, "p", 1),
                "rows": self._p(get, "rows", 50),
            }
        )

    @_api
    def set_rule_exclude(self, get):
        scope = str(self._p(get, "scope", "global") or "global")
        site_name = str(self._p(get, "site_name", "") or "").strip()
        type_key = str(self._p(get, "type", "") or "").strip()
        ids = self._obj_param(get, "ids", [])
        if not isinstance(ids, list):
            raise ValueError("ids 必须是数组")
        if scope == "site":
            self._check_site_exists(site_name)
        res = R.set_rule_exclude(scope, site_name, type_key, ids)
        self._audit("更新规则排除：%s/%s" % (scope, type_key))
        return res

    @_api
    def save_block_page(self, get):
        html = self._p(get, "html", "") or ""
        use_custom = bool(self._p(get, "use_custom", True))
        if len(html) > 65536:
            raise ValueError("拦截页不能超过 64KB")
        res = E.save_block_page(html, use_custom)
        self._audit("更新自定义拦截页")
        return res

    @_api
    def preview_block_page(self, get):
        html = self._p(get, "html", "") or ""
        clean, removed = util.sanitize_block_page(html)
        return {"html": clean, "removed": removed, "intercepted": removed, "size": len(clean)}

    # ---------------- 站点 ----------------
    @_api
    def get_sites(self, get):
        keyword = str(self._p(get, "keyword", "") or "").strip().lower()
        status = str(self._p(get, "status", "") or "").strip().lower()
        p = util.safe_int(self._p(get, "p"), 1, 1)
        rows = util.safe_int(self._p(get, "rows"), 50, 1, 200)
        db = self._db()
        cfg_sites = C.load_sites()
        items = S.site_with_status(db, cfg_sites)
        today = util.date_str()
        hits, last_hits = L.site_hit_counts(today)
        out = []
        for item in items:
            name = item["site_name"]
            if keyword and keyword not in name.lower() and not any(keyword in d for d in item.get("domains") or []):
                continue
            is_open = bool(item.get("open", True))
            if status == "open" and not is_open:
                continue
            if status in ("unprotected", "closed") and is_open:
                continue
            item["today_blocks"] = hits.get(name, 0)
            item["last_hit"] = last_hits.get(name, 0)
            out.append(item)
        total = len(out)
        start = (p - 1) * rows
        return {"list": out[start : start + rows], "total": total, "page": p, "rows": rows}

    @_api
    def sync_sites(self, get):
        db = self._db()
        res = S.sync(db)
        self._audit("同步站点：%s" % json.dumps(res, ensure_ascii=False))
        return res

    @_api
    def get_site_config(self, get):
        name = self._site_name(get)
        self._check_site_exists(name)
        cfg_sites = C.load_sites()
        raw = cfg_sites.get(name) or C.default_site_entry()
        glob = C.load_global()
        return {
            "site_name": name,
            "config": C.effective_site(glob, raw),
            "raw": raw,
            "global": glob,
        }

    @_api
    def save_site_config(self, get):
        name = self._site_name(get)
        self._check_site_exists(name)
        payload = self._obj_param(get, "config", None)
        if not isinstance(payload, dict):
            raise ValueError("config 参数必须是对象")
        cfg_sites = C.load_sites()
        cur = cfg_sites.get(name) or C.default_site_entry()
        # 站点配置允许把可选字段显式置回“继承全局”（JSON null / "__inherit__"）
        INHERIT = ("observe",)
        base = C.deep_merge(cur, {k: v for k, v in payload.items() if k not in INHERIT})
        for key in INHERIT:
            if key in payload:
                v = payload.get(key)
                base[key] = None if (v is None or v == "__inherit__") else v
        for sect, subkeys in (("cc", ("open", "url_cc")), ("attack_block", ("open",))):
            if isinstance(payload.get(sect), dict):
                cur_sect = base.get(sect) if isinstance(base.get(sect), dict) else {}
                for sub in subkeys:
                    if sub in payload[sect]:
                        v = payload[sect][sub]
                        cur_sect[sub] = None if (v is None or v == "__inherit__") else v
                base[sect] = cur_sect
        merged = C.clean_site(base)
        merged["update_time"] = util.now()
        cfg_sites[name] = merged
        C.save_sites(cfg_sites)
        E.apply_config("save_site_config")
        self._audit("更新站点配置：%s" % name)
        return {"saved": True, "apply_at": state.get_apply_time()}

    @_api
    def set_site_open(self, get):
        names = self._obj_param(get, "site_names", [])
        if not isinstance(names, list) or not names:
            raise ValueError("site_names 必须是非空数组")
        open_flag = self._p(get, "open", None)
        if open_flag is None:
            raise ValueError("缺少 open 参数")
        open_flag = bool(open_flag) if not isinstance(open_flag, str) else open_flag.lower() in ("1", "true", "yes", "on")
        cfg_sites = C.load_sites()
        updated = 0
        for name in names:
            name = str(name).strip()
            if not name:
                continue
            entry = cfg_sites.get(name) or C.default_site_entry()
            entry["open"] = open_flag
            entry["update_time"] = util.now()
            cfg_sites[name] = entry
            updated += 1
        C.save_sites(cfg_sites)
        E.apply_config("set_site_open")
        self._audit("批量%s防护：%d 个站点" % ("开启" if open_flag else "关闭", updated))
        return {"updated": updated}

    # ---------------- 拦截记录 / 封锁 ----------------
    @_api
    def get_attack_logs(self, get):
        date = self._date(get)
        params = {
            "date": date,
            "site": self._p(get, "site", ""),
            "keyword": self._p(get, "keyword", ""),
            "type": self._p(get, "type", ""),
            "ip": self._p(get, "ip", ""),
            "action": self._p(get, "log_action", "") or self._p(get, "action", ""),
            "log_action": self._p(get, "log_action", ""),
            "p": self._p(get, "p", 1),
            "rows": self._p(get, "rows", 20),
        }
        res = L.query_logs(params)
        lookup = self._area_lookup()
        if callable(lookup):
            for rec in res.get("list") or []:
                if not rec.get("area"):
                    rec["area"] = L.area_of(rec.get("ip"), lookup)
        return res

    @_api
    def get_attack_stat(self, get):
        date = self._date(get)
        site = str(self._p(get, "site", "") or "").strip()
        return L.stat_for_date(date, site or None)

    @_api
    def get_block_list(self, get):
        params = {
            "site": self._p(get, "site", ""),
            "status": self._p(get, "status", "current"),
            "p": self._p(get, "p", 1),
            "rows": self._p(get, "rows", 50),
        }
        return L.block_list(params, self._area_lookup())

    @_api
    def unban_ip(self, get):
        ip = str(self._p(get, "ip", "") or "").strip()
        site_name = str(self._p(get, "site", "") or "").strip()
        L.unban(ip, site_name)
        self._audit("解封 IP：%s%s" % (ip, (" @ " + site_name) if site_name else ""))
        return {"unbanned": 1, "ip": ip, "site": site_name}

    @_api
    def unban_all(self, get):
        site_name = str(self._p(get, "site", "") or "").strip()
        count = L.unban_all(site_name, self._area_lookup())
        self._audit("解封全部 IP（%s）：%d 个" % (site_name or "全部站点", count))
        return {"unbanned": count}

    # ---------------- 黑白名单 ----------------
    @_api
    def get_lists(self, get):
        scope = str(self._p(get, "scope", "global") or "global")
        if scope == "site":
            name = self._site_name(get)
            self._check_site_exists(name)
            entry = C.load_sites().get(name) or C.default_site_entry()
            lists = entry.get("lists") or {}
        else:
            lists = C.load_global().get("lists") or {}
        return {"lists": lists, "scope": scope}

    @_api
    def set_lists(self, get):
        scope = str(self._p(get, "scope", "global") or "global")
        type_key = str(self._p(get, "type", "") or "").strip()
        if type_key not in ("ip_black", "ip_white", "url_black", "url_white", "ua_black", "ua_white", "param_white"):
            raise ValueError("名单类型不支持")
        items = self._obj_param(get, "items", [])
        if not isinstance(items, list):
            raise ValueError("items 必须是数组")
        clean = C.clean_lists({type_key: items})[type_key]
        if scope == "site":
            name = self._site_name(get)
            self._check_site_exists(name)
            cfg_sites = C.load_sites()
            entry = cfg_sites.get(name) or C.default_site_entry()
            entry.setdefault("lists", {})
            entry["lists"][type_key] = clean
            entry["update_time"] = util.now()
            cfg_sites[name] = entry
            C.save_sites(cfg_sites)
        else:
            cfg = C.load_global()
            cfg.setdefault("lists", {})
            cfg["lists"][type_key] = clean
            C.save_global(cfg)
        E.apply_config("set_lists")
        self._audit("更新%s：%s，%d 条" % (scope, type_key, len(clean)))
        return {"saved": True, "count": len(clean)}

    # ---------------- 自定义规则 ----------------
    @_api
    def get_custom_rules(self, get):
        keyword = str(self._p(get, "keyword", "") or "").strip().lower()
        p = util.safe_int(self._p(get, "p"), 1, 1)
        rows = util.safe_int(self._p(get, "rows"), 50, 1, 200)
        data = C.load_custom()
        items = data.get("rules") or []
        if keyword:
            items = [
                r
                for r in items
                if keyword in (r.get("name", "") + " " + r.get("value", "") + " " + r.get("id", "")).lower()
            ]
        items = sorted(items, key=lambda x: util.safe_int(x.get("priority"), 10))
        total = len(items)
        start = (p - 1) * rows
        page_items = items[start : start + rows]
        try:
            hits = L.rule_hits_for([r.get("id") for r in page_items])
        except Exception:
            hits = {}
        for r in page_items:
            r["hits"] = util.safe_int(hits.get(r.get("id")), 0)
        return {"list": page_items, "total": total, "page": p, "rows": rows}

    @_api
    def save_custom_rule(self, get):
        payload = self._obj_param(get, "rule", None)
        if not isinstance(payload, dict):
            raise ValueError("rule 参数必须是对象")
        ok, msg = C.valid_custom_rule(payload)
        if not ok:
            raise ValueError(msg)
        data = C.load_custom()
        rules = data.get("rules") or []
        clean = C.clean_custom_rule(payload)
        rid = str(clean.get("id") or "").strip()
        if rid:
            found = False
            for i, r in enumerate(rules):
                if r.get("id") == rid:
                    rules[i] = clean
                    found = True
                    break
            if not found:
                rules.append(clean)
        else:
            clean["id"] = C.next_custom_id(rules)
            rules.append(clean)
            rid = clean["id"]
        data["rules"] = sorted(rules, key=lambda x: util.safe_int(x.get("priority"), 10))
        C.save_custom(data)
        E.apply_config("save_custom_rule")
        self._audit("保存自定义规则：%s %s" % (rid, clean.get("name", "")))
        return {"id": rid, "saved": True}

    @_api
    def del_custom_rule(self, get):
        rid = str(self._p(get, "id", "") or "").strip()
        if not rid:
            raise ValueError("缺少规则 ID")
        data = C.load_custom()
        rules = data.get("rules") or []
        new_rules = [r for r in rules if r.get("id") != rid]
        data["rules"] = new_rules
        C.save_custom(data)
        E.apply_config("del_custom_rule")
        self._audit("删除自定义规则：%s" % rid)
        return {"deleted": len(rules) - len(new_rules)}

    # ---------------- 导入导出 ----------------
    @_api
    def export_config(self, get):
        return {
            "config": C.load_global(),
            "site": C.load_sites(),
            "custom": C.load_custom(),
            "exported_at": util.now(),
        }

    @_api
    def import_config(self, get):
        payload = self._obj_param(get, "payload", None)
        if not isinstance(payload, dict):
            raise ValueError("payload 必须是对象")
        cfg = payload.get("config")
        if isinstance(cfg, dict):
            saved, _warnings = C.save_global(cfg)
            if saved.get("block", {}).get("page"):
                util.write_text(paths.BLOCK_PAGE, saved["block"]["page"], 0o644)
        site_cfg = payload.get("site")
        if isinstance(site_cfg, dict):
            out = {}
            for name, entry in site_cfg.items():
                if isinstance(name, str) and name.strip() and isinstance(entry, dict):
                    out[name.strip()] = C.clean_site(entry)
            C.save_sites(out)
        custom = payload.get("custom")
        if isinstance(custom, dict) and isinstance(custom.get("rules"), list):
            C.save_custom({"rules": [C.clean_custom_rule(r) for r in custom["rules"] if isinstance(r, dict)]})
        E.apply_config("import_config")
        self._audit("导入配置")
        return {"imported": True}

    # ---------------- 自测 ----------------
    @_api
    def run_selftest(self, get):
        name = self._site_name(get, "site")
        self._check_site_exists(name)
        payload = str(self._p(get, "payload", "") or "")
        if not payload:
            raise ValueError("payload 不能为空")
        if len(payload) > 2048:
            raise ValueError("payload 不能超过 2048 字符")
        location = str(self._p(get, "location", "query") or "query").lower()
        if location not in ("query", "body", "header", "ua"):
            raise ValueError("location 不支持")
        start = util.now() - 2
        status = 0
        try:
            import urllib.error
            import urllib.parse
            import urllib.request

            url = "http://127.0.0.1/"
            headers = {"Host": name, "User-Agent": "btwaf-ce-selftest/1.0"}
            data = None
            method = "GET"
            if location == "query":
                url = "http://127.0.0.1/?q=" + urllib.parse.quote(payload)
            elif location == "body":
                method = "POST"
                data = ("q=" + urllib.parse.quote(payload)).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif location == "header":
                headers["X-Test"] = payload
            elif location == "ua":
                headers["User-Agent"] = payload
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                status = resp.getcode()
                resp.read(1024)
            except urllib.error.HTTPError as he:
                status = he.code
            except Exception as e:
                raise ValueError("本地请求失败：%s" % str(e)[:200])
        except ValueError:
            raise
        except Exception as e:
            raise ValueError("自测请求失败：%s" % str(e)[:200])
        time.sleep(0.5)
        records = L.recent(50)
        hit = None
        for rec in records:
            if rec.get("site") == name and rec.get("time", 0) >= start:
                hit = rec
                break
        return {
            "blocked": bool(hit and hit.get("action") == "block"),
            "status": status,
            "hits": (hit or {}).get("hits") or [],
            "request_id": (hit or {}).get("req_id") or "",
            "log": hit,
        }

    # ---------------- 兼容/占位 ----------------
    @_api
    def index(self, get):
        return {"version": paths.VERSION, "title": "宝塔WAF社区版"}


# 供面板识别（部分版本会读取该变量）
__plugin_name__ = "btwaf_ce"
