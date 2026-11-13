# coding: utf-8
"""面板站点枚举与同步。"""
import os

from . import config as C
from . import paths, util


def _fetch_sites(db):
    """db 为 public.M 风格的可调用对象。返回 [{id,name,path,status}]。"""
    try:
        rows = db("sites").field("id,name,path,status").select()
    except Exception:
        try:
            rows = db("sites").select()
        except Exception:
            return []
    if not isinstance(rows, list):
        return []
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or "").strip()
        if not name:
            continue
        out.append(
            {
                "id": r.get("id"),
                "name": name,
                "path": str(r.get("path") or ""),
                "status": util.safe_int(r.get("status"), 1),
            }
        )
    return out


def _fetch_domains(db):
    """返回 {pid: [domain,...]}。"""
    try:
        rows = db("domain").field("pid,name,port").select()
    except Exception:
        try:
            rows = db("domain").select()
        except Exception:
            return {}
    out = {}
    if not isinstance(rows, list):
        return out
    for r in rows:
        if not isinstance(r, dict):
            continue
        try:
            pid = int(r.get("pid"))
        except Exception:
            continue
        name = str(r.get("name") or "").strip().lower()
        if not name:
            continue
        out.setdefault(pid, [])
        if name not in out[pid]:
            out[pid].append(name)
    return out


def list_sites(db):
    """返回 [{site_name, domains, path, status}]，按名称排序。"""
    sites = _fetch_sites(db)
    domains = _fetch_domains(db)
    out = []
    for s in sites:
        doms = list(domains.get(s.get("id"), []))
        if s["name"].lower() not in doms:
            doms.insert(0, s["name"].lower())
        out.append(
            {
                "site_name": s["name"],
                "domains": doms,
                "path": s.get("path") or "",
                "status": s.get("status", 1),
            }
        )
    out.sort(key=lambda x: x["site_name"])
    return out


def site_names(db):
    return [s["site_name"] for s in list_sites(db)]


def site_by_name(db, name):
    if not name:
        return None
    for s in list_sites(db):
        if s["site_name"] == name:
            return s
    return None


def sync(db, write=True):
    """用面板站点数据重建 hosts.json，并补齐 site.json 条目。"""
    sites = list_sites(db)
    cfg_sites = C.load_sites()
    hosts = {}
    added = 0
    for s in sites:
        name = s["site_name"]
        if name not in cfg_sites:
            cfg_sites[name] = C.default_site_entry()
            added += 1
        for host in s.get("domains") or []:
            h = host.strip().lower()
            if not h:
                continue
            # 去掉可能存在的端口
            if h.startswith("["):
                h = h.split("]")[0].strip("[")
            elif h.count(":") == 1:
                h = h.split(":")[0]
            if h:
                hosts[h] = name
        hosts[name.lower()] = name
        # 泛域名：*.example.com 同时注册主域
        for h in list(hosts.keys()):
            if h.startswith("*.") and h[2:] not in hosts:
                hosts[h[2:]] = hosts[h]
    if write:
        C.save_hosts(hosts)
        C.save_sites(cfg_sites)
    return {"sites": len(sites), "hosts": len(hosts), "added": added}


def ensure_site(db, name):
    """站点不存在时抛 ValueError。"""
    if name not in site_names(db):
        raise ValueError("站点不存在：%s" % name)
    return name


def site_with_status(db, sites_cfg):
    """站点列表 + 防护状态（供 get_sites）。"""
    out = []
    for s in list_sites(db):
        name = s["site_name"]
        cfg = sites_cfg.get(name) or C.default_site_entry()
        out.append(
            {
                "site_name": name,
                "domains": s.get("domains") or [],
                "path": s.get("path") or "",
                "status": s.get("status", 1),
                "open": bool(cfg.get("open", True)),
                "sensitivity": cfg.get("sensitivity", 0),
                "today_blocks": 0,
                "last_hit": 0,
            }
        )
    return out


def hosts_map():
    return C.load_hosts()


def default_data_files():
    """确保运行期目录与默认数据文件存在（repair/安装兜底）。"""
    util.ensure_dir(paths.DATA_DIR, 0o755)
    util.ensure_dir(paths.runtime_lua_dir(), 0o755)
    util.ensure_dir(paths.runtime_rule_dir(), 0o755)
    util.ensure_dir(paths.DATA_DIR + "/data", 0o750)
    util.ensure_dir(paths.DATA_DIR + "/logs", 0o755)
    util.ensure_dir(paths.LOG_DIR, 0o750)
    if not os.path.isfile(paths.GLOBAL_CONFIG):
        cfg, _ = C.clean_global({})
        util.write_json(paths.GLOBAL_CONFIG, cfg)
    if not os.path.isfile(paths.SITE_CONFIG):
        util.write_json(paths.SITE_CONFIG, {})
    if not os.path.isfile(paths.HOSTS_CONFIG):
        util.write_json(paths.HOSTS_CONFIG, {})
    if not os.path.isfile(paths.CUSTOM_RULES):
        util.write_json(paths.CUSTOM_RULES, {"rules": []})
    for p in (paths.BLOCK_LOG, paths.UNBAN_LOG, paths.PERF_FILE):
        if not os.path.isfile(p):
            util.write_text(p, "", 0o664)
    if not os.path.isfile(paths.STATE_FILE):
        util.write_json(paths.STATE_FILE, {})
    if not os.path.isfile(paths.PLUGIN_LOG):
        util.write_text(paths.PLUGIN_LOG, "", 0o644)
    return True


