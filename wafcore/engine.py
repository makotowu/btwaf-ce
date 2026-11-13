# coding: utf-8
"""引擎状态、部署、Nginx 配置自愈。"""
import os
import re

from . import config as C
from . import paths, sites, state, util


def _norm(text):
    return "\n".join([ln.strip() for ln in (text or "").strip().splitlines()])


def expected_hash():
    return paths.conf_hash()


def hash_text(text):
    return util.md5_text(_norm(text))


def read_conf():
    return util.read_text(paths.CONF_PATH, "")


def conf_status():
    text = read_conf()
    exists = bool(text)
    try:
        with open(paths.CONF_PATH, "r", encoding="utf-8", errors="ignore") as f:
            exists = True
    except Exception:
        exists = False
    return {
        "path": paths.CONF_PATH,
        "exists": exists,
        "hash_ok": bool(text) and hash_text(text) == expected_hash(),
        "text": text,
    }


def nginx_test():
    return util.nginx_test(paths.NGINX_BIN, paths.NGINX_CONF)


def nginx_lua_ok():
    return util.nginx_lua_supported(paths.NGINX_BIN)


def reload_nginx():
    ok, detail = util.reload_nginx(paths.NGINX_INIT)
    if ok:
        state.update_state(last_reload=util.now())
    return ok, detail


def write_conf():
    util.ensure_dir(os.path.dirname(paths.CONF_PATH), 0o755)
    util.write_text(paths.CONF_PATH, paths.CONF_TEXT, 0o644)
    return True


def remove_conf():
    try:
        if os.path.isfile(paths.CONF_PATH):
            os.remove(paths.CONF_PATH)
        return True
    except Exception:
        return False


def ensure_conf(force=False):
    """确保 conf 存在且与模板一致；不一致时重写。返回 changes 描述。"""
    cur = conf_status()
    changed = False
    if force or not cur["exists"] or not cur["hash_ok"]:
        old_text = cur["text"]
        write_conf()
        ok, out = nginx_test()
        if not ok:
            # 回滚
            if old_text:
                util.write_text(paths.CONF_PATH, old_text, 0o644)
            else:
                remove_conf()
            return {"changed": False, "error": "nginx -t failed", "output": out}
        changed = True
    return {"changed": changed, "error": "", "output": ""}


def deploy_runtime():
    """把插件目录的 lua 复制到运行期目录（升级/自愈用）。"""
    sites.default_data_files()
    src = paths.PLUGIN_LUA
    if not os.path.isdir(src):
        return False, "插件缺少 lua 目录"
    dst = paths.runtime_lua_dir()
    try:
        util.copy_tree(src, dst)
        for root, dirs, files in os.walk(dst):
            try:
                os.chmod(root, 0o755)
            except Exception:
                pass
            for name in files:
                if name.endswith(".lua"):
                    try:
                        os.chmod(os.path.join(root, name), 0o644)
                    except Exception:
                        pass
        return True, ""
    except Exception as e:
        return False, str(e)


def ensure_defaults():
    return sites.default_data_files()


def read_perf():
    data = util.read_json(paths.PERF_FILE, {})
    if not isinstance(data, dict):
        return {"requests": 0, "hits": 0, "avg_ms": 0.0, "updated_at": 0}
    reqs = util.safe_int(data.get("requests"), 0)
    hits = util.safe_int(data.get("hits"), 0)
    total_ms = util.safe_int(data.get("total_ms"), 0)
    return {
        "requests": reqs,
        "hits": hits,
        "avg_ms": round(float(total_ms) / reqs, 3) if reqs else 0.0,
        "updated_at": util.safe_int(data.get("updated_at") or data.get("updated"), 0),
        "errors": util.safe_int(data.get("errors"), 0),
    }


def rules_meta():
    index = {}
    for p in (paths.RULES_INDEX, os.path.join(paths.PLUGIN_DIR, "lua", "rules", "index.json")):
        data = util.read_json(p, None)
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            index = data
            break
    rules = index.get("rules") or []
    by_src = {"crs": 0, "ce": 0, "custom": 0}
    for r in rules:
        src = str(r.get("src") or "")
        if src in by_src:
            by_src[src] += 1
    custom = C.load_custom().get("rules") or []
    by_src["custom"] = len(custom)
    skipped = index.get("skipped") or []
    if not isinstance(skipped, list):
        skipped = []
    clean_skipped = []
    for item in skipped[:5000]:
        if isinstance(item, dict):
            clean_skipped.append(
                {
                    "id": util.truncate(item.get("id") or "", 64),
                    "reason": util.truncate(item.get("reason") or "", 200),
                }
            )
        elif isinstance(item, str):
            clean_skipped.append({"id": util.truncate(item, 64), "reason": ""})
    return {
        "crs_version": str(index.get("crs_version") or ""),
        "total": len(rules) + len(custom),
        "by_src": by_src,
        "skipped": clean_skipped,
        "skipped_count": len(clean_skipped),
        "generated_at": util.safe_int(index.get("generated_at"), 0),
        "index_ok": bool(rules),
    }


def save_block_page(html, use_custom=False):
    clean, removed = util.sanitize_block_page(html or "")
    util.write_text(paths.BLOCK_PAGE, clean, 0o644)
    cfg = C.load_global()
    cfg["block"]["page"] = clean
    cfg["block"]["use_custom"] = bool(use_custom)
    saved, _ = C.save_global(cfg)
    state.mark_config_applied("block_page")
    return {"saved": True, "removed": removed, "size": len(clean)}


def read_block_page():
    return util.read_text(paths.BLOCK_PAGE, "")


def dirs_status():
    checks = {
        "data": paths.DATA_DIR,
        "lua": paths.runtime_lua_dir(),
        "rule": paths.runtime_rule_dir(),
        "logs": paths.LOG_DIR,
        "data_dir_data": os.path.join(paths.DATA_DIR, "data"),
    }
    out = {}
    for key, path in checks.items():
        out[key] = os.path.isdir(path)
    writable = False
    probe = os.path.join(paths.DATA_DIR, "data", ".write_probe")
    try:
        util.write_text(probe, "1", 0o600)
        os.remove(probe)
        writable = True
    except Exception:
        writable = False
    out["writable"] = writable
    return out


def status():
    cfg = C.load_global()
    conf = conf_status()
    dirs = dirs_status()
    lua_ok = nginx_lua_ok()
    lua_dir = paths.runtime_lua_dir()
    lua_files = 0
    if os.path.isdir(lua_dir):
        for root, _dirs, files in os.walk(lua_dir):
            lua_files += len([f for f in files if f.endswith(".lua")])
    rules = rules_meta()
    ready = bool(
        conf["exists"]
        and conf["hash_ok"]
        and dirs.get("lua")
        and dirs.get("data")
        and dirs.get("logs")
        and lua_ok
        and lua_files > 0
    )
    st = state.load_state()
    return {
        "version": paths.VERSION,
        "ready": ready,
        "enabled": bool(cfg.get("enabled")),
        "observe": bool(cfg.get("observe")),
        "sensitivity": cfg.get("sensitivity", 2),
        "nginx": {
            "bin": paths.NGINX_BIN,
            "exists": os.path.isfile(paths.NGINX_BIN),
            "lua": lua_ok,
            "conf_path": paths.CONF_PATH,
            "conf_exists": conf["exists"],
            "conf_ok": conf["exists"] and conf["hash_ok"],
            "conf_hash_ok": conf["hash_ok"],
        },
        "dirs": dirs,
        "lua_files": lua_files,
        "rules": rules,
        "config_apply_at": util.safe_int(st.get("config_apply_at"), 0),
        "last_reload": util.safe_int(st.get("last_reload"), 0),
        "errors": state.read_error_log_tail(20),
        "perf": read_perf(),
    }


def check_env():
    cfg = C.load_global()
    conf = conf_status()
    dirs = dirs_status()
    items = []

    def add(name, ok, detail, repairable=False):
        items.append({"name": name, "ok": bool(ok), "detail": detail, "repairable": bool(repairable)})

    add("Nginx 可执行文件", os.path.isfile(paths.NGINX_BIN), paths.NGINX_BIN)
    add(
        "Nginx Lua 模块",
        nginx_lua_ok(),
        "已编译 lua-nginx-module" if nginx_lua_ok() else "当前 Nginx 不支持 Lua，请切换 Nginx 1.22–1.24 或 OpenResty",
    )
    add("Nginx 配置文件", conf["exists"], paths.CONF_PATH, True)
    add("配置与插件模板一致", conf["hash_ok"], "被修改或缺失时点一键修复即可恢复", True)
    ok_cfg = True
    try:
        C.load_global()
    except Exception:
        ok_cfg = False
    add("全局配置可解析", ok_cfg, paths.GLOBAL_CONFIG, True)
    add("数据目录", dirs.get("data") and dirs.get("data_dir_data"), paths.DATA_DIR, True)
    add("运行期 Lua 目录", dirs.get("lua"), paths.runtime_lua_dir(), True)
    add("日志目录", dirs.get("logs"), paths.LOG_DIR, True)
    add("数据目录可写", dirs.get("writable"), "插件需要写入配置/状态", True)
    rules = rules_meta()
    add("规则索引", rules.get("index_ok"), "规则条数：%d" % rules.get("total", 0), True)
    lua_ok, out = nginx_test()
    add("nginx -t 通过", lua_ok, util.truncate(out.replace("\n", " "), 300))
    needs_repair = any(i["repairable"] and not i["ok"] for i in items)
    manual_required = any((not i["ok"]) and (not i["repairable"]) for i in items)
    return {
        "items": items,
        "repairable": needs_repair,
        "needs_repair": needs_repair,
        "manual_required": manual_required,
        "all_ok": all(i["ok"] for i in items),
    }


def repair_env():
    actions = []
    ok, msg = deploy_runtime()
    actions.append("重新部署 Lua 引擎" + ("" if ok else "（失败：%s）" % msg))
    ensure_defaults()
    actions.append("确保数据目录与默认文件")
    res = ensure_conf(force=True)
    if res.get("error"):
        actions.append("恢复 Nginx 配置失败：%s" % util.truncate(res.get("output", ""), 300))
    else:
        actions.append("恢复 Nginx 配置" if res.get("changed") else "Nginx 配置无需恢复")
    test_ok, out = nginx_test()
    actions.append("nginx -t：" + ("通过" if test_ok else "失败（%s）" % util.truncate(out, 300)))
    reloaded = False
    if test_ok and os.path.isfile(paths.NGINX_BIN):
        reloaded, detail = reload_nginx()
        actions.append("重载 Nginx：" + ("成功" if reloaded else "失败（%s）" % util.truncate(detail, 200)))
    state.append_plugin_log("repair_env：" + "；".join(actions))
    return {"actions": actions, "nginx_test": "ok" if test_ok else "failed", "reloaded": reloaded}


def apply_config(reason=""):
    """配置保存后：标记应用时间；若 conf 漂移则修复。"""
    state.mark_config_applied(reason)
    res = ensure_conf(force=False)
    return res, state.get_apply_time()


def lua_version_meta():
    text = util.read_text(os.path.join(paths.runtime_lua_dir(), "rules", "version.lua"), "")
    out = {"crs": 0, "ce": 0}
    for key in out:
        m = re.search(r"%s\s*=\s*(\d+)" % key, text)
        if m:
            out[key] = int(m.group(1))
    return out
