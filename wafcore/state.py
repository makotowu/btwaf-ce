# coding: utf-8
"""运行状态、操作日志、应用时间。"""
import os

from . import paths, util


def load_state():
    data = util.read_json(paths.STATE_FILE, {})
    if not isinstance(data, dict):
        data = {}
    return data


def save_state(state):
    util.write_json(paths.STATE_FILE, state or {})
    return state


def update_state(**kwargs):
    state = load_state()
    state.update(kwargs)
    save_state(state)
    return state


def mark_config_applied(reason=""):
    ts = util.now()
    update_state(config_apply_at=ts, config_apply_reason=reason)
    return ts


def get_apply_time():
    return util.safe_int(load_state().get("config_apply_at"), 0)


def get_unban_offset():
    return util.safe_int(load_state().get("unban_offset"), 0)


def set_unban_offset(offset):
    update_state(unban_offset=util.safe_int(offset, 0))


def append_plugin_log(content):
    try:
        line = "%s  %s" % (util.time_str(), util.truncate(content, 2000))
        util.append_line(paths.PLUGIN_LOG, line, 0o644)
    except Exception:
        pass


def read_plugin_log(max_bytes=1024 * 1024):
    path = paths.PLUGIN_LOG
    if not os.path.isfile(path):
        return []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            data = f.read().decode("utf-8", "ignore")
        lines = [ln for ln in data.splitlines() if ln.strip()]
        return lines[-5000:]
    except Exception:
        return []


def clear_plugin_log():
    try:
        util.write_text(paths.PLUGIN_LOG, "", 0o644)
        return True
    except Exception:
        return False


def read_error_log_tail(limit=50):
    """读取 Lua 错误日志（data/logs/error.log），返回 [{time,msg}]。"""
    path = os.path.join(paths.DATA_DIR, "logs", "error.log")
    if not os.path.isfile(path):
        return []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > 262144:
                f.seek(size - 262144)
            data = f.read().decode("utf-8", "ignore")
        items = []
        for ln in data.splitlines()[-limit:]:
            ln = ln.strip()
            if not ln:
                continue
            items.append({"time": 0, "msg": util.truncate(ln, 500)})
        return items
    except Exception:
        return []
