# coding: utf-8
"""Nginx/OpenResty/Tengine 路径发现与 Lua 指令探测（安装与诊断共用）。"""
import argparse
import glob
import os
import re
import shlex
import sys
import tempfile
import threading
import time

if __package__:
    from . import util
else:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from wafcore import util

PANEL_ROOT = "/www/server/nginx"
PANEL_VHOST_DIR = "/www/server/panel/vhost/nginx"


def _test_mode():
    return os.environ.get("BTWAF_CE_TEST_MODE") == "1"


def resolve_paths():
    """Use BaoTa's Nginx paths; overrides are enabled only for isolated tests."""
    test_mode = _test_mode()
    root = os.environ.get("BTWAF_CE_SERVER_ROOT", PANEL_ROOT) if test_mode else PANEL_ROOT
    return (
        (os.environ.get("BTWAF_CE_NGINX_BIN") if test_mode else None) or os.path.join(root, "sbin", "nginx"),
        (os.environ.get("BTWAF_CE_NGINX_CONF") if test_mode else None) or os.path.join(root, "conf", "nginx.conf"),
        (os.environ.get("BTWAF_CE_NGINX_INIT") if test_mode else None) or "/etc/init.d/nginx",
    )


def _configured_vhost_dir(nginx_conf):
    if not nginx_conf or not os.path.isfile(nginx_conf):
        return ""
    try:
        with open(nginx_conf, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        for scope, words, _raw in _directives(text, ()):
            if scope != ("http",) or words[0] != "include" or len(words) != 2:
                continue
            pattern = words[1]
            if not (pattern.startswith("/") or os.path.isabs(pattern)):
                pattern = os.path.join(os.path.dirname(os.path.abspath(nginx_conf)), pattern)
            directory = os.path.normcase(os.path.normpath(os.path.dirname(pattern)))
            if directory == os.path.normcase(os.path.normpath(PANEL_VHOST_DIR)):
                return PANEL_VHOST_DIR
    except (OSError, ValueError):
        pass
    return ""


def resolve_vhost_dir():
    """Use the panel's Nginx vhost directory, preferring its HTTP include."""
    test_mode = _test_mode()
    override = os.environ.get("BTWAF_CE_VHOST_DIR") if test_mode else None
    if override:
        return override
    nginx_conf = resolve_paths()[1]
    return _configured_vhost_dir(nginx_conf) or PANEL_VHOST_DIR


def _prefix_from_banner(text):
    arguments = (text or "").partition("configure arguments:")[2] or text or ""
    try:
        for word in shlex.split(arguments):
            if word.startswith("--prefix="):
                return word[len("--prefix="):]
    except ValueError:
        pass
    return ""


def _token(text, pos):
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
        elif text[pos] == "#":
            end = text.find("\n", pos)
            pos = len(text) if end < 0 else end + 1
        else:
            break
    start = pos
    if pos == len(text):
        return None
    if text[pos] in "{};":
        return text[pos], True, start, pos + 1
    chars = []
    quote = None
    while pos < len(text):
        char = text[pos]
        if char == "\\" and pos + 1 < len(text):
            chars.append(text[pos + 1])
            pos += 2
            continue
        if quote:
            if char == quote:
                quote = None
            else:
                chars.append(char)
        elif char in ("'", '"'):
            quote = char
        elif text.startswith("${", pos):
            end = text.find("}", pos + 2)
            if end < 0:
                raise ValueError("配置中的变量未闭合")
            chars.append(text[pos : end + 1])
            pos = end + 1
            continue
        elif char.isspace() or char in "{};#":
            break
        else:
            chars.append(char)
        pos += 1
    if quote:
        raise ValueError("配置中的引号未闭合")
    return "".join(chars), False, start, pos


def _lua_block_end(text, pos):
    depth = 1
    pos += 1
    while pos < len(text):
        char = text[pos]
        comment = text.startswith("--", pos)
        long = re.match(r"\[(=*)\[", text[pos + 2 :] if comment else text[pos:]) if char == "[" or comment else None
        if long:
            close = "]" + long.group(1) + "]"
            start = pos + (2 if comment else 0) + len(long.group(0))
            end = text.find(close, start)
            if end < 0:
                break
            pos = end + len(close)
            continue
        if comment:
            end = text.find("\n", pos)
            pos = len(text) if end < 0 else end + 1
            continue
        if char in ("'", '"'):
            quote = char
            pos += 1
            while pos < len(text):
                if text[pos] == "\\":
                    pos += 2
                    continue
                if text[pos] == quote:
                    break
                pos += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return pos + 1
        pos += 1
    raise ValueError("配置中的 Lua 块未闭合")


def _directives(text, scope):
    scopes = [scope]
    words = []
    start = pos = 0
    while True:
        token = _token(text, pos)
        if token is None:
            break
        value, punctuation, begin, pos = token
        if not punctuation:
            if not words:
                start = begin
            words.append(value)
            continue
        if value == "{":
            name = words[0] if words else ""
            if name.endswith("_by_lua_block"):
                pos = _lua_block_end(text, begin)
            else:
                scopes.append(scopes[-1] + (name,))
        elif value == "}":
            if words:
                raise ValueError("配置中的指令缺少分号")
            if len(scopes) == 1:
                raise ValueError("配置中存在多余的右花括号")
            scopes.pop()
        elif words:
            yield scopes[-1], words, text[start:pos]
        words = []
    if len(scopes) != 1 or words:
        raise ValueError("配置中的指令或块未闭合")


def _probe_directives(nginx_conf):
    """只继承主级模块加载和 http 级库路径，不执行已有插件的 Lua 处理链。"""
    main, http, dso = [], [], []
    active = set()
    conf_root = os.path.dirname(os.path.abspath(nginx_conf))

    def visit(path, scope=()):
        key = os.path.realpath(path)
        if key in active:
            raise ValueError("include 存在循环：%s" % path)
        active.add(key)
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        for current, words, raw in _directives(text, scope):
            name = words[0]
            if name == "include" and current in ((), ("http",), ("dso",)):
                if len(words) != 2:
                    raise ValueError("include 指令需要一个路径")
                pattern = words[1]
                if not os.path.isabs(pattern):
                    pattern = os.path.join(conf_root, pattern)
                matches = sorted(glob.glob(pattern))
                if not matches and not glob.has_magic(pattern):
                    raise ValueError("include 文件不存在：%s" % pattern)
                for included in matches:
                    visit(included, current)
            elif not current and name == "load_module":
                main.append(raw)
            elif current == ("dso",):
                dso.append(raw)
            elif current == ("http",) and name in ("lua_package_path", "lua_package_cpath", "lua_load_resty_core"):
                http.append(raw)
        active.remove(key)

    visit(nginx_conf)
    if dso:
        main.append("dso {\n" + "\n".join(dso) + "\n}")
    return main, http


def _quote(value):
    return '"' + value.replace("\\", "/").replace('"', '\\"') + '"'


def _check_env(nginx_bin, nginx_conf):
    rc, out, err = util.run([nginx_bin, "-V"], timeout=20)
    banner = (out + "\n" + err).strip()
    result = {"name": "Nginx", "version": "", "lua": False, "detail": ""}
    for name in ("Tengine", "OpenResty", "Nginx"):
        version = re.search(r"\b%s/([^\s]+)" % name, banner, re.I)
        if version:
            result["name"] = name
            result["version"] = version.group(1).rstrip(")]},;:")
            break
    if rc != 0:
        result["detail"] = "无法执行 Web 服务器：" + util.truncate(banner, 300)
        return result
    try:
        main, http = _probe_directives(nginx_conf)
        with tempfile.TemporaryDirectory(prefix="btwaf_ce_lua_probe_") as tmp:
            conf_file = os.path.join(tmp, "nginx.conf")
            lua_file = os.path.join(tmp, "probe.lua")
            util.write_text(lua_file, "-- 仅用于 nginx -t，不启动 worker\n")
            text = "\n".join(main) + "\nerror_log stderr;\npid %s;\nevents { worker_connections 16; }\nhttp {\n" % _quote(os.path.join(tmp, "nginx.pid"))
            text += "\n".join(http) + "\naccess_log off;\nlua_shared_dict btwaf_ce_lua_probe 64k;\n"
            text += "init_by_lua_file %s;\ninit_worker_by_lua_file %s;\naccess_by_lua_file %s;\n}\n" % ((_quote(lua_file),) * 3)
            util.write_text(conf_file, text)
            prefix = os.environ.get("BTWAF_CE_NGINX_PREFIX") or _prefix_from_banner(banner) or None
            ok, detail = util.nginx_test(nginx_bin, conf_file, prefix=prefix)
            result["lua"] = ok
            result["detail"] = (
                "Lua 指令探测通过（lua_shared_dict / init_worker_by_lua_file / access_by_lua_file）"
                if ok else "Lua 指令探测失败：" + util.truncate(detail, 500)
            )
    except Exception as exc:
        result["detail"] = "Lua 指令探测失败：" + util.truncate(str(exc), 300)
    return result


_ENV_CACHE = {}
_ENV_LOCK = threading.Lock()


def clear_cache():
    with _ENV_LOCK:
        _ENV_CACHE.clear()


def _file_stamp(path):
    try:
        stat = os.stat(path)
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def check_env(nginx_bin, nginx_conf, cached=False):
    """状态刷新复用短期结果；安装和手动诊断强制重新探测。"""
    key = (nginx_bin, nginx_conf, os.environ.get("BTWAF_CE_NGINX_PREFIX", ""))
    stamp = (_file_stamp(nginx_bin), _file_stamp(nginx_conf))
    with _ENV_LOCK:
        entry = _ENV_CACHE.get(key)
        if cached and entry:
            checked_at, old_stamp, result = entry
            ttl = 30 if result["lua"] else 3
            if stamp == old_stamp and time.monotonic() - checked_at < ttl:
                return dict(result)
        result = _check_env(nginx_bin, nginx_conf)
        if len(_ENV_CACHE) >= 4 and key not in _ENV_CACHE:
            _ENV_CACHE.pop(next(iter(_ENV_CACHE)))
        _ENV_CACHE[key] = (time.monotonic(), stamp, dict(result))
        return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("paths")
    check = sub.add_parser("check")
    check.add_argument("--bin", required=True)
    check.add_argument("--conf", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "paths":
        for path in resolve_paths() + (resolve_vhost_dir(),):
            print(path)
        return 0
    result = check_env(args.bin, args.conf)
    print("%s %s：%s" % (result["name"], result["version"], result["detail"]))
    return 0 if result["lua"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
