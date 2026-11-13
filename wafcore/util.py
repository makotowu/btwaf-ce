# coding: utf-8
"""通用工具：文件、进程、校验、时间。"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

# 允许在测试中替换（不依赖面板）
NGINX_BIN = "/www/server/nginx/sbin/nginx"
NGINX_CONF = "/www/server/nginx/conf/nginx.conf"


def now():
    return int(time.time())


def date_str(ts=None, fmt="%Y-%m-%d"):
    return time.strftime(fmt, time.localtime(now() if ts is None else int(ts)))


def time_str(ts=None, fmt="%Y-%m-%d %H:%M:%S"):
    return time.strftime(fmt, time.localtime(now() if ts is None else int(ts)))


def md5_text(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


# ---------------- 文件 ----------------
def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return default


def write_text(path, text, mode=0o644):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(path, mode)
    except Exception:
        pass
    return True


def atomic_write(path, text, mode=0o644):
    d = os.path.dirname(path) or "."
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, ".%s.tmp.%d" % (os.path.basename(path), os.getpid()))
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except Exception:
            pass
        return True
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, obj, mode=0o644):
    return atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2), mode)


def append_line(path, line, mode=0o644):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def ensure_dir(path, mode=0o755):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def file_size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def copy_tree(src, dst):
    if not os.path.isdir(src):
        return False
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    return True


# ---------------- 进程 ----------------
def run(args, timeout=60, cwd=None):
    """执行命令（list 形式，避免注入）。返回 (rc, stdout, stderr)。"""
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out.decode("utf-8", "ignore"), err.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def nginx_test(nginx_bin=None, nginx_conf=None):
    nginx_bin = nginx_bin or NGINX_BIN
    nginx_conf = nginx_conf or NGINX_CONF
    rc, out, err = run([nginx_bin, "-t", "-c", nginx_conf], timeout=30)
    text = (out + "\n" + err).strip()
    ok = rc == 0 and "successful" in text
    return ok, text


def nginx_lua_supported(nginx_bin=None):
    nginx_bin = nginx_bin or NGINX_BIN
    rc, out, err = run([nginx_bin, "-V"], timeout=20)
    text = (out + "\n" + err).lower()
    return ("lua_nginx_module" in text) or ("ngx_http_lua" in text) or ("http_lua_module" in text)


def reload_nginx(init_script="/etc/init.d/nginx"):
    if os.path.exists(init_script) and os.access(init_script, os.X_OK):
        rc, out, err = run([init_script, "reload"], timeout=40)
        if rc == 0:
            return True, out.strip()
        rc2, out2, err2 = run([init_script, "restart"], timeout=60)
        return rc2 == 0, (out.strip() + " " + err.strip() + " " + out2.strip()).strip()
    rc, out, err = run(["/usr/bin/systemctl", "reload", "nginx"], timeout=40)
    if rc == 0:
        return True, out.strip()
    rc2, out2, err2 = run(["/usr/bin/systemctl", "restart", "nginx"], timeout=60)
    return rc2 == 0, (out.strip() + " " + err.strip()).strip()


# ---------------- 校验 ----------------
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def valid_ip(ip):
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if IP_RE.match(ip):
        try:
            return all(0 <= int(p) <= 255 for p in ip.split("."))
        except Exception:
            return False
    if ":" in ip and IPV6_RE.match(ip):
        return True
    return False


def valid_cidr(cidr):
    if not cidr or not isinstance(cidr, str):
        return False
    cidr = cidr.strip()
    if not CIDR_RE.match(cidr):
        return False
    ip, mask = cidr.split("/")
    try:
        return valid_ip(ip) and 0 <= int(mask) <= 32
    except Exception:
        return False


def valid_ip_or_cidr(value):
    return valid_ip(value) or valid_cidr(value)


def valid_regex(pattern):
    try:
        re.compile(pattern)
        return True
    except Exception:
        return False


def safe_int(value, default=0, min_v=None, max_v=None):
    try:
        v = int(float(value))
    except Exception:
        v = default
    if min_v is not None and v < min_v:
        v = min_v
    if max_v is not None and v > max_v:
        v = max_v
    return v


def truncate(text, n=512):
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    return text[:n]


BLOCK_PAGE_BAD = [
    # 先整块移除脚本/内联框架（含内容），再做标签级兜底
    (re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.I | re.S), ""),
    (re.compile(r"<\s*script\b[^>]*>.*$", re.I | re.S), ""),
    (re.compile(r"<\s*/\s*script\s*>", re.I), ""),
    (re.compile(r"<\s*iframe\b[^>]*>.*?<\s*/\s*iframe\s*>", re.I | re.S), ""),
    (re.compile(r"<\s*iframe\b[^>]*>", re.I), ""),
    (re.compile(r"\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I), " data-removed="),
    (re.compile(r"javascript\s*:", re.I), ""),
    (re.compile(r"vbscript\s*:", re.I), ""),
    (re.compile(r"data\s*:\s*text/html", re.I), ""),
]


def sanitize_block_page(html):
    """拦截页 HTML 白名单化：去掉脚本/事件/伪协议。返回 (清理后, 命中的规则名列表)。"""
    if not isinstance(html, str):
        return "", []
    html = html[:65536]
    removed = []
    for rep, sub in BLOCK_PAGE_BAD:
        if rep.search(html):
            removed.append(rep.pattern)
        html = rep.sub(sub, html)
    return html, removed


def safe_join(root, *parts):
    path = os.path.abspath(os.path.join(root, *parts))
    root = os.path.abspath(root)
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("path out of root")
    return path


def human_size(n):
    try:
        n = float(n)
    except Exception:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%.0f %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%.1f TB" % n
