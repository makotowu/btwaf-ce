# coding: utf-8
"""可选 YARA Webshell 扫描：引擎检测、规则、任务与状态。

引擎不随插件分发。只调用系统包管理器按需安装，扫描过程只读。
"""
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

from . import paths, sites as S, state, util

MAX_FILES = 20000
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_RESULTS = 500
MAX_SECONDS = 600
SCAN_THREADS = 4
ALLOWED_EXTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".inc")
ENGINE_ENV = "BTWAF_CE_YARA_BIN"
_RULE_RE = re.compile(r"^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*\b", re.M)


def _now():
    return util.now()


def _ensure_dirs():
    util.ensure_dir(paths.WEBSHELL_DIR, 0o750)


def _rules_path():
    return paths.default_file("webshell/rules.yar")


def engine_path():
    candidates = []
    override = str(os.environ.get(ENGINE_ENV) or "").strip()
    if override:
        candidates.append(override)
    candidates.append(shutil.which("yara") or "")
    candidates.extend(["/usr/bin/yara", "/usr/local/bin/yara", "/bin/yara"])
    seen = set()
    for path in candidates:
        if not path or path in seen:
            continue
        seen.add(path)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def _version_of(path):
    rc, out, err = util.run([path, "--version"], timeout=10)
    if rc != 0:
        return ""
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", (out or "") + "\n" + (err or ""))
    return m.group(1) if m else ""


def engine_info():
    path = engine_path()
    if not path:
        return {"installed": False, "path": "", "version": ""}
    return {"installed": True, "path": path, "version": _version_of(path)}


def rules_info():
    path = _rules_path()
    if not os.path.isfile(path):
        return {"available": False, "count": 0, "version": "", "path": path}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        return {"available": True, "count": len(_RULE_RE.findall(text)), "version": digest, "path": path}
    except Exception:
        return {"available": False, "count": 0, "version": "", "path": path}


def _manager():
    checks = [
        ("apt-get", "apt", "apt-get install -y yara"),
        ("dnf", "dnf", "dnf install -y yara"),
        ("yum", "yum", "yum install -y yara"),
        ("apk", "apk", "apk add --no-cache yara"),
    ]
    for binary, name, hint in checks:
        if shutil.which(binary):
            return {"supported": True, "manager": name, "binary": binary, "hint": hint}
    return {"supported": False, "manager": "", "binary": "", "hint": "请手动安装 YARA 4.0 或更高版本"}


def _job_file():
    return paths.WEBSHELL_JOB


def load_job():
    data = util.read_json(_job_file(), {})
    if not isinstance(data, dict):
        data = {}
    if data.get("status") == "running":
        pid = util.safe_int(data.get("pid"), 0)
        if pid and not _pid_alive(pid):
            data["status"] = "failed"
            data["finished"] = _now()
            data["error"] = "扫描进程已退出"
            save_job(data)
    return data


def save_job(job):
    _ensure_dirs()
    util.write_json(_job_file(), job or {})
    return job


def _pid_alive(pid):
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def site_options(db):
    try:
        return [{"site_name": s.get("site_name")} for s in S.list_sites(db) if s.get("site_name")]
    except Exception:
        return []


def status(db=None):
    engine = engine_info()
    manager = _manager()
    engine["install_supported"] = bool(manager.get("supported"))
    engine["manager"] = manager.get("manager") or ""
    engine["install_hint"] = manager.get("hint") or ""
    rules = rules_info()
    return {
        "engine": engine,
        "rules": rules,
        "sites": site_options(db),
        "job": load_job(),
        "limits": {
            "max_files": MAX_FILES,
            "max_file_size": MAX_FILE_SIZE,
            "max_results": MAX_RESULTS,
            "max_seconds": MAX_SECONDS,
        },
    }


def validate_site(db, site_name):
    name = str(site_name or "").strip()
    if not name:
        raise ValueError("缺少站点名")
    site = S.site_by_name(db, name)
    if not site:
        raise ValueError("站点不存在：%s" % name)
    path = str(site.get("path") or "").strip()
    if not path or not os.path.isabs(path):
        raise ValueError("站点目录无效")
    real = os.path.realpath(path)
    if real in ("/", ""):
        raise ValueError("站点目录无效")
    if not os.path.isdir(real):
        raise ValueError("站点目录不存在：%s" % path)
    return name, real


def start_scan(db, site_name):
    engine = engine_info()
    if not engine.get("installed"):
        raise ValueError("未安装 YARA 引擎")
    rules = rules_info()
    if not rules.get("available") or not rules.get("count"):
        raise ValueError("Webshell 规则不可用")
    job = load_job()
    if job.get("status") == "running" and _pid_alive(util.safe_int(job.get("pid"), 0)):
        raise ValueError("已有扫描任务在运行")
    name, path = validate_site(db, site_name)
    _ensure_dirs()
    job_id = time.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    job = {
        "id": job_id,
        "status": "running",
        "site_name": name,
        "path": path,
        "started": _now(),
        "finished": 0,
        "pid": 0,
        "scanned": 0,
        "total_files": 0,
        "matched": 0,
        "truncated": False,
        "error": "",
        "results": [],
    }
    save_job(job)
    worker = os.path.join(paths.PLUGIN_DIR, "wafcore", "webshell_worker.py")
    log = None
    try:
        log = open(paths.WEBSHELL_LOG, "ab")
        env = os.environ.copy()
        env["PYTHONPATH"] = paths.PLUGIN_DIR + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        proc = subprocess.Popen(
            [sys.executable, worker, job_id],
            cwd=paths.PLUGIN_DIR,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            env=env,
        )
        current = load_job() or job
        current["pid"] = proc.pid
        save_job(current)
        state.append_plugin_log("Webshell 扫描开始：%s（%s）" % (name, path))
        return current
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = "无法启动扫描进程：%s" % str(exc)[:300]
        job["finished"] = _now()
        save_job(job)
        raise ValueError(job["error"])
    finally:
        if log is not None:
            try:
                log.close()
            except Exception:
                pass


def cancel_scan():
    job = load_job()
    if job.get("status") != "running":
        raise ValueError("没有运行中的扫描任务")
    pid = util.safe_int(job.get("pid"), 0)
    if pid and _pid_alive(pid):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
    job["status"] = "cancelled"
    job["finished"] = _now()
    job["error"] = "已取消"
    save_job(job)
    state.append_plugin_log("Webshell 扫描取消：%s" % (job.get("site_name") or "-"))
    return job


def install_engine():
    current = engine_info()
    if current.get("installed"):
        return status(None)
    manager = _manager()
    if not manager.get("supported"):
        raise ValueError("未找到可用的包管理器。%s" % manager.get("hint", ""))
    binary = manager["binary"]
    if binary == "apt-get":
        cmd = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "yara"]
    elif binary in ("dnf", "yum"):
        cmd = [binary, "install", "-y", "yara"]
    else:
        cmd = [binary, "add", "--no-cache", "yara"]
    rc, out, err = util.run(cmd, timeout=300)
    if rc != 0:
        detail = (err or out or "").strip().splitlines()
        raise ValueError("安装失败：%s" % (" / ".join(detail[-3:]) if detail else "包管理器返回错误"))
    info = engine_info()
    if not info.get("installed"):
        raise ValueError("安装命令已完成，但仍未检测到 yara")
    state.append_plugin_log("Webshell 引擎安装：%s" % info.get("version"))
    return status(None)


def collect_files(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            if not name.lower().endswith(ALLOWED_EXTS):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE:
                    continue
            except Exception:
                continue
            if "\n" in full or "\r" in full:
                continue
            files.append(full)
            if len(files) > MAX_FILES:
                raise ValueError("文件数量超过 %d 个" % MAX_FILES)
    return files


def parse_output(text, root):
    results = []
    seen = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("error:") or line.startswith("warning:"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        rule, path = parts[0], parts[1].strip()
        try:
            rel = os.path.relpath(path, root)
        except Exception:
            rel = path
        if rel == ".." or rel.startswith(".." + os.sep):
            continue
        key = (rel, rule)
        if key in seen:
            continue
        seen.add(key)
        results.append({"file": rel, "rule": rule})
        if len(results) >= MAX_RESULTS:
            break
    return results


def _write_list(files):
    with open(paths.WEBSHELL_LIST, "w", encoding="utf-8") as f:
        for path in files:
            f.write(path + "\n")


def run_scan(job_id):
    """Worker 入口：只读扫描并写 job 状态。"""
    job = load_job()
    if not job or job.get("id") != job_id:
        return
    root = job.get("path") or ""
    list_path = paths.WEBSHELL_LIST
    try:
        engine = engine_path()
        if not engine:
            raise ValueError("未安装 YARA 引擎")
        rules = _rules_path()
        if not os.path.isfile(rules):
            raise ValueError("Webshell 规则不可用")
        job["status"] = "running"
        job["total_files"] = 0
        save_job(job)
        files = collect_files(root)
        job["total_files"] = len(files)
        job["scanned"] = len(files)
        save_job(job)
        _write_list(files)
        cmd = [engine, "-w", "-p", str(SCAN_THREADS), "-a", str(MAX_SECONDS), "--scan-list", rules, list_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root)
        try:
            out, err = proc.communicate(timeout=MAX_SECONDS + 30)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            out, err = proc.communicate()
            raise ValueError("扫描超时")
        text = out.decode("utf-8", "ignore")
        errtext = err.decode("utf-8", "ignore")
        if proc.returncode != 0:
            raise ValueError((errtext or text or "YARA 扫描失败").strip()[:500])
        results = parse_output(text, root)
        job["results"] = results
        job["matched"] = len(results)
        job["truncated"] = len(results) >= MAX_RESULTS
        job["status"] = "done"
        job["finished"] = _now()
        save_job(job)
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)[:500]
        job["finished"] = _now()
        save_job(job)
    finally:
        try:
            if os.path.isfile(list_path):
                os.remove(list_path)
        except Exception:
            pass
