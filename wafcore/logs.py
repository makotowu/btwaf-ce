# coding: utf-8
"""WAF 日志读取、统计、封锁记录与解封。"""
import json
import os
import time

from . import paths, util

MAX_SCAN_LINES = 200000


def _date_compact(date):
    return (date or util.date_str()).replace("-", "")


def log_file_for_date(date=None):
    date = date or util.date_str()
    if date == util.date_str():
        if os.path.isfile(paths.WAF_LOG):
            return paths.WAF_LOG
        rotated = os.path.join(paths.LOG_DIR, "waf-%s.log" % _date_compact(date))
        return rotated if os.path.isfile(rotated) else paths.WAF_LOG
    return os.path.join(paths.LOG_DIR, "waf-%s.log" % _date_compact(date))


def available_days(limit=60):
    days = [util.date_str()]
    try:
        for name in os.listdir(paths.LOG_DIR):
            if not name.startswith("waf-") or not name.endswith(".log"):
                continue
            raw = name[4:-4]
            if len(raw) == 8 and raw.isdigit():
                day = "%s-%s-%s" % (raw[0:4], raw[4:6], raw[6:8])
                if day not in days:
                    days.append(day)
    except Exception:
        pass
    days.sort(reverse=True)
    return days[:limit]


def parse_line(line):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    return normalize_record(obj)


def normalize_record(obj):
    rec = {
        "time": util.safe_int(obj.get("time"), 0),
        "site": util.truncate(obj.get("site") or obj.get("host") or "", 255),
        "host": util.truncate(obj.get("host") or "", 255),
        "ip": util.truncate(obj.get("ip") or "", 64),
        "method": util.truncate(obj.get("method") or "", 16),
        "uri": util.truncate(obj.get("uri") or "", 512),
        "query": util.truncate(obj.get("query") or "", 512),
        "status": util.safe_int(obj.get("status"), 0, 0, 599),
        "action": util.truncate(obj.get("action") or "", 16),
        "score": util.safe_int(obj.get("score"), 0, -10000, 100000),
        "sensitivity": util.safe_int(obj.get("sensitivity"), 0, 0, 3),
        "hits": [],
        "ua": util.truncate(obj.get("ua") or "", 256),
        "referer": util.truncate(obj.get("referer") or "", 256),
        "ctype": util.truncate(obj.get("ctype") or "", 128),
        "body_len": util.safe_int(obj.get("body_len"), 0, 0),
        "snippet": util.truncate(obj.get("snippet") or "", 512),
        "block_time": util.safe_int(obj.get("block_time"), 0, 0),
        "rule_source": util.truncate(obj.get("rule_source") or "", 16),
        "req_id": util.truncate(obj.get("req_id") or "", 64),
        "area": util.truncate(obj.get("area") or "", 128),
    }
    hits = obj.get("hits")
    if isinstance(hits, list):
        for h in hits[:20]:
            if not isinstance(h, dict):
                continue
            rec["hits"].append(
                {
                    "module": util.truncate(h.get("module") or "", 32),
                    "rule": util.truncate(h.get("rule") or "", 64),
                    "name": util.truncate(h.get("name") or "", 256),
                    "score": util.safe_int(h.get("score"), 0, 0),
                    "tier": util.safe_int(h.get("tier"), 0, 0, 3),
                    "src": util.truncate(h.get("src") or "", 16),
                }
            )
    return rec


def _iter_file(path, max_lines=MAX_SCAN_LINES):
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            n = 0
            for line in f:
                n += 1
                if n > max_lines:
                    break
                rec = parse_line(line)
                if rec:
                    yield rec
    except Exception:
        return


def _tail_lines(path, limit):
    """从文件末尾读取至多 limit 行（真实尾部，用于最新记录）。"""
    if not os.path.isfile(path) or limit <= 0:
        return []
    try:
        size = os.path.getsize(path)
        block = 64 * 1024
        data = b""
        with open(path, "rb") as f:
            pos = size
            while pos > 0 and data.count(b"\n") <= limit:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
            lines = data.decode("utf-8", "ignore").splitlines()
            return lines[-limit:]
    except Exception:
        return []


def _tail_records(path, limit):
    out = []
    for line in _tail_lines(path, limit):
        rec = parse_line(line)
        if rec:
            out.append(rec)
    return out


def _tail_raw(path, limit):
    """按原样读取尾部 JSON 行（用于 block.log / unban.log，避免被 WAF 日志字段裁剪）。"""
    out = []
    for line in _tail_lines(path, limit):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def parse_block_record(obj):
    return {
        "time": util.safe_int(obj.get("time"), 0),
        "ip": util.truncate(obj.get("ip") or "", 64),
        "site": util.truncate(obj.get("site") or "", 255),
        "reason": util.truncate(obj.get("reason") or "attack", 24),
        "expire": util.safe_int(obj.get("expire"), 0),
        "block_time": util.safe_int(obj.get("block_time"), 0),
    }


def parse_unban_record(obj):
    return {
        "time": util.safe_int(obj.get("time"), 0),
        "ip": util.truncate(obj.get("ip") or "", 64),
        "site": util.truncate(obj.get("site") or "", 255),
    }


# ---------------- 查询 ----------------
def query_logs(params=None):
    params = params or {}
    date = params.get("date") or util.date_str()
    site = (params.get("site") or "").strip().lower()
    keyword = (params.get("keyword") or "").strip().lower()
    type_key = (params.get("type") or "").strip().lower()
    ip = (params.get("ip") or "").strip()
    action = (params.get("action") or params.get("log_action") or "").strip().lower()
    page = util.safe_int(params.get("p"), 1, 1)
    rows = util.safe_int(params.get("rows"), 20, 1, 200)

    path = log_file_for_date(date)
    # 只需要第 page 页，最多从尾部读 page*rows*20 条做筛选
    window = min(MAX_SCAN_LINES, page * rows * 20 + 1000)
    records = _tail_records(path, window)
    filtered = []
    type_counts = {}
    for rec in reversed(records):
        if site and rec["site"].lower() != site:
            continue
        if ip and rec["ip"] != ip:
            continue
        if action and rec["action"] != action:
            continue
        rec_type = ""
        if rec["action"] in ("cc", "blacklist"):
            rec_type = rec["action"]
        elif rec["hits"]:
            rec_type = rec["hits"][0].get("module") or ""
        if type_key and rec_type != type_key:
            continue
        if keyword and not (
            keyword in rec["ip"].lower()
            or keyword in rec["uri"].lower()
            or keyword in rec["query"].lower()
            or keyword in rec["ua"].lower()
            or any(keyword in (h.get("name") or "").lower() for h in rec["hits"])
            or any(keyword in (h.get("rule") or "").lower() for h in rec["hits"])
        ):
            continue
        rec["_module"] = rec_type
        filtered.append(rec)
    # 类型统计基于已筛选结果
    for rec in filtered:
        key = rec["_module"] or "unknown"
        type_counts[key] = type_counts.get(key, 0) + 1

    total = len(filtered)
    start = (page - 1) * rows
    items = filtered[start : start + rows]
    for rec in items:
        rec.pop("_module", None)
    types = [
        {"module": k, "name": module_label(k), "count": v}
        for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
    ]
    return {"list": items, "total": total, "page": page, "rows": rows, "types": types, "limited": total >= window}


def module_label(key):
    for k, name in (
        ("sqli", "SQL 注入"),
        ("xss", "XSS 跨站"),
        ("rce", "命令执行"),
        ("lfi", "文件包含"),
        ("php", "PHP 注入"),
        ("java", "Java 注入"),
        ("scan", "扫描器"),
        ("crawler", "恶意爬虫"),
        ("sensitive", "敏感文件"),
        ("upload", "恶意上传"),
        ("protocol", "协议异常"),
        ("custom", "自定义"),
        ("cc", "CC 攻击"),
        ("blacklist", "黑名单"),
    ):
        if k == key:
            return name
    return key or "未知"


def stat_for_date(date=None, site=None):
    date = date or util.date_str()
    path = log_file_for_date(date)
    by_type = {}
    by_site = {}
    by_ip = {}
    total = 0
    blocks = 0
    allowed = 0
    cc = 0
    for rec in _iter_file(path):
        if site and rec["site"] != site:
            continue
        total += 1
        action = rec["action"]
        if action == "allow":
            allowed += 1
        else:
            blocks += 1
        if action == "cc":
            cc += 1
        if action in ("cc", "blacklist"):
            module = action
        else:
            module = rec["hits"][0].get("module") if rec["hits"] else "unknown"
        by_type[module] = by_type.get(module, 0) + 1
        by_site[rec["site"]] = by_site.get(rec["site"], 0) + 1
        if rec["ip"]:
            by_ip[rec["ip"]] = by_ip.get(rec["ip"], 0) + 1
    return {
        "total": total,
        "blocks": blocks,
        "allowed": allowed,
        "cc": cc,
        "types": [
            {"module": k, "name": module_label(k), "count": v}
            for k, v in sorted(by_type.items(), key=lambda x: -x[1])
        ],
        "sites": [
            {"site": k, "count": v} for k, v in sorted(by_site.items(), key=lambda x: -x[1])[:50]
        ],
        "ips": [{"ip": k, "count": v} for k, v in sorted(by_ip.items(), key=lambda x: -x[1])[:50]],
    }


def trend(days=7):
    out = []
    today = util.now()
    for i in range(days - 1, -1, -1):
        ts = today - i * 86400
        day = util.date_str(ts)
        path = log_file_for_date(day)
        blocks = 0
        cc = 0
        for rec in _iter_file(path, 100000):
            if rec["action"] == "allow":
                continue
            blocks += 1
            if rec["action"] == "cc":
                cc += 1
        out.append({"date": day, "blocks": blocks, "cc": cc})
    return out


def recent(limit=10):
    path = log_file_for_date()
    return list(reversed(_tail_records(path, limit * 3)))[:limit]


def top_ips(date=None, limit=10, lookup=None):
    st = stat_for_date(date)
    out = []
    for item in st["ips"][:limit]:
        out.append({"ip": item["ip"], "count": item["count"], "area": area_of(item["ip"], lookup)})
    return out


def top_urls(date=None, limit=10):
    date = date or util.date_str()
    path = log_file_for_date(date)
    counter = {}
    for rec in _iter_file(path):
        uri = rec["uri"] or "-"
        counter[uri] = counter.get(uri, 0) + 1
    return [{"uri": k, "count": v} for k, v in sorted(counter.items(), key=lambda x: -x[1])[:limit]]


def rule_hits_for(ids, date=None):
    """统计今日日志中指定规则 ID 的命中次数（一次流式扫描，供规则库命中列）。"""
    wanted = set([str(x) for x in (ids or []) if str(x)])
    out = dict((i, 0) for i in wanted)
    if not wanted:
        return out
    for rec in _iter_file(log_file_for_date(date)):
        for h in rec.get("hits") or []:
            rid = h.get("rule")
            if rid in out:
                out[rid] += 1
    return out


def site_hit_counts(date=None):
    date = date or util.date_str()
    path = log_file_for_date(date)
    out = {}
    last = {}
    for rec in _iter_file(path):
        s = rec["site"] or ""
        if rec["action"] != "allow":
            out[s] = out.get(s, 0) + 1
        if rec["time"] > last.get(s, 0):
            last[s] = rec["time"]
    return out, last


def area_of(ip, lookup=None):
    """lookup 为可调用对象（通常 public.get_ip_location），失败返回空串。"""
    if not ip or not callable(lookup):
        return ""
    try:
        info = lookup(ip)
        if not isinstance(info, dict):
            return ""
        country = (info.get("country") or {})
        city = (info.get("city") or {})
        parts = []
        for v in (country.get("names", {}).get("zh-CN"), country.get("names", {}).get("en"), city.get("names", {}).get("zh-CN")):
            if v and v not in parts:
                parts.append(v)
        return "-".join(parts[:3])
    except Exception:
        return ""


# ---------------- 封锁 / 解封 ----------------
def block_list(params=None, lookup=None):
    """当前/历史封锁。

    params.status: current(默认) | history | all
    返回项 state: blocked | expired | unbanned
    """
    params = params or {}
    site = (params.get("site") or "").strip()
    status = (params.get("status") or "current").strip().lower()
    if status not in ("current", "history", "all"):
        status = "current"
    page = util.safe_int(params.get("p"), 1, 1)
    rows = util.safe_int(params.get("rows"), 50, 1, 200)
    now = util.now()
    records = [parse_block_record(x) for x in _tail_raw(paths.BLOCK_LOG, 5000)]
    latest = {}
    for rec in records:
        key = (rec.get("site") or "", rec.get("ip") or "")
        prev = latest.get(key)
        if prev is None or rec.get("time", 0) >= prev.get("time", 0):
            latest[key] = rec
    unbans = [parse_unban_record(x) for x in _tail_raw(paths.UNBAN_LOG, 5000)]
    unban_map = {}
    for u in unbans:
        key = (u.get("site") or "", u.get("ip") or "")
        unban_map[key] = max(unban_map.get(key, 0), u.get("time", 0))
    items = []
    for key, rec in latest.items():
        if site and key[0] != site:
            continue
        expire = util.safe_int(rec.get("expire"), 0)
        unban_time = unban_map.get(key, 0)
        if unban_time and unban_time >= rec.get("time", 0):
            state = "unbanned"
        elif expire and expire > now:
            state = "blocked"
        else:
            state = "expired"
        if status == "current" and state != "blocked":
            continue
        if status == "history" and state == "blocked":
            continue
        items.append(
            {
                "ip": rec.get("ip", ""),
                "site": rec.get("site", ""),
                "reason": rec.get("reason", "attack"),
                "time": rec.get("time", 0),
                "expire": expire,
                "block_time": util.safe_int(rec.get("block_time"), 0),
                "state": state,
                "unban_time": unban_time if state == "unbanned" else 0,
                "area": area_of(rec.get("ip", ""), lookup),
            }
        )
    items.sort(key=lambda x: -x["time"])
    total = len(items)
    start = (page - 1) * rows
    return {
        "list": items[start : start + rows],
        "total": total,
        "page": page,
        "rows": rows,
        "status": status,
        "window": 5000,
    }


def unban(ip, site="", reason="manual"):
    ip = (ip or "").strip()
    if not util.valid_ip(ip):
        raise ValueError("IP 格式错误")
    rec = {"time": util.now(), "ip": ip, "site": (site or "").strip(), "reason": reason}
    util.append_line(paths.UNBAN_LOG, json.dumps(rec, ensure_ascii=False), 0o664)
    return True


def unban_all(site="", lookup=None):
    current = block_list({"site": site, "p": 1, "rows": 200, "status": "current"}, lookup)
    count = 0
    for item in current.get("list") or []:
        unban(item["ip"], item.get("site") or "", "manual_all")
        count += 1
    return count
