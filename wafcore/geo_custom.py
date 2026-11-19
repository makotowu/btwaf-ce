# coding: utf-8
"""China IP range custom overlay.

The bundled cn.ranges file is immutable. Custom include/exclude ranges live in
DATA_DIR/data/geo_custom.json and are merged with the bundled data by both the
Python status API and lua/lib/geo.lua.
"""
import json
import os

from . import geo as G
from . import paths, util

MAX_ENTRIES = 10000
MAX_FILE_SIZE = 1024 * 1024


def _ip_to_int(value):
    text = str(value or "").strip()
    if ":" in text or not util.valid_ip(text):
        return None
    try:
        parts = [int(x) for x in text.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return None


def _int_to_ip(value):
    return "%d.%d.%d.%d" % (
        (value >> 24) & 255,
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255,
    )


def _entry(item, label):
    if isinstance(item, dict):
        start, end = item.get("start"), item.get("end")
    elif isinstance(item, (list, tuple)) and len(item) >= 2:
        start, end = item[0], item[1]
    else:
        raise ValueError("%s 范围格式不正确" % label)
    a = _ip_to_int(start)
    b = _ip_to_int(end)
    if a is None or b is None:
        raise ValueError("%s 包含无效 IPv4 地址" % label)
    if a > b:
        raise ValueError("%s 起始 IP 不能大于结束 IP" % label)
    return [a, b]


def _normalize_input(value, label):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("%s 必须是数组" % label)
    out = {}
    for item in value:
        a, b = _entry(item, label)
        out[(a, b)] = [a, b]
    return [out[k] for k in sorted(out)]


def merge_ranges(ranges):
    out = []
    for start, end in sorted(ranges):
        if not out or start > out[-1][1] + 1:
            out.append([start, end])
        elif end > out[-1][1]:
            out[-1][1] = end
    return out


def subtract_ranges(base, cuts):
    cuts = merge_ranges(cuts)
    out = []
    j = 0
    for start, end in base:
        cur = start
        while j < len(cuts) and cuts[j][1] < cur:
            j += 1
        k = j
        while k < len(cuts) and cuts[k][0] <= end:
            if cuts[k][0] > cur:
                out.append([cur, min(end, cuts[k][0] - 1)])
            cur = max(cur, cuts[k][1] + 1)
            if cur > end:
                break
            k += 1
        if cur <= end:
            out.append([cur, end])
    return merge_ranges(out)


def _parse_builtin():
    path = G.data_path()
    if not os.path.isfile(path):
        return []
    ranges = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                a, b = _ip_to_int(parts[0]), _ip_to_int(parts[1])
                if a is not None and b is not None and a <= b:
                    ranges.append([a, b])
    except Exception:
        return []
    return merge_ranges(ranges)


def _ranges_out(ranges):
    return [{"start": _int_to_ip(a), "end": _int_to_ip(b)} for a, b in ranges]


def _read_custom(strict=False):
    path = paths.GEO_CUSTOM
    if not os.path.isfile(path):
        return {"version": 1, "include": [], "exclude": []}
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            raise ValueError("自定义中国 IP 段文件超过 1MB")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("自定义中国 IP 段格式不正确")
        return {
            "version": 1,
            "include": _normalize_input(data.get("include"), "补充范围"),
            "exclude": _normalize_input(data.get("exclude"), "排除范围"),
        }
    except ValueError:
        if strict:
            raise
        return {"version": 1, "include": [], "exclude": [], "invalid": True}
    except Exception:
        if strict:
            raise ValueError("自定义中国 IP 段文件无法解析")
        return {"version": 1, "include": [], "exclude": [], "invalid": True}


def status():
    builtin = _parse_builtin()
    try:
        custom = _read_custom(strict=True)
    except ValueError as exc:
        return {
            "builtin": _builtin_info(builtin),
            "include": [],
            "exclude": [],
            "effective": len(builtin),
            "error": str(exc),
        }
    included = merge_ranges(builtin + custom["include"])
    effective = subtract_ranges(included, custom["exclude"])
    return {
        "builtin": _builtin_info(builtin),
        "include": _ranges_out(custom["include"]),
        "exclude": _ranges_out(custom["exclude"]),
        "effective": len(effective),
        "error": "",
    }


def _builtin_info(builtin):
    meta = G.meta()
    return {
        "available": bool(builtin),
        "records": len(builtin),
        "source": meta.get("source") or "",
        "release": meta.get("source_release") or "",
    }


def save(include, exclude):
    inc = _normalize_input(include, "补充范围")
    exc = _normalize_input(exclude, "排除范围")
    if len(inc) > MAX_ENTRIES or len(exc) > MAX_ENTRIES:
        raise ValueError("补充或排除范围不能超过 %d 条" % MAX_ENTRIES)
    data = {
        "version": 1,
        "include": _ranges_out(inc),
        "exclude": _ranges_out(exc),
    }
    util.write_json(paths.GEO_CUSTOM, data, 0o644)
    return status()
