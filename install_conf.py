#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Backup/disable conflicting nginx Lua handlers and restore them.

Only init_worker_by_lua* and access_by_lua* are touched because the plugin owns
those phases. Every modified file is backed up verbatim and recorded in a JSON
manifest; restore writes the original bytes and metadata back.
"""
from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import time

PHASES = ("init_worker", "access")
FILE_RE = re.compile(r"^\s*(?P<phase>%s)_by_lua_file\s+(?P<arg>[^;]+);" % "|".join(PHASES))
BLOCK_RE = re.compile(r"^\s*(?P<phase>%s)_by_lua_block\s*\{" % "|".join(PHASES))


def sha256_file(path):
    h = hashlib.sha256()
    with io.open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_lines(path):
    with io.open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def write_bytes(path, data):
    tmp = path + ".btwaf_ce_tmp"
    with io.open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def backup_file(path, backup_dir):
    rel = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    dest = os.path.join(backup_dir, rel + ".conf")
    if not os.path.exists(dest):
        shutil.copy2(path, dest)
    st = os.stat(path)
    return {
        "path": path,
        "backup": dest,
        "sha256": sha256_file(dest),
        "mode": st.st_mode & 0o777,
        "uid": st.st_uid,
        "gid": st.st_gid,
    }


def block_end(lines, start):
    """Return index after a *_by_lua_block closing brace, or -1."""
    depth = 0
    quote = None
    escape = False
    in_comment = False
    for i in range(start, len(lines)):
        line = lines[i]
        j = 0
        while j < len(line):
            ch = line[j]
            nxt = line[j + 1] if j + 1 < len(line) else ""
            if in_comment:
                break
            if quote:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
            else:
                if ch in ("'", '"'):
                    quote = ch
                elif ch == "#":
                    in_comment = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return i + 1
            j += 1
        in_comment = False
    return -1


def scan_file(path, our_marker):
    lines = read_lines(path)
    edits = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = FILE_RE.match(line)
        if m and our_marker not in m.group("arg"):
            edits.append((i, i + 1, "file", m.group("phase")))
            i += 1
            continue
        m = BLOCK_RE.match(line)
        if m:
            end = block_end(lines, i)
            if end < 0:
                raise RuntimeError("无法解析 Lua 块：%s:%d" % (path, i + 1))
            edits.append((i, end, "block", m.group("phase")))
            i = end
            continue
        i += 1
    return edits


def comment_edits(lines, edits):
    out = list(lines)
    for start, end, kind, phase in reversed(edits):
        if kind == "file":
            original = out[start]
            out[start] = "# btwaf_ce: disabled conflicting %s_by_lua_file (restored on uninstall): %s" % (phase, original.strip())
        else:
            for i in range(start, end):
                out[i] = "# " + out[i]
            out[start] = "# btwaf_ce: disabled conflicting %s_by_lua_block (restored on uninstall)\n%s" % (phase, out[start])
    return out


def iter_conf_files(nginx_conf, vhost_dir):
    seen = set()
    if nginx_conf and os.path.isfile(nginx_conf):
        seen.add(os.path.abspath(nginx_conf))
        yield os.path.abspath(nginx_conf)
    if vhost_dir and os.path.isdir(vhost_dir):
        for root, _dirs, files in os.walk(vhost_dir):
            for name in files:
                if not name.endswith(".conf"):
                    continue
                p = os.path.abspath(os.path.join(root, name))
                if p in seen:
                    continue
                seen.add(p)
                yield p


def load_manifest(path):
    if not os.path.isfile(path):
        return {"version": "0.1.0", "files": []}
    with io.open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError("manifest 格式错误")
    data.setdefault("files", [])
    return data


def prepare(args):
    manifest = load_manifest(args.manifest)
    known = set(os.path.abspath(x.get("path", "")) for x in manifest.get("files", []))
    backup_dir = args.backup_dir
    if not os.path.isdir(backup_dir):
        os.makedirs(backup_dir)
    changed = []
    try:
        for path in iter_conf_files(args.nginx_conf, args.vhost_dir):
            if path in known or os.path.basename(path) == "btwaf_ce.conf":
                continue
            edits = scan_file(path, "/www/server/btwaf_ce/")
            if not edits:
                continue
            entry = backup_file(path, backup_dir)
            entry["conflicts"] = [{"kind": e[2], "phase": e[3], "start": e[0] + 1} for e in edits]
            lines = comment_edits(read_lines(path), edits)
            write_bytes(path, ("\n".join(lines) + "\n").encode("utf-8"))
            manifest["files"].append(entry)
            changed.append(entry)
        manifest["version"] = "0.1.0"
        manifest["updated_at"] = int(time.time())
        tmp = args.manifest + ".tmp"
        with io.open(tmp, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, args.manifest)
    except Exception as exc:
        for entry in reversed(changed):
            if os.path.isfile(entry["backup"]):
                shutil.copy2(entry["backup"], entry["path"])
                os.chmod(entry["path"], entry["mode"])
                try:
                    os.chown(entry["path"], entry["uid"], entry["gid"])
                except Exception:
                    pass
        raise exc
    print("conflicts: %d" % len(changed))
    return 0


def restore(args):
    manifest = load_manifest(args.manifest)
    files = manifest.get("files", [])
    for entry in files:
        path = entry.get("path", "")
        backup = entry.get("backup", "")
        if not path or not backup or not os.path.isfile(backup):
            raise RuntimeError("备份缺失：%s" % path)
        if entry.get("sha256") and sha256_file(backup) != entry["sha256"]:
            raise RuntimeError("备份校验失败：%s" % backup)
        shutil.copy2(backup, path)
        try:
            os.chmod(path, entry.get("mode", 0o644))
            os.chown(path, entry.get("uid", 0), entry.get("gid", 0))
        except Exception:
            pass
    print("restored: %d" % len(files))
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("prepare")
    a.add_argument("--manifest", required=True)
    a.add_argument("--backup-dir", required=True)
    a.add_argument("--nginx-conf", required=True)
    a.add_argument("--vhost-dir", required=True)
    b = sub.add_parser("restore")
    b.add_argument("--manifest", required=True)
    args = p.parse_args()
    try:
        if args.cmd == "prepare":
            return prepare(args)
        return restore(args)
    except Exception as exc:
        sys.stderr.write("install_conf: %s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
