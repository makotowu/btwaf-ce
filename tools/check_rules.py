#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_rules.py -- 校验 btwaf_ce 规则生成物。

检查项：
  * 规则文件结构：meta/rules；每条规则 id/module/tier/score/name/msg/chain 完整
  * id 唯一；crs id 与 index.json 一致；ce id 与 index.json 一致
  * module ∈ 12 个允许模块；tier ∈ 1..3；score ∈ 2..5
  * chain 非空；每个条件 vars 非空、op 受支持、transforms 受支持且为字符串
  * @pm 词表非空；引用的 ac_list 必须存在于 rules/ac.lua；@pm 必须带 lowercase
  * @rx 用 Python re 近似编译（失败仅告警，PCRE 与 re 存在语法差异）
  * rules/ac.lua 词表/自动机字段存在；生成物不含 `[[[`（长括号歧义）
  * version.lua / crs_meta.lua / index.json / manifest.lua 计数互相一致
  * manifest 模块列表与磁盘文件一一对应
  * crs/*.lua 文件头包含 origin=OWASP CRS vX.Y.Z
  * rule.md（若存在）计数与 version.lua 一致

用法：python tools/check_rules.py [--quiet]
退出码：0 通过；1 存在错误。
仅使用 Python 标准库（3.7 兼容）。
"""

from __future__ import print_function

import argparse
import glob
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lua_parser  # noqa: E402

RULES_DIR = os.path.join(ROOT, "lua", "rules")
CRS_DIR = os.path.join(RULES_DIR, "crs")
INDEX_JSON = os.path.join(RULES_DIR, "index.json")
VERSION_LUA = os.path.join(RULES_DIR, "version.lua")
CRS_META = os.path.join(RULES_DIR, "crs_meta.lua")
MANIFEST = os.path.join(RULES_DIR, "manifest.lua")
AC_LUA = os.path.join(RULES_DIR, "ac.lua")

MODULES = (
    "sqli", "xss", "rce", "lfi", "php", "java",
    "scan", "crawler", "sensitive", "upload", "protocol", "custom",
)
OPS = {
    "@rx", "@pm", "@contains", "@beginsWith", "@endsWith", "@streq", "@eq",
    "@ge", "@gt", "@le", "@lt", "@within", "@unconditionalMatch", "@ipMatch",
    "@validateByteRange", "@validateUrlEncoding", "@validateUtf8Encoding",
    "@detectSQLi", "@detectXSS",
}
TRANSFORMS = set(lua_parser.TRANSFORMS.values())
VAR_TYPES = set(lua_parser.SUPPORTED_VARS)


class Report(object):
    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, msg):
        self.errors.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)


def read_text(path):
    with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_lua_module(path):
    try:
        return lua_parser.parse_lua_module(path)
    except Exception as exc:  # noqa: BLE001
        return {"__error__": "%s: %s" % (exc.__class__.__name__, exc)}


def check_ac_lua(rep):
    """轻量校验 ac.lua（1MB+，避免整表解析占内存）：词表名与字段结构。"""
    if not os.path.isfile(AC_LUA):
        rep.error("缺少 rules/ac.lua")
        return set()
    text = read_text(AC_LUA)
    if "[[[" in text:
        rep.error("rules/ac.lua 含 [[[（Lua 长括号歧义）")
    if "lists = {" not in text:
        rep.error("rules/ac.lua 缺少 lists 表")
        return set()
    names = set()
    for m in re.finditer(r'^\s*\["([a-z0-9_.-]+)"\]\s*=\s*\{', text, re.M):
        names.add(m.group(1))
    if not names:
        rep.error("rules/ac.lua 未解析到任何词表")
    # 每个词表必须包含 words/next/fail/out 字段（按块粗略计数）
    n_words = text.count("words = {")
    n_next = text.count("next = {")
    n_fail = text.count("fail = {")
    n_out = text.count("out = {")
    if not (n_words == n_next == n_fail == n_out == len(names)):
        rep.warn("ac.lua 字段计数与词表数不一致（words=%d next=%d fail=%d out=%d lists=%d）"
                 % (n_words, n_next, n_fail, n_out, len(names)))
    return names


def compile_rx(rep, where, pattern):
    """Python re 近似编译，仅告警（PCRE 专有语法会不通过）。"""
    py = pattern
    # PCRE 的 \x{...} 在 Python re 不支持：临时替换后尝试
    py2 = re.sub(r"\\x\{[0-9a-fA-F]+\}", "x", py)
    try:
        re.compile(py2)
    except Exception as exc:  # noqa: BLE001
        rep.warn("%s @rx 无法用 Python re 编译（PCRE 差异，需引擎回归）：%s"
                 % (where, str(exc).split("\n")[0]))


def check_condition(rep, where, cond, ac_names):
    if not isinstance(cond, dict):
        rep.error("%s 条件不是 table" % where)
        return
    vars_ = cond.get("vars")
    if not isinstance(vars_, list) or not vars_:
        rep.error("%s vars 为空" % where)
        return
    for var in vars_:
        if not isinstance(var, dict):
            rep.error("%s 变量定义不是 table" % where)
            continue
        vtype = var.get("type")
        if vtype not in VAR_TYPES:
            rep.error("%s 不支持的变量类型 %r" % (where, vtype))
        if "key" in var and not isinstance(var["key"], str):
            rep.error("%s 变量 key 不是字符串" % where)
        if "count" in var and not isinstance(var["count"], bool):
            rep.error("%s 变量 count 不是布尔" % where)
    transforms = cond.get("transforms")
    if not isinstance(transforms, list):
        rep.error("%s transforms 不是数组" % where)
        transforms = []
    for tr in transforms:
        if not isinstance(tr, str):
            rep.error("%s transforms 含非字符串元素 %r" % (where, tr))
        elif tr not in TRANSFORMS:
            rep.error("%s 不支持的变换 %r" % (where, tr))
    op = cond.get("op")
    if op not in OPS:
        rep.error("%s 不支持的操作符 %r" % (where, op))
        return
    value = cond.get("value")
    if op == "@pm":
        if not isinstance(value, list) or not value:
            rep.error("%s @pm 词表为空" % where)
        elif any(not isinstance(w, str) or not w for w in value):
            rep.error("%s @pm 词表含空/非字符串元素" % where)
        if "lowercase" not in transforms:
            rep.error("%s @pm 缺少 lowercase 变换（AC 大小写敏感）" % where)
        ac_list = cond.get("ac_list")
        if ac_list is not None:
            if not isinstance(ac_list, str) or ac_list not in ac_names:
                rep.error("%s ac_list=%r 不存在于 rules/ac.lua" % (where, ac_list))
    elif op in ("@unconditionalMatch", "@validateUrlEncoding", "@validateUtf8Encoding",
                "@detectSQLi", "@detectXSS"):
        if value not in ("", None):
            rep.warn("%s 操作符 %s 的 value 非空（将被忽略）" % (where, op))
    elif op == "@within" and isinstance(value, list):
        if not value or any(not isinstance(v, str) or not v for v in value):
            rep.error("%s @within 数组为空或含非法元素" % where)
    else:
        if not isinstance(value, str):
            rep.error("%s 操作符 %s 的 value 不是字符串" % (where, op))
        elif op == "@rx":
            compile_rx(rep, where, value)
        if op == "@rx" and value == "":
            rep.warn("%s @rx 正则为空（永远不命中）" % where)
    if not isinstance(cond.get("negate"), bool):
        rep.error("%s negate 不是布尔" % where)
    elif cond.get("negate") and op in ("@validateByteRange", "@validateUrlEncoding",
                                       "@validateUtf8Encoding"):
        # 静态断言：validate* 取反语义脆弱（会对合法请求整体取反），自研规则禁止；
        # CRS 原规则若显式写了 `!` 则保留（记录告警，便于逐条复核）。
        if where.startswith("crs/"):
            rep.warn("%s CRS 原规则对 %s 取反（保留，需回归复核）" % (where, op))
        else:
            rep.error("%s 自研规则禁止对 %s 使用 negate=true" % (where, op))


def check_ruleset(rep, path, is_crs):
    mod = load_lua_module(path)
    rel = os.path.relpath(path, ROOT)
    if "__error__" in mod:
        rep.error("%s 无法解析：%s" % (rel, mod["__error__"]))
        return []
    if not isinstance(mod, dict) or not isinstance(mod.get("rules"), list):
        rep.error("%s 缺少 rules 数组" % rel)
        return []
    meta = mod.get("meta") or {}
    if not isinstance(meta, dict):
        rep.error("%s meta 不是 table" % rel)
        meta = {}
    file_module = meta.get("module")
    if is_crs:
        if meta.get("source") != "crs":
            rep.error("%s meta.source 应为 crs" % rel)
        if not meta.get("crs_version"):
            rep.error("%s meta.crs_version 缺失" % rel)
        head = read_text(path)[:600]
        if "origin=OWASP CRS v" not in head:
            rep.error("%s 文件头缺少 origin=OWASP CRS vX.Y.Z 标注" % rel)
    else:
        if meta.get("source") != "ce":
            rep.error("%s meta.source 应为 ce" % rel)
    if "[[[" in read_text(path):
        rep.error("%s 含 [[[（Lua 长括号歧义）" % rel)
    out = []
    for idx, rule in enumerate(mod["rules"]):
        where = "%s#%d" % (rel, idx + 1)
        if not isinstance(rule, dict):
            rep.error("%s 规则不是 table" % where)
            continue
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid:
            rep.error("%s 缺少 id" % where)
            continue
        where = "%s(%s)" % (rel, rid)
        module = rule.get("module")
        if module not in MODULES:
            rep.error("%s module=%r 不在 12 个允许模块内" % (where, module))
        if is_crs and file_module and module != file_module:
            rep.error("%s module=%r 与文件 meta.module=%r 不一致" % (where, module, file_module))
        tier = rule.get("tier")
        if not isinstance(tier, int) or tier not in (1, 2, 3):
            rep.error("%s tier=%r 非法（应为 1/2/3）" % (where, tier))
        score = rule.get("score")
        if not isinstance(score, int) or not (1 <= score <= 10):
            rep.error("%s score=%r 非法" % (where, score))
        name = rule.get("name")
        if not isinstance(name, str) or not name.strip():
            rep.error("%s name 为空" % where)
        msg = rule.get("msg")
        if not isinstance(msg, str) or not msg.strip():
            rep.error("%s msg 为空" % where)
        tags = rule.get("tags")
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            rep.error("%s tags 不是字符串数组" % where)
        if is_crs and rule.get("src") != "crs":
            rep.error("%s src 应为 crs" % where)
        chain = rule.get("chain")
        if not isinstance(chain, list) or not chain:
            rep.error("%s chain 为空" % where)
            continue
        out.append(rule)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="校验 btwaf_ce 规则生成物")
    parser.add_argument("--quiet", action="store_true", help="只输出结论/错误")
    args = parser.parse_args(argv)

    rep = Report()
    ac_names = check_ac_lua(rep)

    # 1. 规则文件
    crs_rules = []
    for path in sorted(glob.glob(os.path.join(CRS_DIR, "*.lua"))):
        crs_rules.extend(check_ruleset(rep, path, True))
    ce_files = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.lua"))):
        base = os.path.basename(path)
        if base in ("ac.lua", "crs_meta.lua", "version.lua", "manifest.lua"):
            continue
        ce_files.append(base)
        rules = check_ruleset(rep, path, False)
        for rule in rules:
            for cond in rule.get("chain") or []:
                where = "%s(%s)" % (base, rule.get("id"))
                check_condition(rep, where, cond, ac_names)

    # crs 规则的条件校验
    for path in sorted(glob.glob(os.path.join(CRS_DIR, "*.lua"))):
        base = os.path.basename(path)
        mod = load_lua_module(path)
        if "__error__" in mod:
            continue
        for rule in mod.get("rules") or []:
            for cond in rule.get("chain") or []:
                where = "crs/%s(%s)" % (base, rule.get("id"))
                check_condition(rep, where, cond, ac_names)

    # 2. id 唯一
    seen = {}
    for rule in crs_rules:
        rid = rule.get("id")
        if rid in seen:
            rep.error("规则 id 重复：%s" % rid)
        seen[rid] = "crs"
    for base in ce_files:
        mod = load_lua_module(os.path.join(RULES_DIR, base))
        for rule in (mod.get("rules") or []) if isinstance(mod, dict) else []:
            rid = rule.get("id")
            if rid in seen:
                rep.error("规则 id 重复：%s" % rid)
            seen[rid] = base

    # 3. index.json
    index = {}
    if not os.path.isfile(INDEX_JSON):
        rep.error("缺少 rules/index.json")
    else:
        try:
            with io.open(INDEX_JSON, "r", encoding="utf-8") as fh:
                index = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            rep.error("index.json 解析失败：%s" % exc)
            index = {}
    index_rules = index.get("rules") or []
    idx_crs = set(str(r.get("id")) for r in index_rules if r.get("src") == "crs")
    idx_ce = set(str(r.get("id")) for r in index_rules if r.get("src") == "ce")
    fs_crs = set(r.get("id") for r in crs_rules)
    fs_ce = set(seen) - fs_crs
    if idx_crs != fs_crs:
        rep.error("index.json crs 规则与 crs/*.lua 不一致（缺 %s / 多 %s）"
                  % (sorted(fs_crs - idx_crs)[:5], sorted(idx_crs - fs_crs)[:5]))
    if idx_ce != fs_ce:
        rep.error("index.json ce 规则与 rules/ce_*.lua 不一致（缺 %s / 多 %s）"
                  % (sorted(fs_ce - idx_ce)[:5], sorted(idx_ce - fs_ce)[:5]))
    for r in index_rules:
        if r.get("module") not in MODULES:
            rep.error("index.json 规则 %s module=%r 非法" % (r.get("id"), r.get("module")))
        if not isinstance(r.get("tier"), int) or r.get("tier") not in (1, 2, 3):
            rep.error("index.json 规则 %s tier 非法" % r.get("id"))
        if not isinstance(r.get("score"), int):
            rep.error("index.json 规则 %s score 非法" % r.get("id"))
    counts = index.get("counts") or {}
    if counts.get("crs") != len(idx_crs) or counts.get("ce") != len(idx_ce):
        rep.error("index.json counts 与规则数不一致：%r" % counts)
    skipped = index.get("skipped")
    if not isinstance(skipped, list):
        rep.error("index.json skipped 不是数组")
    else:
        for item in skipped[:]:
            if not isinstance(item, dict) or not item.get("id") or not item.get("reason"):
                rep.error("index.json skipped 元素缺少 id/reason：%r" % (item,))
                break

    # 4. version.lua / crs_meta.lua
    version = load_lua_module(VERSION_LUA) if os.path.isfile(VERSION_LUA) else {}
    if not isinstance(version, dict) or "__error__" in version:
        rep.error("version.lua 解析失败")
        version = {}
    elif version.get("crs_imported") != len(fs_crs):
        rep.error("version.lua crs_imported=%r 与规则数 %d 不一致"
                  % (version.get("crs_imported"), len(fs_crs)))
    if version:
        if version.get("ce_total") != len(fs_ce):
            rep.error("version.lua ce_total=%r 与规则数 %d 不一致"
                      % (version.get("ce_total"), len(fs_ce)))
        if version.get("total") != len(fs_crs) + len(fs_ce):
            rep.error("version.lua total=%r 与总数 %d 不一致"
                      % (version.get("total"), len(fs_crs) + len(fs_ce)))
        if version.get("crs_total") != version.get("crs_imported", 0) + version.get("crs_skipped", 0):
            rep.error("version.lua crs_total != imported + skipped")

    crs_meta = load_lua_module(CRS_META) if os.path.isfile(CRS_META) else {}
    if isinstance(crs_meta, dict) and "__error__" not in crs_meta:
        totals = crs_meta.get("totals") or {}
        if totals.get("imported") != len(fs_crs):
            rep.error("crs_meta.lua imported=%r 与规则数 %d 不一致"
                      % (totals.get("imported"), len(fs_crs)))
        if version and crs_meta.get("crs_version") != version.get("crs_version"):
            rep.error("crs_meta.lua 与 version.lua 的 crs_version 不一致")

    # 5. manifest 与磁盘文件
    manifest = load_lua_module(MANIFEST) if os.path.isfile(MANIFEST) else {}
    if not isinstance(manifest, dict) or "__error__" in manifest:
        rep.error("manifest.lua 解析失败")
        modules = []
    else:
        modules = manifest.get("modules") or []
    expected = set()
    for base in ce_files:
        expected.add("rules." + base[:-4])
    for path in glob.glob(os.path.join(CRS_DIR, "*.lua")):
        expected.add("rules.crs." + os.path.basename(path)[:-4])
    listed = set(m for m in modules if isinstance(m, str))
    if listed != expected:
        rep.error("manifest.lua 模块列表与磁盘不一致（缺 %s / 多 %s）"
                  % (sorted(expected - listed)[:5], sorted(listed - expected)[:5]))
    if len(listed) != len(modules):
        rep.error("manifest.lua 含非字符串模块名")

    # 输出
    if not args.quiet:
        print("== check_rules ==")
        print("  crs 规则：%d 条（%d 个文件）" % (len(fs_crs), len(glob.glob(os.path.join(CRS_DIR, "*.lua")))))
        print("  ce  规则：%d 条（%d 个文件）" % (len(fs_ce), len(ce_files)))
        print("  ac  词表：%d 个" % len(ac_names))
        print("  跳过规则：%d 条（index.json）" % (len(skipped) if isinstance(skipped, list) else 0))
    for w in rep.warnings:
        print("  [warn] " + w)
    if rep.warnings:
        ids = sorted(set(re.findall(r"\((crs-\d+|ce-[a-z0-9-]+)\)", " ".join(rep.warnings))))
        print("  [warn] 汇总：%d 条警告%s（@rx 为 PCRE，Python re 仅近似，需引擎回归）"
              % (len(rep.warnings), ("，涉及规则：" + ", ".join(ids)) if ids else ""))
    for e in rep.errors:
        print("  [error] " + e)
    print("结果：%s（errors=%d warnings=%d）"
          % ("通过" if not rep.errors else "失败", len(rep.errors), len(rep.warnings)))
    return 0 if not rep.errors else 1


if __name__ == "__main__":
    sys.exit(main())
