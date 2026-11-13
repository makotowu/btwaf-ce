#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_lua51.py -- 扫描 lua 下 Lua 5.1/5.4 公共子集禁用构造。

Lua 5.1/5.4 公共子集禁止：goto / `//` / bit32 / utf8. / table.move / string.pack。
本脚本先做最小 Lua 词法分析（正确处理注释与字符串），再检查代码 token，
避免把正则字符串里的 `//`、`http://` 等误判。

用法：python tools/check_lua51.py [目录...]
退出码：0 无违规；1 存在违规。
仅使用 Python 标准库（3.7 兼容）。
"""

from __future__ import print_function

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_DIR = os.path.join(ROOT, "lua")


class Token(object):
    __slots__ = ("kind", "value", "line")

    def __init__(self, kind, value, line):
        self.kind = kind
        self.value = value
        self.line = line

    def __repr__(self):
        return "%s:%r" % (self.kind, self.value)


def lex(text):
    """最小 Lua 词法：返回 token 列表（跳过空白/注释，保留字符串与符号）。"""
    tokens = []
    i = 0
    n = len(text)
    line = 1

    def long_bracket(pos):
        """匹配 [=*[ ... ]=*]；返回 (内容起止, 结束位置) 或 None。"""
        m = pos
        if m >= n or text[m] != "[":
            return None
        eq = 0
        m += 1
        while m < n and text[m] == "=":
            eq += 1
            m += 1
        if m >= n or text[m] != "[":
            return None
        close = "]" + "=" * eq + "]"
        end = text.find(close, m + 1)
        if end < 0:
            return None
        return (m + 1, end, end + len(close))

    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue
        # 注释
        if ch == "-" and i + 1 < n and text[i + 1] == "-":
            lb = long_bracket(i + 2)
            if lb is not None:
                content_start, content_end, end = lb
                line += text[i:end].count("\n")
                i = end
                continue
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        # 长字符串
        if ch == "[":
            lb = long_bracket(i)
            if lb is not None:
                content_start, content_end, end = lb
                tokens.append(Token("string", text[content_start:content_end], line))
                line += text[i:end].count("\n")
                i = end
                continue
        # 短字符串
        if ch in "'\"":
            q = ch
            start_line = line
            i += 1
            buf = []
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    nxt = text[i + 1]
                    if nxt == "\n":
                        line += 1
                    buf.append(nxt)
                    i += 2
                    continue
                if c == q:
                    i += 1
                    break
                if c == "\n":
                    line += 1
                buf.append(c)
                i += 1
            tokens.append(Token("string", "".join(buf), start_line))
            continue
        # 数字
        if ch.isdigit() or (ch == "." and i + 1 < n and text[i + 1].isdigit()):
            j = i
            while j < n and (text[j].isalnum() or text[j] in "._"):
                j += 1
            tokens.append(Token("number", text[i:j], line))
            i = j
            continue
        # 名字
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(Token("name", text[i:j], line))
            i = j
            continue
        # 多字符符号
        for sym in ("...", "..", "//", "::", "==", "~=", "<=", ">=",
                    "<<", ">>", "&&", "||"):
            if text.startswith(sym, i):
                tokens.append(Token("symbol", sym, line))
                i += len(sym)
                break
        else:
            tokens.append(Token("symbol", ch, line))
            i += 1
    return tokens


FORBIDDEN_NAMES = {"goto", "_ENV", "bit32"}


def scan_file(path):
    with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    toks = lex(text)
    problems = []

    def code(i):
        return toks[i] if 0 <= i < len(toks) else None

    for i, tok in enumerate(toks):
        if tok.kind == "symbol" and tok.value in ("//", "::"):
            problems.append((tok.line, "禁用符号 %r（Lua 5.1 不支持）" % tok.value))
        if tok.kind == "name":
            if tok.value == "goto":
                problems.append((tok.line, "禁用关键字 goto"))
            elif tok.value == "_ENV":
                problems.append((tok.line, "禁用 _ENV（Lua 5.2+）"))
            elif tok.value == "bit32":
                nxt = code(i + 1)
                if nxt and nxt.kind == "symbol" and nxt.value in (".", "["):
                    problems.append((tok.line, "禁用 bit32 位运算库"))
            elif tok.value == "utf8":
                nxt = code(i + 1)
                if nxt and nxt.kind == "symbol" and nxt.value == ".":
                    problems.append((tok.line, "禁用 utf8. 库（Lua 5.3+）"))
            elif tok.value == "table":
                n1, n2 = code(i + 1), code(i + 2)
                if (n1 and n1.value == "." and n2 and n2.value == "move"):
                    problems.append((tok.line, "禁用 table.move（Lua 5.3+）"))
            elif tok.value == "string":
                n1, n2 = code(i + 1), code(i + 2)
                if n1 and n1.value == "." and n2 and n2.value in ("pack", "unpack", "packsize"):
                    problems.append((tok.line, "禁用 string.%s（Lua 5.3+）" % n2.value))
    return problems


def main(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])
    targets = argv or [DEFAULT_DIR]
    files = []
    for target in targets:
        if os.path.isdir(target):
            for base, _dirs, names in os.walk(target):
                for name in names:
                    if name.endswith(".lua"):
                        files.append(os.path.join(base, name))
        elif os.path.isfile(target):
            files.append(target)
    files.sort()
    if not files:
        print("[error] 未找到 Lua 文件：%s" % ", ".join(targets))
        return 1
    total = 0
    print("== check_lua51: 扫描 %d 个 Lua 文件 ==" % len(files))
    for path in files:
        problems = scan_file(path)
        rel = os.path.relpath(path, ROOT)
        for line, msg in problems:
            total += 1
            print("  [error] %s:%d %s" % (rel, line, msg))
    if total:
        print("结果：失败（%d 处禁用构造）" % total)
        return 1
    print("结果：通过（无 goto//、bit32、utf8.、table.move、string.pack 等）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
