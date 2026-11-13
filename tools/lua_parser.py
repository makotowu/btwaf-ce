#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal parser for generated Lua rule modules used by check_rules.py."""
from __future__ import print_function

import io
import re

def read_text(path):
    with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()



# CRS transform（小写）→ 规范名
TRANSFORMS = {
    "lowercase": "lowercase",
    "urldecode": "urlDecode",
    "urldecodeuni": "urlDecodeUni",
    "htmlentitydecode": "htmlEntityDecode",
    "jsdecode": "jsDecode",
    "cssdecode": "cssDecode",
    "removenulls": "removeNulls",
    "replacenulls": "replaceNulls",
    "compresswhitespace": "compressWhitespace",
    "removewhitespace": "removeWhitespace",
    "trim": "trim",
    "trimleft": "trimLeft",
    "trimright": "trimRight",
    "base64decode": "base64Decode",
    "hexdecode": "hexDecode",
    "normalizepath": "normalizePath",
    "normalizepathwin": "normalizePathWin",
    "cmdline": "cmdLine",
    "length": "length",
    "utf8tounicode": "utf8ToUnicode",
    "escapeseqdecode": "escapeSeqDecode",
    "sqlhexdecode": "sqlHexDecode",
}

# 变量 → 支持类型（支持类型）
SUPPORTED_VARS = {
    "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST",
    "REQUEST_URI", "REQUEST_FILENAME", "REQUEST_BASENAME", "QUERY_STRING",
    "REQUEST_METHOD", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES",
    "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "REQUEST_BODY",
    "FILES", "FILES_NAMES", "REMOTE_ADDR", "REQUEST_LINE",
}


class LuaParser(object):
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.n = len(text)

    def skip(self):
        s, n = self.s, self.n
        while self.i < n:
            ch = s[self.i]
            if ch in " \t\r\n":
                self.i += 1
            elif s.startswith("--", self.i):
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end + 1
            else:
                break

    def parse(self):
        self.skip()
        v = self.value()
        return v

    def value(self):
        self.skip()
        s = self.s
        if self.i >= self.n:
            raise ValueError("unexpected EOF")
        ch = s[self.i]
        if ch == "{":
            return self.table()
        if ch == '"' or ch == "'":
            return self.string(ch)
        if ch == "[":
            return self.long_string()
        m = re.compile(r"-?\d+(?:\.\d+)?").match(s, self.i)
        if m:
            self.i = m.end()
            txt = m.group(0)
            return float(txt) if "." in txt else int(txt)
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(s, self.i)
        if m:
            word = m.group(0)
            self.i = m.end()
            if word == "true":
                return True
            if word == "false":
                return False
            if word == "nil":
                return None
            return word
        raise ValueError("unexpected char %r at %d" % (ch, self.i))

    def long_string(self):
        m = re.compile(r"\[(=*)\[").match(self.s, self.i)
        if not m:
            raise ValueError("bad long string")
        eq = m.group(1)
        start = m.end()
        close = "]" + eq + "]"
        end = self.s.find(close, start)
        if end < 0:
            raise ValueError("unterminated long string")
        self.i = end + len(close)
        return self.s[start:end]

    def string(self, q):
        s = self.s
        self.i += 1
        out = []
        while self.i < self.n:
            ch = s[self.i]
            if ch == "\\" and self.i + 1 < self.n:
                nx = s[self.i + 1]
                mapping = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\",
                           '"': '"', "'": "'", "0": "\x00"}
                out.append(mapping.get(nx, nx))
                self.i += 2
            elif ch == q:
                self.i += 1
                return "".join(out)
            else:
                out.append(ch)
                self.i += 1
        raise ValueError("unterminated string")

    def table(self):
        s = self.s
        self.i += 1  # {
        arr = []
        obj = {}
        while True:
            self.skip()
            if self.i >= self.n:
                raise ValueError("unterminated table")
            if s[self.i] == "}":
                self.i += 1
                break
            # key = value ?
            m = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)").match(s, self.i)
            if m:
                key = m.group(1)
                self.i = m.end()
                obj[key] = self.value()
            else:
                arr.append(self.value())
            self.skip()
            if self.i < self.n and s[self.i] in ",;":
                self.i += 1
        if obj and not arr:
            return obj
        if obj:
            # 混合：把数组放到数字键，保留命名键
            for idx, v in enumerate(arr, 1):
                obj[idx] = v
            return obj
        return arr



def parse_lua_module(path):
    text = read_text(path)
    m = re.search(r"(?m)^\s*return\b", text)
    if not m:
        raise ValueError("no return: %s" % path)
    return LuaParser(text[m.end():]).parse()


