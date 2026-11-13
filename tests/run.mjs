#!/usr/bin/env node
/**
 * btwaf_ce Lua 引擎测试 harness
 *
 * 设计：
 *   1. 用 wasmoon（Lua 5.4 WASM）创建独立 Lua 引擎，加载仓库中**真实的** lua 文件
 *      （btwaf_ce/lua/init.lua、access.lua、lib/*.lua），不复制、不桩化业务代码；
 *   2. 注入 OpenResty ngx 垫片（tests/mock/ngx.lua）：shared/var/ctx/req/header/
 *      status/log/timer/time/escape_uri/worker/re；
 *   3. ngx.re 优先使用 vscode-oniguruma 近似 PCRE；不可用时降级 JS RegExp，
 *      不兼容模式记录进最终报告；
 *   4. 文件系统经 JS 桥（Node fs）映射到 tests/.tmp/<suite>/，同一份 Lua 代码可在
 *      无 nginx、无 LuaJIT 的 Windows 环境运行；
 *   5. 输出每个用例通过/失败明细 + 机器可读 JSON 统计，失败时退出码非 0。
 *
 * 运行：node tests/run.mjs     （离线可跑，依赖仅 wasmoon，可选 vscode-oniguruma）
 *
 * 环境变量（详见 tests/README.md）：
 *   BTWAF_CE_FAST=1              跳过语法关与语料，只跑 suites（快速回归）
 *   BTWAF_CE_SUITES=05,06        只跑名称包含这些子串的 suite
 *   BTWAF_CE_CORPUS_PER_FILE=60  每个语料文件抽样行数；0 = 全量（默认 60）
 *   BTWAF_CE_CORPUS_GATE=1       启用 contract §13 语料门禁：恶意检出≥95% 且 良性误报=0
 *                                （不达标退出码 1；默认仅报告不参与退出码）
 *   BTWAF_CE_CORPUS_BUDGET_SEC=240 语料跑批 CPU 秒预算；0=不限（超预算提前收敛并报告）
 * 语料分档：恶意语料 tier=3（最大检出），benign/ 与 libinjection false_positives
 * 用 tier=1 + sensitivity=2（默认部署口径），两档分别统计并给合并门禁。
 * 语料中 "known_fp": true 的样例不计入良性误报，单独统计 known_fp_skipped/known_fp_ids。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { LuaFactory } = require('wasmoon');

// wasmoon 在把含任意二进制字节的 Lua 字符串（如 hex/base64 解码后的载荷）转成 JS
// 字符串时会打印 “Invalid UTF-8 ... warning”。这是 PCRE 近似桥的编码告警、非致命，
// 统一计数并在报告里展示，避免污染输出/拖慢 stderr 写入。
const utf8Warnings = { count: 0, samples: [] };
function noteUtf8Warning(msg) {
  if (!msg.includes('Invalid UTF-8')) return false;
  utf8Warnings.count += 1;
  if (utf8Warnings.samples.length < 5) utf8Warnings.samples.push(msg.trim());
  return true;
}
const origConsoleWarn = console.warn.bind(console);
console.warn = (...args) => {
  const m = args.map((x) => String(x)).join(' ');
  if (noteUtf8Warning(m)) return;
  origConsoleWarn(...args);
};
const origStderrWrite = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, encoding, cb) => {
  let text = '';
  try {
    text = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString();
  } catch {
    text = '';
  }
  if (noteUtf8Warning(text)) {
    const done = typeof encoding === 'function' ? encoding : cb;
    if (typeof done === 'function') done();
    return true;
  }
  return origStderrWrite(chunk, encoding, cb);
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const LUA_ROOT = path.join(REPO_ROOT, 'lua');
const MOCK_ROOT = path.join(__dirname, 'mock');
const SUITE_DIR = path.join(MOCK_ROOT, 'suites');
const TMP_ROOT = path.join(__dirname, '.tmp');

// ---------------------------------------------------------------------------
// 正则桥（PCRE 近似）
// ---------------------------------------------------------------------------
const regexStats = {
  engine: 'js-regexp',
  calls: 0,
  uniquePatterns: 0,
  onigurumaCompileErrors: [],
  jsFallbacks: [],
  compileErrors: [],
  runtimeErrors: [],
};
const seenPatterns = new Set();
const scannerCache = new Map();
const reportedSets = {
  onig: new Set(),
  js: new Set(),
  err: new Set(),
};
let onig = null;

function pushLimited(list, set, value) {
  if (!set.has(value) && list.length < 20) {
    set.add(value);
    list.push(value);
  }
}

async function initOniguruma() {
  try {
    const pkg = require('vscode-oniguruma');
    let pkgDir;
    try {
      pkgDir = path.dirname(require.resolve('vscode-oniguruma/package.json'));
    } catch {
      pkgDir = path.dirname(require.resolve('vscode-oniguruma'));
    }
    const wasmPath = path.join(pkgDir, 'release', 'onig.wasm');
    const buf = fs.readFileSync(wasmPath);
    await pkg.loadWASM(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    // 自检：能编译基础 PCRE 模式才算可用
    const scanner = pkg.createOnigScanner(['\\bunion\\b']);
    const str = pkg.createOnigString('x union y');
    const m = scanner.findNextMatchSync(str, 0);
    if (!m) {
      throw new Error('oniguruma 自检未匹配');
    }
    onig = pkg;
    regexStats.engine = 'vscode-oniguruma(PCRE 近似)';
    return true;
  } catch (e) {
    onig = null;
    regexStats.engine = 'js-regexp(降级)';
    regexStats.onigurumaLoadError = String((e && e.message) || e);
    return false;
  }
}

/** PCRE -> JS RegExp 近似翻译（尽力而为，失败返回 null） */
function pcreToJs(pattern) {
  let flags = '';
  let p = pattern;

  // 行首内联标志 (?i)(?m)(?s)(?x)
  const flagMatch = p.match(/^((?:\(\?[imsx]+\))+)/);
  if (flagMatch) {
    for (const ch of flagMatch[1].match(/[imsx]/g) || []) {
      if (ch === 'i' || ch === 'm' || ch === 's') {
        if (!flags.includes(ch)) flags += ch;
      }
      // (?x) 扩展模式：JS 不支持，忽略（已在模式中去除该组）
    }
    p = p.slice(flagMatch[1].length);
  }

  p = p
    .replace(/\\z/g, '$')
    .replace(/\\A/g, '^')
    .replace(/\\R/g, '(?:\\r\\n|\\r|\\n)')
    .replace(/([*+?])\+/g, '$1') // 占有量词 -> 贪婪
    .replace(/\}\+/g, '}')
    .replace(/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g, '(?<$1>')
    .replace(/\(\?>/g, '(?:') // 原子组近似
    .replace(/\\h/g, '[0-9a-fA-F]');

  // POSIX 字符类
  const posix = {
    alpha: 'a-zA-Z', digit: '0-9', alnum: 'a-zA-Z0-9', space: '\\s',
    upper: 'A-Z', lower: 'a-z', xdigit: '0-9a-fA-F', blank: ' \\t',
    punct: '!-/:-@\\[-`{-~', cntrl: '\\x00-\\x1f\\x7f', graph: '!-~',
    print: ' -~',
  };
  p = p.replace(/\[:(\w+):\]/g, (mm, name) => posix[name] ?? mm);

  // \x{...} 需要 u 标志
  if (/\\x\{[0-9a-fA-F]+\}/.test(p)) {
    p = p.replace(/\\x\{([0-9a-fA-F]+)\}/g, '\\u{$1}');
    flags += 'u';
  }

  try {
    // 先验证可用性
    // eslint-disable-next-line no-new
    new RegExp(p, flags);
    return { pattern: p, flags };
  } catch {
    // 去掉 u 再试一次（部分模式在 u 下非法）
    try {
      new RegExp(p, flags.replace('u', ''));
      return { pattern: p, flags: flags.replace('u', '') };
    } catch {
      return null;
    }
  }
}

function jsFind(subject, pattern, opts) {
  const tr = pcreToJs(pattern);
  if (!tr) {
    pushLimited(regexStats.compileErrors, reportedSets.err, pattern);
    return { error: '正则不兼容 PCRE/JS: ' + pattern };
  }
  let flags = tr.flags;
  if (opts.includes('i') && !flags.includes('i')) flags += 'i';
  if (opts.includes('s') && !flags.includes('s')) flags += 's';
  if (opts.includes('m') && !flags.includes('m')) flags += 'm';
  try {
    const re = new RegExp(tr.pattern, flags);
    const m = re.exec(subject);
    if (!m) return { none: true };
    return { from: m.index + 1, to: m.index + m[0].length };
  } catch (e) {
    pushLimited(regexStats.compileErrors, reportedSets.err, pattern);
    return { error: String((e && e.message) || e) };
  }
}

function onigFind(subject, pattern, opts) {
  const key = pattern + '\u0000' + opts;
  let entry = scannerCache.get(key);
  if (entry === undefined) {
    try {
      let flagPrefix = '';
      if (opts.includes('i')) flagPrefix += 'i';
      if (opts.includes('s')) flagPrefix += 's';
      if (opts.includes('m')) flagPrefix += 'm';
      const full = flagPrefix ? `(?${flagPrefix})${pattern}` : pattern;
      entry = { scanner: onig.createOnigScanner([full]) };
    } catch (e) {
      entry = { error: String((e && e.message) || e) };
      pushLimited(regexStats.onigurumaCompileErrors, reportedSets.onig, pattern);
      pushLimited(regexStats.jsFallbacks, reportedSets.js, pattern);
    }
    scannerCache.set(key, entry);
  }
  if (entry.error) {
    return { fallback: true, reason: entry.error };
  }
  try {
    const str = onig.createOnigString(subject);
    const m = entry.scanner.findNextMatchSync(str, 0);
    if (!m) return { none: true };
    const cap = m.captureIndices && m.captureIndices[0];
    if (!cap) return { none: true };
    return { from: cap.start + 1, to: cap.end };
  } catch (e) {
    pushLimited(regexStats.runtimeErrors, reportedSets.err, pattern);
    return { fallback: true, reason: String((e && e.message) || e) };
  }
}

/** JS 桥：__BTWAF_RE_FIND(subject, pattern, opts) -> "" | "from,to" | "E:err" */
function regexFind(subject, pattern, opts) {
  regexStats.calls += 1;
  const s = String(subject ?? '');
  const p = String(pattern ?? '');
  const o = String(opts ?? '');
  if (!seenPatterns.has(p)) {
    seenPatterns.add(p);
    regexStats.uniquePatterns += 1;
  }
  let result;
  if (onig) {
    result = onigFind(s, p, o);
    if (result.fallback) {
      result = jsFind(s, p, o);
    }
  } else {
    result = jsFind(s, p, o);
  }
  if (result.error) return 'E:' + result.error;
  if (result.none) return '';
  const from = Math.max(1, result.from);
  const to = Math.max(from - 1, result.to);
  return from + ',' + to;
}

// ---------------------------------------------------------------------------
// 文件系统桥（Node fs，同步返回；用 false/-1 表示缺失，避免 wasmoon 对 null 的歧义）
// ---------------------------------------------------------------------------
function ensureParent(p) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
}

const fsBridge = {
  __BTWAF_FS_READ: (p) => {
    try {
      return fs.readFileSync(String(p), 'utf8');
    } catch {
      return false;
    }
  },
  __BTWAF_FS_WRITE: (p, data) => {
    try {
      ensureParent(String(p));
      fs.writeFileSync(String(p), String(data ?? ''));
      return true;
    } catch {
      return false;
    }
  },
  __BTWAF_FS_APPEND: (p, data) => {
    try {
      ensureParent(String(p));
      fs.appendFileSync(String(p), String(data ?? ''));
      return true;
    } catch {
      return false;
    }
  },
  __BTWAF_FS_EXISTS: (p) => {
    try {
      return fs.existsSync(String(p));
    } catch {
      return false;
    }
  },
  __BTWAF_FS_REMOVE: (p) => {
    try {
      fs.rmSync(String(p), { force: true });
      return true;
    } catch {
      return false;
    }
  },
  __BTWAF_FS_RENAME: (a, b) => {
    try {
      ensureParent(String(b));
      fs.renameSync(String(a), String(b));
      return true;
    } catch {
      return false;
    }
  },
  __BTWAF_FS_SIZE: (p) => {
    try {
      return fs.statSync(String(p)).size;
    } catch {
      return -1;
    }
  },
  __BTWAF_FS_MTIME: (p) => {
    try {
      return fs.statSync(String(p)).mtimeMs / 1000;
    } catch {
      return -1;
    }
  },
  __BTWAF_FS_MKDIR: (p) => {
    try {
      fs.mkdirSync(String(p), { recursive: true });
      return true;
    } catch {
      return false;
    }
  },
};

// ---------------------------------------------------------------------------
// 引擎创建
// ---------------------------------------------------------------------------
const factory = new LuaFactory();

async function createEngineForSuite(suiteName, dataDir, logDir) {
  const lua = await factory.createEngine();
  for (const [k, v] of Object.entries(fsBridge)) {
    lua.global.set(k, v);
  }
  lua.global.set('__BTWAF_RE_FIND', regexFind);
  lua.global.set('__LUA_ROOT', LUA_ROOT);
  // mock 模块的 require 根目录应是 tests/（require("mock.ngx") -> tests/mock/ngx.lua）
  lua.global.set('__MOCK_ROOT', path.dirname(MOCK_ROOT));
  lua.global.set('BTWAF_CE_LUA_DIR', LUA_ROOT);
  lua.global.set('BTWAF_CE_DATA_DIR', dataDir);
  lua.global.set('BTWAF_CE_LOG_DIR', logDir);

  const harness = fs.readFileSync(path.join(MOCK_ROOT, 'harness.lua'), 'utf8');
  await lua.doString(harness, '@tests/mock/harness.lua');
  return lua;
}

// ---------------------------------------------------------------------------
// 工具：递归列文件
// ---------------------------------------------------------------------------
function walkFiles(dir, filter) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(cur, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === 'node_modules' || ent.name === '.tmp') continue;
        stack.push(full);
      } else if (ent.isFile() && filter(full)) {
        out.push(full);
      }
    }
  }
  out.sort();
  return out;
}

function relToRepo(p) {
  return path.relative(REPO_ROOT, p).split(path.sep).join('/');
}

// ---------------------------------------------------------------------------
// 语法关：load() 全部 Lua 文件（rules/** 额外执行并检查返回 table）
// 说明：整个循环在一次 Lua 调用内完成（wasmoon 连续 doString 数十次后不稳定）。
// ---------------------------------------------------------------------------
const SYNTAX_LUA = String.raw`
local json = require("lib.json")
local files = json.decode(rawget(_G, "__SYNTAX_FILES") or "[]") or {}
local results = {}
for i = 1, #files do
  local item = files[i]
  local entry = { file = item.rel, status = "OK", detail = "", rules = item.rules == true }
  local src = __BTWAF_FS_READ(item.abs)
  if src == false or src == nil then
    entry.status = "MISS"
    entry.detail = "文件读取失败"
  else
    local ok, f, err = pcall(load, src, "@" .. item.rel)
    if not ok or not f then
      entry.status = "ERR"
      entry.detail = tostring(err)
    elseif entry.rules then
      local ok2, ret = pcall(f)
      if not ok2 then
        entry.status = "RUNERR"
        entry.detail = tostring(ret)
      elseif type(ret) ~= "table" then
        entry.status = "OK_NONTABLE"
        entry.detail = "执行结果类型为 " .. type(ret)
      end
    end
  end
  results[#results + 1] = entry
end
return json.encode(results)
`;

async function runSyntaxCheck() {
  const all = [
    ...walkFiles(LUA_ROOT, (f) => f.endsWith('.lua')),
    ...walkFiles(MOCK_ROOT, (f) => f.endsWith('.lua')),
  ];
  const rulesDir = path.join(LUA_ROOT, 'rules') + path.sep;
  const payload = all.map((file) => ({
    abs: file,
    rel: relToRepo(file),
    rules: file.startsWith(rulesDir),
  }));

  let results = [];
  const lua = await factory.createEngine();
  try {
    for (const [k, v] of Object.entries(fsBridge)) {
      lua.global.set(k, v);
    }
    lua.global.set('__LUA_ROOT', LUA_ROOT);
    lua.global.set('__MOCK_ROOT', path.dirname(MOCK_ROOT));
    lua.global.set('BTWAF_CE_LUA_DIR', LUA_ROOT);
    // 加载 harness（提供模块加载器与 json），再一次性执行语法循环
    const harness = fs.readFileSync(path.join(MOCK_ROOT, 'harness.lua'), 'utf8');
    await lua.doString(harness, '@tests/mock/harness.lua');
    lua.global.set('__SYNTAX_FILES', JSON.stringify(payload));
    const out = await lua.doString(SYNTAX_LUA, '@syntax-gate');
    results = JSON.parse(String(out));
  } catch (e) {
    results = payload.map((p) => ({
      file: p.rel,
      status: 'ERR',
      detail: '语法关执行异常: ' + String((e && e.message) || e),
    }));
  } finally {
    try {
      await lua.global.close();
    } catch {
      /* 忽略 */
    }
  }

  const bad = results.filter((r) => r.status === 'ERR' || r.status === 'RUNERR' || r.status === 'MISS');
  const warned = results.filter((r) => r.status === 'OK_NONTABLE');
  return {
    total: results.length,
    ok: results.length - bad.length - warned.length,
    bad,
    warned,
  };
}

function printSyntaxReport(report) {
  console.log('---------------- Lua 语法关 ----------------');
  console.log(`文件: ${report.total}  通过: ${report.ok}  失败: ${report.bad.length}  警告: ${report.warned.length}`);
  for (const f of report.bad) {
    console.log(`  ✗ ${f.file}`);
    for (const line of String(f.detail).split('\n').slice(0, 6)) {
      console.log('      ' + line);
    }
  }
  for (const f of report.warned) {
    console.log(`  ! ${f.file} 未返回 table（load 语法正常）`);
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// 语料跑批（tests/corpus/**/*.jsonl，contract §13）
// 不存在时打印 no corpus 并正常继续；BTWAF_CE_CORPUS_GATE=1 时纳入退出码。
// ---------------------------------------------------------------------------
const CORPUS_LUA = String.raw`
local json = require("lib.json")
local mock = require("mock.ngx")
local files = json.decode(rawget(_G, "__CORPUS_FILES_JSON") or "[]") or {}
-- 引擎初始化（读配置文件；规则缺失/损坏只记录不崩溃）
local bootstrap = require("lib.bootstrap")
bootstrap.init()

local config = require("lib.config")
local config_ok = true
local config_err = nil
local function set_tier(t)
  -- 通过 lib/config 的显式覆盖钩子切换全体模块 tier（会失效合并缓存）
  local ok, err = config.set_module_tier_override(t)
  if not ok then
    config_ok = false
    config_err = "set_module_tier_override 失败: " .. tostring(err)
    return false
  end
  local site = config.site("www.example.com")
  if not site or type(site.modules) ~= "table" then
    config_ok = false
    config_err = "站点配置缺失"
    return false
  end
  for name, m in pairs(site.modules) do
    if tonumber(m.tier) ~= t then
      config_ok = false
      config_err = "tier 覆盖未生效: " .. tostring(name) .. "=" .. tostring(m.tier)
      return false
    end
  end
  return true
end

-- 载入 access（不自动执行）；诊断钩子用于归因误报/漏报的命中规则
local access = require("access")
rawset(_G, "BTWAF_CE_DEBUG_LAST", {})

local per_file = tonumber(rawget(_G, "__CORPUS_PER_FILE")) or 60
-- 时间预算（CPU 秒）：0=不限；超预算提前收敛，防止病态载荷把 CI 卡死
local budget = tonumber(rawget(_G, "__CORPUS_BUDGET_SEC")) or 240
local clock = os.clock
local started = clock()
local slow_cases = setmetatable({}, json.array_mt)

local function new_stats()
  return {
    total = 0, block_cases = 0, detected = 0, missed = 0, fp = 0,
    missed_nohit = 0, missed_lowscore = 0, known_fp_skipped = 0,
    low_score_skipped = 0,
    missed_samples = {}, fp_samples = {},
    missed_rules = {}, fp_rules = {}, missed_expect = {},
    detect_rate = 0,
  }
end

local results = {
  malicious = new_stats(),
  benign = new_stats(),
  by_file = {},
  files = #files,
  sampled = false,
  known_fp_ids = setmetatable({}, json.array_mt),
  low_score_ids = setmetatable({}, json.array_mt),
}

local function record(list, item)
  if #list < 40 then
    list[#list + 1] = item
  end
end

local function bump(map, key)
  if type(key) == "string" and key ~= "" then
    map[key] = (map[key] or 0) + 1
  end
end

local function top_rules(map, n)
  local arr = {}
  for k, v in pairs(map) do
    arr[#arr + 1] = { rule = k, count = v }
  end
  table.sort(arr, function(a, b)
    if a.count == b.count then
      return a.rule < b.rule
    end
    return a.count > b.count
  end)
  local out = {}
  for i = 1, math.min(n or 10, #arr) do
    out[i] = arr[i]
  end
  return out
end

local function hit_ids(hits)
  local out = setmetatable({}, json.array_mt)
  if type(hits) ~= "table" then
    return out
  end
  for i = 1, math.min(#hits, 8) do
    local h = hits[i]
    if type(h) == "table" then
      out[#out + 1] = {
        rule = tostring(h.rule or ""),
        tier = tonumber(h.tier) or 0,
        src = tostring(h.src or ""),
        module = tostring(h.module or ""),
      }
    end
  end
  return out
end

for fi = 1, #files do
  if results.budget_exceeded then
    break
  end
  local item = files[fi]
  local rel = item.rel or item.abs
  -- 良性语料判定：benign/ 与 libinjection false_positives 使用默认 tier=1
  local is_benign = rel:find("/benign/", 1, true) ~= nil
    or rel:find("false_positives", 1, true) ~= nil
  local tier = 1
  if not is_benign then
    tier = 3
  end
  set_tier(tier)
  local stats = results[is_benign and "benign" or "malicious"]
  local fstat = {
    file = rel, benign = is_benign, tier = tier,
    total = 0, block_cases = 0, detected = 0, missed = 0, fp = 0,
  }
  local data = __BTWAF_FS_READ(item.abs)
  if type(data) == "string" and data ~= "" then
    for line in data:gmatch("[^\n]+") do
      if per_file > 0 and fstat.total >= per_file then
        results.sampled = true
        break
      end
      local case = json.decode(line)
      if type(case) == "table" and type(case.input) == "table" then
        local inp = case.input
        -- 清空封锁/CC 字典，保证每个样例独立
        local bd = ngx.shared["btwaf_ce_block"]
        if bd and bd.flush_all then pcall(bd.flush_all, bd) end
        local cd = ngx.shared["btwaf_ce_cc"]
        if cd and cd.flush_all then pcall(cd.flush_all, cd) end
        local dbg = rawget(_G, "BTWAF_CE_DEBUG_LAST")
        dbg.decision = nil
        dbg.hits = nil
        mock.set_request({
          method = inp.method or "GET",
          uri = inp.uri or "/",
          query = inp.query or "",
          headers = inp.headers or {},
          body = inp.body,
          host = inp.host or "www.example.com",
          remote_addr = inp.ip or "1.2.3.4",
        })
        local t0 = clock()
        local ok = pcall(access)
        local dt = clock() - t0
        -- 记录慢样例（>0.5s），便于定位病态载荷/规则
        if dt > 0.5 and #slow_cases < 20 then
          slow_cases[#slow_cases + 1] = {
            id = case.id, file = rel,
            sec = math.floor(dt * 100) / 100,
          }
        end
        if budget > 0 and (clock() - started) > budget then
          results.budget_exceeded = true
          results.sampled = true
          break
        end
        local blocked = false
        if ok then
          blocked = (ngx.status or 200) >= 400 or mock.exit_status ~= nil
        end
        local hits = dbg.hits or {}
        local expect = case.expect or {}
        fstat.total = fstat.total + 1
        stats.total = stats.total + 1
        if expect.block == true then
          if expect.low_score == true then
            -- 契约 §9.4：单条低分规则（< 阈值 5）在 CRS 默认阈值下同样不会 block；
            -- 语料标注 low_score 的样例不计入 block 检出分母，单独统计
            stats.low_score_skipped = stats.low_score_skipped + 1
            record(results.low_score_ids, {
              id = case.id, file = rel, expect_rule = expect.rule, hits = hit_ids(hits),
            })
          else
            fstat.block_cases = fstat.block_cases + 1
            stats.block_cases = stats.block_cases + 1
            if blocked then
              fstat.detected = fstat.detected + 1
              stats.detected = stats.detected + 1
            else
              fstat.missed = fstat.missed + 1
              stats.missed = stats.missed + 1
              if #hits == 0 then
                stats.missed_nohit = stats.missed_nohit + 1
              else
                stats.missed_lowscore = stats.missed_lowscore + 1
              end
              bump(stats.missed_expect, tostring(expect.rule or expect.module or "?"))
              record(stats.missed_samples, {
                id = case.id, file = rel, uri = inp.uri,
                module = expect.module, expect_rule = expect.rule,
                hits = hit_ids(hits),
              })
              for hi = 1, #hits do
                bump(stats.missed_rules, hits[hi].rule)
              end
            end
          end
        else
          if blocked then
            if case.known_fp == true then
              -- CRS 上游已知误报（rules 在语料中标注）：不计入门禁，单独计数供 TEST_REPORT
              stats.known_fp_skipped = stats.known_fp_skipped + 1
              record(results.known_fp_ids, {
                id = case.id, file = rel, uri = inp.uri, hits = hit_ids(hits),
              })
            else
              fstat.fp = fstat.fp + 1
              stats.fp = stats.fp + 1
              record(stats.fp_samples, {
                id = case.id, file = rel, uri = inp.uri, hits = hit_ids(hits),
              })
              for hi = 1, #hits do
                bump(stats.fp_rules, hits[hi].rule)
              end
            end
          end
        end
      end
    end
  end
  results.by_file[#results.by_file + 1] = fstat
end

local function finalize(s)
  if s.block_cases > 0 then
    s.detect_rate = math.floor(s.detected / s.block_cases * 10000) / 100
  else
    s.detect_rate = 100
  end
  s.missed_top = top_rules(s.missed_rules, 10)
  s.fp_top = top_rules(s.fp_rules, 10)
  s.missed_expect_top = top_rules(s.missed_expect, 10)
  s.missed_rules = nil
  s.fp_rules = nil
  s.missed_expect = nil
end

finalize(results.malicious)
finalize(results.benign)
results.slow_cases = slow_cases
results.elapsed_sec = math.floor((clock() - started) * 100) / 100

-- 合并门禁：恶意检出 ≥95%、良性误报 = 0
local gate_ok = config_ok and results.malicious.detect_rate >= 95 and results.benign.fp == 0
results.gate = {
  ok = gate_ok,
  malicious_ok = results.malicious.detect_rate >= 95,
  benign_ok = results.benign.fp == 0,
  config_ok = config_ok,
  detail = "恶意检出率 " .. tostring(results.malicious.detect_rate) .. "%（≥95%）; 良性误报 "
    .. tostring(results.benign.fp) .. "（=0）"
    .. (config_ok and "" or ("; 配置错误: " .. tostring(config_err))),
}
-- 兼容旧字段（汇总打印用）
results.total = results.malicious.total + results.benign.total
results.block_cases = results.malicious.block_cases
results.detected = results.malicious.detected
results.missed = results.malicious.missed + results.benign.missed
results.fp = results.benign.fp
results.detect_rate = results.malicious.detect_rate

local jsonm = require("lib.json")
local mt = jsonm.array_mt
for _, s in ipairs({ results.malicious, results.benign }) do
  setmetatable(s.missed_samples, mt)
  setmetatable(s.fp_samples, mt)
  setmetatable(s.missed_top, mt)
  setmetatable(s.fp_top, mt)
  setmetatable(s.missed_expect_top, mt)
end
setmetatable(results.by_file, mt)
return json.encode(results)
`;

async function runCorpus() {
  const corpusDir = path.join(__dirname, 'corpus');
  if (!fs.existsSync(corpusDir)) {
    console.log('---------------- 语料跑批 ----------------');
    console.log('no corpus（tests/corpus 不存在，跳过；exit 0 不受影响）');
    console.log('');
    return null;
  }
  const files = walkFiles(corpusDir, (f) => f.endsWith('.jsonl'));
  if (files.length === 0) {
    console.log('---------------- 语料跑批 ----------------');
    console.log('no corpus（tests/corpus 下没有 *.jsonl，跳过）');
    console.log('');
    return null;
  }
  const dataDir = path.join(TMP_ROOT, 'corpus');
  const logDir = path.join(TMP_ROOT, 'corpus_logs');
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });

  // 最小配置：站点匹配、全模块 tier=3、关闭 CC/攻击计数，规则来自真实 rules/
  const modules = {};
  for (const m of ['sqli', 'xss', 'rce', 'lfi', 'php', 'java', 'scan', 'crawler', 'sensitive', 'upload', 'protocol', 'custom']) {
    modules[m] = { open: true, tier: 3 };
  }
  const config = {
    schema: 1, version: '0.1.0', enabled: true, observe: false, sensitivity: 2,
    block: { status: 403, use_custom: false, page: '' },
    scan: { body_limit: 1048576, arg_limit: 8192, header_limit: 8192, upload_scan_limit: 20971520, max_args: 200 },
    log: { enabled: false, retain_days: 30, rotate_size: 52428800, snippet: 512 },
    cc: { open: false, cycle: 60, limit: 120, block_time: 300, status: 444, url_cc: false, skip_static: true },
    attack_block: { open: false, cycle: 120, limit: 20, block_time: 86400 },
    modules,
    lists: { ip_black: [], ip_white: [], url_black: [], url_white: [], ua_black: [], ua_white: [], param_white: [] },
    rule_exclude: { crs: [], ce: [] },
    trusted_proxies: [],
    crawler: { allow: ['baiduspider', 'googlebot', 'bingbot'], block_fake: true },
    fail_open: true, whitelist_first: true, update_time: 0,
  };
  const site = {
    'www.example.com': {
      open: true, sensitivity: 2, observe: false, modules,
      cc: { open: false }, attack_block: { open: false },
      lists: { ip_black: [], ip_white: [], url_black: [], url_white: [], ua_black: [], ua_white: [], param_white: [] },
      rule_exclude: { crs: [], ce: [] },
      custom_rules: [],
    },
  };
  const hosts = { 'www.example.com': 'www.example.com' };
  fs.mkdirSync(path.join(dataDir, 'rule'), { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'config.json'), JSON.stringify(config));
  fs.writeFileSync(path.join(dataDir, 'site.json'), JSON.stringify(site));
  fs.writeFileSync(path.join(dataDir, 'hosts.json'), JSON.stringify(hosts));
  fs.writeFileSync(path.join(dataDir, 'rule', 'custom.json'), JSON.stringify({ rules: [] }));

  let lua;
  let stats;
  try {
    lua = await createEngineForSuite('corpus', dataDir, logDir);
    // 每个语料文件抽样上限（默认 60），覆盖全部来源；0 = 全量
    const perFile = Number(process.env.BTWAF_CE_CORPUS_PER_FILE ?? 60);
    lua.global.set('__CORPUS_PER_FILE', Number.isFinite(perFile) ? perFile : 60);
    const budget = Number(process.env.BTWAF_CE_CORPUS_BUDGET_SEC ?? 240);
    lua.global.set('__CORPUS_BUDGET_SEC', Number.isFinite(budget) ? budget : 240);
    lua.global.set(
      '__CORPUS_FILES_JSON',
      JSON.stringify(files.map((f) => ({ abs: f, rel: relToRepo(f) })))
    );
    // 禁止自动执行 access，由语料循环显式调用
    await lua.doString('rawset(_G, "BTWAF_CE_ACCESS_AUTORUN", false)', '@corpus-autorun');
    const out = await lua.doString(CORPUS_LUA, '@corpus');
    stats = JSON.parse(String(out));
  } catch (e) {
    stats = { error: String((e && e.stack) || e), total: 0, detected: 0, missed: 0, fp: 0, detect_rate: 0 };
  } finally {
    if (lua) {
      try {
        await lua.global.close();
      } catch {
        /* 忽略 */
      }
    }
  }
  console.log('---------------- 语料跑批（分档门禁） ----------------');
  if (stats.error) {
    console.log('  语料跑批异常: ' + String(stats.error).split('\n')[0]);
    console.log('');
    stats.corpusDir = relToRepo(corpusDir);
    return stats;
  }
  const mal = stats.malicious || {
    total: 0, block_cases: 0, detected: 0, missed: 0, detect_rate: 0,
    missed_top: [], missed_samples: [],
  };
  const ben = stats.benign || {
    total: 0, fp: 0, fp_top: [], fp_samples: [],
  };
  const sampledNote = stats.sampled
    ? '（抽样：BTWAF_CE_CORPUS_PER_FILE 控制，0=全量）'
    : '（全量）';
  console.log(
    `[档1 恶意 tier=3] 样例 ${mal.total}  恶意样例 ${mal.block_cases}  检出 ${mal.detected}` +
      `（${mal.detect_rate}%）  漏报 ${mal.missed}${sampledNote}`
  );
  console.log(`[档2 良性 tier=1] 样例 ${ben.total}  误报 ${ben.fp}`);
  const gate = stats.gate || { ok: false, malicious_ok: false, benign_ok: false, detail: '门禁数据缺失' };
  console.log(
    `[合并门禁] 恶意检出≥95%: ${gate.malicious_ok ? 'PASS' : 'FAIL'}` +
      `  良性误报=0: ${gate.benign_ok ? 'PASS' : 'FAIL'}` +
      `  总判定: ${gate.ok ? 'PASS' : 'FAIL'}（${gate.detail}）`
  );
  for (const f of asArray(stats.by_file)) {
    if ((f.missed || 0) > 0 || (f.fp || 0) > 0) {
      console.log(
        `  [${f.benign ? '良性' : '恶意'} tier=${f.tier}] ${f.file}` +
          `  样例 ${f.total}  漏报 ${f.missed || 0}  误报 ${f.fp || 0}`
      );
    }
  }
  const printTopRules = (label, top) => {
    const arr = asArray(top);
    if (arr.length === 0) return;
    console.log(`  ${label} top 规则: ` +
      arr.slice(0, 8).map((x) => `${x.rule}×${x.count}`).join(', '));
  };
  console.log(`  漏报归因: 无规则命中 ${mal.missed_nohit || 0} 条 / 有命中但未达阈值 ${mal.missed_lowscore || 0} 条`);
  printTopRules('漏报期望规则', mal.missed_expect_top);
  printTopRules('漏报命中', mal.missed_top);
  printTopRules('误报命中', ben.fp_top);
  // 命中规则明细：{rule,tier,src,module}（rules 组用于定位需收紧的规则）
  const fmtHits = (arr) => asArray(arr).slice(0, 6)
    .map((h) => `${h.rule}(t${h.tier}/${h.src})`).join(';');
  const knownFp = asArray(stats.known_fp_ids);
  const knownFpCount = (ben.known_fp_skipped || 0) > 0 ? ben.known_fp_skipped : knownFp.length;
  if (knownFpCount > 0) {
    console.log(`  已知误报跳过: ${knownFpCount} 条（case.known_fp=true，不计入门禁；CRS 上游规则已知 FP）`);
    for (const k of knownFp.slice(0, 10)) {
      console.log(`    - ${k.id} ${k.uri} 命中=[${fmtHits(k.hits)}]`);
    }
  }
  const lowScore = asArray(stats.low_score_ids);
  const lowScoreCount = (mal.low_score_skipped || 0) > 0 ? mal.low_score_skipped : lowScore.length;
  if (lowScoreCount > 0) {
    console.log(`  低分样例排除: ${lowScoreCount} 条（expect.low_score=true，单条规则 score<5，不计入 block 分母）`);
    for (const k of lowScore.slice(0, 8)) {
      console.log(`    - ${k.id} 期望=${k.expect_rule || '?'} 命中=[${fmtHits(k.hits)}]`);
    }
  }
  for (const s of asArray(mal.missed_samples).slice(0, 5)) {
    console.log(`  漏报样例: ${s.id || '?'} ${s.uri || ''} [${s.module || ''}] 命中=[${fmtHits(s.hits)}]`);
  }
  for (const s of asArray(ben.fp_samples).slice(0, 5)) {
    console.log(`  误报样例: ${s.id || '?'} ${s.uri || ''} 命中=[${fmtHits(s.hits)}]`);
  }
  console.log('');
  stats.corpusDir = relToRepo(corpusDir);
  return stats;
}

// ---------------------------------------------------------------------------
// suite 执行
// ---------------------------------------------------------------------------
function listSuites() {
  if (!fs.existsSync(SUITE_DIR)) return [];
  return fs
    .readdirSync(SUITE_DIR)
    .filter((f) => f.endsWith('.lua'))
    .sort();
}

function sanitize(name) {
  return name.replace(/[^A-Za-z0-9_.-]/g, '_');
}

async function runSuite(file) {
  const suiteName = file.replace(/\.lua$/, '');
  const dataDir = path.join(TMP_ROOT, sanitize(suiteName));
  const logDir = path.join(TMP_ROOT, sanitize(suiteName) + '_logs');
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });

  const started = Date.now();
  let lua;
  let report;
  try {
    lua = await createEngineForSuite(suiteName, dataDir, logDir);
    await lua.doString(
      `__reset_suite(${JSON.stringify(suiteName)})`,
      '@reset'
    );
    const src = fs.readFileSync(path.join(SUITE_DIR, file), 'utf8');
    await lua.doString(src, '@' + file);
    const reportJson = await lua.doString(
      'return require("mock.framework").report_json()',
      '@report'
    );
    if (typeof reportJson !== 'string') {
      throw new Error('suite 未返回 JSON 报告: ' + typeof reportJson);
    }
    report = JSON.parse(reportJson);
    report.file = file;
  } catch (e) {
    report = {
      suite: suiteName,
      file,
      passed: 0,
      failed: 1,
      total: 1,
      failures: [{ name: 'suite 加载/执行异常', error: String((e && e.stack) || e) }],
    };
  } finally {
    if (lua) {
      try {
        await lua.global.close();
      } catch {
        /* 忽略清理异常 */
      }
    }
  }
  report.durationMs = Date.now() - started;
  return report;
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------
function asArray(v) {
  if (Array.isArray(v)) return v;
  if (v && typeof v === 'object') return Object.values(v);
  return [];
}

async function main() {
  const hasOnig = await initOniguruma();
  console.log('btwaf_ce Lua 引擎测试');
  console.log('  Lua 运行时 : wasmoon (Lua 5.4 WASM)');
  console.log('  正则引擎   : ' + regexStats.engine + (hasOnig ? '' : '（vscode-oniguruma 不可用）'));
  console.log('  真实代码   : ' + LUA_ROOT);
  console.log('  用例目录   : ' + SUITE_DIR);
  console.log('');

  // 1) 语法关（rules/** 额外执行检查）
  const fast = process.env.BTWAF_CE_FAST === '1';
  let syntax;
  if (fast) {
    syntax = { total: 0, ok: 0, bad: [], warned: [] };
    console.log('(fast 模式：跳过语法关与语料)');
  } else {
    syntax = await runSyntaxCheck();
    printSyntaxReport(syntax);
  }

  // 2) 单元/集成用例
  let suites = listSuites();
  const suiteFilter = process.env.BTWAF_CE_SUITES;
  if (suiteFilter) {
    const wanted = suiteFilter.split(',');
    suites = suites.filter((s) => wanted.some((w) => s.includes(w)));
  }
  if (suites.length === 0) {
    console.log('未找到任何测试套件：tests/mock/suites/*.lua');
  }

  const reports = [];
  let passed = 0;
  let failed = 0;
  for (const file of suites) {
    const report = await runSuite(file);
    reports.push(report);
    passed += report.passed;
    failed += report.failed;
    const status = report.failed === 0 ? '通过' : '失败';
    console.log(
      `[${status}] ${report.suite}  ${report.passed}/${report.total}  ${report.durationMs}ms`
    );
    for (const f of asArray(report.failures)) {
      console.log('   ✗ ' + f.name);
      const lines = String(f.error).split('\n');
      for (const line of lines.slice(0, 8)) {
        console.log('       ' + line);
      }
    }
  }

  // 3) 语料跑批（存在才跑；默认不影响退出码，可用 BTWAF_CE_CORPUS_GATE=1 纳入门禁）
  const corpus = fast ? null : await runCorpus();

  const corpusGate = process.env.BTWAF_CE_CORPUS_GATE === '1';
  // 语料门禁（contract §13）：恶意检出 ≥95%、良性/误报 0；
  // 默认不参与退出码（规则仍在迭代），QA/CI 可设 BTWAF_CE_CORPUS_GATE=1 强制。
  let corpusGateFailure = null;
  if (corpusGate && corpus) {
    if (corpus.error) {
      corpusGateFailure = '语料跑批异常';
    } else if (!corpus.gate || !corpus.gate.ok) {
      corpusGateFailure = (corpus.gate && corpus.gate.detail) || '分档门禁未通过';
    }
  }
  const exitFailed = failed + syntax.bad.length + (corpusGateFailure ? 1 : 0);
  if (corpusGateFailure) {
    console.log(`语料门禁: 失败（${corpusGateFailure}）`);
  }

  console.log('================ 统计 ================');
  console.log(
    `语法: ${syntax.total} 文件 / ${syntax.bad.length} 失败` +
      `  用例: ${passed + failed} / 通过 ${passed} / 失败 ${failed}` +
      (corpus
        ? `  语料: 恶意检出 ${corpus.malicious ? corpus.malicious.detect_rate : 0}%（漏报 ${
            corpus.malicious ? corpus.malicious.missed : 0
          }）/ 良性误报 ${corpus.benign ? corpus.benign.fp : 0}（门禁 ${
            corpus.gate && corpus.gate.ok ? 'PASS' : 'FAIL'
          }）`
        : '  语料: 未跑')
  );
  console.log(
    `正则: 调用 ${regexStats.calls} 次 / 模式 ${regexStats.uniquePatterns} 个` +
      ` / oniguruma 编译失败 ${regexStats.onigurumaCompileErrors.length}` +
      ` / JS 降级 ${regexStats.jsFallbacks.length}` +
      ` / 不兼容 ${regexStats.compileErrors.length}` +
      ` / UTF-8 编码告警 ${utf8Warnings.count}（非致命，二进制载荷经 JS 桥近似匹配）`
  );
  if (regexStats.jsFallbacks.length > 0) {
    console.log('  JS 降级模式（仅记录前 20 个）:');
    for (const p of regexStats.jsFallbacks) console.log('    - ' + p);
  }
  if (regexStats.compileErrors.length > 0) {
    console.log('  不兼容 PCRE/JS 模式（仅记录前 20 个）:');
    for (const p of regexStats.compileErrors) console.log('    - ' + p);
  }
  console.log(exitFailed === 0 ? '\n结果: 全部通过' : `\n结果: 失败 ${exitFailed} 项`);

  const summary = {
    type: 'summary',
    runtime: 'wasmoon-lua5.4',
    luaRoot: LUA_ROOT,
    regexEngine: regexStats.engine,
    regex: {
      calls: regexStats.calls,
      uniquePatterns: regexStats.uniquePatterns,
      onigurumaLoadError: regexStats.onigurumaLoadError || null,
      onigurumaCompileErrors: regexStats.onigurumaCompileErrors,
      jsFallbacks: regexStats.jsFallbacks,
      compileErrors: regexStats.compileErrors,
      runtimeErrors: regexStats.runtimeErrors,
      utf8Warnings: { count: utf8Warnings.count, samples: utf8Warnings.samples },
    },
    syntax,
    corpus,
    corpusGate: { enabled: corpusGate, failure: corpusGateFailure },
    suites: reports.map((r) => ({
      suite: r.suite,
      total: r.total,
      passed: r.passed,
      failed: r.failed,
      durationMs: r.durationMs,
      failures: asArray(r.failures),
    })),
    totals: {
      suites: reports.length,
      total: passed + failed,
      passed,
      failed,
      syntaxFailed: syntax.bad.length,
    },
  };

  console.log('JSON_REPORT_BEGIN');
  console.log(JSON.stringify(summary, null, 2));
  console.log('JSON_REPORT_END');

  // 落一份报告，便于 CI/其他成员读取（tests/.tmp 为生成目录）
  try {
    fs.mkdirSync(TMP_ROOT, { recursive: true });
    fs.writeFileSync(path.join(TMP_ROOT, 'report.json'), JSON.stringify(summary, null, 2));
  } catch {
    /* 忽略报告落盘失败 */
  }

  process.exitCode = exitFailed > 0 ? 1 : 0;
}

main().catch((e) => {
  console.error('测试 harness 致命错误:', e && e.stack ? e.stack : e);
  process.exitCode = 1;
});




