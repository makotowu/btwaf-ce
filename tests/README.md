# 测试

本目录是 Lua 引擎与后端测试的可复现入口，不随安装包分发。

## 目录

```
tests/
  run.mjs                 Lua 引擎 + 语料测试入口
  mock/                   ngx 垫片与 suites
  python/                 后端单元测试
  e2e/                    宝塔面板内 E2E 冒烟
  corpus/                 按来源标注的回归语料
  package.json            wasmoon / vscode-oniguruma 测试依赖
```

## 运行

```bash
cd tests && npm install && cd ..
node tests/run.mjs
python tests/python/test_backend.py
```

全量语料门禁：

```bash
BTWAF_CE_CORPUS_PER_FILE=0 BTWAF_CE_CORPUS_GATE=1 node tests/run.mjs
```

环境变量与测试分层见 [docs/TESTING.md](../docs/TESTING.md)。

## 语料

`corpus/NOTICE.md` 记录来源、许可证与归属，详见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。请不要删除来源说明。

## 限制

测试使用 wasmoon（Lua 5.4 WASM）和近似的 PCRE 实现，不能完全等价于线上 LuaJIT + `ngx.re`；涉及正则兼容性时需在真实 Nginx 环境复核。
