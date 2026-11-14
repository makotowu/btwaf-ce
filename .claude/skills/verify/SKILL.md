---
name: verify
description: Verify the WAF installer, Lua request flow, and diagnostics against an isolated real Nginx or Tengine instance.
---

# Runtime verification

Use a temporary directory and a loopback-only unused port. Do not install/uninstall on the host's real panel or reload its existing server.

## Obtain a server

Use a compatible installed Nginx/OpenResty/Tengine, or build Tengine in the temporary directory:

- Tengine 3.1.0: `https://codeload.github.com/alibaba/tengine/tar.gz/refs/tags/3.1.0`.
- OpenResty LuaJIT: `v2.1-20230410`; `make -j4 && make install PREFIX="$WORK/luajit"`.
- Export `LUAJIT_INC="$WORK/luajit/include/luajit-2.1"` and `LUAJIT_LIB="$WORK/luajit/lib"`.
- Configure Tengine with `--prefix="$WORK/tengine" --with-http_lua_module --without-pcre2 --with-pcre-jit --with-ld-opt="-Wl,-rpath,$LUAJIT_LIB"`, then `make -j4 && make install`.
- The bundled module is ngx_lua 0.10.25; use matching `lua-resty-core` v0.1.27 and `lua-resty-lrucache` v0.13. Put their `lib/?.lua` paths in `lua_package_path`.
- For dynamic-module verification, replace `--with-http_lua_module` with `--add-dynamic-module=<tengine-source>/modules/ngx_http_lua_module` and load the installed `modules/ngx_http_lua_module.so` in the main context.

## Launch and drive

Copy the repo's `lua/` into `$WORK/data/lua`. Create data/data, data/logs, data/rule and a log directory. Copy defaults/config.json; disable CC and attack_block initially. Write site.json with `{"www.example.com":{"open":true}}`, hosts.json with `{"www.example.com":"www.example.com"}`, rule/custom.json with `{"rules":[]}`, and data/state.json with `{}`; create empty block.log/unban.log under data/data.

Prefer the real installer to generate the WAF snippet and `runtime_paths.lua`: set `BTWAF_CE_DATA_DIR`, `BTWAF_CE_LOG_DIR`, `BTWAF_CE_LUA_DIR` (inside DATA_DIR), `BTWAF_CE_VHOST_DIR`, `BTWAF_CE_NGINX_BIN`, `BTWAF_CE_NGINX_CONF`, `BTWAF_CE_NGINX_PREFIX`, and `BTWAF_CE_NGINX_INIT` to isolated paths. Set `BTWAF_CE_PANEL_ROOT` and `BTWAF_CE_INSTALL_LOG` to temporary locations too. Supply an executable service wrapper that reloads only this instance. The WAF entrypoints read their adjacent `runtime_paths.lua`; do not inject WAF path globals through the host's init_by handler. Keep the host's own init_by handler and library paths to observe coexistence.

Configure `daemon off; master_process off;`, an isolated PID/error-log path, the three shared dictionaries from install.sh, and HTTP-level `init_worker_by_lua_file <data>/lua/init.lua` and `access_by_lua_file <data>/lua/access.lua`. A loopback-only server can return `ok` using `content_by_lua_file`; a rewrite-phase `return 200` would bypass access protection.

1. Run `BTWAF_CE_NGINX_BIN="$BIN" BTWAF_CE_NGINX_CONF="$CONF" BTWAF_CE_VHOST_DIR="$WORK/conf" bash install.sh check`; capture stdout. The main config hash must stay unchanged.
2. Launch `"$BIN" -c "$CONF"`. Drive HTTP through its socket with `Host: www.example.com`: normal GET → 200; `/index.php?id=1%27%20union%20select%20null%2Cnull--` → 403; URL-encoded XSS POST → 403. An unmapped Host should bypass the WAF.
3. Atomically set observe=true in the temporary config: the attack should become 200 after about 3 seconds with the same PID. Set false and observe 403 again; inspect waf.log actions `allow` and `block`.
4. Restart only this instance with `ngx.timer.every = nil` in the bootstrap. Repeat hot updates; enable a low CC threshold, observe blocking, append an unban record, then observe 200 and an advanced unban_offset.
5. Probe missing binary and a dynamic build without load_module: check must fail. Loading the module must pass; relative load_module paths should use the server prefix.
6. Stop only the subprocess you started; capture HTTP statuses, timing, logs and PID evidence.

## Diagnostics browser surface

Use real panel credentials only when provided. Without a panel, a temporary loopback HTTP host may serve index.html/static assets and dispatch the existing controller at POST `/plugin?action=a&name=btwaf_ce&s=...`; report this as local-host verification, not panel integration. Supply Vue/Element Plus and panel base styles. In Chrome/CDP, click 系统诊断, expand 高级信息, and capture visible `Tengine <version>` plus Lua 正常 and the real API responses. Capture primitive fields or JSON.stringify Vue reactive objects (CDP otherwise returns `{}`). Missing plugin conf warnings are expected if the temporary instance was not installed through the panel.

On Windows prefer PowerShell for WSL commands with Linux path arguments; Git Bash/MSYS can rewrite `/mnt/...` and `/tmp/...`. Use an isolated Chrome user-data-dir and close the browser/host afterward. Runtime screenshots and scratch hosts belong in ignored `tests/artifacts/` and `tests/.tmp/`.
