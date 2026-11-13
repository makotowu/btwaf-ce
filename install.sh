#!/bin/bash
# 宝塔WAF社区版（btwaf_ce）安装脚本
# 用法：bash install.sh install|update|uninstall
# 安装会备份并自动禁用冲突的 Nginx Lua 处理链；卸载按清单恢复安装前配置。
set -u

PATH=/www/server/panel/pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="/www/server/btwaf_ce"
LOG_DIR="/www/wwwlogs/btwaf_ce"
PRE_DATA="${DATA_DIR}.preinstall"
PRE_LOG="${LOG_DIR}.preinstall"
ICON_BACKUP="${DATA_DIR}.icons"
INSTALL_DIR="${DATA_DIR}/.install"
CONF_MANIFEST="${INSTALL_DIR}/nginx.json"
CONF_BACKUP="${INSTALL_DIR}/nginx"
NGINX_BIN="/www/server/nginx/sbin/nginx"
NGINX_CONF="/www/server/nginx/conf/nginx.conf"
VHOST_DIR="/www/server/panel/vhost/nginx"
VHOST_CONF="${VHOST_DIR}/btwaf_ce.conf"
PANEL_ROOT="/www/server/panel"
NGINX_INIT="/etc/init.d/nginx"
INSTALL_TMP="/tmp/bt_install.pl"
DATA_EXISTED=0
LOG_EXISTED=0

log() { echo "$*"; echo "$*" >>"${INSTALL_TMP}" 2>/dev/null; }
fail() { log "失败: $*"; echo "失败: $*" >"${INSTALL_TMP}"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

py() {
    if [ -x "${PANEL_ROOT}/pyenv/bin/python3" ]; then
        "${PANEL_ROOT}/pyenv/bin/python3" "$@"
    else
        python3 "$@"
    fi
}

check_env() {
    [ -x "${NGINX_BIN}" ] || fail "未找到 Nginx（${NGINX_BIN}）"
    [ -d "${VHOST_DIR}" ] || fail "未找到面板 Nginx 配置目录：${VHOST_DIR}"
    [ -f "${NGINX_CONF}" ] || fail "未找到 Nginx 主配置：${NGINX_CONF}"
    [ -d "${PLUGIN_DIR}/lua" ] || fail "插件文件不完整：缺少 lua/ 目录"
    [ -f "${PLUGIN_DIR}/install_conf.py" ] || fail "插件文件不完整：缺少 install_conf.py"
    log "正在检测 Nginx Lua 支持..."
    local nginx_v
    nginx_v="$(${NGINX_BIN} -V 2>&1)"
    if ! echo "${nginx_v}" | grep -qiE 'lua_nginx_module|ngx_http_lua|http_lua_module'; then
        fail "当前 Nginx 未编译 lua-nginx-module"
    fi
    log "Nginx Lua 支持检测通过"
}

test_nginx() {
    local out rc
    out="$(${NGINX_BIN} -t -c "${NGINX_CONF}" 2>&1)" || rc=$?
    echo "${out}"
    [ "${rc:-0}" -eq 0 ] && echo "${out}" | grep -q 'successful'
}

reload_nginx() {
    if [ -x "${NGINX_INIT}" ]; then
        ${NGINX_INIT} reload >/dev/null 2>&1 || ${NGINX_INIT} restart >/dev/null 2>&1
    else
        systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1
    fi
}

backup_preexisting_dirs() {
    if [ -d "${DATA_DIR}" ] && [ ! -d "${PRE_DATA}" ]; then
        cp -a "${DATA_DIR}" "${PRE_DATA}" || fail "备份原数据目录失败"
        DATA_EXISTED=1
    elif [ -d "${DATA_DIR}" ] && [ -d "${PRE_DATA}" ]; then
        DATA_EXISTED=1
    fi
    if [ -d "${LOG_DIR}" ] && [ ! -d "${PRE_LOG}" ]; then
        cp -a "${LOG_DIR}" "${PRE_LOG}" || fail "备份原日志目录失败"
        LOG_EXISTED=1
    elif [ -d "${LOG_DIR}" ] && [ -d "${PRE_LOG}" ]; then
        LOG_EXISTED=1
    fi
}

prepare_conflicts() {
    mkdir -p "${INSTALL_DIR}" "${CONF_BACKUP}" || fail "无法创建安装清单目录"
    log "正在检查 Nginx Lua 处理链冲突..."
    if ! py "${PLUGIN_DIR}/install_conf.py" prepare \
        --manifest "${CONF_MANIFEST}" --backup-dir "${CONF_BACKUP}" \
        --nginx-conf "${NGINX_CONF}" --vhost-dir "${VHOST_DIR}"; then
        fail "处理 Nginx 冲突失败，未修改站点配置；请检查权限或配置格式"
    fi
}

restore_conflicts() {
    [ -f "${CONF_MANIFEST}" ] || return 0
    py "${PLUGIN_DIR}/install_conf.py" restore --manifest "${CONF_MANIFEST}"
}

copy_runtime() {
    log "正在部署 Lua 引擎与规则..."
    mkdir -p "${DATA_DIR}/lua" "${DATA_DIR}/rule" "${DATA_DIR}/data" "${DATA_DIR}/logs"
    rm -rf "${DATA_DIR}/lua"
    mkdir -p "${DATA_DIR}/lua"
    cp -a "${PLUGIN_DIR}/lua/." "${DATA_DIR}/lua/" || fail "复制 lua 目录失败"
    if [ -d "${PLUGIN_DIR}/defaults" ]; then
        mkdir -p "${DATA_DIR}/defaults"
        cp -a "${PLUGIN_DIR}/defaults/." "${DATA_DIR}/defaults/" || fail "复制默认配置失败"
    fi
    mkdir -p "${LOG_DIR}"
    chmod -R 755 "${DATA_DIR}" 2>/dev/null || true
    find "${DATA_DIR}/lua" -type f -name '*.lua' -exec chmod 644 {} \; 2>/dev/null || true
    chown -R root:root "${DATA_DIR}" 2>/dev/null || true
    chown www:www "${DATA_DIR}/data" 2>/dev/null || true
    chmod 750 "${DATA_DIR}/data" 2>/dev/null || true
    chown www:www "${DATA_DIR}/logs" 2>/dev/null || true
    chmod 750 "${DATA_DIR}/logs" 2>/dev/null || true
    chown -R www:www "${LOG_DIR}" 2>/dev/null || true
    chmod 750 "${LOG_DIR}" 2>/dev/null || true
}

init_data() {
    log "正在初始化数据文件..."
    local d="${DATA_DIR}"
    mkdir -p "${d}/data" "${d}/logs" "${d}/rule"
    for f in config.json site.json hosts.json; do
        if [ ! -f "${d}/${f}" ] && [ -f "${PLUGIN_DIR}/defaults/${f}" ]; then
            cp -a "${PLUGIN_DIR}/defaults/${f}" "${d}/${f}"
        fi
    done
    if [ ! -f "${d}/rule/custom.json" ]; then
        if [ -f "${PLUGIN_DIR}/defaults/custom.json" ]; then
            cp -a "${PLUGIN_DIR}/defaults/custom.json" "${d}/rule/custom.json"
        else
            echo '{"rules": []}' >"${d}/rule/custom.json"
        fi
    fi
    for f in block.log unban.log perf.json; do [ -f "${d}/data/${f}" ] || : >"${d}/data/${f}"; done
    [ -f "${d}/data/state.json" ] || echo '{}' >"${d}/data/state.json"
    [ -f "${d}/logs/plugin.log" ] || : >"${d}/logs/plugin.log"
    chown www:www "${d}/data/block.log" "${d}/data/unban.log" "${d}/data/perf.json" "${d}/data/state.json" 2>/dev/null || true
    chmod 664 "${d}/data/block.log" "${d}/data/unban.log" "${d}/data/perf.json" "${d}/data/state.json" 2>/dev/null || true
    chmod 644 "${d}/config.json" "${d}/site.json" "${d}/hosts.json" "${d}/rule/custom.json" 2>/dev/null || true
    chmod 644 "${d}/data/blockpage.html" 2>/dev/null || true
    chmod 644 "${d}/logs/plugin.log" 2>/dev/null || true
    chown www:www "${d}/logs" 2>/dev/null || true
    chmod 750 "${d}/logs" 2>/dev/null || true
}

write_conf() {
    log "正在写入 Nginx 配置：${VHOST_CONF}"
    cat >"${VHOST_CONF}" <<'EOF'
# 宝塔WAF社区版（btwaf_ce 插件自动生成，请勿手工修改；插件诊断页会自动校验并恢复）
lua_shared_dict btwaf_ce_cfg 16m;
lua_shared_dict btwaf_ce_cc 16m;
lua_shared_dict btwaf_ce_block 8m;
init_worker_by_lua_file /www/server/btwaf_ce/lua/init.lua;
access_by_lua_file /www/server/btwaf_ce/lua/access.lua;
EOF
    chmod 644 "${VHOST_CONF}"
}

backup_icons() {
    mkdir -p "${ICON_BACKUP}" || return 0
    : >"${ICON_BACKUP}/state.tsv"
    local src="${PLUGIN_DIR}/icon.png" d target key
    [ -f "${src}" ] || return 0
    for d in "${PANEL_ROOT}/BTPanel/static/img/soft_ico" "${PANEL_ROOT}/BTPanel/static/images/soft_ico"; do
        [ -d "${d}" ] || continue
        target="${d}/ico-btwaf_ce.png"
        key="$(printf '%s' "${target}" | md5sum | cut -d' ' -f1)"
        if [ -f "${target}" ]; then
            cp -a "${target}" "${ICON_BACKUP}/${key}" || continue
            printf '%s\t%s\t1\n' "${target}" "${ICON_BACKUP}/${key}" >>"${ICON_BACKUP}/state.tsv"
        else
            printf '%s\t\t0\n' "${target}" >>"${ICON_BACKUP}/state.tsv"
        fi
    done
}

install_icon() {
    local src="${PLUGIN_DIR}/icon.png"
    [ -f "${src}" ] || return 0
    local d
    for d in "${PANEL_ROOT}/BTPanel/static/img/soft_ico" "${PANEL_ROOT}/BTPanel/static/images/soft_ico"; do
        [ -d "${d}" ] || mkdir -p "${d}" 2>/dev/null || continue
        cp -f "${src}" "${d}/ico-btwaf_ce.png" 2>/dev/null || continue
        chmod 644 "${d}/ico-btwaf_ce.png" 2>/dev/null || true
    done
}

restore_icons() {
    [ -f "${ICON_BACKUP}/state.tsv" ] || return 0
    while IFS=$'\t' read -r target backup existed; do
        [ -n "${target}" ] || continue
        if [ "${existed}" = "1" ] && [ -f "${backup}" ]; then
            cp -a "${backup}" "${target}"
        else
            rm -f "${target}"
        fi
    done <"${ICON_BACKUP}/state.tsv"
    rm -rf "${ICON_BACKUP}"
}

remove_runtime() {
    rm -rf "${DATA_DIR}" "${LOG_DIR}" "${ICON_BACKUP}"
}

restore_preexisting_dirs() {
    if [ -d "${PRE_DATA}" ]; then
        rm -rf "${DATA_DIR}"
        mv "${PRE_DATA}" "${DATA_DIR}"
    else
        rm -rf "${DATA_DIR}"
    fi
    if [ -d "${PRE_LOG}" ]; then
        rm -rf "${LOG_DIR}"
        mv "${PRE_LOG}" "${LOG_DIR}"
    else
        rm -rf "${LOG_DIR}"
    fi
    rm -rf "${PRE_DATA}" "${PRE_LOG}"
}

rollback_install() {
    restore_conflicts || true
    rm -f "${VHOST_CONF}"
    restore_icons || true
    restore_preexisting_dirs
}

do_install() {
    echo '正在安装 宝塔WAF社区版...' >"${INSTALL_TMP}"
    check_env
    backup_preexisting_dirs
    prepare_conflicts
    copy_runtime
    backup_icons
    install_icon
    init_data
    write_conf
    log "正在检查 Nginx 配置..."
    if ! test_nginx; then
        log "Nginx 配置检查失败，回滚..."
        rollback_install
        test_nginx >/dev/null 2>&1 || true
        fail "Nginx 配置检测失败，已回滚"
    fi
    reload_nginx
    log "================================================="
    log "安装完成，宝塔WAF社区版已就绪（数据目录：${DATA_DIR}）"
    echo '安装完成' >"${INSTALL_TMP}"
}

do_uninstall() {
    echo '正在卸载 宝塔WAF社区版...' >"${INSTALL_TMP}"
    if [ -f "${CONF_MANIFEST}" ]; then
        if ! restore_conflicts; then
            fail "恢复 Nginx 冲突配置失败；未删除数据，请检查安装清单"
        fi
    fi
    rm -f "${VHOST_CONF}"
    if ! test_nginx; then
        # 恢复失败：把当前状态重新装回，避免留下坏配置
        write_conf
        test_nginx >/dev/null 2>&1 || true
        reload_nginx
        fail "恢复安装前 Nginx 配置失败，已回到卸载前状态"
    fi
    reload_nginx
    restore_icons
    restore_preexisting_dirs
    rm -rf "${INSTALL_DIR}" "${DATA_DIR}.icons"
    if grep -RIn '/www/server/btwaf_ce' "${VHOST_DIR}" "${NGINX_CONF}" 2>/dev/null | grep -v 'btwaf_ce.conf' >/tmp/btwaf_ce_residual 2>/dev/null; then
        log "警告：Nginx 配置仍包含 btwaf_ce 引用："
        cat /tmp/btwaf_ce_residual
    fi
    rm -f /tmp/btwaf_ce_residual
    log "卸载完成"
    echo '卸载完成' >"${INSTALL_TMP}"
}

action="${1:-}"
case "${action}" in
install | update) do_install ;;
uninstall) do_uninstall ;;
*) echo "用法: bash install.sh install|update|uninstall"; exit 1 ;;
esac
