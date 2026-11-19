/*! btwaf_ce 控制台方法：common */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;
    Object.assign(WAF.methods, {
            fmtTime: fmtTime,
            fmtDate: fmtDate,
            num: num,
            isIpList: function (type) {
                return type === 'ip_black' || type === 'ip_white';
            },
            importListMessage: function (d) {
                var msg = '已导入 ' + num(d && d.added) + ' 条';
                var duplicates = num(d && d.duplicates);
                var invalid = num(d && d.invalid);
                if (duplicates) msg += '，重复 ' + duplicates + ' 条';
                if (invalid) msg += '，忽略 ' + invalid + ' 条无效项';
                if (d && d.truncated) msg += '，已到达 2000 条上限';
                return msg;
            },
            downloadTextFile: function (filename, text) {
                var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                setTimeout(function () {
                    try { URL.revokeObjectURL(url); a.parentNode.removeChild(a); } catch (e) { }
                }, 800);
            },
            showConfirm: function (title, content) {
                var self = this;
                return new Promise(function (resolve) {
                    self.confirmDialog = {
                        visible: true, title: title, content: content, resolve: resolve,
                        checkbox: false, checkboxLabel: '', checked: false, withOption: false
                    };
                });
            },
            showConfirmWithOption: function (title, content, checkboxLabel, checked) {
                var self = this;
                return new Promise(function (resolve) {
                    self.confirmDialog = {
                        visible: true, title: title, content: content, resolve: resolve,
                        checkbox: !!checkboxLabel, checkboxLabel: checkboxLabel || '',
                        checked: !!checked, withOption: true
                    };
                });
            },
            onConfirmOk: function () {
                var d = this.confirmDialog;
                d.visible = false;
                if (d.resolve) {
                    var r = d.resolve;
                    d.resolve = null;
                    r(d.withOption ? { ok: true, checked: !!d.checked } : true);
                }
            },
            onConfirmCancel: function () {
                var d = this.confirmDialog;
                d.visible = false;
                if (d.resolve) { var r = d.resolve; d.resolve = null; r(false); }
            },
            onConfirmClosed: function () {
                var d = this.confirmDialog;
                if (d.resolve) { var r = d.resolve; d.resolve = null; r(false); }
            },
            sensitivityLabel: function (v) {
                v = num(v);
                return v === 1 ? '宽松' : (v === 3 ? '严格' : '标准');
            },
            moduleName: function (key) {
                var m = null;
                MODULES.forEach(function (x) { if (x.key === key) m = x; });
                return m ? m.name : (key || '-');
            },
            tierLabel: function (v) {
                v = num(v);
                return v === 0 ? '默认' : ('PL' + v);
            },
            actionLabel: function (a) {
                var map = { block: '拦截', allow: '记录/放行', cc: 'CC 拦截', blacklist: '黑名单', geo: '地区限制', log: '记录' };
                return map[a] || a || '-';
            },
            actionTag: function (a) {
                var map = { block: 'danger', allow: 'info', cc: 'warning', blacklist: 'danger', geo: 'danger', log: 'info' };
                return map[a] || 'info';
            },
            stateLabel: function (s) {
                var map = { blocked: '封锁中', expired: '已到期', unbanned: '已解封' };
                return map[s] || (s || '-');
            },
            stateTag: function (s) {
                var map = { blocked: 'danger', expired: 'info', unbanned: 'success' };
                return map[s] || 'info';
            },
            reasonLabel: function (r) {
                var map = { cc: 'CC 超限', attack: '攻击拦截', blacklist: '黑名单', upload: '上传拦截', geo: '地区限制' };
                return map[r] || r || '-';
            },
            reasonTag: function (r) { return r === 'cc' ? 'warning' : 'danger'; },
            remain: function (expire) { return remainText(expire); },
            mb: function (v) { return (num(v) / 1048576).toFixed(1); },
            hitsText: function (hits) {
                if (!hits || !hits.length) return '无命中详情';
                return hits.map(function (h) { return h.rule || h.module; }).join(' / ');
            },
            sourceLabel: function (src) {
                var map = { crs: 'CRS', ce: 'CE', custom: '自定义' };
                return map[src] || (src || '-');
            },
            countryLabel: function (c) {
                var map = { CN: '中国大陆', OTHER: '中国大陆以外', PRIVATE: '内网/保留地址', UNKNOWN: '无法识别' };
                return map[c] || (c || '-');
            },
            listLabel: function (key) {
                var found = null;
                LIST_META.forEach(function (m) { if (m.key === key) found = m; });
                return found ? found.label : (key || '-');
            },
            listHint: function (key) {
                var found = null;
                LIST_META.forEach(function (m) { if (m.key === key) found = m; });
                return found ? found.hint : '';
            },
            customRuleExpr: function (row) {
                if (!row) return '-';
                var left = row.field || '';
                if (row.field === 'header' && row.header) left = 'header[' + row.header + ']';
                return left + ' ' + (row.operator || '') + ' ' + (row.value || '');
            },
            customRuleTarget: function (row) {
                if (!row) return '-';
                if (row.scope === 'site') {
                    return (row.sites && row.sites.length) ? row.sites.join(', ') : '指定站点（未设置）';
                }
                return '全局';
            },
            boolText: function (v) { return v ? '是' : '否'; },
            okTag: function (v) { return v ? 'success' : 'danger'; },
            okText: function (v) { return v ? '正常' : '异常'; },
            loadStatus: async function () {
                this.statusLoading = true;
                try {
                    var d = await WafAPI.data('get_engine_status');
                    this.status = normalizeStatus(d || {});
                    this.statusFailed = false;
                } catch (e) {
                    this.statusFailed = true;
                } finally {
                    this.statusLoading = false;
                }
            },
            refreshStatusAfterSave: function () {
                var self = this;
                // 任意写操作成功后：状态 + 当前视图数据都重新拉取，避免页面停留在旧数据
                this.loaded = {};
                this.ruleExcludeLoaded = false;
                setTimeout(async function () {
                    await self.loadStatus();
                    try { await self.refreshCurrent(); } catch (e) { }
                }, 350);
            },
            boot: async function () {
                await this.loadStatus();
                await this.refreshCurrent();
            },
            refreshCurrent: function () {
                var map = {
                    overview: 'loadOverview', logs: 'loadLogs', sites: 'loadSites', config: 'loadConfig',
                    rules: 'loadRules', blocks: 'loadBlocks', oplogs: 'loadOpLogs', diagnostics: 'loadDiagnostics'
                };
                var fn = map[this.view];
                return fn ? this[fn]() : Promise.resolve();
            },
            reloadAll: function () {
                this.loaded = {};
                this.errors = { overview: '', logs: '', sites: '', config: '', rules: '', blocks: '', oplogs: '', diagnostics: '' };
                this.ruleExcludeLoaded = false;
                this.boot();
            },
            manualRefresh: function () {
                var self = this;
                this.refreshing = true;
                this.loadStatus().then(function () { return self.refreshCurrent(); }).then(function () {
                    self.refreshing = false;
                }).catch(function () { self.refreshing = false; });
            },
            runStatusAction: function () {
                var n = this.statusNotice;
                if (!n) return;
                if (n.act === 'retry') this.manualRefresh();
                else if (n.act === 'diagnostics') this.switchView('diagnostics');
                else if (n.act === 'enable') this.quickEnable();
                else if (n.act === 'observeOff') this.quickObserveOff();
            },
            quickPatch: async function (patch, msg) {
                this.quickSaving = true;
                try {
                    await WafAPI.data('save_plugin_config', { config: JSON.stringify(patch) });
                    BTP.msg(msg, 'success');
                    this.refreshStatusAfterSave();
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                } finally {
                    this.quickSaving = false;
                }
            },
            quickEnable: function () {
                var self = this;
                this.showConfirm('开启防护', '将立即开启防护并关闭观察模式（命中规则会拦截请求），确定继续？').then(function (ok) {
                    if (ok) self.quickPatch({ enabled: true, observe: false }, '防护已开启');
                });
            },
            quickObserveOff: function () {
                var self = this;
                this.showConfirm('关闭观察模式', '关闭后命中规则将直接拦截请求，确定继续？').then(function (ok) {
                    if (ok) self.quickPatch({ observe: false }, '观察模式已关闭');
                });
            },
            goUnprotected: function () {
                this.siteStatus = 'unprotected';
                this.sitePage = 1;
                this.switchView('sites');
                this.loadSites();
            },
            enableAllUnprotected: function () {
                var self = this;
                this.showConfirm('开启未防护站点', '将为所有未开启防护的站点开启防护，确定继续？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        var d = await WafAPI.data('get_sites', { status: 'unprotected', p: 1, rows: 500, keyword: '' });
                        var names = ((d && d.list) || []).map(function (s) { return s.site_name; }).filter(Boolean);
                        if (!names.length) { BTP.msg('当前没有未防护站点', 'info'); return; }
                        await WafAPI.data('set_site_open', { site_names: JSON.stringify(names), open: true });
                        BTP.msg('已开启 ' + names.length + ' 个站点防护', 'success');
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
            filterConfigFields: function () {
                var q = String(this.cfgSearch || '').trim().toLowerCase();
                var nodes = document.querySelectorAll('#btwaf-ce-app .waf-view .el-form-item');
                var visible = 0;
                for (var i = 0; i < nodes.length; i++) {
                    var el = nodes[i];
                    var show = !q || (el.innerText || '').toLowerCase().indexOf(q) >= 0;
                    el.style.display = show ? '' : 'none';
                    if (show) visible++;
                }
                this.cfgSearchEmpty = !!q && visible === 0;
            },
            removeLogFilter: function (key) {
                if (key === 'date') return;
                this.logFilter[key] = '';
                this.logPage = 1;
                this.loadLogs();
            },
            fitPanelLayer: function () {
                try {
                    var $ = window.jQuery;
                    if (!$) return false;
                    var $page = $('.layui-layer-page');
                    if (!$page.length) return false;
                    $page.addClass('waf-layer-page');
                    $page.find('.layui-layer-setwin .layui-layer-close')
                        .removeClass('layui-layer-close2').addClass('layui-layer-close1');
                    return true;
                } catch (e) { return false; }
            },
            switchView: function (key) {
                var self = this;
                this.view = key;
                var main = document.querySelector('#btwaf-ce-app .waf-main');
                if (main) { main.scrollTop = 0; main.scrollLeft = 0; }
                this.$nextTick(function () {
                    if (key === 'overview') self.renderOverviewCharts();
                    else if (window.WafCharts) WafCharts.resizeAll();
                });
                // 每次从侧边栏进入都拉取最新数据，避免使用旧缓存
                this.refreshCurrent();
                if (key === 'overview') this.renderOverviewCharts();
            },
    });
})(window);
