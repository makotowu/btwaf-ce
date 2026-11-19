/*! btwaf_ce 控制台方法：monitor */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;
    Object.assign(WAF.methods, {
            loadOverview: async function () {
                this.ovLoading = true;
                this.errors.overview = '';
                try {
                    var d = await WafAPI.data('get_overview', { date: this.ovDate });
                    d = d || {};
                    this.ov = {
                        date: d.date || this.ovDate,
                        stats: d.stats || {},
                        trend: Array.isArray(d.trend) ? d.trend : [],
                        types: Array.isArray(d.types) ? d.types : [],
                        top_ips: Array.isArray(d.top_ips) ? d.top_ips : [],
                        top_urls: Array.isArray(d.top_urls) ? d.top_urls : [],
                        recent: Array.isArray(d.recent) ? d.recent : [],
                        hits_by_site: (d.hits_by_site && typeof d.hits_by_site === 'object') ? d.hits_by_site : {}
                    };
                    this.loaded.overview = true;
                    this.renderOverviewCharts();
                } catch (e) {
                    this.errors.overview = errText(e);
                } finally {
                    this.ovLoading = false;
                }
            },
            renderOverviewCharts: function () {
                var self = this;
                this.$nextTick(function () {
                    if (self.view !== 'overview' || !window.WafCharts) return;
                    var trend = self.ov.trend || [];
                    WafCharts.render('waf-trend-chart', {
                        tooltip: { trigger: 'axis' },
                        legend: { data: ['拦截', 'CC'], top: 0, right: 0 },
                        grid: { left: 40, right: 14, top: 30, bottom: 24 },
                        xAxis: { type: 'category', data: trend.map(function (t) { return (t.date || '').slice(5); }) },
                        yAxis: { type: 'value', minInterval: 1 },
                        series: [
                            {
                                name: '拦截', type: 'bar', barMaxWidth: 18,
                                itemStyle: { borderRadius: [3, 3, 0, 0] },
                                data: trend.map(function (t) { return num(t.blocks); })
                            },
                            {
                                name: 'CC', type: 'line', smooth: true, symbolSize: 5,
                                data: trend.map(function (t) { return num(t.cc); })
                            }
                        ]
                    });
                    var types = self.ov.types || [];
                    WafCharts.render('waf-type-chart', {
                        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
                        legend: { type: 'scroll', bottom: 0 },
                        series: [{
                            type: 'pie', radius: ['46%', '68%'], center: ['50%', '44%'],
                            itemStyle: { borderWidth: 1, borderColor: 'transparent' },
                            label: { show: true, formatter: '{b}\n{c}' },
                            data: types.map(function (t) {
                                return { name: t.name || self.moduleName(t.module), value: num(t.count) };
                            })
                        }]
                    });
                });
            },
            openRecent: function (row) {
                this.logDetail = row;
                this.logDetailVisible = true;
            },
            loadLogs: async function () {
                this.logLoading = true;
                this.errors.logs = '';
                try {
                    var d = await WafAPI.data('get_attack_logs', {
                        site: this.logFilter.site, date: this.logFilter.date,
                        keyword: this.logFilter.keyword, type: this.logFilter.type,
                        ip: this.logFilter.ip, log_action: this.logFilter.action,
                        p: this.logPage, rows: this.logRows
                    });
                    d = d || {};
                    this.logList = Array.isArray(d.list) ? d.list : [];
                    this.logTotal = num(d.total);
                    if (Array.isArray(d.types) && d.types.length) this.logTypes = d.types;
                    this.logLimited = !!d.limited;
                    this.loaded.logs = true;
                } catch (e) {
                    this.errors.logs = errText(e);
                    this.logList = [];
                    this.logTotal = 0;
                } finally {
                    this.logLoading = false;
                }
            },
            logSearch: function () { this.logPage = 1; this.loadLogs(); },
            logReset: function () {
                this.logFilter = { site: '', date: todayStr(), keyword: '', type: '', ip: '', action: '' };
                this.logPage = 1;
                this.loadLogs();
            },
            onLogPageChange: function (p) { this.logPage = p; this.loadLogs(); },
            onLogSizeChange: function (n) { this.logRows = n; this.logPage = 1; this.loadLogs(); },
            onLogAction: function (cmd, row) {
                if (!row) return;
                if (cmd === 'black') this.addIpToList(row, 'ip_black');
                else if (cmd === 'white') this.addIpToList(row, 'ip_white');
                else if (cmd === 'unban') this.unbanLogIp(row);
            },
            openLogDetail: function (row) {
                if (!row) return;
                this.logDetail = row;
                this.logDetailVisible = true;
            },
            logPayloadText: function (row) {
                if (!row) return '';
                var lines = [];
                if (row.method || row.uri) lines.push((row.method || '') + ' ' + (row.uri || ''));
                if (row.query) lines.push('QUERY: ' + row.query);
                if (row.ua) lines.push('UA: ' + row.ua);
                if (row.referer) lines.push('REFERER: ' + row.referer);
                if (row.ctype) lines.push('CONTENT-TYPE: ' + row.ctype);
                if (row.body_len) lines.push('BODY-LEN: ' + row.body_len);
                if (row.snippet) lines.push('SNIPPET: ' + row.snippet);
                return lines.join('\n');
            },
            addIpToList: async function (row, type) {
                if (!row || !row.ip) return;
                var scope = row.site ? 'site' : 'global';
                var params = { scope: scope };
                if (scope === 'site') params.site_name = row.site;
                try {
                    var d = await WafAPI.data('get_lists', params);
                    var lists = (d && d.lists) || {};
                    var arr = (lists[type] || []).slice();
                    if (arr.indexOf(row.ip) < 0) arr.push(row.ip);
                    await WafAPI.data('set_lists', {
                        scope: scope, site_name: params.site_name || '',
                        type: type, items: JSON.stringify(arr)
                    });
                    BTP.msg((type === 'ip_black' ? '已加入黑名单：' : '已加入白名单：') + row.ip, 'success');
                    this.refreshStatusAfterSave();
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                }
            },
            unbanLogIp: function (row) {
                var self = this;
                if (!row || !row.ip) return;
                this.showConfirm('解封确认', '确定解封 IP ' + row.ip + ' 吗？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        await WafAPI.data('unban_ip', { ip: row.ip, site: row.site || '' });
                        BTP.msg('已提交解封：' + row.ip, 'success');
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
            loadBlocks: async function () {
                this.blockLoading = true;
                this.errors.blocks = '';
                try {
                    var d = await WafAPI.data('get_block_list', {
                        status: this.blockTab, site: this.blockSite || '', p: this.blockPage, rows: this.blockRows
                    });
                    d = d || {};
                    this.blockList = Array.isArray(d.list) ? d.list : [];
                    this.blockTotal = num(d.total);
                    this.loaded.blocks = true;
                } catch (e) {
                    this.errors.blocks = errText(e);
                    this.blockList = [];
                    this.blockTotal = 0;
                } finally {
                    this.blockLoading = false;
                }
            },
            switchBlockTab: function (tab) { this.blockTab = tab; this.blockPage = 1; this.loadBlocks(); },
            onBlockPageChange: function (p) { this.blockPage = p; this.loadBlocks(); },
            onBlockSizeChange: function (n) { this.blockRows = n; this.blockPage = 1; this.loadBlocks(); },
            unbanBlock: function (row) {
                var self = this;
                this.showConfirm('解封确认', '确定解封 IP ' + row.ip + (row.site ? '（' + row.site + '）' : '') + ' 吗？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        await WafAPI.data('unban_ip', { ip: row.ip, site: row.site || '' });
                        BTP.msg('已提交解封：' + row.ip, 'success');
                        self.loadBlocks();
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
            unbanAll: function () {
                var self = this;
                this.showConfirm('全部解封', '确定解封当前所有临时封锁的 IP 吗？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        var d = await WafAPI.data('unban_all', { site: '' });
                        BTP.msg('已提交全部解封：' + num(d && d.unbanned) + ' 条', 'success');
                        self.loadBlocks();
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
            loadOpLogs: async function () {
                this.opLogLoading = true;
                this.errors.oplogs = '';
                try {
                    var d = await WafAPI.data('get_logs', {
                        p: this.opLogPage, rows: this.opLogRows,
                        date: this.opLogFilter.date || '', keyword: this.opLogFilter.keyword || ''
                    });
                    d = d || {};
                    this.opLogs = Array.isArray(d.list) ? d.list : [];
                    this.opLogTotal = num(d.total);
                } catch (e) {
                    this.errors.oplogs = errText(e);
                    this.opLogs = [];
                    this.opLogTotal = 0;
                } finally {
                    this.opLogLoading = false;
                }
            },
            opLogSearch: function () { this.opLogPage = 1; this.loadOpLogs(); },
            opLogReset: function () {
                this.opLogFilter = { date: '', keyword: '' };
                this.opLogPage = 1;
                this.loadOpLogs();
            },
            onOpLogPageChange: function (p) { this.opLogPage = p; this.loadOpLogs(); },
            onOpLogSizeChange: function (n) { this.opLogRows = n; this.opLogPage = 1; this.loadOpLogs(); },
            clearOpLogs: function () {
                var self = this;
                this.showConfirm('清空操作日志', '确定清空插件操作日志吗？该操作不可恢复。').then(async function (ok) {
                    if (!ok) return;
                    try {
                        await WafAPI.data('clear_logs');
                        BTP.msg('操作日志已清空', 'success');
                        self.opLogPage = 1;
                        self.loadOpLogs();
                    } catch (e) { }
                });
            },
    });
})(window);
