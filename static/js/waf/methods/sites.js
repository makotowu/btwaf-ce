/*! btwaf_ce 控制台方法：sites */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;
    Object.assign(WAF.methods, {
            loadSites: async function () {
                this.siteLoading = true;
                this.errors.sites = '';
                try {
                    var d = await WafAPI.data('get_sites', { keyword: this.siteKeyword, status: this.siteStatus, p: this.sitePage, rows: this.siteRows });
                    d = d || {};
                    this.siteList = Array.isArray(d.list) ? d.list : [];
                    this.siteTotal = num(d.total);
                    this.siteSelection = [];
                    this.loaded.sites = true;
                    if (!this.customRuleOptions.length) this.loadCustomRuleOptions();
                    if (!this.siteNames.length) this.loadSiteNames();
                } catch (e) {
                    this.errors.sites = errText(e);
                    this.siteList = [];
                    this.siteTotal = 0;
                } finally {
                    this.siteLoading = false;
                }
            },
            siteSearch: function () { this.sitePage = 1; this.loadSites(); },
            onSitePageChange: function (p) { this.sitePage = p; this.loadSites(); },
            onSiteSizeChange: function (n) { this.siteRows = n; this.sitePage = 1; this.loadSites(); },
            onSiteSelection: function (rows) { this.siteSelection = rows || []; },
            loadSiteNames: async function () {
                try {
                    var d = await WafAPI.data('get_sites', { p: 1, rows: 500, keyword: '' });
                    this.siteNames = ((d && d.list) || []).map(function (s) { return s.site_name; }).filter(Boolean);
                } catch (e) { }
            },
            syncSites: function () {
                var self = this;
                this.showConfirm('同步站点', '从面板数据库重新同步站点与域名（不会删除已有站点配置），确认继续？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        var d = await WafAPI.data('sync_sites');
                        BTP.msg('同步完成：站点 ' + num(d && d.sites) + ' 个，域名 ' + num(d && d.hosts) + ' 个', 'success');
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
            toggleSite: async function (row, value) {
                try {
                    await WafAPI.data('set_site_open', { site_names: JSON.stringify([row.site_name]), open: !!value });
                    BTP.msg((value ? '已开启防护：' : '已关闭防护：') + row.site_name, 'success');
                    this.refreshStatusAfterSave();
                } catch (e) {
                    row.open = !value;
                }
            },
            batchSetSites: function (open) {
                var self = this;
                if (!this.siteSelection.length) { BTP.msg('请先选择站点', 'warning'); return; }
                var names = this.siteSelection.map(function (s) { return s.site_name; });
                this.showConfirm(open ? '批量开启' : '批量关闭', '将 ' + names.length + ' 个站点' + (open ? '开启' : '关闭') + '防护，确认继续？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        await WafAPI.data('set_site_open', { site_names: JSON.stringify(names), open: !!open });
                        BTP.msg('已更新 ' + names.length + ' 个站点', 'success');
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
            siteFingerprint: function () {
                try {
                    return JSON.stringify({ config: this.siteDialog.config, text: this.siteText, tri: this.siteTri });
                } catch (e) { return ''; }
            },
            beforeCloseSite: function (done) {
                if (!this.siteDialogDirty) { done(); return; }
                this.showConfirm('放弃未保存修改', '站点配置有未保存的修改，确定关闭吗？').then(function (ok) { if (ok) done(); });
            },
            closeSiteDialog: function () {
                var self = this;
                this.beforeCloseSite(function () { self.siteDialog.visible = false; });
            },
            viewSiteLogs: function (row) {
                this.logFilter.site = row.site_name;
                this.logPage = 1;
                this.switchView('logs');
                this.loadLogs();
            },
            openSiteDialog: function (row) {
                var self = this;
                var d = this.siteDialog;
                d.visible = true;
                d.loading = true;
                d.saving = false;
                d.tab = 'basic';
                d.site_name = row.site_name;
                this.errors.sites = '';
                WafAPI.data('get_site_config', { site_name: row.site_name }).then(function (res) {
                    res = res || {};
                    // 编辑用站点自身配置 raw（保留 0/null 继承语义）；config 为合并后生效值，仅作回退
                    d.config = normalizeSiteConfig(res.raw || res.config || {});
                    d.raw = res.raw || {};
                    d.global = res.global || {};
                    d.panelCdn = res.panel_cdn || null;
                    self.buildSiteTexts();
                    d.snapshot = self.siteFingerprint();
                    if (!self.customRuleOptions.length) self.loadCustomRuleOptions();
                    if (!self.siteNames.length) self.loadSiteNames();
                }).catch(function (e) {
                    BTP.msg('读取站点配置失败：' + errText(e), 'error');
                }).then(function () {
                    d.loading = false;
                });
            },
            detectCdnPreset: function (headers) {
                var normalized = (Array.isArray(headers) ? headers : []).map(function (h) { return String(h || '').toLowerCase(); });
                for (var i = 0; i < CDN_PRESETS.length; i++) {
                    var p = CDN_PRESETS[i];
                    if (p.value === 'custom') continue;
                    if (p.headers.length === normalized.length && p.headers.every(function (h, idx) { return h === normalized[idx]; })) {
                        return p.value;
                    }
                }
                return 'custom';
            },
            applyCdnPreset: function (value) {
                var preset = null;
                for (var i = 0; i < CDN_PRESETS.length; i++) {
                    if (CDN_PRESETS[i].value === value) { preset = CDN_PRESETS[i]; break; }
                }
                this.siteDialog.cdnPreset = value;
                if (!preset || value === 'custom') return;
                this.siteDialog.config.cdn.open = true;
                this.siteText.cdn_headers = joinLines(preset.headers);
            },
            panelCdnOpen: function () {
                return !!(this.siteDialog.panelCdn && this.siteDialog.panelCdn.open);
            },
            buildSiteTexts: function () {
                var c = this.siteDialog.config;
                var t = this.siteText;
                LIST_META.forEach(function (m) { t[m.key] = joinLines((c.lists && c.lists[m.key]) || []); });
                t.disable_php_path = joinLines(c.disable_php_path || []);
                t.disable_ext = joinLines(c.disable_ext || []);
                t.upload_ext = joinLines(c.upload_ext || []);
                t.cdn_headers = joinLines((c.cdn && c.cdn.headers) || []);
                t.cdn_trusted = joinLines((c.cdn && c.cdn.trusted) || []);
                this.siteDialog.cdnPreset = this.detectCdnPreset((c.cdn && c.cdn.headers) || []);
                this.siteTri = {
                    observe: toTri(c.observe),
                    cc_open: toTri(c.cc && c.cc.open),
                    url_cc: toTri(c.cc && c.cc.url_cc),
                    attack_open: toTri(c.attack_block && c.attack_block.open),
                    geo_open: toTri(c.geo && c.geo.open),
                    geo_mode: (c.geo && c.geo.mode) || 'inherit',
                    geo_unknown: (c.geo && c.geo.unknown) || 'inherit'
                };
                c.geo = c.geo || {};
                if (!Array.isArray(c.geo.regions)) c.geo.regions = [];
            },
            applySiteTexts: function () {
                var c = this.siteDialog.config;
                var t = this.siteText;
                c.lists = c.lists || {};
                LIST_META.forEach(function (m) { c.lists[m.key] = splitLines(t[m.key]); });
                c.disable_php_path = splitLines(t.disable_php_path);
                c.disable_ext = splitLines(t.disable_ext);
                c.upload_ext = splitLines(t.upload_ext);
                c.cdn = c.cdn || {};
                c.cdn.headers = splitLines(t.cdn_headers);
                c.cdn.trusted = splitLines(t.cdn_trusted);
                c.observe = fromTri(this.siteTri.observe);
                c.cc = c.cc || {};
                c.cc.open = fromTri(this.siteTri.cc_open);
                c.cc.url_cc = fromTri(this.siteTri.url_cc);
                c.cc.cycle = num(c.cc.cycle);
                c.cc.limit = num(c.cc.limit);
                c.cc.block_time = num(c.cc.block_time);
                c.cc.status = num(c.cc.status);
                c.attack_block = c.attack_block || {};
                c.attack_block.open = fromTri(this.siteTri.attack_open);
                c.attack_block.cycle = num(c.attack_block.cycle);
                c.attack_block.limit = num(c.attack_block.limit);
                c.attack_block.block_time = num(c.attack_block.block_time);
                c.geo = c.geo || {};
                c.geo.open = fromTri(this.siteTri.geo_open);
                c.geo.mode = this.siteTri.geo_mode === 'inherit' ? null : this.siteTri.geo_mode;
                c.geo.unknown = this.siteTri.geo_unknown === 'inherit' ? null : this.siteTri.geo_unknown;
                c.geo.regions = (Array.isArray(c.geo.regions) && c.geo.regions.length) ? c.geo.regions : null;
                c.geo.status = num(c.geo.status) || 0;
                c.sensitivity = num(c.sensitivity);
                MODULES.forEach(function (m) {
                    if (!c.modules[m.key]) c.modules[m.key] = { open: true, tier: 0 };
                    c.modules[m.key].open = !!c.modules[m.key].open;
                    c.modules[m.key].tier = num(c.modules[m.key].tier);
                });
            },
            saveSiteConfig: async function () {
                var d = this.siteDialog;
                if (!d.site_name) return;
                this.applySiteTexts();
                d.saving = true;
                var self = this;
                try {
                    await WafAPI.data('save_site_config', { site_name: d.site_name, config: JSON.stringify(d.config) });
                    BTP.msg('站点配置已保存：' + d.site_name, 'success');
                    d.visible = false;
                    self.refreshStatusAfterSave();
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                } finally {
                    d.saving = false;
                }
            },
    });
})(window);
