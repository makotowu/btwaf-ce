/*! btwaf_ce 控制台 app：Vue shell + 生命周期 */
(function (window) {
    'use strict';
    var WAF = window.WAF;
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;

    function buildTemplate() {
        return '<div id="btwaf-ce-app" class="waf-app" :class="{ \'waf-dark\': isDark }">' +
            (WAF.tpl.top || '') + (WAF.tpl.overview || '') + (WAF.tpl.logs || '') + (WAF.tpl.sites || '') +
            (WAF.tpl.config || '') + (WAF.tpl.rules || '') + (WAF.tpl.blocks || '') + (WAF.tpl.oplogs || '') + (WAF.tpl.diagnostics || '') +
            (WAF.tpl.dialogs || '') + '</div>';
    }

    BTP.createApp({
        template: buildTemplate(),
        data: function () {
            var today = todayStr();
            return {
                views: VIEWS,
                modules: MODULES,
                listMeta: LIST_META,
                sensitivityOptions: SENSITIVITY_OPTIONS,
                siteSensitivityOptions: SITE_SENSITIVITY_OPTIONS,
                triOptions: TRI_OPTIONS,
                siteTierOptions: SITE_TIER_OPTIONS,
                globalTierOptions: GLOBAL_TIER_OPTIONS,
                logActionOptions: LOG_ACTION_OPTIONS,
                ruleSourceOptions: RULE_SOURCE_OPTIONS,
                ruleModuleOptions: RULE_MODULE_OPTIONS,
                customFieldOptions: CUSTOM_FIELD_OPTIONS,
                customOperatorOptions: CUSTOM_OPERATOR_OPTIONS,
                customActionOptions: CUSTOM_ACTION_OPTIONS,
                customScopeOptions: CUSTOM_SCOPE_OPTIONS,
                cdnPresets: CDN_PRESETS,
                ruleStatusOptions: RULE_STATUS_OPTIONS,
                blockStatusOptions: BLOCK_STATUS_OPTIONS,
                geoRegionOptions: GEO_REGION_OPTIONS,
                geoModeOptions: GEO_MODE_OPTIONS,
                geoUnknownOptions: GEO_UNKNOWN_OPTIONS,

                view: 'overview',
                isDark: false,
                refreshing: false,
                status: emptyStatus(),
                statusFailed: false,
                statusLoading: false,
                loaded: {},
                errors: {
                    overview: '', logs: '', sites: '', config: '', rules: '', blocks: '', oplogs: '', diagnostics: ''
                },

                ovDate: today,
                ov: emptyOverview(),
                ovLoading: false,

                logFilter: { site: '', date: today, keyword: '', type: '', ip: '', action: '' },
                logList: [], logTotal: 0, logPage: 1, logRows: 10,
                logTypes: [], logLimited: false, logLoading: false,
                logDetail: null, logDetailVisible: false,
                siteLogVisible: false, siteLogSite: '', siteLogDate: '', siteLogDates: [],
                siteLogList: [], siteLogTotal: 0, siteLogPage: 1, siteLogRows: 10,
                siteLogLoading: false, siteLogError: '',

                siteKeyword: '', siteStatus: '', siteList: [], siteTotal: 0, sitePage: 1, siteRows: 10,
                siteLoading: false, siteSelection: [],
                siteDialog: {
                    visible: false, loading: false, saving: false, tab: 'basic', snapshot: '',
                    site_name: '', config: defaultSiteConfig(), raw: null, global: {},
                    panelCdn: null, cdnPreset: 'custom'
                },
                siteTri: { observe: 'inherit', cc_open: 'inherit', url_cc: 'inherit', attack_open: 'inherit', geo_open: 'inherit', geo_mode: 'inherit', geo_unknown: 'inherit' },
                siteText: {
                    ip_black: '', ip_white: '', url_black: '', url_white: '', ua_black: '', ua_white: '',
                    param_white: '', disable_php_path: '', disable_ext: '', upload_ext: '',
                    cdn_headers: '', cdn_trusted: ''
                },
                siteNames: [],
                siteListType: 'ip_black',

                cfgTab: 'basic',
                cfg: defaultGlobalConfig(),
                cfgLoading: false, cfgSaving: false, cfgSearch: '', cfgSearchEmpty: false, cfgSnapshot: '',
                globalLists: emptyLists(),
                globalListType: 'ip_black',
                listImporting: false,
                globalListText: {
                    ip_black: '', ip_white: '', url_black: '', url_white: '', ua_black: '', ua_white: '', param_white: ''
                },
                crawlerText: '', trustedText: '',
                blockPageText: '',
                blockPagePreview: '', blockPagePreviewVisible: false, blockPageIntercepted: [],
                excludeText: { crs: '', ce: '' },

                ruleTab: 'builtin',
                ruleFilter: { source: '', module: '', keyword: '', status: '' },
                ruleScope: 'global', ruleSite: '',
                ruleList: [], ruleTotal: 0, rulePage: 1, ruleRows: 10, ruleLoading: false,
                ruleExclude: { crs: [], ce: [] }, ruleExcludeLoaded: false,
                customKeyword: '', customRules: [], customTotal: 0, customPage: 1, customRows: 10,
                customLoading: false, customRuleOptions: [],
                customDialogVisible: false, customSaving: false, customForm: defaultCustomRule(),

                blockTab: 'current', blockSite: '', blockList: [], blockTotal: 0, blockPage: 1, blockRows: 10, blockLoading: false,
                blockSystem: { available: false, source: '', list: [], total: 0, sync_count: 0, error: '' },
                blockSystemLoading: false,

                advancedOpen: [],
                envItems: [], envRepairable: true, envNeedsRepair: false, envLoading: false, repairLoading: false,
                opLogs: [], opLogTotal: 0, opLogPage: 1, opLogRows: 10, opLogLoading: false,
        opLogFilter: { date: '', keyword: '' },
                importLoading: false,

                /* 通用确认弹窗（不使用 BTP.confirm，避免 z-index 被面板 layer 遮挡） */
                confirmDialog: { visible: false, title: '', content: '', resolve: null, checkbox: false, checkboxLabel: '', checked: false, withOption: false }
            };
        },

        computed: {
            pluginVersion: function () {
                return this.status.version || '0.1.0';
            },
            readyTagType: function () { return this.status.ready ? 'success' : 'danger'; },
            readyText: function () { return this.status.ready ? '引擎就绪' : '引擎未就绪'; },
            enabledTagType: function () { return this.status.enabled ? 'success' : 'warning'; },
            enabledText: function () { return this.status.enabled ? '防护已开启' : '防护已关闭'; },
            sensitivityText: function () { return this.sensitivityLabel(this.status.sensitivity); },
            logActiveFilters: function () {
                var f = this.logFilter || {};
                var out = [];
                if (f.site) out.push({ key: 'site', label: '站点：' + f.site });
                if (f.ip) out.push({ key: 'ip', label: 'IP：' + f.ip });
                if (f.type) out.push({ key: 'type', label: '类型：' + f.type });
                if (f.action) out.push({ key: 'action', label: '动作：' + f.action });
                if (f.keyword) out.push({ key: 'keyword', label: '关键字：' + f.keyword });
                return out;
            },
            siteDialogDirty: function () {
                if (!this.siteDialog || !this.siteDialog.visible) return false;
                return this.siteFingerprint() !== this.siteDialog.snapshot;
            },
            cfgDirty: function () {
                if (!this.loaded.config) return false;
                return this.cfgFingerprint() !== this.cfgSnapshot;
            },
            statusNotice: function () {
                if (this.statusFailed) return { level: 'error', title: '无法获取引擎状态', desc: '请检查面板接口或插件安装是否完整。', label: '重试', act: 'retry' };
                if (!this.status.ready) return { level: 'error', title: '引擎未就绪', desc: '请到「系统诊断」查看检测项并一键修复。', label: '去诊断', act: 'diagnostics' };
                if (!this.status.enabled) return { level: 'warning', title: '防护已关闭', desc: '当前所有请求都不会被检测。', label: '立即开启防护', act: 'enable' };
                if (this.status.observe) return { level: 'info', title: '观察模式', desc: '命中规则只写日志，不会拦截请求。', label: '关闭观察模式', act: 'observeOff' };
                return null;
            },
            ruleExcludedCount: function () {
                return ((this.ruleExclude && this.ruleExclude.crs) || []).length + ((this.ruleExclude && this.ruleExclude.ce) || []).length;
            },
            unprotectedCount: function () {
                return Math.max(0, num(this.ov && this.ov.stats && this.ov.stats.sites_total) - num(this.ov && this.ov.stats && this.ov.stats.sites_open));
            },
            topSites: function () {
                var m = (this.ov && this.ov.hits_by_site) || {};
                var out = [];
                Object.keys(m).forEach(function (k) {
                    if (!k) return;
                    var n = num(m[k]);
                    if (n > 0) out.push({ site: k, count: n });
                });
                out.sort(function (a, b) { return b.count - a.count; });
                return out.slice(0, 5);
            },
            viewGroups: function () {
                var groups = [];
                var map = {};
                (this.views || []).forEach(function (v) {
                    var g = v.group || '其他';
                    if (!map[g]) { map[g] = { label: g, items: [] }; groups.push(map[g]); }
                    map[g].items.push(v);
                });
                return groups;
            },
            envAllOk: function () {
                return !!(this.envItems && this.envItems.length) && this.envItems.every(function (i) { return i && i.ok; });
            },
        },

        mounted: function () {
            var self = this;
            this.isDark = window.BTPanelTheme && window.BTPanelTheme.isDark
                ? !!window.BTPanelTheme.isDark()
                : (window.BTP && BTP.theme && BTP.theme.isDark ? !!BTP.theme.isDark() : false);
            try {
                if (window.BTPanelTheme && window.BTPanelTheme.onChange) {
                    window.BTPanelTheme.onChange(function (s) { self.isDark = !!(s && s.isDark); });
                } else if (window.BTP && BTP.theme && BTP.theme.onChange) {
                    BTP.theme.onChange(function (s) { self.isDark = !!(s && s.isDark); });
                }
            } catch (e) { }
            // 供 preview.html 的"空数据/接口失败/窄屏/深色"切换后触发整页重载
            window.__btwafCeApp = this;
            this.boot();
            // 兼容面板缓存的旧 index.html（内联适配脚本可能未更新）：由版本化的 app.js 再次打标/纠正
            this.fitPanelLayer();
            var fitTries = 0;
            var fitTimer = setInterval(function () {
                fitTries++;
                if (self.fitPanelLayer() || fitTries > 40) clearInterval(fitTimer);
            }, 250);
            window.addEventListener('resize', function () { self.fitPanelLayer(); });
            window.addEventListener('btwaf-theme-change', function (ev) {
                var detail = ev && ev.detail;
                self.isDark = detail && typeof detail.dark === 'boolean'
                    ? detail.dark
                    : !!(window.BTPanelTheme && window.BTPanelTheme.isDark && window.BTPanelTheme.isDark());
                if (self.view === 'overview') self.renderOverviewCharts();
                else if (window.WafCharts && WafCharts.resizeAll) WafCharts.resizeAll();
            });
        },
        methods: WAF.methods
    }).mount('#app');
})(window);
