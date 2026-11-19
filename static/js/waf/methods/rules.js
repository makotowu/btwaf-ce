/*! btwaf_ce 控制台方法：rules */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;
    Object.assign(WAF.methods, {
            loadRules: async function () {
                this.ruleLoading = true;
                this.errors.rules = '';
                try {
                    if (!this.ruleExcludeLoaded) await this.ensureRuleExclude();
                    if (this.ruleScope === 'site') {
                        if (!this.siteNames.length) await this.loadSiteNames();
                        if (!this.ruleSite && this.siteNames.length) this.ruleSite = this.siteNames[0];
                        if (!this.ruleSite) throw new Error('请选择站点');
                    }
                    var d = await WafAPI.data('get_rules', {
                        source: this.ruleFilter.source, module: this.ruleFilter.module,
                        keyword: this.ruleFilter.keyword, status: this.ruleFilter.status,
                        scope: this.ruleScope, site_name: this.ruleScope === 'site' ? this.ruleSite : '',
                        p: this.rulePage, rows: this.ruleRows
                    });
                    d = d || {};
                    this.ruleList = Array.isArray(d.list) ? d.list : [];
                    this.ruleTotal = num(d.total);
                    this.loaded.rules = true;
                } catch (e) {
                    this.errors.rules = errText(e);
                    this.ruleList = [];
                    this.ruleTotal = 0;
                } finally {
                    this.ruleLoading = false;
                }
            },
            ensureRuleExclude: async function () {
                try {
                    var d = await WafAPI.data('get_plugin_config');
                    var ex = (d && d.rule_exclude) || {};
                    this.ruleExclude = { crs: ex.crs || [], ce: ex.ce || [] };
                    this.ruleExcludeLoaded = true;
                } catch (e) {
                    this.ruleExcludeLoaded = true;
                }
            },
            ruleSearch: function () { this.rulePage = 1; this.loadRules(); },
            ruleReset: function () {
                this.ruleFilter = { source: '', module: '', keyword: '', status: '' };
                this.rulePage = 1;
                this.loadRules();
            },
            onRulePageChange: function (p) { this.rulePage = p; this.loadRules(); },
            onRuleSizeChange: function (n) { this.ruleRows = n; this.rulePage = 1; this.loadRules(); },
            isRuleEnabled: function (row) {
                if (!row) return false;
                if (row.src !== 'crs' && row.src !== 'ce') return row.enabled !== false;
                var list = this.ruleExclude[row.src] || [];
                return list.indexOf(row.id) < 0;
            },
            ruleScopeChange: function () {
                this.rulePage = 1;
                this.loadRules();
            },
            setRuleStatus: async function (row, status) {
                if (!row) return;
                try {
                    await WafAPI.data('set_rule_status', {
                        scope: this.ruleScope,
                        site_name: this.ruleScope === 'site' ? this.ruleSite : '',
                        rule_id: row.id,
                        status: status
                    });
                    row.status_override = num(status);
                    BTP.msg('响应码已更新', 'success');
                } catch (e) {
                    BTP.msg('设置失败：' + errText(e), 'error');
                    this.loadRules();
                }
            },
            toggleRule: async function (row, value) {
                if (!row) return;
                if (row.src !== 'crs' && row.src !== 'ce') {
                    BTP.msg('自定义规则请在“自定义规则”页启用/停用', 'warning');
                    return;
                }
                var src = row.src;
                var list = (this.ruleExclude[src] || []).slice();
                var idx = list.indexOf(row.id);
                if (value && idx >= 0) list.splice(idx, 1);
                if (!value && idx < 0) list.push(row.id);
                try {
                    await WafAPI.data('set_rule_exclude', { scope: 'global', type: src, ids: JSON.stringify(list) });
                    this.ruleExclude[src] = list;
                    row.enabled = !!value;
                    BTP.msg((value ? '已启用规则 ' : '已排除规则 ') + row.id, 'success');
                    this.refreshStatusAfterSave();
                } catch (e) { }
            },
            loadCustomRules: async function () {
                this.customLoading = true;
                try {
                    var d = await WafAPI.data('get_custom_rules', { keyword: this.customKeyword, p: this.customPage, rows: this.customRows });
                    d = d || {};
                    this.customRules = Array.isArray(d.list) ? d.list : [];
                    this.customTotal = num(d.total);
                } catch (e) {
                    this.customRules = [];
                    this.customTotal = 0;
                } finally {
                    this.customLoading = false;
                }
            },
            loadCustomRuleOptions: async function () {
                try {
                    var d = await WafAPI.data('get_custom_rules', { p: 1, rows: 500, keyword: '' });
                    this.customRuleOptions = ((d && d.list) || []).map(function (r) {
                        return { value: r.id, label: (r.name || r.id) + '（' + (r.id || '') + '）' };
                    });
                } catch (e) { }
            },
            onCustomPageChange: function (p) { this.customPage = p; this.loadCustomRules(); },
            onCustomSizeChange: function (n) { this.customRows = n; this.customPage = 1; this.loadCustomRules(); },
            openCustomDialog: function (row) {
                this.customForm = row ? clone(row) : defaultCustomRule();
                if (!this.customForm.sites) this.customForm.sites = [];
                if (!this.customForm.scope) this.customForm.scope = 'global';
                this.customDialogVisible = true;
                if (!this.siteNames.length) this.loadSiteNames();
            },
            customFieldChange: function (v) {
                if (v !== 'header') this.customForm.header = '';
            },
            saveCustomRule: async function () {
                var f = this.customForm;
                if (!f.name) { BTP.msg('请填写规则名称', 'warning'); return; }
                if (!String(f.value || '').length) { BTP.msg('请填写匹配值', 'warning'); return; }
                if (String(f.value).length > 2048) { BTP.msg('匹配值不能超过 2048 字符', 'warning'); return; }
                if (f.operator === 'regexp') {
                    try { new RegExp(f.value); } catch (e) { BTP.msg('正则表达式不合法：' + e.message, 'error'); return; }
                }
                if (f.scope === 'site' && (!f.sites || !f.sites.length)) { BTP.msg('请选择生效站点', 'warning'); return; }
                var rule = {
                    id: f.id || '',
                    name: String(f.name),
                    open: !!f.open,
                    priority: num(f.priority, 10),
                    scope: f.scope || 'global',
                    sites: f.scope === 'site' ? (f.sites || []) : [],
                    field: f.field || 'uri',
                    header: f.field === 'header' ? (f.header || '') : '',
                    operator: f.operator || 'regexp',
                    value: String(f.value),
                    action: f.action || 'block',
                    status: num(f.status, 403),
                    score: num(f.score, 5),
                    note: f.note || ''
                };
                this.customSaving = true;
                var self = this;
                try {
                    await WafAPI.data('save_custom_rule', { rule: JSON.stringify(rule) });
                    BTP.msg('自定义规则已保存', 'success');
                    this.customDialogVisible = false;
                    self.loadCustomRules();
                    self.loadCustomRuleOptions();
                    self.refreshStatusAfterSave();
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                } finally {
                    this.customSaving = false;
                }
            },
            deleteCustomRule: function (row) {
                var self = this;
                this.showConfirm('删除自定义规则', '确定删除规则「' + (row.name || row.id) + '」吗？').then(async function (ok) {
                    if (!ok) return;
                    try {
                        await WafAPI.data('del_custom_rule', { id: row.id });
                        BTP.msg('规则已删除', 'success');
                        self.loadCustomRules();
                        self.loadCustomRuleOptions();
                        self.refreshStatusAfterSave();
                    } catch (e) { }
                });
            },
    });
})(window);
