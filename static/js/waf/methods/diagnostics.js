/*! btwaf_ce 控制台方法：diagnostics */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;
    Object.assign(WAF.methods, {
            loadDiagnostics: async function () {
                this.diagLoading = true;
                this.errors.diagnostics = '';
                try {
                    if (!this.status.version) await this.loadStatus();
                    await this.loadEnv();
                    this.loaded.diagnostics = true;
                } catch (e) {
                    this.errors.diagnostics = errText(e);
                } finally {
                    this.diagLoading = false;
                }
            },
            loadEnv: async function () {
                this.envLoading = true;
                try {
                    var d = await WafAPI.data('check_env');
                    this.envItems = (d && d.items) || [];
                    this.envRepairable = !!(d && d.repairable);
                    this.envNeedsRepair = !!(d && (d.needs_repair || d.manual_required))
                        || this.envItems.some(function (it) { return it && !it.ok; });
                } catch (e) {
                    this.envItems = [];
                } finally {
                    this.envLoading = false;
                }
            },
            repairEnv: function () {
                var self = this;
                this.showConfirm('一键修复', '将恢复插件 conf / lua / 目录 / 权限并执行 nginx -t 与 reload，确定继续？').then(async function (ok) {
                    if (!ok) return;
                    self.repairLoading = true;
                    try {
                        var d = await WafAPI.data('repair_env');
                        var acts = (d && d.actions) || [];
                        BTP.msg('环境修复完成' + (d && d.nginx_test ? '（nginx -t: ' + d.nginx_test + '）' : ''), 'success');
                        if (acts.length) console.log('[btwaf_ce] repair actions:', acts);
                        self.refreshStatusAfterSave();
                    } catch (e) {
                    } finally {
                        self.repairLoading = false;
                    }
                });
            },
    });
})(window);
