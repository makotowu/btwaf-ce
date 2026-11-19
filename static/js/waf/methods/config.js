/*! btwaf_ce 控制台方法：config */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var MODULES = WAF.const.MODULES, LIST_META = WAF.const.LIST_META, SENSITIVITY_OPTIONS = WAF.const.SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS = WAF.const.SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS = WAF.const.TRI_OPTIONS, SITE_TIER_OPTIONS = WAF.const.SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS = WAF.const.GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS = WAF.const.LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS = WAF.const.RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS = WAF.const.RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS = WAF.const.CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS = WAF.const.CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS = WAF.const.CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS = WAF.const.CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS = WAF.const.BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS = WAF.const.RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS = WAF.const.GEO_REGION_OPTIONS, GEO_MODE_OPTIONS = WAF.const.GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS = WAF.const.GEO_UNKNOWN_OPTIONS, CDN_PRESETS = WAF.const.CDN_PRESETS, ICON = WAF.const.ICON, VIEWS = WAF.const.VIEWS;
    var pad2 = WAF.util.pad2, num = WAF.util.num, clone = WAF.util.clone, todayStr = WAF.util.todayStr, fmtTime = WAF.util.fmtTime, fmtDate = WAF.util.fmtDate, splitLines = WAF.util.splitLines, joinLines = WAF.util.joinLines, errText = WAF.util.errText, toTri = WAF.util.toTri, fromTri = WAF.util.fromTri, remainText = WAF.util.remainText, mergeDeep = WAF.util.mergeDeep, emptyStatus = WAF.util.emptyStatus, normalizeStatus = WAF.util.normalizeStatus, emptyOverview = WAF.util.emptyOverview, defaultModules = WAF.util.defaultModules, defaultSiteModules = WAF.util.defaultSiteModules, emptyLists = WAF.util.emptyLists, defaultGlobalConfig = WAF.util.defaultGlobalConfig, normalizeGlobalConfig = WAF.util.normalizeGlobalConfig, defaultSiteConfig = WAF.util.defaultSiteConfig, normalizeSiteConfig = WAF.util.normalizeSiteConfig, defaultCustomRule = WAF.util.defaultCustomRule;
    Object.assign(WAF.methods, {
            openCustomFromSite: function () {
                this.openCustomDialog(null);
            },
            cfgFingerprint: function () {
                try {
                    return JSON.stringify({
                        cfg: this.cfg,
                        blockPageText: this.blockPageText,
                        excludeText: this.excludeText,
                        crawlerText: this.crawlerText,
                        trustedText: this.trustedText,
                        globalListText: this.globalListText
                    });
                } catch (e) { return ''; }
            },
            resetGlobalConfig: function () {
                var self = this;
                this.showConfirm('撤销修改', '将丢弃当前未保存的修改并重新读取配置，确定继续？').then(function (ok) {
                    if (ok) self.loadConfig();
                });
            },
            loadConfig: async function () {
                this.cfgLoading = true;
                this.errors.config = '';
                try {
                    if (!this.status.version) await this.loadStatus();
                    var d = await WafAPI.data('get_plugin_config');
                    this.cfg = normalizeGlobalConfig(d || {});
                    var defaultPage = this.status.default_block_page || '';
                    var useCustom = !!(this.cfg.block && this.cfg.block.use_custom);
                    this.blockPageText = useCustom
                        ? ((this.cfg.block && this.cfg.block.page) || defaultPage)
                        : defaultPage;
                    this.excludeText.crs = joinLines((this.cfg.rule_exclude && this.cfg.rule_exclude.crs) || []);
                    this.excludeText.ce = joinLines((this.cfg.rule_exclude && this.cfg.rule_exclude.ce) || []);
                    this.crawlerText = joinLines((this.cfg.crawler && this.cfg.crawler.allow) || []);
                    this.trustedText = joinLines(this.cfg.trusted_proxies || []);
                    await this.loadGlobalLists();
                    this.loaded.config = true;
                    this.cfgSnapshot = this.cfgFingerprint();
                } catch (e) {
                    this.errors.config = errText(e);
                } finally {
                    this.cfgLoading = false;
                }
            },
            loadGlobalLists: async function () {
                try {
                    var d = await WafAPI.data('get_lists', { scope: 'global' });
                    this.globalLists = mergeDeep(emptyLists(), (d && d.lists) || {});
                    var self = this;
                    LIST_META.forEach(function (m) {
                        self.globalListText[m.key] = joinLines(self.globalLists[m.key] || []);
                    });
                } catch (e) { }
            },
            saveGlobalConfig: async function () {
                var c = this.cfg;
                var payload = {
                    enabled: !!c.enabled, observe: !!c.observe, sensitivity: num(c.sensitivity, 2),
                    block: {
                        status: num(c.block && c.block.status, 403),
                        use_custom: !!(c.block && c.block.use_custom),
                        page: this.blockPageText || ''
                    }, scan: c.scan, log: c.log, cc: c.cc, attack_block: c.attack_block,
                    crawler: {
                        allow: splitLines(this.crawlerText),
                        block_fake: !!(c.crawler && c.crawler.block_fake)
                    },
                    trusted_proxies: splitLines(this.trustedText),
                    fail_open: !!c.fail_open, whitelist_first: !!c.whitelist_first
                };
                this.cfgSaving = true;
                var self = this;
                try {
                    var d = await WafAPI.data('save_plugin_config', { config: JSON.stringify(payload) });
                    var warns = (d && d.warnings) || [];
                    if (warns.length) {
                        BTP.msg('配置已保存，但有以下提示：' + warns.join('；'), 'warning', { duration: 5000 });
                    } else {
                        BTP.msg('全局配置已保存（生效时间 ' + fmtTime(d && d.apply_at) + '）', 'success');
                    }
                    self.cfgSnapshot = self.cfgFingerprint();
                    self.refreshStatusAfterSave();
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                } finally {
                    this.cfgSaving = false;
                }
            },
            saveGlobalModules: async function () {
                var cfg = this.cfg;
                var modules = {};
                MODULES.forEach(function (m) {
                    var cur = (cfg.modules && cfg.modules[m.key]) || { open: true, tier: 1 };
                    modules[m.key] = { open: !!cur.open, tier: num(cur.tier, 1) };
                });
                var self = this;
                try {
                    await WafAPI.data('save_modules', { modules: JSON.stringify(modules) });
                    BTP.msg('模块配置已保存', 'success');
                    self.refreshStatusAfterSave();
                } catch (e) { }
            },
            saveGlobalList: async function (type) {
                var items = splitLines(this.globalListText[type]);
                try {
                    var d = await WafAPI.data('set_lists', { scope: 'global', type: type, items: JSON.stringify(items) });
                    BTP.msg('已保存，共 ' + num(d && d.count, items.length) + ' 条', 'success');
                    this.globalLists[type] = items;
                    this.refreshStatusAfterSave();
                } catch (e) { }
            },
            saveBlockPage: async function () {
                try {
                    await WafAPI.data('save_block_page', {
                        html: this.blockPageText,
                        use_custom: !!(this.cfg.block && this.cfg.block.use_custom)
                    });
                    BTP.msg('自定义拦截页面已保存', 'success');
                    this.refreshStatusAfterSave();
                } catch (e) { }
            },
            previewBlockPage: async function () {
                try {
                    var d = await WafAPI.data('preview_block_page', { html: this.blockPageText });
                    this.blockPagePreview = (d && d.html) || '';
                    // 后端新版本返回 removed，旧版本返回 intercepted，二者内容一致
                    this.blockPageIntercepted = (d && (d.removed || d.intercepted)) || [];
                    this.blockPagePreviewVisible = true;
                } catch (e) { }
            },
            saveExcludes: async function () {
                var self = this;
                try {
                    await WafAPI.data('set_rule_exclude', { scope: 'global', type: 'crs', ids: JSON.stringify(splitLines(this.excludeText.crs)) });
                    await WafAPI.data('set_rule_exclude', { scope: 'global', type: 'ce', ids: JSON.stringify(splitLines(this.excludeText.ce)) });
                    this.ruleExcludeLoaded = false;
                    BTP.msg('规则排除清单已保存', 'success');
                    self.refreshStatusAfterSave();
                } catch (e) { }
            },
            exportConfig: async function () {
                try {
                    var r = await WafAPI.call('export_config');
                    var data = (r && r.data) || {};
                    var text = JSON.stringify(data, null, 2);
                    var blob = new Blob([text], { type: 'application/json;charset=utf-8' });
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    a.href = url;
                    a.download = 'btwaf_ce-config-' + todayStr() + '.json';
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(function () {
                        try { URL.revokeObjectURL(url); a.parentNode.removeChild(a); } catch (e) { }
                    }, 800);
                    BTP.msg('配置已导出', 'success');
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                }
            },
            onImportFile: function (uploadFile) {
                var self = this;
                var file = uploadFile && uploadFile.raw;
                if (!file) return;
                this.showConfirm('导入配置', '导入将覆盖全局配置、站点配置与自定义规则，确定继续？').then(function (ok) {
                    if (!ok) return;
                    self.importLoading = true;
                    var reader = new FileReader();
                    reader.onload = async function () {
                        try {
                            var text = String(reader.result || '');
                            JSON.parse(text); // 先做一次本地 JSON 校验
                            await WafAPI.data('import_config', { payload: text });
                            BTP.msg('配置导入成功', 'success');
                            self.reloadAll();
                        } catch (e) {
                            if (!e || !e.__msgShown) BTP.msg('导入失败：' + errText(e), 'error');
                        } finally {
                            self.importLoading = false;
                        }
                    };
                    reader.onerror = function () {
                        self.importLoading = false;
                        BTP.msg('读取文件失败', 'error');
                    };
                    reader.readAsText(file, 'utf-8');
                });
            }
    });
})(window);
