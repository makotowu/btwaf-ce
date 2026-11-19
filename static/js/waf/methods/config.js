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
                    protocol: { from_data: !!(c.protocol && c.protocol.from_data) },
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
            onImportGlobalList: function (uploadFile) {
                var self = this;
                var file = uploadFile && uploadFile.raw;
                var type = this.globalListType;
                if (!file || !this.isIpList(type)) return;
                if (file.size > 1024 * 1024) { BTP.msg('名单文件不能超过 1MB', 'error'); return; }
                this.listImporting = true;
                var reader = new FileReader();
                reader.onload = async function () {
                    try {
                        var base = splitLines(self.globalListText[type]);
                        var d = await WafAPI.data('import_lists', {
                            scope: 'global', type: type,
                            base: JSON.stringify(base),
                            text: String(reader.result || '')
                        });
                        self.globalLists[type] = (d && d.items) || [];
                        self.globalListText[type] = joinLines(self.globalLists[type]);
                        BTP.msg(self.importListMessage(d), 'success');
                        self.refreshStatusAfterSave();
                    } catch (e) {
                        if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                    } finally {
                        self.listImporting = false;
                    }
                };
                reader.onerror = function () {
                    self.listImporting = false;
                    BTP.msg('读取文件失败', 'error');
                };
                reader.readAsText(file, 'utf-8');
            },
            exportGlobalList: function () {
                var type = this.globalListType;
                if (!this.isIpList(type)) return;
                var items = splitLines(this.globalListText[type]);
                if (!items.length) { BTP.msg('名单为空', 'info'); return; }
                this.downloadTextFile(
                    'btwaf_ce-' + type + '-' + todayStr().replace(/-/g, '') + '.txt',
                    items.join('\n') + '\n'
                );
                BTP.msg('已导出 ' + items.length + ' 条', 'success');
            },
            isIpv4Address: function (value) {
                var text = String(value || '').trim();
                if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return false;
                return text.split('.').every(function (p) { return Number(p) >= 0 && Number(p) <= 255; });
            },
            ipv4ToInt: function (value) {
                var parts = String(value || '').trim().split('.');
                if (parts.length !== 4) return 0;
                return (((Number(parts[0]) << 24) | (Number(parts[1]) << 16) | (Number(parts[2]) << 8) | Number(parts[3])) >>> 0);
            },
            intToIpv4: function (value) {
                value = value >>> 0;
                return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
            },
            geoCnCurrent: function () {
                return this.geoCnDialog.tab === 'exclude' ? this.geoCnDialog.exclude : this.geoCnDialog.include;
            },
            geoCnSort: function (list) {
                list.sort(function (a, b) {
                    var ai = this.ipv4ToInt(a.start), bi = this.ipv4ToInt(b.start);
                    if (ai === bi) return this.ipv4ToInt(a.end) - this.ipv4ToInt(b.end);
                    return ai - bi;
                }.bind(this));
                return list;
            },
            geoCnAppend: function (list, start, end) {
                for (var i = 0; i < list.length; i++) {
                    if (list[i].start === start && list[i].end === end) return false;
                }
                list.push({ start: start, end: end });
                this.geoCnSort(list);
                return true;
            },
            addGeoCn: function () {
                var d = this.geoCnDialog;
                var start = String(d.start || '').trim();
                var end = String(d.end || '').trim();
                if (!this.isIpv4Address(start) || !this.isIpv4Address(end)) {
                    BTP.msg('请输入正确的 IPv4 地址', 'error');
                    return;
                }
                if (this.ipv4ToInt(start) > this.ipv4ToInt(end)) {
                    BTP.msg('起始 IP 不能大于结束 IP', 'error');
                    return;
                }
                if (!this.geoCnAppend(this.geoCnCurrent(), start, end)) {
                    BTP.msg('该范围已存在', 'info');
                    return;
                }
                d.start = '';
                d.end = '';
                d.error = '';
            },
            removeGeoCn: function (index) {
                var d = this.geoCnDialog;
                var list = this.geoCnCurrent();
                var pos = (d.page - 1) * d.rows + index;
                if (pos < 0 || pos >= list.length) return;
                list.splice(pos, 1);
                var maxPage = Math.max(1, Math.ceil(list.length / d.rows));
                if (d.page > maxPage) d.page = maxPage;
            },
            geoCnTabChange: function () {
                this.geoCnDialog.page = 1;
            },
            parseGeoCnLine: function (line) {
                line = String(line || '').trim();
                if (!line || line.charAt(0) === '#') return null;
                var hash = line.indexOf('#');
                if (hash >= 0) line = line.slice(0, hash).trim();
                var start, end;
                if (line.indexOf('/') >= 0) {
                    var cidr = line.split('/');
                    if (cidr.length !== 2 || !this.isIpv4Address(cidr[0])) return null;
                    var bits = Number(cidr[1]);
                    if (!isFinite(bits) || bits < 0 || bits > 32) return null;
                    var base = this.ipv4ToInt(cidr[0]);
                    var mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
                    start = this.intToIpv4((base & mask) >>> 0);
                    end = this.intToIpv4(((base & mask) | (~mask)) >>> 0);
                } else {
                    var parts = line.split(/\s+/);
                    if (parts.length >= 2) {
                        start = parts[0];
                        end = parts[1];
                    } else {
                        var range = line.split('-');
                        if (range.length === 2) {
                            start = range[0].trim();
                            end = range[1].trim();
                        } else {
                            start = line;
                            end = line;
                        }
                    }
                }
                if (!this.isIpv4Address(start) || !this.isIpv4Address(end)) return null;
                if (this.ipv4ToInt(start) > this.ipv4ToInt(end)) return null;
                return { start: start, end: end };
            },
            onImportGeoCn: function (uploadFile) {
                var self = this;
                var file = uploadFile && uploadFile.raw;
                if (!file) return;
                if (file.size > 1024 * 1024) { BTP.msg('文件不能超过 1MB', 'error'); return; }
                this.geoCnDialog.importing = true;
                var reader = new FileReader();
                reader.onload = function () {
                    var lines = String(reader.result || '').split(/\r?\n/);
                    var added = 0;
                    var skipped = 0;
                    lines.forEach(function (line) {
                        var item = self.parseGeoCnLine(line);
                        if (!item) {
                            if (String(line || '').trim() && String(line || '').trim().charAt(0) !== '#') skipped++;
                            return;
                        }
                        if (self.geoCnAppend(self.geoCnCurrent(), item.start, item.end)) {
                            added++;
                        } else {
                            skipped++;
                        }
                    });
                    BTP.msg('导入 ' + added + ' 条，跳过 ' + skipped + ' 条', added ? 'success' : 'info');
                    self.geoCnDialog.page = 1;
                    self.geoCnDialog.importing = false;
                };
                reader.onerror = function () {
                    self.geoCnDialog.importing = false;
                    BTP.msg('读取文件失败', 'error');
                };
                reader.readAsText(file, 'utf-8');
            },
            exportGeoCn: function () {
                var self = this;
                var list = this.geoCnCurrent();
                if (!list.length) { BTP.msg('当前分类为空', 'info'); return; }
                var lines = list.map(function (item) { return item.start + '-' + item.end; });
                this.downloadTextFile(
                    'btwaf_ce-cn-' + this.geoCnDialog.tab + '-' + todayStr().replace(/-/g, '') + '.txt',
                    lines.join('\n') + '\n'
                );
                BTP.msg('已导出 ' + lines.length + ' 条', 'success');
            },
            openGeoCnDialog: function () {
                var d = this.geoCnDialog;
                d.visible = true;
                d.loading = true;
                d.tab = 'include';
                d.page = 1;
                d.start = '';
                d.end = '';
                d.include = [];
                d.exclude = [];
                d.builtin = {};
                d.error = '';
                this.loadGeoCn();
            },
            loadGeoCn: async function () {
                var d = this.geoCnDialog;
                d.loading = true;
                d.error = '';
                try {
                    var res = await WafAPI.data('get_geo_custom');
                    res = res || {};
                    d.builtin = res.builtin || {};
                    d.include = res.include || [];
                    d.exclude = res.exclude || [];
                    if (res.error) d.error = res.error;
                } catch (e) {
                    d.error = errText(e);
                } finally {
                    d.loading = false;
                }
            },
            saveGeoCn: async function () {
                var d = this.geoCnDialog;
                d.saving = true;
                d.error = '';
                try {
                    var res = await WafAPI.data('save_geo_custom', {
                        include: JSON.stringify(d.include),
                        exclude: JSON.stringify(d.exclude)
                    }, { timeout: 120000 });
                    var payload = (res && res.data) || res || {};
                    d.builtin = payload.builtin || d.builtin;
                    d.include = payload.include || d.include;
                    d.exclude = payload.exclude || d.exclude;
                    d.error = payload.error || '';
                    if (res && res.reloaded === false) {
                        BTP.msg('已保存，但 Nginx 重载失败：' + (res.reload_error || ''), 'warning');
                    } else {
                        BTP.msg('中国 IP 段已保存', 'success');
                    }
                } catch (e) {
                    if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
                } finally {
                    d.saving = false;
                }
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
