/*! btwaf_ce 控制台 app.js — Vue 3 + Element Plus，挂载 #app */
(function (window) {
    'use strict';

    /* 跟随面板主题色/圆角，生成 --btp-* */
    (function () {
        var WHITE = { r: 255, g: 255, b: 255 }, BLACK = { r: 0, g: 0, b: 0 };
        var LIGHT_RATIOS = { 3: 0.3, 5: 0.5, 7: 0.7, 8: 0.8, 9: 0.9 };
        var DARK_LIGHT_RATIOS = { 3: 0.15, 5: 0.25, 7: 0.35, 8: 0.45, 9: 0.55 };
        var RADIUS_MAP = {
            none: ['0px', '0px', '0px', '0px', '0px', '0px', '50px'],
            smaller: ['2px', '2px', '2px', '4px', '6px', '4px', '25px'],
            small: ['2px', '4px', '6px', '8px', '12px', '20px', '50px'],
            medium: ['4px', '6px', '8px', '12px', '16px', '24px', '50px'],
            large: ['6px', '8px', '12px', '16px', '20px', '28px', '50px']
        };
        var RADIUS_NAMES = ['small', 'base', 'medium', 'large', 'extra-large', 'round', 'extra-round'];
        var state = { color: '', dark: false, radius: '', applying: false, applied: false };

        function panelDocument() {
            try { return (window.parent && window.parent.document) || document; } catch (e) { return document; }
        }
        function parseColor(str) {
            str = String(str || '').trim();
            var m = str.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
            if (m) {
                var h = m[1];
                if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
                return { r: parseInt(h.substr(0, 2), 16), g: parseInt(h.substr(2, 2), 16), b: parseInt(h.substr(4, 2), 16) };
            }
            m = str.match(/^rgba?\(([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i);
            if (m) return { r: Math.round(+m[1]), g: Math.round(+m[2]), b: Math.round(+m[3]) };
            return null;
        }
        function mix(c1, c2, ratio) {
            return {
                r: Math.round(c1.r * (1 - ratio) + c2.r * ratio),
                g: Math.round(c1.g * (1 - ratio) + c2.g * ratio),
                b: Math.round(c1.b * (1 - ratio) + c2.b * ratio)
            };
        }
        function hex(c) { return '#' + ((1 << 24) + (c.r << 16) + (c.g << 8) + c.b).toString(16).slice(1); }
        function readColor() {
            var color = '';
            try { color = getComputedStyle(panelDocument().documentElement).getPropertyValue('--el-color-primary'); } catch (e) { }
            color = (color || '').trim();
            if (!color) {
                try { color = getComputedStyle(document.documentElement).getPropertyValue('--el-color-primary'); } catch (e) { }
                color = (color || '').trim();
            }
            if (!color) {
                try {
                    var theme = window.vite_public_panel_theme || {};
                    color = (theme.theme && theme.theme.color) || '';
                } catch (e) { }
            }
            return color || '#20a53a';
        }
        function readDark() {
            try {
                if (document.documentElement.classList.contains('dark')) return true;
                return panelDocument().documentElement.classList.contains('dark');
            } catch (e) { return false; }
        }
        function readRadius() {
            try {
                var theme = window.vite_public_panel_theme || {};
                var r = (theme.interface && theme.interface.rounded) || '';
                return RADIUS_MAP[r] ? r : 'medium';
            } catch (e) { return 'medium'; }
        }
        function apply() {
            var color = readColor();
            var dark = readDark();
            var radius = readRadius();
            if (state.applied && !state.applying && color === state.color && dark === state.dark && radius === state.radius) return;
            state.applying = true;
            state.color = color;
            state.dark = dark;
            state.radius = radius;
            state.applied = true;
            var c = parseColor(color);
            var root = document.documentElement;
            if (c) {
                var ratios = dark ? DARK_LIGHT_RATIOS : LIGHT_RATIOS;
                root.style.setProperty('--btp-primary', color);
                root.style.setProperty('--btp-primary-dark-2', hex(mix(c, dark ? WHITE : BLACK, dark ? 0.3 : 0.2)));
                Object.keys(ratios).forEach(function (k) {
                    root.style.setProperty('--btp-primary-light-' + k,
                        hex(mix(c, dark ? BLACK : WHITE, ratios[k])));
                });
                root.style.setProperty('--waf-chart-1', color);
                root.style.setProperty('--waf-chart-2', hex(mix(c, dark ? WHITE : BLACK, dark ? 0.35 : 0.25)));
                root.style.setProperty('--waf-chart-3', hex(mix(c, dark ? BLACK : WHITE, dark ? 0.2 : 0.45)));
                root.style.setProperty('--waf-chart-6', hex(mix(c, { r: 144, g: 147, b: 153 }, 0.45)));
            }
            var vals = RADIUS_MAP[radius] || RADIUS_MAP.medium;
            RADIUS_NAMES.forEach(function (n, i) { root.style.setProperty('--btp-radius-' + n, vals[i]); });
            root.style.setProperty('--btp-radius-circle', '100%');
            try { document.body.classList.toggle('waf-dark', dark); } catch (e) { }
            state.applying = false;
            try { window.dispatchEvent(new CustomEvent('btwaf-theme-change', { detail: { color: color, dark: dark } })); } catch (e) { }
        }
        window.addEventListener('message', function (ev) {
            var d = ev.data;
            if (d && d.type === 'theme-change') { apply(); }
        });
        if (window.MutationObserver) {
            new MutationObserver(function () { apply(); })
                .observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme'] });
            try {
                var ts = panelDocument().getElementById('bt-theme-colors');
                if (ts) new MutationObserver(function () { apply(); }).observe(ts, { childList: true, characterData: true, subtree: true });
            } catch (e) { }
        }
        setInterval(function () { apply(); }, 3000);
        apply();
        window.BTPanelTheme = {
            isDark: function () { return state.dark; },
            color: function () { return state.color; },
            refresh: function () { state.applied = false; apply(); return window.BTPanelTheme; }
        };
    })();

    var MODULES = [
        { key: 'sqli', name: 'SQL注入' },
        { key: 'xss', name: '跨站脚本' },
        { key: 'rce', name: '命令执行' },
        { key: 'lfi', name: '文件包含' },
        { key: 'php', name: 'PHP防护' },
        { key: 'java', name: 'Java防护' },
        { key: 'scan', name: '扫描器' },
        { key: 'crawler', name: '爬虫' },
        { key: 'sensitive', name: '敏感信息' },
        { key: 'upload', name: '上传防护' },
        { key: 'protocol', name: '协议校验' },
        { key: 'custom', name: '自定义' }
    ];
    var LIST_META = [
        { key: 'ip_black', label: 'IP 黑名单', hint: '单 IP 或 CIDR，一行一个' },
        { key: 'ip_white', label: 'IP 白名单', hint: '单 IP 或 CIDR，一行一个' },
        { key: 'url_black', label: 'URL 黑名单', hint: '^ 开头为前缀匹配，~ 开头为正则' },
        { key: 'url_white', label: 'URL 白名单', hint: '^ 开头为前缀匹配，~ 开头为正则' },
        { key: 'ua_black', label: 'UA 黑名单', hint: 'User-Agent 关键字/正则，一行一个' },
        { key: 'ua_white', label: 'UA 白名单', hint: 'User-Agent 关键字/正则，一行一个' },
        { key: 'param_white', label: '参数白名单', hint: '参数名，一行一个' }
    ];
    var SENSITIVITY_OPTIONS = [
        { value: 1, label: '1 · 宽松' },
        { value: 2, label: '2 · 标准' },
        { value: 3, label: '3 · 严格' }
    ];
    var SITE_SENSITIVITY_OPTIONS = [{ value: 0, label: '继承全局' }].concat(SENSITIVITY_OPTIONS);
    var TRI_OPTIONS = [
        { value: 'inherit', label: '继承全局' },
        { value: 'on', label: '开启' },
        { value: 'off', label: '关闭' }
    ];
    var SITE_TIER_OPTIONS = [
        { value: 0, label: '继承全局' },
        { value: 1, label: 'PL1（宽松）' },
        { value: 2, label: 'PL2' },
        { value: 3, label: 'PL3（严格）' }
    ];
    var GLOBAL_TIER_OPTIONS = [
        { value: 1, label: 'PL1（宽松）' },
        { value: 2, label: 'PL2' },
        { value: 3, label: 'PL3（严格）' }
    ];
    var LOG_ACTION_OPTIONS = [
        { value: '', label: '全部动作' },
        { value: 'block', label: '拦截' },
        { value: 'allow', label: '记录/放行' },
        { value: 'cc', label: 'CC 拦截' },
        { value: 'blacklist', label: '黑名单' }
    ];
    var RULE_SOURCE_OPTIONS = [
        { value: '', label: '全部来源' },
        { value: 'crs', label: 'OWASP CRS' },
        { value: 'ce', label: '自研 CE' },
        { value: 'custom', label: '自定义' }
    ];
    var RULE_MODULE_OPTIONS = [{ value: '', label: '全部模块' }].concat(MODULES.map(function (m) {
        return { value: m.key, label: m.name };
    }));
    var CUSTOM_FIELD_OPTIONS = [
        { value: 'uri', label: '请求 URI' },
        { value: 'query', label: '查询串' },
        { value: 'body', label: '请求体' },
        { value: 'header', label: '请求头' },
        { value: 'ua', label: 'User-Agent' },
        { value: 'ip', label: '客户端 IP' },
        { value: 'method', label: '请求方法' },
        { value: 'cookie', label: 'Cookie' }
    ];
    var CUSTOM_OPERATOR_OPTIONS = [
        { value: 'regexp', label: '正则匹配 (regexp)' },
        { value: 'contains', label: '包含 (contains)' },
        { value: 'eq', label: '等于 (eq)' },
        { value: 'prefix', label: '前缀 (prefix)' },
        { value: 'suffix', label: '后缀 (suffix)' },
        { value: 'in', label: '在集合中 (in)' },
        { value: 'not_in', label: '不在集合中 (not_in)' },
        { value: 'gt', label: '大于 (gt)' },
        { value: 'lt', label: '小于 (lt)' }
    ];
    var CUSTOM_ACTION_OPTIONS = [
        { value: 'block', label: '拦截' },
        { value: 'allow', label: '放行' },
        { value: 'log', label: '仅记录' }
    ];
    var CUSTOM_SCOPE_OPTIONS = [
        { value: 'global', label: '全局' },
        { value: 'site', label: '指定站点' }
    ];
    var ICON = {
        overview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z"/></svg>',
        logs: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 3h14a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm2 4v2h10V7H7Zm0 4v2h10v-2H7Zm0 4v2h7v-2H7Z"/></svg>',
        sites: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 9h-3.02a15.6 15.6 0 0 0-1.32-5.6A8.02 8.02 0 0 1 18.9 11ZM12 4c.9 1.3 1.7 3.5 1.9 7H10.1c.2-3.5 1-5.7 1.9-7ZM5.1 13h3.02c.15 2.05.6 3.98 1.32 5.6A8.02 8.02 0 0 1 5.1 13Zm3.02-2H5.1a8.02 8.02 0 0 1 4.34-5.6A15.6 15.6 0 0 0 8.12 11ZM12 20c-.9-1.3-1.7-3.5-1.9-7h3.8c-.2 3.5-1 5.7-1.9 7Zm2.56-1.4A15.6 15.6 0 0 0 15.88 13h3.02a8.02 8.02 0 0 1-4.34 5.6Z"/></svg>',
        config: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm8.4 4c0 .46-.04.9-.12 1.33l2.03 1.58-1.92 3.32-2.4-.96c-.7.58-1.5 1.04-2.37 1.35L15.3 22h-3.84l-.42-2.38a8.2 8.2 0 0 1-2.37-1.35l-2.4.96-1.92-3.32 2.03-1.58A8.6 8.6 0 0 1 6.26 12c0-.46.04-.9.12-1.33L4.35 9.09l1.92-3.32 2.4.96c.7-.58 1.5-1.04 2.37-1.35L11.46 3h3.84l.42 2.38c.87.31 1.67.77 2.37 1.35l2.4-.96 1.92 3.32-2.03 1.58c.08.43.12.87.12 1.33Z"/></svg>',
        rules: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 2h9l5 5v15H6V2Zm8 1.5V8h4.5L14 3.5ZM9 12h8v-2H9v2Zm0 4h8v-2H9v2Zm0 4h6v-2H9v2Z"/></svg>',
        blocks: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5.05 3.4 9.74 8 11 4.6-1.26 8-5.95 8-11V5l-8-3Zm0 4a6 6 0 0 1 6 6c0 .9-.2 1.76-.55 2.53L10.47 7.55A5.96 5.96 0 0 1 12 6Zm-5.45 3.47 6.98 6.98A5.96 5.96 0 0 1 12 18a6 6 0 0 1-5.45-8.53Z"/></svg>',
        diagnostics: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 13h4l2-5 4 10 2-5h6v2h-4.6l-3.4 8-4-10-1 3H3v-3Z"/></svg>'
    };
    var VIEWS = [
        { key: 'overview', label: '概览', group: '监控', icon: ICON.overview },
        { key: 'logs', label: '拦截记录', group: '监控', icon: ICON.logs },
        { key: 'blocks', label: '封锁记录', group: '监控', icon: ICON.blocks },
        { key: 'sites', label: '网站防护', group: '配置', icon: ICON.sites },
        { key: 'config', label: '全局配置', group: '配置', icon: ICON.config },
        { key: 'rules', label: '规则库', group: '配置', icon: ICON.rules },
        { key: 'diagnostics', label: '系统诊断', group: '系统', icon: ICON.diagnostics }
    ];

    /* Element Plus 中文本地化：
       插件使用 vendor 里的 Element Plus UMD 实例（与面板自身 EP 实例不同源），
       默认语言是英文，这里显式提供 zh-cn 文案（分页/表格/下拉/日期/弹框）。 */
    var WAF_ZH_LOCALE = {
        name: 'zh-cn',
        el: {
            colorpicker: { confirm: '确定', clear: '清空' },
            datepicker: {
                now: '此刻', today: '今天', cancel: '取消', clear: '清空', confirm: '确定',
                dateTablePrompt: '使用方向键与 Enter 键可选择日期。',
                monthTablePrompt: '使用方向键与 Enter 键可选择月份。',
                yearTablePrompt: '使用方向键与 Enter 键可选择年份。',
                selectedDate: '已选择日期',
                selectDate: '选择日期', selectTime: '选择时间',
                startDate: '开始日期', startTime: '开始时间', endDate: '结束日期', endTime: '结束时间',
                prevYear: '前一年', nextYear: '后一年', prevMonth: '上个月', nextMonth: '下个月',
                year: '年',
                month1: '1 月', month2: '2 月', month3: '3 月', month4: '4 月',
                month5: '5 月', month6: '6 月', month7: '7 月', month8: '8 月',
                month9: '9 月', month10: '10 月', month11: '11 月', month12: '12 月',
                week: '周',
                weeks: { sun: '日', mon: '一', tue: '二', wed: '三', thu: '四', fri: '五', sat: '六' },
                weeksFull: { sun: '星期日', mon: '星期一', tue: '星期二', wed: '星期三', thu: '星期四', fri: '星期五', sat: '星期六' },
                months: {
                    jan: '一月', feb: '二月', mar: '三月', apr: '四月', may: '五月', jun: '六月',
                    jul: '七月', aug: '八月', sep: '九月', oct: '十月', nov: '十一月', dec: '十二月'
                }
            },
            pagination: {
                goto: '前往', pagesize: '条/页', total: '共 {total} 条', pageClassifier: '页',
                page: '页', prev: '上一页', next: '下一页', currentPage: '第 {pager} 页',
                prevPages: '向前 {pager} 页', nextPages: '向后 {pager} 页'
            },
            table: {
                emptyText: '暂无数据', sumText: '合计', selectAll: '全选', selectNone: '清空选择',
                confirmFilter: '筛选', resetFilter: '重置', clearFilter: '清空筛选'
            },
            select: { loading: '加载中', noMatch: '无匹配数据', noData: '无数据', placeholder: '请选择' },
            messagebox: { title: '提示', confirm: '确定', cancel: '取消', error: '输入的数据不合法!', close: '关闭此对话框' },
            upload: { deleteTip: '按 delete 键可删除', delete: '删除', preview: '查看图片', continue: '继续上传' },
            empty: { description: '暂无数据' },
            dialog: { title: '提示' }
        }
    };
    try {
        if (window.BTP && BTP.config) {
            BTP.config.elementPlusOptions = Object.assign({}, BTP.config.elementPlusOptions || {}, {
                zIndex: 30000000,
                locale: WAF_ZH_LOCALE
            });
        }
    } catch (e) { }

    function pad2(n) { return n < 10 ? '0' + n : '' + n; }
    function num(v, def) {
        var n = Number(v);
        return isNaN(n) ? (def === undefined ? 0 : def) : n;
    }
    function clone(o) {
        if (o === undefined || o === null) return o;
        try { return JSON.parse(JSON.stringify(o)); } catch (e) { return o; }
    }
    function todayStr() {
        var d = new Date();
        return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
    }
    function fmtTime(ts) {
        if (!ts) return '-';
        var d = new Date(Number(ts) * 1000);
        if (isNaN(d.getTime())) return '-';
        return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
            ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    }
    function fmtDate(ts) {
        if (!ts) return '-';
        var d = new Date(Number(ts) * 1000);
        if (isNaN(d.getTime())) return '-';
        return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
    }
    function splitLines(text) {
        return String(text === undefined || text === null ? '' : text)
            .split(/\r?\n/).map(function (s) { return s.trim(); })
            .filter(function (s) { return s.length > 0; });
    }
    function joinLines(arr) {
        return (Array.isArray(arr) ? arr : []).join('\n');
    }
    function errText(e) {
        if (!e) return '请求失败';
        return e.message || e.msg || String(e);
    }
    function toTri(v) { return v === true ? 'on' : (v === false ? 'off' : 'inherit'); }
    function fromTri(v) { return v === 'on' ? true : (v === 'off' ? false : null); }
    function remainText(expire) {
        var left = num(expire) - Math.floor(Date.now() / 1000);
        if (!expire) return '-';
        if (left <= 0) return '已到期';
        if (left < 60) return left + ' 秒';
        if (left < 3600) return Math.floor(left / 60) + ' 分 ' + (left % 60) + ' 秒';
        return Math.floor(left / 3600) + ' 小时 ' + Math.floor((left % 3600) / 60) + ' 分';
    }
    function mergeDeep(base, actual) {
        var out = clone(base) || {};
        if (!actual || typeof actual !== 'object') return out;
        Object.keys(actual).forEach(function (k) {
            var av = actual[k];
            if (av === undefined) return;
            if (av && typeof av === 'object' && !Array.isArray(av) && out[k] && typeof out[k] === 'object' && !Array.isArray(out[k])) {
                out[k] = mergeDeep(out[k], av);
            } else {
                out[k] = av;
            }
        });
        return out;
    }

    function emptyStatus() {
        return {
            version: '', ready: false, enabled: true, observe: false, sensitivity: 2,
            nginx: {}, dirs: {},
            rules: {
                crs_version: '', total: 0, crs_total: 0, crs_enabled: 0, ce_total: 0,
                custom_total: 0, skipped_count: 0, skipped: [], generated_at: 0, index_ok: false
            },
            config_apply_at: 0, last_reload: 0, errors: [], perf: { requests: 0, hits: 0, avg_ms: 0 }
        };
    }
    function normalizeStatus(d) {
        var s = mergeDeep(emptyStatus(), d || {});
        if (!Array.isArray(s.rules.skipped)) s.rules.skipped = [];
        // 后端 rules 结构为 {crs_version,total,by_src:{crs,ce,custom},skipped,...}，
        // 这里兼容出 crs_total/ce_total/custom_total 供模板直接使用。
        var bySrc = s.rules.by_src;
        if (bySrc && typeof bySrc === 'object') {
            s.rules.crs_total = num(bySrc.crs);
            s.rules.ce_total = num(bySrc.ce);
            s.rules.custom_total = num(bySrc.custom);
        }
        if (!s.rules.total) {
            s.rules.total = num(s.rules.crs_total) + num(s.rules.ce_total) + num(s.rules.custom_total);
        }
        if (s.rules.crs_enabled === undefined || s.rules.crs_enabled === null) s.rules.crs_enabled = null;
        if (!Array.isArray(s.errors)) s.errors = [];
        if (!s.perf || typeof s.perf !== 'object') s.perf = { requests: 0, hits: 0, avg_ms: 0 };
        if (!s.nginx || typeof s.nginx !== 'object') s.nginx = {};
        if (!s.dirs || typeof s.dirs !== 'object') s.dirs = {};
        return s;
    }
    function emptyOverview() {
        return { date: '', stats: {}, trend: [], types: [], top_ips: [], top_urls: [], recent: [] };
    }
    function defaultModules() {
        var m = {};
        MODULES.forEach(function (x) { m[x.key] = { open: true, tier: 1 }; });
        return m;
    }
    function defaultSiteModules() {
        var m = {};
        MODULES.forEach(function (x) { m[x.key] = { open: true, tier: 0 }; });
        return m;
    }
    function emptyLists() {
        return {
            ip_black: [], ip_white: [], url_black: [], url_white: [],
            ua_black: [], ua_white: [], param_white: []
        };
    }
    function defaultGlobalConfig() {
        return {
            schema: 1, version: '0.1.0', enabled: true, observe: false, sensitivity: 2,
            block: { status: 403, use_custom: false, page: '' },
            scan: { body_limit: 1048576, arg_limit: 8192, header_limit: 8192, upload_scan_limit: 20971520, max_args: 200 },
            log: { enabled: true, retain_days: 30, rotate_size: 52428800, snippet: 512 },
            cc: { open: true, cycle: 60, limit: 120, block_time: 300, status: 444, url_cc: false, skip_static: true },
            attack_block: { open: true, cycle: 120, limit: 20, block_time: 1800 },
            modules: defaultModules(),
            lists: emptyLists(),
            rule_exclude: { crs: [], ce: [] },
            trusted_proxies: [],
            crawler: { allow: ['baiduspider', 'googlebot', 'bingbot', 'bytespider', 'sogou', '360spider', 'yandex', 'duckduckbot', 'applebot'], block_fake: true },
            fail_open: true, whitelist_first: true, update_time: 0
        };
    }
    function normalizeGlobalConfig(d) {
        return mergeDeep(defaultGlobalConfig(), d || {});
    }
    function defaultSiteConfig() {
        return {
            open: true, sensitivity: 0, observe: null,
            modules: defaultSiteModules(),
            cc: { open: null, cycle: 0, limit: 0, block_time: 0, status: 0, url_cc: null },
            attack_block: { open: null, cycle: 0, limit: 0, block_time: 0 },
            cdn: { open: false, headers: ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'], trusted: [] },
            lists: emptyLists(),
            rule_exclude: { crs: [], ce: [] },
            disable_php_path: [], disable_ext: [], upload_ext: [],
            custom_rules: [], update_time: 0
        };
    }
    function normalizeSiteConfig(d) {
        var cfg = mergeDeep(defaultSiteConfig(), d || {});
        MODULES.forEach(function (m) {
            if (!cfg.modules[m.key] || typeof cfg.modules[m.key] !== 'object') cfg.modules[m.key] = { open: true, tier: 0 };
            if (cfg.modules[m.key].tier === undefined) cfg.modules[m.key].tier = 0;
        });
        if (!Array.isArray(cfg.custom_rules)) cfg.custom_rules = [];
        return cfg;
    }
    function defaultCustomRule() {
        return {
            id: '', name: '', open: true, priority: 10, scope: 'global', sites: [],
            field: 'uri', header: '', operator: 'regexp', value: '',
            action: 'block', status: 403, score: 5, note: ''
        };
    }

    var TPL = {};
    TPL.top = `
<div class="waf-topbar">
    <div class="waf-brand">
        <span class="waf-brand-name">宝塔WAF社区版</span>
        <el-tag size="small" type="info" effect="plain">v{{ pluginVersion }}</el-tag>
    </div>
    <div class="waf-chips">
        <el-tag size="small" :type="status.observe ? 'primary' : enabledTagType" effect="dark">{{ status.observe ? '观察模式' : enabledText }}</el-tag>
    </div>
    <div class="waf-topbar-actions">
        <el-button size="small" :loading="refreshing" @click="manualRefresh">刷新</el-button>
        <el-button v-if="!status.ready" size="small" type="primary" plain @click="switchView('diagnostics')">去诊断</el-button>
    </div>
</div>
<div class="waf-layout">
    <nav class="waf-nav">
        <el-menu :default-active="view" class="waf-menu">
            <template v-for="g in viewGroups" :key="g.label">
                <div class="waf-nav-group">{{ g.label }}</div>
                <el-menu-item v-for="v in g.items" :key="v.key" :index="v.key" @click="switchView(v.key)">
                    <span class="waf-nav-icon" v-html="v.icon"></span>
                    <span class="waf-nav-label">{{ v.label }}</span>
                </el-menu-item>
            </template>
        </el-menu>
    </nav>
    <main class="waf-main">
        <div class="waf-status-bar" v-if="statusNotice" :class="'is-' + statusNotice.level">
            <span class="waf-status-dot"></span>
            <div class="waf-status-copy">
                <b>{{ statusNotice.title }}</b>
                <span>{{ statusNotice.desc }}</span>
            </div>
            <el-button size="small" :type="statusNotice.level === 'error' ? 'danger' : 'primary'" plain
                :loading="quickSaving || refreshing" @click="runStatusAction">{{ statusNotice.label }}</el-button>
        </div>
`;

    TPL.overview = `
<section class="waf-view" v-show="view === 'overview'">
    <div class="waf-view-head">
        <div class="waf-view-title">概览</div>
        <div class="waf-view-tools">
            <el-date-picker v-model="ovDate" type="date" value-format="YYYY-MM-DD" size="small" :clearable="false" popper-class="waf-popper" style="width:150px" @change="loadOverview"></el-date-picker>
        </div>
    </div>
    <div class="waf-error" v-if="errors.overview">
        <span>{{ errors.overview }}</span>
        <el-button link type="primary" size="small" @click="loadOverview">重试</el-button>
    </div>

    <div class="waf-cards waf-cards-5">
        <div class="waf-card">
            <div class="waf-card-label">今日拦截</div>
            <div class="waf-card-val">{{ num(ov.stats.blocks) }}</div>
        </div>
        <div class="waf-card">
            <div class="waf-card-label">CC 拦截</div>
            <div class="waf-card-val">{{ num(ov.stats.cc_blocks) }}</div>
        </div>
        <div class="waf-card">
            <div class="waf-card-label">攻击 IP</div>
            <div class="waf-card-val">{{ num(ov.stats.attack_ips) }}</div>
        </div>
        <div class="waf-card">
            <div class="waf-card-label">站点</div>
            <div class="waf-card-val">{{ num(ov.stats.sites_open) }}<span class="waf-card-unit">/ {{ num(ov.stats.sites_total) }}</span></div>
        </div>
        <div class="waf-card waf-card-action" @click="goUnprotected">
            <div class="waf-card-label">未防护站点</div>
            <div class="waf-card-val" :class="{ 'waf-danger-text': unprotectedCount > 0 }">{{ unprotectedCount }}</div>
        </div>
    </div>

    <div class="waf-grid-2">
        <div class="waf-panel">
            <div class="waf-panel-head">近 7 日攻击趋势</div>
            <div id="waf-trend-chart" class="waf-chart"></div>
        </div>
        <div class="waf-panel">
            <div class="waf-panel-head">攻击类型分布</div>
            <div id="waf-type-chart" class="waf-chart"></div>
        </div>
    </div>

    <div class="waf-grid-3">
        <div class="waf-panel">
            <div class="waf-panel-head">Top 被攻击站点</div>
            <el-table :data="topSites" size="small" max-height="240" empty-text="暂无数据">
                <el-table-column label="站点" prop="site" min-width="130" show-overflow-tooltip></el-table-column>
                <el-table-column label="次数" prop="count" width="70" align="center"></el-table-column>
            </el-table>
        </div>
        <div class="waf-panel">
            <div class="waf-panel-head">Top 攻击 IP</div>
            <el-table :data="ov.top_ips" size="small" max-height="240" empty-text="暂无数据">
                <el-table-column label="IP" min-width="130">
                    <template #default="s"><span class="waf-mono">{{ s.row.ip }}</span></template>
                </el-table-column>
                <el-table-column label="归属" min-width="120">
                    <template #default="s"><span class="waf-sub">{{ s.row.area || '-' }}</span></template>
                </el-table-column>
                <el-table-column label="次数" prop="count" width="80" align="center"></el-table-column>
            </el-table>
        </div>
        <div class="waf-panel">
            <div class="waf-panel-head">Top 被攻击 URL</div>
            <el-table :data="ov.top_urls" size="small" max-height="240" empty-text="暂无数据">
                <el-table-column label="URI" min-width="220">
                    <template #default="s"><span class="waf-mono waf-ellipsis">{{ s.row.uri }}</span></template>
                </el-table-column>
                <el-table-column label="次数" prop="count" width="80" align="center"></el-table-column>
            </el-table>
        </div>
    </div>

    <div class="waf-panel">
        <div class="waf-panel-head">最近命中</div>
        <el-table :data="ov.recent" size="small" border empty-text="当日暂无攻击记录" @row-click="openRecent" class="waf-clickable-table">
            <el-table-column label="时间" width="150">
                <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
            </el-table-column>
            <el-table-column label="站点" prop="site" min-width="130" show-overflow-tooltip></el-table-column>
            <el-table-column label="IP" min-width="120">
                <template #default="s"><span class="waf-mono">{{ s.row.ip }}</span></template>
            </el-table-column>
            <el-table-column label="请求" min-width="220">
                <template #default="s"><span class="waf-mono waf-ellipsis">{{ (s.row.method || '') + ' ' + (s.row.uri || '') }}</span></template>
            </el-table-column>
            <el-table-column label="动作" width="84">
                <template #default="s"><el-tag size="small" :type="actionTag(s.row.action)">{{ actionLabel(s.row.action) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="命中规则" min-width="170">
                <template #default="s"><span class="waf-sub waf-ellipsis">{{ hitsText(s.row.hits) }}</span></template>
            </el-table-column>
        </el-table>
    </div>
</section>
`;

    TPL.logs = `
<section class="waf-view" v-show="view === 'logs'">
    <div class="waf-view-head">
        <div class="waf-view-title">拦截记录</div>
        <div class="waf-view-tools">
            <el-button size="small" :loading="logLoading" @click="loadLogs">刷新</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.logs">
        <span>{{ errors.logs }}</span>
        <el-button link type="primary" size="small" @click="loadLogs">重试</el-button>
    </div>
    <div class="waf-filters">
        <el-date-picker v-model="logFilter.date" type="date" value-format="YYYY-MM-DD" size="small" :clearable="false" popper-class="waf-popper" style="width:150px"></el-date-picker>
        <el-input v-model="logFilter.site" placeholder="站点" size="small" clearable style="width:140px" @keyup.enter="logSearch"></el-input>
        <el-input v-model="logFilter.ip" placeholder="IP" size="small" clearable style="width:130px" @keyup.enter="logSearch"></el-input>
        <el-input v-model="logFilter.keyword" placeholder="URI / 参数关键字" size="small" clearable style="width:180px" @keyup.enter="logSearch"></el-input>
        <el-select v-model="logFilter.type" placeholder="攻击类型" size="small" clearable style="width:130px">
            <el-option v-for="t in logTypes" :key="t.module" :label="t.name || t.module" :value="t.module"></el-option>
        </el-select>
        <el-select v-model="logFilter.action" placeholder="全部动作" clearable size="small" style="width:124px">
            <el-option v-for="a in logActionOptions" :key="a.value" :label="a.label" :value="a.value"></el-option>
        </el-select>
        <el-button size="small" type="primary" @click="logSearch">查询</el-button>
        <el-button size="small" @click="logReset">重置</el-button>
    </div>
    <div class="waf-filter-chips" v-if="logActiveFilters.length">
        <el-tag v-for="f in logActiveFilters" :key="f.key" size="small" closable @close="removeLogFilter(f.key)">{{ f.label }}</el-tag>
        <el-button link type="primary" size="small" @click="logReset">清空筛选</el-button>
    </div>
    <el-alert v-if="logLimited" type="info" :closable="false" show-icon class="waf-tiny-alert" title="结果基于最近日志窗口，更早的记录可能未包含"></el-alert>
    <el-table :data="logList" size="small" border stripe v-loading="logLoading" empty-text="暂无拦截记录" @row-click="openLogDetail" class="waf-clickable-table">
        <el-table-column label="时间" width="150">
            <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
        </el-table-column>
        <el-table-column label="站点 / IP" min-width="168">
            <template #default="s">
                <div class="waf-cell-stack">
                    <span class="waf-ellipsis">{{ s.row.site || '-' }}</span>
                    <span class="waf-sub waf-ellipsis">{{ s.row.ip }}<template v-if="s.row.area"> · {{ s.row.area }}</template></span>
                </div>
            </template>
        </el-table-column>
        <el-table-column label="请求" min-width="190">
            <template #default="s">
                <div class="waf-cell-stack">
                    <span class="waf-mono waf-ellipsis">{{ (s.row.method || '') + ' ' + (s.row.uri || '') }}</span>
                    <span class="waf-sub waf-ellipsis">{{ s.row.query || '-' }}</span>
                </div>
            </template>
        </el-table-column>
        <el-table-column label="命中规则" min-width="148">
            <template #default="s">
                <el-tag v-if="s.row.hits && s.row.hits.length" size="small" type="danger" effect="plain">{{ s.row.hits.length }} 条</el-tag>
                <span v-else class="waf-sub">-</span>
                <div class="waf-sub waf-ellipsis">{{ hitsText(s.row.hits) }}</div>
            </template>
        </el-table-column>
        <el-table-column label="动作" width="88">
            <template #default="s"><el-tag size="small" :type="actionTag(s.row.action)">{{ actionLabel(s.row.action) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="操作" width="190" fixed="right">
            <template #default="s">
                <div class="waf-row-actions">
                    <el-button link type="primary" size="small" @click.stop="openLogDetail(s.row)">详情</el-button>
                    <el-dropdown trigger="click" @command="onLogAction($event, s.row)">
                        <el-button link size="small" @click.stop>更多</el-button>
                        <template #dropdown>
                            <el-dropdown-menu>
                                <el-dropdown-item command="black">加入 IP 黑名单</el-dropdown-item>
                                <el-dropdown-item command="white">加入 IP 白名单</el-dropdown-item>
                                <el-dropdown-item command="unban" divided>解封该 IP</el-dropdown-item>
                            </el-dropdown-menu>
                        </template>
                    </el-dropdown>
                </div>
            </template>
        </el-table-column>
    </el-table>
    <div class="waf-pager">
        <el-pagination background small layout="total, sizes, prev, pager, next" :total="logTotal" :page-size="logRows" :current-page="logPage" :page-sizes="[10, 20, 50, 100]" @current-change="onLogPageChange" @size-change="onLogSizeChange"></el-pagination>
    </div>
</section>
`;

    TPL.sites = `
<section class="waf-view" v-show="view === 'sites'">
    <div class="waf-view-head">
        <div class="waf-view-title">网站防护</div>
        <div class="waf-view-tools">
            <el-input v-model="siteKeyword" placeholder="站点 / 域名" size="small" clearable style="width:200px" @keyup.enter="siteSearch"></el-input>
            <el-select v-model="siteStatus" size="small" style="width:120px" @change="siteSearch">
                <el-option label="全部状态" value=""></el-option>
                <el-option label="已防护" value="open"></el-option>
                <el-option label="未防护" value="unprotected"></el-option>
            </el-select>
            <el-button size="small" type="primary" @click="siteSearch">搜索</el-button>
            <el-button size="small" @click="loadSites">刷新</el-button>
            <el-button size="small" type="primary" plain @click="syncSites">同步面板站点</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.sites">
        <span>{{ errors.sites }}</span>
        <el-button link type="primary" size="small" @click="loadSites">重试</el-button>
    </div>
    <div class="waf-filters waf-site-toolbar" v-if="siteSelection.length || unprotectedCount > 0">
        <template v-if="siteSelection.length">
            <span class="waf-selection-count">已选 {{ siteSelection.length }} 个站点</span>
            <el-button size="small" type="success" plain @click="batchSetSites(true)">批量开启</el-button>
            <el-button size="small" type="warning" plain @click="batchSetSites(false)">批量关闭</el-button>
            <el-button size="small" @click="siteSelection = []">取消选择</el-button>
        </template>
        <el-button v-else size="small" type="success" @click="enableAllUnprotected">一键开启未防护（{{ unprotectedCount }}）</el-button>
    </div>
    <el-table :data="siteList" size="small" border stripe v-loading="siteLoading" @selection-change="onSiteSelection" @row-click="openSiteDialog" class="waf-clickable-table">
        <el-table-column type="selection" width="42"></el-table-column>
        <el-table-column label="站点" prop="site_name" min-width="160" show-overflow-tooltip></el-table-column>
        <el-table-column label="域名" min-width="180">
            <template #default="s"><span class="waf-sub">{{ (s.row.domains || []).join(', ') || '-' }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="92">
            <template #default="s">
                <el-tag size="small" :type="s.row.open ? 'success' : 'info'">{{ s.row.open ? '已防护' : '未防护' }}</el-tag>
            </template>
        </el-table-column>
        <el-table-column label="防护" width="80">
            <template #default="s"><el-switch :model-value="!!s.row.open" size="small" @click.stop @update:model-value="toggleSite(s.row, $event)"></el-switch></template>
        </el-table-column>
        <el-table-column label="灵敏度" width="90">
            <template #default="s">{{ num(s.row.sensitivity) ? sensitivityLabel(s.row.sensitivity) : '继承' }}</template>
        </el-table-column>
        <el-table-column label="今日拦截" width="96" align="center">
            <template #default="s">
                <el-button link type="primary" size="small" :disabled="!s.row.today_blocks" @click.stop="viewSiteLogs(s.row)">{{ num(s.row.today_blocks) }}</el-button>
            </template>
        </el-table-column>
        <el-table-column label="最近命中" width="150">
            <template #default="s"><span class="waf-mono waf-sub">{{ s.row.last_hit ? fmtTime(s.row.last_hit) : '-' }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
            <template #default="s"><el-button size="small" type="primary" plain @click.stop="openSiteDialog(s.row)">配置</el-button></template>
        </el-table-column>
        <template #empty>
            <div class="waf-empty">
                <div class="waf-empty-title">暂无站点</div>
                <div class="waf-empty-desc">从面板同步站点后即可按站点配置防护。</div>
                <el-button size="small" type="primary" @click="syncSites">同步面板站点</el-button>
            </div>
        </template>
    </el-table>
    <div class="waf-pager">
        <el-pagination background small layout="total, sizes, prev, pager, next" :total="siteTotal" :page-size="siteRows" :current-page="sitePage" :page-sizes="[10, 20, 50, 100]" @current-change="onSitePageChange" @size-change="onSiteSizeChange"></el-pagination>
    </div>
</section>
`;

    TPL.config = `
<section class="waf-view" v-show="view === 'config'">
    <div class="waf-view-head">
        <div class="waf-view-title">全局配置</div>
        <div class="waf-view-tools">
            <el-input v-model="cfgSearch" placeholder="搜索设置项" size="small" clearable style="width:200px" @input="filterConfigFields"></el-input>
            <el-button size="small" :loading="cfgLoading" @click="loadConfig">重新读取</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.config">
        <span>{{ errors.config }}</span>
        <el-button link type="primary" size="small" @click="loadConfig">重试</el-button>
    </div>
    <div class="waf-panel" v-loading="cfgLoading">
        <el-tabs v-model="cfgTab" tab-position="left" class="waf-tabs waf-config-tabs">
            <el-tab-pane label="基础" name="basic">
                <el-form label-width="150px" size="small" class="waf-form">
                    <el-form-item label="总开关"><el-switch v-model="cfg.enabled"></el-switch></el-form-item>
                    <el-form-item label="观察模式"><el-switch v-model="cfg.observe"></el-switch></el-form-item>
                    <el-form-item label="灵敏度">
                        <el-select v-model="cfg.sensitivity" style="width:180px">
                            <el-option v-for="o in sensitivityOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="拦截状态码">
                        <el-input-number v-model="cfg.block.status" :min="400" :max="599" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="自定义拦截页"><el-switch v-model="cfg.block.use_custom"></el-switch></el-form-item>
                    <el-form-item label="引擎异常时放行"><el-switch v-model="cfg.fail_open"></el-switch></el-form-item>
                    <el-form-item label="白名单优先"><el-switch v-model="cfg.whitelist_first"></el-switch></el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="扫描限制" name="scan">
                <el-form label-width="170px" size="small" class="waf-form">
                    <el-form-item label="请求体上限（字节）">
                        <el-input-number v-model="cfg.scan.body_limit" :min="0" :step="1024" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="参数总长（字节）">
                        <el-input-number v-model="cfg.scan.arg_limit" :min="0" :step="1024" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="请求头上限（字节）">
                        <el-input-number v-model="cfg.scan.header_limit" :min="0" :step="1024" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="上传扫描上限（字节）">
                        <el-input-number v-model="cfg.scan.upload_scan_limit" :min="0" :step="1048576" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="参数数量上限">
                        <el-input-number v-model="cfg.scan.max_args" :min="0" :step="10" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="日志" name="log">
                <el-form label-width="170px" size="small" class="waf-form">
                    <el-form-item label="记录攻击日志"><el-switch v-model="cfg.log.enabled"></el-switch></el-form-item>
                    <el-form-item label="保留天数（天）">
                        <el-input-number v-model="cfg.log.retain_days" :min="1" :max="3650" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="轮转大小（字节）">
                        <el-input-number v-model="cfg.log.rotate_size" :min="1048576" :step="1048576" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="截断长度（字节）">
                        <el-input-number v-model="cfg.log.snippet" :min="64" :max="4096" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="CC / 攻击拦截" name="cc">
                <el-form label-width="170px" size="small" class="waf-form">
                    <el-form-item label="CC 防护开关"><el-switch v-model="cfg.cc.open"></el-switch></el-form-item>
                    <el-form-item label="CC 周期（秒）">
                        <el-input-number v-model="cfg.cc.cycle" :min="1" :max="3600" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="CC 上限（次）">
                        <el-input-number v-model="cfg.cc.limit" :min="1" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="CC 封禁（秒）">
                        <el-input-number v-model="cfg.cc.block_time" :min="1" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="CC 状态码（0=继承）">
                        <el-input-number v-model="cfg.cc.status" :min="400" :max="599" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="URL 级 CC"><el-switch v-model="cfg.cc.url_cc"></el-switch></el-form-item>
                    <el-form-item label="跳过静态资源"><el-switch v-model="cfg.cc.skip_static"></el-switch></el-form-item>
                    <el-form-item label="攻击次数拦截"><el-switch v-model="cfg.attack_block.open"></el-switch></el-form-item>
                    <el-form-item label="攻击周期（秒）">
                        <el-input-number v-model="cfg.attack_block.cycle" :min="1" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="攻击上限（次）">
                        <el-input-number v-model="cfg.attack_block.limit" :min="1" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="攻击封禁（秒）">
                        <el-input-number v-model="cfg.attack_block.block_time" :min="1" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="模块" name="modules">
                <el-table :data="modules" size="small" border>
                    <el-table-column label="模块" width="150">
                        <template #default="s">{{ s.row.name }}</template>
                    </el-table-column>
                    <el-table-column label="启用" width="90">
                        <template #default="s"><el-switch v-model="cfg.modules[s.row.key].open"></el-switch></template>
                    </el-table-column>
                    <el-table-column label="Tier（PL）" width="180">
                        <template #default="s">
                            <el-select v-model="cfg.modules[s.row.key].tier" size="small" style="width:150px">
                                <el-option v-for="t in globalTierOptions" :key="t.value" :label="t.label" :value="t.value"></el-option>
                            </el-select>
                        </template>
                    </el-table-column>
                </el-table>
                <div class="waf-pane-actions">
                    <el-button type="primary" size="small" @click="saveGlobalModules">保存模块配置</el-button>
                </div>
            </el-tab-pane>

            <el-tab-pane label="黑白名单" name="lists">
                <div class="waf-list-editor">
                    <el-select v-model="globalListType" size="small" style="width:180px">
                        <el-option v-for="m in listMeta" :key="m.key" :label="m.label" :value="m.key"></el-option>
                    </el-select>
                    
                </div>
                <el-input v-model="globalListText[globalListType]" type="textarea" :rows="10" class="waf-mono" placeholder="一行一条"></el-input>
                <div class="waf-pane-actions">
                    <el-button type="primary" size="small" @click="saveGlobalList(globalListType)">保存该列表</el-button>
                </div>
            </el-tab-pane>

            <el-tab-pane label="拦截页面" name="blockpage">
                <el-input v-model="blockPageText" type="textarea" :rows="12" class="waf-mono" placeholder="自定义拦截页面 HTML（≤ 64KB，后端会过滤 script / on* / javascript:）"></el-input>
                <div class="waf-pane-actions">
                    <el-button size="small" @click="previewBlockPage">预览</el-button>
                    <el-button type="primary" size="small" @click="saveBlockPage">保存拦截页面</el-button>
                </div>
            </el-tab-pane>

            <el-tab-pane label="规则排除" name="exclude">
                <el-alert type="info" :closable="false" show-icon class="waf-tiny-alert" title="一行一个规则 ID（如 crs-942100 / ce-sqli-001），被排除的规则不参与匹配"></el-alert>
                <div class="waf-grid-2">
                    <div>
                        <div class="waf-panel-head">OWASP CRS 排除</div>
                        <el-input v-model="excludeText.crs" type="textarea" :rows="8" class="waf-mono" placeholder="crs-942100"></el-input>
                    </div>
                    <div>
                        <div class="waf-panel-head">自研 CE 排除</div>
                        <el-input v-model="excludeText.ce" type="textarea" :rows="8" class="waf-mono" placeholder="ce-sqli-001"></el-input>
                    </div>
                </div>
                <div class="waf-pane-actions">
                    <el-button type="primary" size="small" @click="saveExcludes">保存规则排除</el-button>
                </div>
            </el-tab-pane>

            <el-tab-pane label="爬虫 / 代理" name="other">
                <el-form label-width="150px" size="small" class="waf-form">
                    <el-form-item label="拦截伪装爬虫"><el-switch v-model="cfg.crawler.block_fake"></el-switch></el-form-item>
                    <el-form-item label="放行爬虫 UA">
                        <el-input v-model="crawlerText" type="textarea" :rows="6" class="waf-mono" placeholder="一行一个 UA 关键字"></el-input>
                    </el-form-item>
                    <el-form-item label="可信代理 IP">
                        <el-input v-model="trustedText" type="textarea" :rows="4" class="waf-mono" placeholder="一行一个 IP / CIDR，用于获取真实客户端 IP"></el-input>
                    </el-form-item>
                </el-form>
            </el-tab-pane>
        </el-tabs>
        <div class="waf-config-savebar">
            <span class="waf-save-state" :class="{ dirty: cfgDirty }">{{ cfgDirty ? '有未保存修改' : '配置已保存' }}</span>
            <el-button size="small" :disabled="!cfgDirty" @click="resetGlobalConfig">撤销修改</el-button>
            <el-button size="small" type="primary" :disabled="!cfgDirty" :loading="cfgSaving" @click="saveGlobalConfig">保存修改</el-button>
        </div>
        <div class="waf-empty" v-if="cfgSearchEmpty">
            <div class="waf-empty-title">没有找到设置项</div>
            <div class="waf-empty-desc">试试更短的关键词，或清除搜索。</div>
            <el-button size="small" @click="cfgSearch=''; filterConfigFields()">清除搜索</el-button>
        </div>
    </div>
</section>
`;

    TPL.rules = `
<section class="waf-view" v-show="view === 'rules'">
    <div class="waf-view-head">
        <div class="waf-view-title">规则库</div>
        <div class="waf-view-tools">
            <el-button size="small" @click="loadRules">刷新</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.rules">
        <span>{{ errors.rules }}</span>
        <el-button link type="primary" size="small" @click="loadRules">重试</el-button>
    </div>
    <el-tabs v-model="ruleTab" class="waf-tabs">
        <el-tab-pane label="内置规则" name="builtin">
            <div class="waf-filters">
                <el-select v-model="ruleFilter.source" placeholder="全部来源" size="small" style="width:150px">
                    <el-option v-for="o in ruleSourceOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                </el-select>
                <el-select v-model="ruleFilter.module" placeholder="全部模块" size="small" style="width:140px">
                    <el-option v-for="o in ruleModuleOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                </el-select>
                <el-select v-model="ruleFilter.status" size="small" style="width:130px">
                    <el-option label="全部状态" value=""></el-option>
                    <el-option label="已启用" value="enabled"></el-option>
                    <el-option label="未启用" value="disabled"></el-option>
                </el-select>
                <el-input v-model="ruleFilter.keyword" placeholder="规则 ID / 名称 / 标签" size="small" clearable style="width:220px" @keyup.enter="ruleSearch"></el-input>
                <el-button size="small" type="primary" @click="ruleSearch">查询</el-button>
                <el-button size="small" @click="ruleReset">重置</el-button>
            </div>
            <el-table :data="ruleList" size="small" border stripe v-loading="ruleLoading" empty-text="暂无规则数据">
                <el-table-column label="规则 ID" width="150">
                    <template #default="s"><span class="waf-mono">{{ s.row.id }}</span></template>
                </el-table-column>
                <el-table-column label="模块" width="100">
                    <template #default="s">{{ moduleName(s.row.module) }}</template>
                </el-table-column>
                <el-table-column label="名称" prop="name" min-width="240" show-overflow-tooltip></el-table-column>
                <el-table-column label="Tier" width="70">
                    <template #default="s">{{ tierLabel(s.row.tier) }}</template>
                </el-table-column>
                <el-table-column label="分值" prop="score" width="52" align="center"></el-table-column>
                <el-table-column label="来源" width="90">
                    <template #default="s"><el-tag size="small" effect="plain" :type="s.row.src === 'crs' ? 'primary' : 'success'">{{ sourceLabel(s.row.src) }}</el-tag></template>
                </el-table-column>
                <el-table-column label="命中" width="80" align="center">
                    <template #default="s">{{ s.row.hits === undefined || s.row.hits === null ? '-' : s.row.hits }}</template>
                </el-table-column>
                <el-table-column label="启用" width="80">
                    <template #default="s">
                        <el-switch :model-value="isRuleEnabled(s.row)" size="small" @update:model-value="toggleRule(s.row, $event)"></el-switch>
                    </template>
                </el-table-column>
            </el-table>
            <div class="waf-pager">
                <el-pagination background small layout="total, sizes, prev, pager, next" :total="ruleTotal" :page-size="ruleRows" :current-page="rulePage" :page-sizes="[10, 20, 50, 100]" @current-change="onRulePageChange" @size-change="onRuleSizeChange"></el-pagination>
            </div>

        </el-tab-pane>

        <el-tab-pane label="自定义规则" name="custom">
            <div class="waf-filters">
                <el-input v-model="customKeyword" placeholder="规则名称 / ID" size="small" clearable style="width:220px" @keyup.enter="customPage = 1; loadCustomRules()"></el-input>
                <el-button size="small" type="primary" @click="customPage = 1; loadCustomRules()">查询</el-button>
                <el-button size="small" @click="loadCustomRules">刷新</el-button>
                <el-button size="small" type="success" @click="openCustomDialog(null)">新增自定义规则</el-button>
            </div>
            <el-table :data="customRules" size="small" border stripe v-loading="customLoading" empty-text="暂无自定义规则">
                <el-table-column label="名称" min-width="160">
                    <template #default="s">
                        <div class="waf-cell-stack">
                            <span>{{ s.row.name }}</span>
                            <span class="waf-mono waf-sub">{{ s.row.id }}</span>
                        </div>
                    </template>
                </el-table-column>
                <el-table-column label="生效范围" min-width="150">
                    <template #default="s"><span class="waf-sub">{{ customRuleTarget(s.row) }}</span></template>
                </el-table-column>
                <el-table-column label="匹配条件" min-width="260" show-overflow-tooltip>
                    <template #default="s"><span class="waf-mono">{{ customRuleExpr(s.row) }}</span></template>
                </el-table-column>
                <el-table-column label="动作" width="84">
                    <template #default="s"><el-tag size="small" :type="actionTag(s.row.action)">{{ actionLabel(s.row.action) }}</el-tag></template>
                </el-table-column>
                <el-table-column label="优先级" prop="priority" width="76" align="center"></el-table-column>
                <el-table-column label="命中" width="76" align="center">
                    <template #default="s">{{ s.row.hits === undefined || s.row.hits === null ? '-' : s.row.hits }}</template>
                </el-table-column>
                <el-table-column label="启用" width="76">
                    <template #default="s">
                        <el-tag size="small" :type="s.row.open ? 'success' : 'info'">{{ s.row.open ? '启用' : '停用' }}</el-tag>
                    </template>
                </el-table-column>
                <el-table-column label="操作" width="120" fixed="right">
                    <template #default="s">
                        <el-button link type="primary" size="small" @click="openCustomDialog(s.row)">编辑</el-button>
                        <el-button link type="danger" size="small" @click="deleteCustomRule(s.row)">删除</el-button>
                    </template>
                </el-table-column>
            </el-table>
            <div class="waf-pager">
                <el-pagination background small layout="total, sizes, prev, pager, next" :total="customTotal" :page-size="customRows" :current-page="customPage" :page-sizes="[10, 20, 50, 100]" @current-change="onCustomPageChange" @size-change="onCustomSizeChange"></el-pagination>
            </div>
        </el-tab-pane>
    </el-tabs>
</section>
`;

    TPL.blocks = `
<section class="waf-view" v-show="view === 'blocks'">
    <div class="waf-view-head">
        <div class="waf-view-title">封锁记录</div>
        <div class="waf-view-tools">
            <el-input v-model="blockSite" placeholder="站点" size="small" clearable style="width:160px" @keyup.enter="loadBlocks"></el-input>
            <el-button size="small" :loading="blockLoading" @click="loadBlocks">刷新</el-button>
            <el-button size="small" type="warning" plain @click="unbanAll">全部解封</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.blocks">
        <span>{{ errors.blocks }}</span>
        <el-button link type="primary" size="small" @click="loadBlocks">重试</el-button>
    </div>
    <div class="waf-filters">
        <el-radio-group v-model="blockTab" size="small" @change="switchBlockTab">
            <el-radio-button value="current">当前封锁</el-radio-button>
            <el-radio-button value="history">历史记录</el-radio-button>
            <el-radio-button value="all">全部</el-radio-button>
        </el-radio-group>
        
    </div>
    <el-table v-if="blockTab !== 'history'" :data="blockList" size="small" border stripe v-loading="blockLoading" empty-text="当前没有临时封锁的 IP">
        <el-table-column label="IP" width="140">
            <template #default="s"><span class="waf-mono">{{ s.row.ip }}</span></template>
        </el-table-column>
        <el-table-column label="站点" prop="site" min-width="150" show-overflow-tooltip></el-table-column>
        <el-table-column label="原因" width="110">
            <template #default="s"><el-tag size="small" :type="reasonTag(s.row.reason)">{{ reasonLabel(s.row.reason) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="封锁时间" width="150">
            <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
        </el-table-column>
        <el-table-column label="剩余" width="130">
            <template #default="s">{{ remain(s.row.expire) }}</template>
        </el-table-column>
        <el-table-column label="封锁时长（0=继承）" width="100">
            <template #default="s">{{ num(s.row.block_time) }} 秒</template>
        </el-table-column>
        <el-table-column label="归属" min-width="120">
            <template #default="s"><span class="waf-sub">{{ s.row.area || '-' }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="90">
            <template #default="s"><el-tag size="small" :type="stateTag(s.row.state || 'blocked')">{{ stateLabel(s.row.state || 'blocked') }}</el-tag></template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
            <template #default="s"><el-button size="small" type="danger" plain @click="unbanBlock(s.row)">解封</el-button></template>
        </el-table-column>
    </el-table>
    <el-table v-else :data="blockList" size="small" border stripe v-loading="blockLoading" empty-text="暂无历史封锁记录">
        <el-table-column label="IP" width="140">
            <template #default="s"><span class="waf-mono">{{ s.row.ip }}</span></template>
        </el-table-column>
        <el-table-column label="站点" prop="site" min-width="150" show-overflow-tooltip></el-table-column>
        <el-table-column label="原因" width="110">
            <template #default="s"><el-tag size="small" :type="reasonTag(s.row.reason)">{{ reasonLabel(s.row.reason) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="封锁时间" width="150">
            <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
        </el-table-column>
        <el-table-column label="到期时间" width="150">
            <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.expire) }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="100">
            <template #default="s"><el-tag size="small" :type="stateTag(s.row.state)">{{ stateLabel(s.row.state) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="解封时间" width="150">
            <template #default="s"><span class="waf-mono">{{ s.row.unban_time ? fmtTime(s.row.unban_time) : '-' }}</span></template>
        </el-table-column>
        <el-table-column label="归属" min-width="120">
            <template #default="s"><span class="waf-sub">{{ s.row.area || '-' }}</span></template>
        </el-table-column>
    </el-table>
    <div class="waf-pager">
        <el-pagination background small layout="total, sizes, prev, pager, next" :total="blockTotal" :page-size="blockRows" :current-page="blockPage" :page-sizes="[10, 20, 50, 100]" @current-change="onBlockPageChange" @size-change="onBlockSizeChange"></el-pagination>
    </div>
</section>
`;

    TPL.diagnostics = `
<section class="waf-view" v-show="view === 'diagnostics'">
    <div class="waf-view-head">
        <div class="waf-view-title">系统诊断</div>
        <div class="waf-view-tools">
            <el-button size="small" :loading="envLoading" @click="loadEnv">重新检测</el-button>
            <el-button size="small" type="primary" :loading="repairLoading" :disabled="!envRepairable" @click="repairEnv">一键修复</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.diagnostics">
        <span>{{ errors.diagnostics }}</span>
        <el-button link type="primary" size="small" @click="loadDiagnostics">重试</el-button>
    </div>

    <el-alert v-if="envAllOk" class="waf-env-banner" type="success" :closable="false" show-icon
        title="全部检测项正常，无需修复"></el-alert>
    <el-alert v-else-if="envNeedsRepair" class="waf-env-banner" type="warning" :closable="false" show-icon
        title="存在需处理的项：可修复项请点“一键修复”，其余需按详情人工处理"></el-alert>

    <div class="waf-panel">
        
        <el-table :data="envItems" size="small" border v-loading="envLoading" empty-text="暂无检测结果">
            <el-table-column label="检测项" min-width="200">
                <template #default="s"><span class="waf-mono">{{ s.row.name }}</span></template>
            </el-table-column>
            <el-table-column label="结果" width="90">
                <template #default="s"><el-tag size="small" :type="okTag(s.row.ok)">{{ okText(s.row.ok) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="详情" min-width="360">
                <template #default="s"><span class="waf-sub">{{ s.row.detail || '-' }}</span></template>
            </el-table-column>
        </el-table>
    </div>

    <el-collapse v-model="advancedOpen" class="waf-advanced">
        <el-collapse-item title="高级信息（引擎 / 规则 / 性能）" name="adv">
    <div class="waf-grid-2">
        <div class="waf-panel">
            <div class="waf-panel-head">引擎 / 环境信息</div>
            <el-descriptions :column="1" size="small" border>
                <el-descriptions-item label="插件版本">{{ pluginVersion }}</el-descriptions-item>
                <el-descriptions-item label="引擎状态">
                    <el-tag size="small" :type="readyTagType">{{ readyText }}</el-tag>
                    <el-tag size="small" :type="enabledTagType" style="margin-left:6px">{{ enabledText }}</el-tag>
                    <el-tag v-if="status.observe" size="small" type="primary" style="margin-left:6px">观察模式</el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="灵敏度">{{ sensitivityText }}</el-descriptions-item>
                <el-descriptions-item label="Nginx">{{ status.nginx.bin || '-' }}</el-descriptions-item>
                <el-descriptions-item label="Lua 模块">
                    <el-tag size="small" :type="okTag(status.nginx.lua)">{{ okText(status.nginx.lua) }}</el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="配置存在">
                    <el-tag size="small" :type="okTag(status.nginx.conf_exists)">{{ okText(status.nginx.conf_exists) }}</el-tag>
                    <el-tag size="small" :type="okTag(status.nginx.conf_ok)" style="margin-left:6px">语法 {{ okText(status.nginx.conf_ok) }}</el-tag>
                    <el-tag size="small" :type="okTag(status.nginx.conf_hash_ok)" style="margin-left:6px">内容 {{ okText(status.nginx.conf_hash_ok) }}</el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="目录">
                    <el-tag size="small" :type="okTag(status.dirs.data)">数据</el-tag>
                    <el-tag size="small" :type="okTag(status.dirs.logs)" style="margin-left:6px">日志</el-tag>
                    <el-tag size="small" :type="okTag(status.dirs.lua)" style="margin-left:6px">规则</el-tag>
                    <el-tag size="small" :type="okTag(status.dirs.writable)" style="margin-left:6px">可写</el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="配置生效时间">{{ status.config_apply_at ? fmtTime(status.config_apply_at) : '-' }}</el-descriptions-item>
                <el-descriptions-item label="上次重载">{{ status.last_reload ? fmtTime(status.last_reload) : '-' }}</el-descriptions-item>
            </el-descriptions>
        </div>
        <div class="waf-panel">
            <div class="waf-panel-head">规则版本 / 条数</div>
            <el-descriptions :column="1" size="small" border>
                <el-descriptions-item label="CRS 版本">{{ status.rules.crs_version || '-' }}</el-descriptions-item>
                <el-descriptions-item label="规则总数">{{ num(status.rules.total) }} 条</el-descriptions-item>
                <el-descriptions-item label="CRS / CE / 自定义">{{ num(status.rules.crs_total) }} / {{ num(status.rules.ce_total) }} / {{ num(status.rules.custom_total) }} 条</el-descriptions-item>
                <el-descriptions-item label="规则索引">
                    <el-tag size="small" :type="okTag(status.rules.index_ok)">{{ okText(status.rules.index_ok) }}</el-tag>
                    
                </el-descriptions-item>
                <el-descriptions-item label="Lua 规则文件">{{ num(status.lua_files) }} 个</el-descriptions-item>
            </el-descriptions>
            <div class="waf-panel-head" style="margin-top:14px">性能统计</div>
            <div class="waf-cards waf-cards-3">
                <div class="waf-card">
                    <div class="waf-card-label">请求数</div>
                    <div class="waf-card-val">{{ num(status.perf.requests) }}</div>
                </div>
                <div class="waf-card">
                    <div class="waf-card-label">命中数</div>
                    <div class="waf-card-val">{{ num(status.perf.hits) }}</div>
                </div>
                <div class="waf-card">
                    <div class="waf-card-label">平均耗时</div>
                    <div class="waf-card-val">{{ num(status.perf.avg_ms) }}<span class="waf-card-unit">ms</span></div>
                </div>
            </div>
        </div>
    </div>

    <div class="waf-panel" v-if="status.errors && status.errors.length">
        <div class="waf-panel-head">最近错误</div>
        <el-table :data="status.errors" size="small" border max-height="220">
            <el-table-column label="时间" width="160">
                <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
            </el-table-column>
            <el-table-column label="错误信息" min-width="320">
                <template #default="s"><span class="waf-sub">{{ s.row.msg }}</span></template>
            </el-table-column>
        </el-table>
    </div>

    </el-collapse-item>
    </el-collapse>

    <div class="waf-panel">
        <div class="waf-panel-head">配置导入 / 导出</div>
        <div class="waf-filters">
            <el-button size="small" type="primary" plain @click="exportConfig">导出全部配置（JSON）</el-button>
            <el-upload :auto-upload="false" :show-file-list="false" accept=".json,application/json" :on-change="onImportFile">
                <el-button size="small" :loading="importLoading">导入配置（JSON）</el-button>
            </el-upload>
            
        </div>
    </div>

    <div class="waf-panel">
        <div class="waf-panel-head">
            <span>操作日志</span>
            <el-button link type="danger" size="small" @click="clearOpLogs">清空</el-button>
        </div>
        <el-table :data="opLogs" size="small" border v-loading="opLogLoading" max-height="260" empty-text="暂无操作日志">
            <el-table-column label="时间" width="160">
                <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
            </el-table-column>
            <el-table-column label="内容" min-width="380">
                <template #default="s"><span class="waf-sub">{{ s.row.content }}</span></template>
            </el-table-column>
        </el-table>
        <div class="waf-pager">
            <el-pagination background small layout="total, sizes, prev, pager, next" :total="opLogTotal" :page-size="opLogRows" :current-page="opLogPage" :page-sizes="[10, 20, 50, 100]" @current-change="onOpLogPageChange" @size-change="onOpLogSizeChange"></el-pagination>
        </div>
    </div>
</section>
`;

    TPL.dialogs = `
    </main>
</div>

<el-drawer v-model="logDetailVisible" title="命中详情" size="640px" append-to-body>
    <div v-if="logDetail" class="waf-detail waf-teleport">
        <el-descriptions :column="2" size="small" border>
            <el-descriptions-item label="时间">{{ fmtTime(logDetail.time) }}</el-descriptions-item>
            <el-descriptions-item label="站点">{{ logDetail.site || '-' }}</el-descriptions-item>
            <el-descriptions-item label="IP">
                <span class="waf-mono">{{ logDetail.ip }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="归属">{{ logDetail.area || '-' }}</el-descriptions-item>
            <el-descriptions-item label="动作">
                <el-tag size="small" :type="actionTag(logDetail.action)">{{ actionLabel(logDetail.action) }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="状态码">{{ logDetail.status || '-' }}</el-descriptions-item>
            <el-descriptions-item label="规则来源">{{ sourceLabel(logDetail.rule_source) }}</el-descriptions-item>
            <el-descriptions-item label="req_id">
                <span class="waf-mono">{{ logDetail.req_id || '-' }}</span>
            </el-descriptions-item>
        </el-descriptions>
        <h4 class="waf-section-title">命中规则（{{ (logDetail.hits || []).length }}）</h4>
        <el-table :data="logDetail.hits || []" size="small" border empty-text="无命中规则明细">
            <el-table-column label="模块" width="90">
                <template #default="s">{{ moduleName(s.row.module) }}</template>
            </el-table-column>
            <el-table-column label="规则" width="140">
                <template #default="s"><span class="waf-mono">{{ s.row.rule }}</span></template>
            </el-table-column>
            <el-table-column label="名称" prop="name" min-width="140" show-overflow-tooltip></el-table-column>
            <el-table-column label="Tier" width="70">
                <template #default="s">{{ tierLabel(s.row.tier) }}</template>
            </el-table-column>
            <el-table-column label="分值" prop="score" width="60" align="center"></el-table-column>
            <el-table-column label="来源" width="80">
                <template #default="s">{{ sourceLabel(s.row.src) }}</template>
            </el-table-column>
        </el-table>
        <h4 class="waf-section-title">请求内容（纯文本展示，不执行任何 HTML）</h4>
        <pre class="waf-pre">{{ logPayloadText(logDetail) }}</pre>
        <div class="waf-drawer-actions">
            <el-button size="small" type="danger" plain @click="addIpToList(logDetail, 'ip_black')">加入 IP 黑名单</el-button>
            <el-button size="small" type="warning" plain @click="addIpToList(logDetail, 'ip_white')">加入 IP 白名单</el-button>
            <el-button size="small" @click="unbanLogIp(logDetail)">解封该 IP</el-button>
        </div>
    </div>
</el-drawer>

<el-drawer v-model="siteDialog.visible" :title="'站点防护配置 · ' + siteDialog.site_name" size="780px" append-to-body :before-close="beforeCloseSite">
    <div v-loading="siteDialog.loading" class="waf-site-drawer waf-teleport">
        <el-tabs v-model="siteDialog.tab" class="waf-tabs">
            <el-tab-pane label="基础" name="basic">
                <el-form label-width="130px" size="small" class="waf-form">
                    <el-form-item label="站点防护开关">
                        <el-switch v-model="siteDialog.config.open"></el-switch>
                        
                    </el-form-item>
                    <el-form-item label="灵敏度">
                        <el-select v-model="siteDialog.config.sensitivity" size="small" style="width:170px">
                            <el-option v-for="o in siteSensitivityOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="观察模式">
                        <el-select v-model="siteTri.observe" size="small" style="width:170px">
                            <el-option v-for="o in triOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="模块" name="modules">
                <el-table :data="modules" size="small" border>
                    <el-table-column label="模块" width="160">
                        <template #default="s">{{ s.row.name }}</template>
                    </el-table-column>
                    <el-table-column label="启用" width="90">
                        <template #default="s"><el-switch v-model="siteDialog.config.modules[s.row.key].open"></el-switch></template>
                    </el-table-column>
                    <el-table-column label="Tier（PL）" width="190">
                        <template #default="s">
                            <el-select v-model="siteDialog.config.modules[s.row.key].tier" size="small" style="width:160px">
                                <el-option v-for="t in siteTierOptions" :key="t.value" :label="t.label" :value="t.value"></el-option>
                            </el-select>
                        </template>
                    </el-table-column>
                </el-table>
            </el-tab-pane>

            <el-tab-pane label="CC / 攻击拦截" name="cc">
                <el-form label-width="150px" size="small" class="waf-form">
                    <el-form-item label="CC 防护">
                        <el-select v-model="siteTri.cc_open" size="small" style="width:150px">
                            <el-option v-for="o in triOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="统计周期（0=继承）">
                        <el-input-number v-model="siteDialog.config.cc.cycle" :min="0" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="周期内上限（0=继承）">
                        <el-input-number v-model="siteDialog.config.cc.limit" :min="0" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="封锁时长（0=继承）">
                        <el-input-number v-model="siteDialog.config.cc.block_time" :min="0" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="CC 状态码（0=继承）">
                        <el-input-number v-model="siteDialog.config.cc.status" :min="0" :max="599" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="URL 级 CC">
                        <el-select v-model="siteTri.url_cc" size="small" style="width:150px">
                            <el-option v-for="o in triOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="攻击次数拦截">
                        <el-select v-model="siteTri.attack_open" size="small" style="width:150px">
                            <el-option v-for="o in triOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="攻击统计周期（0=继承）">
                        <el-input-number v-model="siteDialog.config.attack_block.cycle" :min="0" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="攻击次数上限（0=继承）">
                        <el-input-number v-model="siteDialog.config.attack_block.limit" :min="0" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                    <el-form-item label="攻击封锁时长（0=继承）">
                        <el-input-number v-model="siteDialog.config.attack_block.block_time" :min="0" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="CDN" name="cdn">
                <el-form label-width="130px" size="small" class="waf-form">
                    <el-form-item label="CDN 模式"><el-switch v-model="siteDialog.config.cdn.open"></el-switch></el-form-item>
                    <el-form-item label="真实 IP 头">
                        <el-input v-model="siteText.cdn_headers" type="textarea" :rows="4" class="waf-mono" placeholder="一行一个请求头，如 cf-connecting-ip"></el-input>
                    </el-form-item>
                    <el-form-item label="可信代理 IP">
                        <el-input v-model="siteText.cdn_trusted" type="textarea" :rows="4" class="waf-mono" placeholder="一行一个 IP / CIDR"></el-input>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="黑白名单" name="lists">
                <div class="waf-list-editor">
                    <el-select v-model="siteListType" size="small" style="width:180px">
                        <el-option v-for="m in listMeta" :key="m.key" :label="m.label" :value="m.key"></el-option>
                    </el-select>
                    
                </div>
                <el-input v-model="siteText[siteListType]" type="textarea" :rows="10" class="waf-mono" placeholder="一行一条"></el-input>
            </el-tab-pane>

            <el-tab-pane label="敏感路径 / 后缀" name="paths">
                <el-form label-width="150px" size="small" class="waf-form">
                    <el-form-item label="敏感路径后缀">
                        <el-input v-model="siteText.disable_php_path" type="textarea" :rows="5" class="waf-mono" placeholder="一行一个，支持 ^ 开头正则，如 ^/cache/"></el-input>
                    </el-form-item>
                    <el-form-item label="禁止访问后缀">
                        <el-input v-model="siteText.disable_ext" type="textarea" :rows="4" class="waf-mono" placeholder="一行一个，如 sql / bak / env"></el-input>
                    </el-form-item>
                    <el-form-item label="上传危险后缀">
                        <el-input v-model="siteText.upload_ext" type="textarea" :rows="4" class="waf-mono" placeholder="一行一个，如 php / jsp / exe"></el-input>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane label="绑定自定义规则" name="custom">
                <div class="waf-list-editor">
                    <el-select v-model="siteDialog.config.custom_rules" multiple collapse-tags size="small" style="width:100%" placeholder="选择要绑定到本站点的自定义规则">
                        <el-option v-for="o in customRuleOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                    </el-select>
                </div>
                <div class="waf-filters">
                    <el-button size="small" type="primary" plain @click="openCustomFromSite">新建自定义规则</el-button>
                    
                </div>
            </el-tab-pane>
        </el-tabs>
    </div>
    <template #footer>
        <div class="waf-drawer-footer-actions">
            <el-button size="small" @click="closeSiteDialog">取消</el-button>
            <el-button size="small" type="primary" :disabled="!siteDialogDirty" :loading="siteDialog.saving" @click="saveSiteConfig">保存站点配置</el-button>
        </div>
    </template>
</el-drawer>

<el-dialog v-model="customDialogVisible" :title="customForm.id ? '编辑自定义规则' : '新增自定义规则'" width="660px" append-to-body>
  <div class="waf-teleport">
    <el-form label-width="100px" size="small" class="waf-form">
        <el-form-item label="规则名称">
            <el-input v-model="customForm.name" placeholder="如：拦截 sqlmap 扫描器" maxlength="120"></el-input>
        </el-form-item>
        <el-form-item label="启用">
            <el-switch v-model="customForm.open"></el-switch>
            
        </el-form-item>
        <el-form-item label="优先级">
            <el-input-number v-model="customForm.priority" :min="1" :max="9999" size="small" controls-position="right"></el-input-number>
            
        </el-form-item>
        <el-form-item label="生效范围">
            <el-select v-model="customForm.scope" size="small" style="width:150px">
                <el-option v-for="o in customScopeOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
            </el-select>
        </el-form-item>
        <el-form-item v-if="customForm.scope === 'site'" label="生效站点">
            <el-select v-model="customForm.sites" multiple collapse-tags filterable size="small" style="width:100%" placeholder="选择站点">
                <el-option v-for="n in siteNames" :key="n" :label="n" :value="n"></el-option>
            </el-select>
        </el-form-item>
        <el-form-item label="匹配字段">
            <el-select v-model="customForm.field" size="small" style="width:160px" @change="customFieldChange">
                <el-option v-for="o in customFieldOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
            </el-select>
        </el-form-item>
        <el-form-item v-if="customForm.field === 'header'" label="请求头名称">
            <el-input v-model="customForm.header" placeholder="如 user-agent" style="width:220px"></el-input>
        </el-form-item>
        <el-form-item label="操作符">
            <el-select v-model="customForm.operator" size="small" style="width:180px">
                <el-option v-for="o in customOperatorOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
            </el-select>
        </el-form-item>
        <el-form-item label="匹配值">
            <el-input v-model="customForm.value" type="textarea" :rows="3" class="waf-mono" placeholder="如 (?i)sqlmap；长度 ≤ 2048"></el-input>
        </el-form-item>
        <el-form-item label="动作">
            <el-select v-model="customForm.action" size="small" style="width:150px">
                <el-option v-for="o in customActionOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
            </el-select>
        </el-form-item>
        <el-form-item label="拦截状态码">
            <el-input-number v-model="customForm.status" :min="400" :max="599" size="small" controls-position="right"></el-input-number>
        </el-form-item>
        <el-form-item label="风险分值">
            <el-input-number v-model="customForm.score" :min="1" :max="100" size="small" controls-position="right"></el-input-number>
            
        </el-form-item>
        <el-form-item label="备注">
            <el-input v-model="customForm.note" placeholder="可选" maxlength="200"></el-input>
        </el-form-item>
    </el-form>
  </div>
    <template #footer>
        <el-button size="small" @click="customDialogVisible = false">取消</el-button>
        <el-button size="small" type="primary" :loading="customSaving" @click="saveCustomRule">保存规则</el-button>
    </template>
</el-dialog>

<el-dialog v-model="blockPagePreviewVisible" title="拦截页面预览（后端已过滤危险标签）" width="720px" append-to-body>
    <div class="waf-teleport">
        
        <iframe class="waf-preview-frame" sandbox="" :srcdoc="blockPagePreview"></iframe>
    </div>
</el-dialog>

<el-dialog v-model="confirmDialog.visible" :title="confirmDialog.title" width="420px" append-to-body @closed="onConfirmClosed">
    <div class="waf-teleport">
        <div class="waf-confirm-text">{{ confirmDialog.content }}</div>
    </div>
    <template #footer>
        <el-button size="small" @click="onConfirmCancel">取消</el-button>
        <el-button size="small" type="primary" @click="onConfirmOk">确定</el-button>
    </template>
</el-dialog>
`;


    function buildTemplate() {
        return '<div id="btwaf-ce-app" class="waf-app" :class="{ \'waf-dark\': isDark }">' +
            (TPL.top || '') + (TPL.overview || '') + (TPL.logs || '') + (TPL.sites || '') +
            (TPL.config || '') + (TPL.rules || '') + (TPL.blocks || '') + (TPL.diagnostics || '') +
            (TPL.dialogs || '') + '</div>';
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

                view: 'overview',
                isDark: false,
                refreshing: false,
                status: emptyStatus(),
                statusFailed: false,
                statusLoading: false,
                loaded: {},
                errors: {
                    overview: '', logs: '', sites: '', config: '', rules: '', blocks: '', diagnostics: ''
                },

                ovDate: today,
                ov: emptyOverview(),
                ovLoading: false,

                logFilter: { site: '', date: today, keyword: '', type: '', ip: '', action: '' },
                logList: [], logTotal: 0, logPage: 1, logRows: 10,
                logTypes: [], logLimited: false, logLoading: false,
                logDetail: null, logDetailVisible: false,

                siteKeyword: '', siteStatus: '', siteList: [], siteTotal: 0, sitePage: 1, siteRows: 10,
                siteLoading: false, siteSelection: [],
                siteDialog: {
                    visible: false, loading: false, saving: false, tab: 'basic', snapshot: '',
                    site_name: '', config: defaultSiteConfig(), raw: null, global: {}
                },
                siteTri: { observe: 'inherit', cc_open: 'inherit', url_cc: 'inherit', attack_open: 'inherit' },
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
                globalListText: {
                    ip_black: '', ip_white: '', url_black: '', url_white: '', ua_black: '', ua_white: '', param_white: ''
                },
                crawlerText: '', trustedText: '',
                blockPageText: '',
                blockPagePreview: '', blockPagePreviewVisible: false, blockPageIntercepted: [],
                excludeText: { crs: '', ce: '' },

                ruleTab: 'builtin',
                ruleFilter: { source: '', module: '', keyword: '', status: '' },
                ruleList: [], ruleTotal: 0, rulePage: 1, ruleRows: 10, ruleLoading: false,
                ruleExclude: { crs: [], ce: [] }, ruleExcludeLoaded: false,
                customKeyword: '', customRules: [], customTotal: 0, customPage: 1, customRows: 10,
                customLoading: false, customRuleOptions: [],
                customDialogVisible: false, customSaving: false, customForm: defaultCustomRule(),

                blockTab: 'current', blockSite: '', blockList: [], blockTotal: 0, blockPage: 1, blockRows: 10, blockLoading: false,

                advancedOpen: [],
                envItems: [], envRepairable: true, envNeedsRepair: false, envLoading: false, repairLoading: false,
                opLogs: [], opLogTotal: 0, opLogPage: 1, opLogRows: 10, opLogLoading: false,
                importLoading: false,

                /* 通用确认弹窗（不使用 BTP.confirm，避免 z-index 被面板 layer 遮挡） */
                confirmDialog: { visible: false, title: '', content: '', resolve: null }
            };
        },

        computed: {
            pluginVersion: function () {
                try { if (window.__BTWAF_ASSET_VERSION) return window.__BTWAF_ASSET_VERSION; } catch (e) { }
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

        methods: {
            fmtTime: fmtTime,
            fmtDate: fmtDate,
            num: num,
            showConfirm: function (title, content) {
                var self = this;
                return new Promise(function (resolve) {
                    self.confirmDialog = { visible: true, title: title, content: content, resolve: resolve };
                });
            },
            onConfirmOk: function () {
                var d = this.confirmDialog;
                d.visible = false;
                if (d.resolve) { var r = d.resolve; d.resolve = null; r(true); }
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
                return v === 0 ? '继承' : ('PL' + v);
            },
            actionLabel: function (a) {
                var map = { block: '拦截', allow: '记录/放行', cc: 'CC 拦截', blacklist: '黑名单', log: '记录' };
                return map[a] || a || '-';
            },
            actionTag: function (a) {
                var map = { block: 'danger', allow: 'info', cc: 'warning', blacklist: 'danger', log: 'info' };
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
                var map = { cc: 'CC 超限', attack: '攻击拦截', blacklist: '黑名单', upload: '上传拦截' };
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
                    rules: 'loadRules', blocks: 'loadBlocks', diagnostics: 'loadDiagnostics'
                };
                var fn = map[this.view];
                return fn ? this[fn]() : Promise.resolve();
            },
            reloadAll: function () {
                this.loaded = {};
                this.errors = { overview: '', logs: '', sites: '', config: '', rules: '', blocks: '', diagnostics: '' };
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
            buildSiteTexts: function () {
                var c = this.siteDialog.config;
                var t = this.siteText;
                LIST_META.forEach(function (m) { t[m.key] = joinLines((c.lists && c.lists[m.key]) || []); });
                t.disable_php_path = joinLines(c.disable_php_path || []);
                t.disable_ext = joinLines(c.disable_ext || []);
                t.upload_ext = joinLines(c.upload_ext || []);
                t.cdn_headers = joinLines((c.cdn && c.cdn.headers) || []);
                t.cdn_trusted = joinLines((c.cdn && c.cdn.trusted) || []);
                this.siteTri = {
                    observe: toTri(c.observe),
                    cc_open: toTri(c.cc && c.cc.open),
                    url_cc: toTri(c.cc && c.cc.url_cc),
                    attack_open: toTri(c.attack_block && c.attack_block.open)
                };
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
                    var d = await WafAPI.data('get_plugin_config');
                    this.cfg = normalizeGlobalConfig(d || {});
                    this.blockPageText = (this.cfg.block && this.cfg.block.page) || '';
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

            loadRules: async function () {
                this.ruleLoading = true;
                this.errors.rules = '';
                try {
                    if (!this.ruleExcludeLoaded) await this.ensureRuleExclude();
                    var d = await WafAPI.data('get_rules', {
                        source: this.ruleFilter.source, module: this.ruleFilter.module,
                        keyword: this.ruleFilter.keyword, status: this.ruleFilter.status, p: this.rulePage, rows: this.ruleRows
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

            loadDiagnostics: async function () {
                this.diagLoading = true;
                this.errors.diagnostics = '';
                try {
                    if (!this.status.version) await this.loadStatus();
                    await this.loadEnv();
                    await this.loadOpLogs();
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
            loadOpLogs: async function () {
                this.opLogLoading = true;
                try {
                    var d = await WafAPI.data('get_logs', { p: this.opLogPage, rows: this.opLogRows });
                    d = d || {};
                    this.opLogs = Array.isArray(d.list) ? d.list : [];
                    this.opLogTotal = num(d.total);
                } catch (e) {
                    this.opLogs = [];
                    this.opLogTotal = 0;
                } finally {
                    this.opLogLoading = false;
                }
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
        }
    }).mount('#app');
})(window);



