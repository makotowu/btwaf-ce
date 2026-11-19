/*! btwaf_ce 控制台 core：主题、常量、工具与默认状态 */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};

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
        { key: 'ip_black', label: 'IP 黑名单', hint: '单 IP、CIDR 或 IP 范围，一行一个' },
        { key: 'ip_white', label: 'IP 白名单', hint: '单 IP、CIDR 或 IP 范围，一行一个' },
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
    var LIST_GROUPS = [
        { label: 'IP', items: LIST_META.slice(0, 2) },
        { label: 'URL', items: LIST_META.slice(2, 4) },
        { label: 'UA', items: LIST_META.slice(4, 6) },
        { label: '参数', items: LIST_META.slice(6, 7) }
    ];
    var SITE_SENSITIVITY_OPTIONS = [{ value: 0, label: '默认' }].concat(SENSITIVITY_OPTIONS);
    var TRI_OPTIONS = [
        { value: 'inherit', label: '默认' },
        { value: 'on', label: '开启' },
        { value: 'off', label: '关闭' }
    ];
    var SITE_TIER_OPTIONS = [
        { value: 0, label: '默认' },
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
        { value: 'blacklist', label: '黑名单' },
        { value: 'geo', label: '地区限制' }
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
    var BLOCK_STATUS_OPTIONS = [403, 404, 444, 429, 503];
    var RULE_STATUS_OPTIONS = [{ value: 0, label: '默认' }].concat(BLOCK_STATUS_OPTIONS.map(function (v) {
        return { value: v, label: String(v) };
    }));
    var GEO_REGION_OPTIONS = [{ value: 'CN', label: '中国大陆' }];
    var GEO_MODE_OPTIONS = [
        { value: 'allow', label: '仅允许选中地区' },
        { value: 'block', label: '拒绝选中地区' }
    ];
    var GEO_UNKNOWN_OPTIONS = [
        { value: 'allow', label: '放行' },
        { value: 'block', label: '拦截' }
    ];
    var CDN_PRESETS = [
        { value: 'generic', label: '通用 CDN / 反代', headers: ['x-real-ip', 'x-forwarded-for'] },
        { value: 'cloudflare', label: 'Cloudflare', headers: ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'] },
        { value: 'baidu', label: '百度云加速', headers: ['x-real-ip', 'x-forwarded-for'] },
        { value: 'tencent', label: '腾讯云 CDN', headers: ['x-forwarded-for', 'x-real-ip'] },
        { value: 'edgeone', label: '腾讯 EdgeOne', headers: ['eo-connecting-ip', 'x-forwarded-for'] },
        { value: 'aliyun', label: '阿里云 CDN', headers: ['ali-cdn-real-ip', 'x-forwarded-for', 'x-real-ip'] },
        { value: 'huawei', label: '华为云 CDN', headers: ['x-real-ip', 'x-forwarded-for'] },
        { value: 'volcengine', label: '火山引擎 CDN', headers: ['x-forwarded-for', 'x-real-ip'] },
        { value: 'qiniu', label: '七牛云 CDN', headers: ['x-real-ip', 'x-forwarded-for'] },
        { value: 'akamai', label: 'Akamai', headers: ['true-client-ip', 'x-forwarded-for'] },
        { value: 'fastly', label: 'Fastly', headers: ['fastly-client-ip', 'x-forwarded-for'] },
        { value: 'custom', label: '自定义', headers: [] }
    ];
    var ICON = {
        overview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z"/></svg>',
        logs: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 3h14a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm2 4v2h10V7H7Zm0 4v2h10v-2H7Zm0 4v2h7v-2H7Z"/></svg>',
        oplogs: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 5v5l4 2-1 1.7-5-2.7V7h2Z"/></svg>',
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
        { key: 'oplogs', label: '操作日志', group: '系统', icon: ICON.oplogs },
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
            geo: { open: false, available: false, source: '', source_release: '', license: '', records: 0 },
            default_block_page: '',
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
        if (!s.geo || typeof s.geo !== 'object') s.geo = { open: false, available: false };
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
            geo: { open: false, mode: 'allow', regions: ['CN'], unknown: 'allow', status: 403 },
            scan: { body_limit: 1048576, arg_limit: 8192, header_limit: 8192, upload_scan_limit: 20971520, max_args: 200 },
            protocol: { from_data: false },
            log: { enabled: true, retain_days: 30, rotate_size: 52428800, snippet: 512 },
            cc: { open: true, cycle: 60, limit: 120, block_time: 300, status: 444, url_cc: false, skip_static: true },
            attack_block: { open: true, cycle: 120, limit: 20, block_time: 1800 },
            modules: defaultModules(),
            lists: emptyLists(),
            rule_exclude: { crs: [], ce: [] },
            rule_status: {},
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
            block: { status: 0 },
            geo: { open: null, mode: null, regions: null, unknown: null, status: 0 },
            modules: defaultSiteModules(),
            cc: { open: null, cycle: 0, limit: 0, block_time: 0, status: 0, url_cc: null },
            attack_block: { open: null, cycle: 0, limit: 0, block_time: 0 },
            cdn: { open: false, headers: ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'], trusted: [] },
            lists: emptyLists(),
            rule_exclude: { crs: [], ce: [] },
            rule_status: {},
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


    WAF.tpl = WAF.tpl || {};
    WAF.methods = WAF.methods || {};
    WAF.const = {MODULES: MODULES, LIST_META: LIST_META, LIST_GROUPS: LIST_GROUPS, SENSITIVITY_OPTIONS: SENSITIVITY_OPTIONS, SITE_SENSITIVITY_OPTIONS: SITE_SENSITIVITY_OPTIONS, TRI_OPTIONS: TRI_OPTIONS, SITE_TIER_OPTIONS: SITE_TIER_OPTIONS, GLOBAL_TIER_OPTIONS: GLOBAL_TIER_OPTIONS, LOG_ACTION_OPTIONS: LOG_ACTION_OPTIONS, RULE_SOURCE_OPTIONS: RULE_SOURCE_OPTIONS, RULE_MODULE_OPTIONS: RULE_MODULE_OPTIONS, CUSTOM_FIELD_OPTIONS: CUSTOM_FIELD_OPTIONS, CUSTOM_OPERATOR_OPTIONS: CUSTOM_OPERATOR_OPTIONS, CUSTOM_ACTION_OPTIONS: CUSTOM_ACTION_OPTIONS, CUSTOM_SCOPE_OPTIONS: CUSTOM_SCOPE_OPTIONS, BLOCK_STATUS_OPTIONS: BLOCK_STATUS_OPTIONS, RULE_STATUS_OPTIONS: RULE_STATUS_OPTIONS, GEO_REGION_OPTIONS: GEO_REGION_OPTIONS, GEO_MODE_OPTIONS: GEO_MODE_OPTIONS, GEO_UNKNOWN_OPTIONS: GEO_UNKNOWN_OPTIONS, CDN_PRESETS: CDN_PRESETS, ICON: ICON, VIEWS: VIEWS};
    WAF.util = {pad2: pad2, num: num, clone: clone, todayStr: todayStr, fmtTime: fmtTime, fmtDate: fmtDate, splitLines: splitLines, joinLines: joinLines, errText: errText, toTri: toTri, fromTri: fromTri, remainText: remainText, mergeDeep: mergeDeep, emptyStatus: emptyStatus, normalizeStatus: normalizeStatus, emptyOverview: emptyOverview, defaultModules: defaultModules, defaultSiteModules: defaultSiteModules, emptyLists: emptyLists, defaultGlobalConfig: defaultGlobalConfig, normalizeGlobalConfig: normalizeGlobalConfig, defaultSiteConfig: defaultSiteConfig, normalizeSiteConfig: normalizeSiteConfig, defaultCustomRule: defaultCustomRule};
})(window);
