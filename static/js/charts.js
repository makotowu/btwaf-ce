/*!
 * btwaf_ce 图表封装  charts.js
 * =====================================================================
 * - 只用面板内置 ECharts：优先 window.echarts（面板插件页会按 <!-- echarts.init -->
 *   标记预加载 /static/js/echarts.min.js）；缺失时显式加载同一路径一次；
 *   仍失败则渲染"图表组件未加载"占位（带简易数据视图，保证信息不丢）。
 * - 主题色/文字色全部读取面板 CSS 变量（--el-* / --btp-*），不写死色值；
 *   html.dark 切换时销毁并按 dark 主题重建全部图表。
 * ===================================================================== */
(function (window, document) {
    'use strict';

    var ECHARTS_SRC = '/static/js/echarts.min.js';
    var LOAD_TIMEOUT = 8000;
    var state = { loading: false, failed: false, waiters: [], boundTheme: false };
    var entries = []; // {el, option, inst}

    function cssVar(name, fallback) {
        try {
            var host = document.querySelector('#btwaf-ce-app') || document.documentElement;
            var v = getComputedStyle(host).getPropertyValue(name);
            v = (v || '').trim();
            if (v) return v;
            v = getComputedStyle(document.documentElement).getPropertyValue(name);
            v = (v || '').trim();
            if (v) return v;
        } catch (e) { }
        return fallback || '';
    }
    function isDark() {
        try {
            if (window.BTP && BTP.theme && typeof BTP.theme.isDark === 'function') return !!BTP.theme.isDark();
        } catch (e) { }
        var root = document.documentElement;
        return root.classList.contains('dark') || root.getAttribute('data-theme') === 'dark';
    }
    function palette() {
        var list = [
            cssVar('--waf-chart-1', '#20a53a'),
            cssVar('--waf-chart-2', '#1f9d8f'),
            cssVar('--waf-chart-3', '#2f7fd1'),
            cssVar('--waf-chart-4', '#e6912c'),
            cssVar('--waf-chart-5', '#d9534f'),
            cssVar('--waf-chart-6', '#7b61c9')
        ];
        return list.filter(function (c, i) { return c && list.indexOf(c) === i; });
    }
    function colors() {
        var p = palette();
        var dark = isDark();
        return {
            dark: dark,
            text: cssVar('--el-text-color-primary', dark ? '#e5eaf3' : '#303133'),
            text2: cssVar('--el-text-color-regular', dark ? '#cfd3dc' : '#606266'),
            sub: cssVar('--el-text-color-secondary', dark ? '#a3a6ad' : '#909399'),
            border: cssVar('--el-border-color-light', dark ? '#414243' : '#e4e7ed'),
            split: cssVar('--el-border-color-extra-light', dark ? '#363637' : '#f2f6fc'),
            bg: cssVar('--el-bg-color-overlay', dark ? '#1d1e1f' : '#ffffff'),
            palette: p
        };
    }

    /* ---------------- 主题化 option ---------------- */
    function axisStyle(c) {
        return {
            axisLine: { lineStyle: { color: c.border } },
            axisTick: { lineStyle: { color: c.border } },
            axisLabel: { color: c.sub, fontSize: 11 },
            splitLine: { lineStyle: { color: c.split, type: 'dashed' } },
            nameTextStyle: { color: c.sub, fontSize: 11 }
        };
    }
    function mergeAxis(axis, c) {
        if (!axis) return axis;
        var list = Array.isArray(axis) ? axis : [axis];
        return list.map(function (a) {
            var base = axisStyle(c);
            var out = {};
            Object.keys(base).forEach(function (k) {
                out[k] = Object.assign({}, base[k], (a && a[k]) || {});
            });
            return Object.assign({}, a, out);
        });
    }
    function themed(option) {
        var c = colors();
        var o = Object.assign({}, option);
        o.color = o.color || c.palette;
        o.backgroundColor = 'transparent';
        o.textStyle = Object.assign({ color: c.text, fontSize: 12 }, o.textStyle || {});
        o.tooltip = Object.assign({
            backgroundColor: c.bg,
            borderColor: c.border,
            borderWidth: 1,
            textStyle: { color: c.text, fontSize: 12 }
        }, o.tooltip || {});
        if (o.legend) o.legend = Object.assign({ textStyle: { color: c.text2, fontSize: 11 }, itemWidth: 10, itemHeight: 10 }, o.legend);
        if (o.xAxis) o.xAxis = Array.isArray(o.xAxis) ? mergeAxis(o.xAxis, c) : mergeAxis(o.xAxis, c)[0];
        if (o.yAxis) o.yAxis = Array.isArray(o.yAxis) ? mergeAxis(o.yAxis, c) : mergeAxis(o.yAxis, c)[0];
        return o;
    }

    /* ---------------- echarts 加载 ---------------- */
    function ensure(cb) {
        if (window.echarts) { cb(true); return; }
        if (state.failed) { cb(false); return; }
        state.waiters.push(cb);
        if (state.loading) return;
        state.loading = true;
        var done = function (ok) {
            state.loading = false;
            if (!ok || !window.echarts) {
                state.failed = true;
                var ws = state.waiters; state.waiters = [];
                ws.forEach(function (w) { try { w(false); } catch (e) { } });
                return;
            }
            var ws = state.waiters; state.waiters = [];
            ws.forEach(function (w) { try { w(true); } catch (e) { } });
        };
        try {
            var s = document.createElement('script');
            s.src = ECHARTS_SRC;
            var timer = setTimeout(function () { timer = null; done(false); }, LOAD_TIMEOUT);
            s.onload = function () { if (timer) { clearTimeout(timer); done(true); } };
            s.onerror = function () { if (timer) { clearTimeout(timer); done(false); } };
            document.head.appendChild(s);
        } catch (e) {
            done(false);
        }
    }

    /* ---------------- 占位 / 简易数据视图（无 ECharts 时） ---------------- */
    function esc(s) {
        return String(s === undefined || s === null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function placeholder(el, option) {
        if (!el) return;
        var p = palette();
        var series = (option && option.series && option.series[0]) || {};
        var data = series.data || [];
        var html = '<div class="waf-chart-empty">图表组件未加载（面板 ECharts 不可用）</div>';
        if (series.type === 'pie' && data.length) {
            var total = data.reduce(function (a, it) { return a + (Number((it && it.value) || 0) || 0); }, 0) || 1;
            var acc = 0;
            var stops = data.map(function (it, i) {
                var v = Number((it && it.value) || 0) || 0;
                var from = (acc / total) * 360;
                acc += v;
                var to = (acc / total) * 360;
                return p[i % p.length] + ' ' + from.toFixed(2) + 'deg ' + to.toFixed(2) + 'deg';
            }).join(',');
            html += '<div class="waf-chart-fb-pie" style="background:conic-gradient(' + stops + ')"></div>';
            html += '<ul class="waf-chart-fb-legend">' + data.map(function (it, i) {
                return '<li><i style="background:' + p[i % p.length] + '"></i>' + esc(it && it.name) +
                    '<b>' + esc(it && it.value) + '</b></li>';
            }).join('') + '</ul>';
        } else if (data.length) {
            var labels = (option && option.xAxis && option.xAxis.data) || [];
            var nums = data.map(function (it) { return Number((it && it.value) !== undefined ? it.value : it) || 0; });
            var max = Math.max.apply(null, nums.concat([1]));
            html += '<div class="waf-chart-fb-bars">' + nums.map(function (n, i) {
                var h = Math.max(2, Math.round((n / max) * 100));
                return '<div class="waf-chart-fb-bar" title="' + esc(labels[i] || '') + ': ' + n + '">' +
                    '<i style="height:' + h + '%;background:' + p[i % p.length] + '"></i>' +
                    '<span>' + esc(labels[i] || '') + '</span></div>';
            }).join('') + '</div>';
        }
        el.innerHTML = html;
    }

    /* ---------------- 渲染 / 重绘 ---------------- */
    function resolveEl(target) {
        if (!target) return null;
        if (typeof target === 'string') return document.getElementById(target.replace(/^#/, ''));
        return target;
    }
    function draw(entry) {
        var el = entry.el;
        var c = colors();
        if (!window.echarts) { placeholder(el, entry.option); return; }
        try {
            if (entry.inst) { try { entry.inst.dispose(); } catch (e) { } }
            entry.inst = window.echarts.init(el, c.dark ? 'dark' : null, { renderer: 'canvas' });
            entry.inst.setOption(themed(entry.option), true);
        } catch (e) {
            entry.inst = null;
            placeholder(el, entry.option);
        }
    }
    function render(target, option) {
        var el = resolveEl(target);
        if (!el) return;
        var entry = null;
        for (var i = 0; i < entries.length; i++) { if (entries[i].el === el) { entry = entries[i]; break; } }
        if (!entry) { entry = { el: el, option: option, inst: null }; entries.push(entry); }
        entry.option = option;
        ensure(function (ok) {
            if (ok) draw(entry); else placeholder(el, entry.option);
        });
    }
    function redrawAll() {
        ensure(function (ok) {
            entries.forEach(function (entry) {
                if (!entry.el || !document.body.contains(entry.el)) return;
                if (ok) draw(entry); else placeholder(entry.el, entry.option);
            });
        });
    }
    function resizeAll() {
        entries.forEach(function (e) {
            if (e.inst) { try { e.inst.resize(); } catch (err) { } }
        });
    }
    function disposeAll() {
        entries.forEach(function (e) { if (e.inst) { try { e.inst.dispose(); } catch (err) { } } });
        entries = [];
    }

    /* ---------------- 初始化：主题/尺寸变化 ---------------- */
    var resizeTimer = null;
    window.addEventListener('resize', function () {
        if (resizeTimer) clearTimeout(resizeTimer);
        resizeTimer = setTimeout(resizeAll, 120);
    });
    function bindTheme() {
        if (state.boundTheme) return;
        state.boundTheme = true;
        try {
            if (window.BTP && BTP.theme && typeof BTP.theme.onChange === 'function') {
                BTP.theme.onChange(function () { redrawAll(); });
            } else {
                if (window.MutationObserver) {
                    new MutationObserver(function () { redrawAll(); })
                        .observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme'] });
                }
            }
        } catch (e) { }
    }
    bindTheme();

    window.WafCharts = {
        render: render,
        redrawAll: redrawAll,
        resizeAll: resizeAll,
        disposeAll: disposeAll,
        isDark: isDark,
        palette: palette,
        colors: colors,
        available: function () { return !!window.echarts; },
        failed: function () { return state.failed; }
    };
})(window, document);
