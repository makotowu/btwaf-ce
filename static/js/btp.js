/*!
 * BTP.js v2 — 宝塔面板插件前端框架(基于 CDN Vue3 + Element Plus)
 * =====================================================================
 * 用真正的 Vue 语法编写插件,组件样式与面板(Element Plus)完全一致。
 *
 * 原理:
 *  插件页面自动从 CDN 加载 Vue 3 全量版 + Element Plus UMD,
 *  并引入面板自身的样式 /static/css/style.css(与面板同源,深色/主题色自动跟随),
 *  然后像写 Vue 一样调用 BTP.createApp({...}).mount('#app')。
 *
 * 用法(插件 index.html 内):
 *   <div id="app"></div>
 *   <script src="/你的插件名/static/js/btp.js"></script>
 *   <script>
 *     BTP.createApp({
 *       template: `
 *         <el-button type="success" @click="save">保存</el-button>
 *         <el-input v-model="form.name" placeholder="名称"></el-input>
 *         <el-table :data="rows">
 *           <el-table-column prop="id" label="ID"></el-table-column>
 *         </el-table>`,
 *       data() { return { form:{name:''}, rows:[] } },
 *       methods: { save(){ BTP.msg('ok','success') } },
 *       mounted() { ... }
 *     }).mount('#app')
 *   </script>
 *
 * CDN 配置(可覆盖):
 *  BTP.config.vue          Vue3 全量版脚本地址列表(默认 bootcdn / jsdelivr / unpkg)
 *  BTP.config.elementPlus  Element Plus UMD 地址列表
 *  BTP.config.panelCss     面板样式(默认 /static/css/style.css,勿改)
 *  BTP.config.timeout      单脚本加载超时(默认 15000ms)
 *
 * 组件 API:
 *  BTP.msg / BTP.confirm / BTP.dialog / BTP.loading / BTP.request / BTP.theme
 *  (BTP.confirm/BTP.loading 基于 ElementPlus 的 ElMessageBox / ElLoading)
 * =====================================================================
 */
(function (window, document) {
    'use strict';

    var BTP = {
        __ready: null,
        config: {
            // 默认使用本地 vendor 目录(与面板同版本:Vue 3.5.x + Element Plus 2.14.x),
            // 可覆盖为数组以添加 CDN 兜底: BTP.config.vue = [本地路径, 'https://...']
            vue: null,
            elementPlus: null,
            panelCss: '/static/css/style.css',
            panelDiffCss: '',      // 面板差异样式,留空则自动推断插件目录下的 static/css/btp-panel.css
            timeout: 15000,
            // [btwaf_ce 差异] 业务请求默认超时(毫秒),由 BTP.request 使用
            requestTimeout: 60000,
            // [btwaf_ce 差异] 面板弹窗(layer)的 z-index 极高(约 19891014),
            // Element Plus 默认 2000 的 ElMessage 会被 layer 遮住,这里统一抬高。
            msgZIndex: 30000000,
            // [btwaf_ce 差异] 传入 ElementPlus 的全局配置(弹出层 z-index 基准等)
            elementPlusOptions: { zIndex: 30000000 }
        }
    };

    /* 推断插件根目录(btp.js 通常位于 插件/static/js/btp.js) */
    function pluginBase() {
        try {
            var s = document.currentScript;
            if (s && s.src) {
                var m = s.src.match(/^(.*?)\/static\/js\/btp\.js/);
                if (m) return m[1];
            }
        } catch (e) { }
        // [btwaf_ce 差异] 面板通过 getConfigHtml 把插件片段注入主文档(layer)执行时，
        // document.currentScript 可能取不到带 src 的脚本；优先使用 index.html 内联脚本算好的
        // window.__btwafCeBase，最后兜底插件固定部署路径 /btwaf_ce，避免 vendor 去 /static/vendor/ 下 404。
        if (window.__btwafCeBase) return window.__btwafCeBase;
        return '/btwaf_ce';
    }

    /* ================= 0. 工具:加载脚本 / 样式 ================= */
    function loadScript(src) {
        return new Promise(function (resolve, reject) {
            var s = document.createElement('script');
            s.src = src;
            s.onload = function () { resolve(src); };
            s.onerror = function () { reject(new Error('加载失败: ' + src)); };
            var timer = setTimeout(function () { s.onerror(new Error('加载超时: ' + src)); }, BTP.config.timeout);
            document.head.appendChild(s);
        });
    }
    function loadCss(href) {
        if (document.querySelector('link[data-btp-css="' + href + '"]')) return Promise.resolve();
        return new Promise(function (resolve, reject) {
            var l = document.createElement('link');
            l.rel = 'stylesheet';
            l.href = href;
            l.setAttribute('data-btp-css', href);
            l.onload = function () { resolve(); };
            l.onerror = function () { reject(new Error('样式加载失败: ' + href)); };
            document.head.appendChild(l);
        });
    }
    function tryEach(urls) {
        var i = 0;
        return new Promise(function (resolve, reject) {
            (function next() {
                if (i >= urls.length) return reject(new Error('所有 CDN 均加载失败'));
                loadScript(urls[i++]).then(resolve, next);
            })();
        });
    }

    /* ================= 1. ready:加载样式 + Vue + ElementPlus(单例,避免重复加载/竞态) ================= */
    function vendorUrl(rel) {
        return (pluginBase() || '') + '/static/vendor/' + rel;
    }
    function loadDeps() {
        var chain = loadCss(BTP.config.panelCss).catch(function () { });
        // 面板差异样式(bt-* 类)
        var diffCss = BTP.config.panelDiffCss || (pluginBase() ? pluginBase() + '/static/css/btp-panel.css' : '');
        if (diffCss) chain = chain.then(function () { return loadCss(diffCss); }).catch(function () { });
        var vueUrls = BTP.config.vue || [vendorUrl('vue.global.prod.js')];
        var epUrls = BTP.config.elementPlus || [vendorUrl('element-plus.full.min.js')];
        if (!window.Vue) chain = chain.then(function () { return tryEach(vueUrls); });
        if (!window.ElementPlus) chain = chain.then(function () { return tryEach(epUrls); });
        return chain;
    }
    var _readyPromise = null;
    function ready(cb) {
        if (window.Vue && window.ElementPlus && window.BTPComponents) { cb(); return; }
        if (!_readyPromise) {
            _readyPromise = loadDeps().catch(function (e) { _readyPromise = null; throw e; });
        }
        _readyPromise.then(function () { cb(); }).catch(function (e) {
            alert('BTP.js 加载依赖失败: ' + e.message);
        });
    }
    BTP.ready = ready;

    /* ================= 2. createApp(等价 Vue.createApp().use(ElementPlus) + 注册 BTP 组件库) ================= */
    BTP.createApp = function (options) {
        return {
            mount: function (el) {
                ready(function () {
                    var app = Vue.createApp(options || {});
                    // [btwaf_ce 差异] 传入全局配置(z-index 基准),否则 ElMessage/ElDialog 会被面板 layer 遮挡
                    if (window.ElementPlus) app.use(ElementPlus, BTP.config.elementPlusOptions || {});
                    // 注册 BTP 组件库(BTPButton/BTPInput/...)
                    if (window.BTPComponents) {
                        Object.keys(window.BTPComponents).forEach(function (name) {
                            app.component(name, window.BTPComponents[name]);
                        });
                    }
                    var container = typeof el === 'string' ? document.querySelector(el) : el;
                    app.mount(container);
                });
                return this;
            }
        };
    };

    /* ================= 3. 主题跟随(读取面板当前主题) ================= */
    var WHITE = { r: 255, g: 255, b: 255 }, BLACK = { r: 0, g: 0, b: 0 };
    var LIGHT_RATIOS = { 3: 0.3, 5: 0.5, 7: 0.7, 8: 0.8, 9: 0.9 };
    var DARK_LIGHT_RATIOS = { 3: 0.15, 5: 0.25, 7: 0.35, 8: 0.45, 9: 0.55 };
    var DARK_MODE_DARK_RATIOS = { 2: 0.3 };
    var RADIUS_MAP = {
        none: ['0px', '0px', '0px', '0px', '0px', '0px', '50px'],
        smaller: ['2px', '2px', '2px', '4px', '6px', '4px', '25px'],
        small: ['2px', '4px', '6px', '8px', '12px', '20px', '50px'],
        medium: ['4px', '6px', '8px', '12px', '16px', '24px', '50px'],
        large: ['6px', '8px', '12px', '16px', '20px', '28px', '50px']
    };
    var RADIUS_NAMES = ['small', 'base', 'medium', 'large', 'extra-large', 'round', 'extra-round'];
    function parseColor(str) {
        str = (str || '').trim();
        if (!str) return null;
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
    function mixColors(c1, c2, ratio) {
        return {
            r: Math.round(c1.r * (1 - ratio) + c2.r * ratio),
            g: Math.round(c1.g * (1 - ratio) + c2.g * ratio),
            b: Math.round(c1.b * (1 - ratio) + c2.b * ratio)
        };
    }
    function rgbToHex(c) { return '#' + ((1 << 24) + (c.r << 16) + (c.g << 8) + c.b).toString(16).slice(1); }
    function panelDocument() { try { return (window.parent && window.parent.document) || document; } catch (e) { return document; } }
    function readPanelColor() {
        var color = '';
        try { color = getComputedStyle(panelDocument().documentElement).getPropertyValue('--el-color-primary'); } catch (e) { }
        color = (color || '').trim();
        if (!color) {
            var theme = window.vite_public_panel_theme || {};
            color = (theme.theme && theme.theme.color) || '';
        }
        return color || '#20a53a';
    }
    function readPanelRadius() {
        var theme = window.vite_public_panel_theme || {};
        var r = (theme.interface && theme.interface.rounded) || '';
        return RADIUS_MAP[r] ? r : 'medium';
    }
    var themeState = { isDark: false, color: '#20a53a', radius: 'medium' };
    var themeListeners = [];
    function applyThemeVars() {
        var root = document.documentElement;
        var vars = {};
        var c = parseColor(themeState.color);
        if (c) {
            var lr = themeState.isDark ? DARK_LIGHT_RATIOS : LIGHT_RATIOS;
            vars['--btp-primary'] = themeState.color;
            vars['--btp-primary-dark-2'] = rgbToHex(mixColors(c, themeState.isDark ? WHITE : BLACK, themeState.isDark ? DARK_MODE_DARK_RATIOS[2] : 0.2));
            Object.keys(lr).forEach(function (k) {
                vars['--btp-primary-light-' + k] = rgbToHex(mixColors(c, themeState.isDark ? BLACK : WHITE, lr[k]));
            });
        }
        var vals = RADIUS_MAP[themeState.radius] || RADIUS_MAP.medium;
        RADIUS_NAMES.forEach(function (nm, i) { vars['--btp-radius-' + nm] = vals[i]; });
        vars['--btp-radius-circle'] = '100%';
        Object.keys(vars).forEach(function (k) { root.style.setProperty(k, vars[k]); });
    }
    function themeRefresh(colorHint) {
        themeState.isDark = document.documentElement.classList.contains('dark');
        themeState.color = colorHint || readPanelColor();
        themeState.radius = readPanelRadius();
        applyThemeVars();
        var snap = { isDark: themeState.isDark, color: themeState.color, radius: themeState.radius };
        themeListeners.slice().forEach(function (cb) { try { cb(snap); } catch (e) { } });
    }
    window.addEventListener('message', function (ev) {
        var d = ev.data;
        if (d && d.type === 'theme-change') themeRefresh(d.color);
    });
    if (window.MutationObserver) {
        new MutationObserver(function () { themeRefresh(); })
            .observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme'] });
    }
    try {
        var ts = panelDocument().getElementById('bt-theme-colors');
        if (ts && window.MutationObserver) {
            new MutationObserver(function () { themeRefresh(); })
                .observe(ts, { childList: true, characterData: true, subtree: true });
        }
    } catch (e) { }
    themeRefresh();
    BTP.theme = {
        isDark: function () { return themeState.isDark; },
        color: function () { return themeState.color; },
        radius: function () { return themeState.radius; },
        onChange: function (cb) { if (typeof cb === 'function') themeListeners.push(cb); return BTP.theme; },
        refresh: function () { themeRefresh(); return BTP.theme; }
    };

    /* ================= 4. 组件 API(基于 ElementPlus) ================= */
    BTP.msg = function (msg, type, options) {
        if (window.ElementPlus && ElementPlus.ElMessage) {
            // [btwaf_ce 差异] 显式抬高 z-index,避免被面板 layer(约 19891014)遮挡
            ElementPlus.ElMessage(Object.assign({
                message: msg,
                type: type || 'info',
                duration: 2600,
                zIndex: BTP.config.msgZIndex || 30000000
            }, options || {}));
        } else {
            alert('[BTP.msg] ' + msg);
        }
    };
    BTP.confirm = function (opts) {
        if (window.ElementPlus && ElementPlus.ElMessageBox) {
            return ElementPlus.ElMessageBox.confirm(opts.content || '', opts.title || '提示', {
                confirmButtonText: opts.okText || '确定',
                cancelButtonText: opts.cancelText || '取消',
                type: opts.type || 'warning'
            }).then(function () { return true; }).catch(function () { return false; });
        }
        return Promise.resolve(window.confirm(opts.content || ''));
    };
    BTP.loading = function (text) {
        if (window.ElementPlus && ElementPlus.ElLoading) {
            return ElementPlus.ElLoading.service({ text: text || '加载中...', background: 'rgba(0,0,0,.3)' });
        }
        return { close: function () { } };
    };
    BTP.dialog = function () {
        // 模板中直接使用 <el-dialog> 组件即可;此方法保留为 JS 方式创建对话框
        if (window.ElementPlus && ElementPlus.ElMessageBox) {
            return ElementPlus.ElMessageBox.alert('', '', {});
        }
        return null;
    };
    /* =====================================================================
     * [btwaf_ce 差异 · 必须保留] 请求封装
     * 与 Demo/framework/btp.js 的差异:
     *   1) 增加面板 CSRF 头 x-http-token：window.vite_public_request_token
     *      → #request_token_head 元素的 token 属性 → cookie request_token_head；
     *   2) 统一响应处理：{status:false} 一律 ElMessage 报错并 reject（err.__msgShown=true，
     *      调用方不必重复提示）；非 JSON / HTTP 异常 / 超时同样统一提示；
     *   3) 统一超时（默认 BTP.config.requestTimeout=60000ms），POST form-urlencoded。
     * 说明：面板插件页由 layer 注入面板主文档执行，因此这里能直接读到面板的 token。
     * ===================================================================== */
    function readCookie(name) {
        try {
            var m = document.cookie.match(new RegExp('(^| )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
            return m ? decodeURIComponent(m[2]) : '';
        } catch (e) { return ''; }
    }
    // 读取面板 CSRF token（按契约优先级）
    function csrfToken() {
        var t = '';
        try { t = window.vite_public_request_token || ''; } catch (e) { }
        if (t) return String(t);
        try {
            var el = document.getElementById('request_token_head');
            if (el) t = el.getAttribute('token') || el.getAttribute('data-token') || '';
        } catch (e) { }
        if (t) return String(t);
        return readCookie('request_token_head');
    }
    // 统一的失败提示 + 生成带标记的错误（避免上层重复弹 ElMessage）
    function requestFail(msg, extra) {
        var err = new Error(msg);
        err.__msgShown = true;
        if (extra) { try { Object.keys(extra).forEach(function (k) { err[k] = extra[k]; }); } catch (e) { } }
        try { BTP.msg(msg, 'error'); } catch (e) { }
        return err;
    }
    BTP.csrf = csrfToken;
    BTP.request = function (plugin, fun, data, options) {
        options = options || {};
        var timeout = options.timeout || BTP.config.requestTimeout || 60000;
        return new Promise(function (resolve, reject) {
            var url = '/plugin?action=a&s=' + encodeURIComponent(fun) + '&name=' + encodeURIComponent(plugin);
            var xhr = new XMLHttpRequest();
            xhr.open('POST', url, true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.timeout = timeout;
            var token = csrfToken();
            if (token) xhr.setRequestHeader('x-http-token', token);
            var body = Object.keys(data || {}).map(function (k) {
                var v = data[k];
                if (v === undefined || v === null) v = '';
                return encodeURIComponent(k) + '=' + encodeURIComponent(v);
            }).join('&');
            xhr.onload = function () {
                var r = null;
                try { r = JSON.parse(xhr.responseText); } catch (e) {
                    return reject(requestFail('接口响应解析失败（HTTP ' + xhr.status + '）', { httpStatus: xhr.status }));
                }
                if (!r || typeof r !== 'object') {
                    return reject(requestFail('接口响应格式异常'));
                }
                if (r.status === false) {
                    return reject(requestFail(r.msg || '操作失败', { apiStatus: false, apiMsg: r.msg }));
                }
                resolve(r);
            };
            xhr.onerror = function () { reject(requestFail('网络请求失败，请检查面板连接')); };
            xhr.ontimeout = function () { reject(requestFail('请求超时（' + Math.round(timeout / 1000) + ' 秒），请稍后重试')); };
            xhr.send(body);
        });
    };

    window.BTP = BTP;
})(window, document);
