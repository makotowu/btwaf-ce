/*!
 * btwaf_ce 前端 API 封装  api.js
 * =====================================================================
 * 唯一后端入口：POST /plugin?action=a&s=<method>&name=btwaf_ce
 *   - header x-http-token 由 btp.js 副本里的 BTP.request 统一附加（CSRF）；
 *   - 参数对象中的对象/数组统一 JSON.stringify 后作为字符串提交（见 docs/API.md §0）；
 *   - 相同请求在途时复用同一个 Promise，防止重复提交/重复拉取；
 *   - 统一超时与错误提示（BTP.request 已弹 {status:false} 的错误，这里不重复弹）；
 *   - 全部返回 docs/API.md 约定的原始响应 {status,msg,data}。
 * ===================================================================== */
(function (window) {
    'use strict';

    var PLUGIN = 'btwaf_ce';
    var DEFAULT_TIMEOUT = 60000;
    var inflight = {};

    /* 参数序列化：对象/数组 -> JSON 字符串；null/undefined -> 空串；其余原样 */
    function serialize(params) {
        var out = {};
        Object.keys(params || {}).forEach(function (k) {
            var v = params[k];
            if (v === undefined) return;
            if (v === null) { out[k] = ''; return; }
            if (typeof v === 'object') {
                try { out[k] = JSON.stringify(v); } catch (e) { out[k] = ''; }
            } else {
                out[k] = v;
            }
        });
        return out;
    }

    function keyOf(method, data) {
        var keys = Object.keys(data).sort();
        return method + '|' + keys.map(function (k) { return k + '=' + data[k]; }).join('&');
    }

    function showError(msg) {
        try {
            if (window.BTP && BTP.msg) BTP.msg(msg, 'error');
            else console.error('[btwaf_ce] ' + msg);
        } catch (e) { }
    }

    /**
     * 调用插件后端。
     * @param {string} method  API 方法名（如 get_overview）
     * @param {object} [params] 参数（对象/数组自动 JSON.stringify）
     * @param {object} [options] { timeout, dedupe, silent }
     * @returns {Promise<{status:boolean,msg:string,data:*}>}
     */
    function call(method, params, options) {
        options = options || {};
        var data = serialize(params);
        var key = keyOf(method, data);
        var dedupe = options.dedupe !== false;

        if (dedupe && inflight[key]) return inflight[key];

        var promise;
        try {
            if (!window.BTP || typeof BTP.request !== 'function') {
                throw new Error('BTP 框架未加载');
            }
            promise = BTP.request(PLUGIN, method, data, { timeout: options.timeout || DEFAULT_TIMEOUT });
        } catch (e) {
            promise = Promise.reject(e);
        }

        promise = promise.then(function (r) {
            if (!r || typeof r !== 'object') throw new Error('接口响应格式异常');
            return r;
        }).catch(function (err) {
            // BTP.request 已对 {status:false}/网络错误弹出提示，这里只补漏
            if (err && !err.__msgShown && !options.silent) {
                showError((err && err.message) || '请求失败');
                if (err) err.__msgShown = true;
            }
            throw err;
        }).then(function (r) {
            delete inflight[key];
            return r;
        }, function (err) {
            delete inflight[key];
            throw err;
        });

        if (dedupe) inflight[key] = promise;
        return promise;
    }

    /* 便捷方法：成功时只返回 data，减少调用方样板代码。
       注意：走 WafAPI.call 属性而不是内部闭包，便于 preview.html 用内联 mock 整体替换。 */
    function data(method, params, options) {
        return window.WafAPI.call(method, params, options).then(function (r) {
            return r && typeof r === 'object' ? r.data : null;
        });
    }

    window.WafAPI = {
        plugin: PLUGIN,
        call: call,
        data: data,
        serialize: serialize,
        pending: function () { return Object.keys(inflight).length; },
        token: function () { try { return window.BTP ? BTP.csrf() : ''; } catch (e) { return ''; } }
    };
})(window);
