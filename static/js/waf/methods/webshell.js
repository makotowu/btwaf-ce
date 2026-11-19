/*! btwaf_ce 控制台方法：webshell */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.methods = WAF.methods || {};
    var errText = WAF.util.errText;

    WAF.methods.loadWebshell = async function () {
        this.webshell.loading = true;
        this.errors.webshell = '';
        try {
            var d = await WafAPI.data('get_webshell_status');
            d = d || {};
            this.webshell.engine = d.engine || {};
            this.webshell.rules = d.rules || {};
            this.webshell.sites = d.sites || [];
            if (!this.webshell.site && this.webshell.sites.length) this.webshell.site = this.webshell.sites[0].site_name;
            this.webshell.job = d.job || {};
            if (d.job && d.job.id && d.job.status === 'running') this.scheduleWebshellPoll();
            this.loaded.webshell = true;
        } catch (e) {
            this.errors.webshell = errText(e);
            this.stopWebshellPoll();
        } finally {
            this.webshell.loading = false;
        }
    };

    WAF.methods.webshellStatusText = function (job) {
        var status = (job && job.status) || '';
        if (status === 'running') return '扫描中';
        if (status === 'done') return '扫描完成';
        if (status === 'failed') return '扫描失败';
        if (status === 'cancelled') return '已取消';
        return '暂无扫描';
    };

    WAF.methods.scheduleWebshellPoll = function () {
        var self = this;
        this.stopWebshellPoll();
        if (this.view !== 'webshell') return;
        this.webshellTimer = setTimeout(async function () {
            try {
                var d = await WafAPI.data('get_webshell_scan');
                if (d && d.id) self.webshell.job = d;
                if (d && d.status === 'running') self.scheduleWebshellPoll();
                else self.stopWebshellPoll();
            } catch (e) {
                self.stopWebshellPoll();
            }
        }, 2000);
    };

    WAF.methods.stopWebshellPoll = function () {
        if (this.webshellTimer) {
            clearTimeout(this.webshellTimer);
            this.webshellTimer = null;
        }
    };

    WAF.methods.startWebshellScan = async function () {
        if (!this.webshell.site || this.webshellRunning) return;
        this.webshell.starting = true;
        this.errors.webshell = '';
        try {
            var d = await WafAPI.data('start_webshell_scan', { site_name: this.webshell.site });
            this.webshell.job = d || {};
            this.scheduleWebshellPoll();
        } catch (e) {
            if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
        } finally {
            this.webshell.starting = false;
        }
    };

    WAF.methods.cancelWebshellScan = async function () {
        if (!this.webshellRunning) return;
        this.webshell.cancelling = true;
        try {
            var d = await WafAPI.data('cancel_webshell_scan');
            if (d && d.id) this.webshell.job = d;
            this.stopWebshellPoll();
        } catch (e) {
            if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
        } finally {
            this.webshell.cancelling = false;
        }
    };

    WAF.methods.installWebshellEngine = async function () {
        var self = this;
        var manager = this.webshell.engine.manager || 'apt';
        var ok = await this.showConfirm('安装 YARA 引擎', '将通过 ' + manager + ' 安装 yara，会修改系统软件包。确定继续？');
        if (!ok) return;
        this.webshell.installing = true;
        try {
            await WafAPI.data('install_webshell_engine', {}, { timeout: 300000 });
            BTP.msg('YARA 引擎已安装', 'success');
            await this.loadWebshell();
        } catch (e) {
            if (!e || !e.__msgShown) BTP.msg(errText(e), 'error');
        } finally {
            this.webshell.installing = false;
        }
    };
})(window);
