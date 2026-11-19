/*! btwaf_ce 控制台模板：webshell */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.tpl = WAF.tpl || {};

    WAF.tpl.webshell = `
    <section class="waf-view" v-show="view === 'webshell'">
        <div class="waf-view-head">
            <div class="waf-view-title">Webshell 查杀</div>
            <div class="waf-view-tools">
                <span v-if="webshell.engine.installed" class="waf-sub">YARA {{ webshell.engine.version }} · {{ webshell.rules.count }} 条规则</span>
                <el-button size="small" :loading="webshell.loading" @click="loadWebshell">重新检测</el-button>
            </div>
        </div>

        <div v-if="errors.webshell" class="waf-error">
            <span>{{ errors.webshell }}</span>
            <el-button link type="primary" size="small" @click="loadWebshell">重试</el-button>
        </div>

        <el-alert v-if="!webshell.loading && !webshell.engine.installed" class="waf-webshell-alert" type="warning" :closable="false" show-icon>
            <div class="waf-webshell-alert-row">
                <span>未安装 YARA 引擎</span>
                <el-button v-if="webshell.engine.install_supported" size="small" type="primary" :loading="webshell.installing" @click="installWebshellEngine">安装引擎</el-button>
                <code v-else>{{ webshell.engine.install_hint }}</code>
            </div>
        </el-alert>
        <el-alert v-else-if="!webshell.loading && !webshell.rules.available" class="waf-webshell-alert" type="error" :closable="false" show-icon
            title="Webshell 规则不可用"></el-alert>

        <div v-if="webshell.engine.installed && webshell.rules.available" class="waf-webshell-toolbar">
            <el-select v-model="webshell.site" size="small" style="width:260px" placeholder="选择站点" :disabled="webshellRunning">
                <el-option v-for="s in webshell.sites" :key="s.site_name" :label="s.site_name" :value="s.site_name"></el-option>
            </el-select>
            <el-button size="small" type="primary" :loading="webshell.starting" :disabled="!webshell.site || webshellRunning" @click="startWebshellScan">开始扫描</el-button>
            <el-button v-if="webshellRunning" size="small" :loading="webshell.cancelling" @click="cancelWebshellScan">停止扫描</el-button>
        </div>

        <div v-if="webshell.job && webshell.job.id" class="waf-webshell-job">
            <div class="waf-webshell-summary">
                <span>{{ webshellStatusText(webshell.job) }}</span>
                <span v-if="webshell.job.site_name" class="waf-sub">{{ webshell.job.site_name }}</span>
                <span v-if="webshell.job.total_files" class="waf-sub">{{ webshell.job.total_files }} 个文件</span>
                <span v-if="webshell.job.matched" class="waf-sub">{{ webshell.job.matched }} 个命中</span>
            </div>
            <el-alert v-if="webshell.job.status === 'failed'" class="waf-webshell-error" type="error" :closable="false" show-icon
                :title="webshell.job.error || '扫描失败'"></el-alert>
            <el-table :data="webshell.job.results || []" size="small" border v-loading="webshellRunning"
                empty-text="未发现可疑文件">
                <el-table-column label="文件" prop="file" min-width="420" show-overflow-tooltip>
                    <template #default="s"><span class="waf-mono">{{ s.row.file }}</span></template>
                </el-table-column>
                <el-table-column label="规则" prop="rule" width="260" show-overflow-tooltip></el-table-column>
            </el-table>
        </div>
    </section>
    `;
})(window);
