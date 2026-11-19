/*! btwaf_ce 控制台模板：manage */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.tpl = WAF.tpl || {};

    WAF.tpl.sites = `
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
        <el-table-column label="操作" width="170" fixed="right">
            <template #default="s">
                <div class="waf-row-actions">
                    <el-button link type="primary" size="small" @click.stop="viewSiteLogs(s.row)">日志</el-button>
                    <el-button size="small" type="primary" plain @click.stop="openSiteDialog(s.row)">配置</el-button>
                </div>
            </template>
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

    WAF.tpl.config = `
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
                    <el-form-item label="From-data">
                        <el-switch v-model="cfg.protocol.from_data"></el-switch>
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
                    <el-upload v-if="isIpList(globalListType)" :auto-upload="false" :show-file-list="false" accept=".txt,text/plain" :on-change="onImportGlobalList">
                        <el-button size="small" :loading="listImporting">导入</el-button>
                    </el-upload>
                    <el-button v-if="isIpList(globalListType)" size="small" @click="exportGlobalList">导出</el-button>
                </div>
                <el-input v-model="globalListText[globalListType]" type="textarea" :rows="10" class="waf-mono" placeholder="一行一条"></el-input>
                <div class="waf-pane-actions">
                    <el-button type="primary" size="small" @click="saveGlobalList(globalListType)">保存该列表</el-button>
                </div>
            </el-tab-pane>

            <el-tab-pane label="地区访问" name="geo">
                <el-form label-width="150px" size="small" class="waf-form">
                    <el-form-item label="地区访问开关"><el-switch v-model="cfg.geo.open"></el-switch></el-form-item>
                    <el-form-item label="模式">
                        <el-radio-group v-model="cfg.geo.mode">
                            <el-radio v-for="o in geoModeOptions" :key="o.value" :label="o.value">{{ o.label }}</el-radio>
                        </el-radio-group>
                    </el-form-item>
                    <el-form-item label="地区">
                        <el-checkbox-group v-model="cfg.geo.regions">
                            <el-checkbox v-for="o in geoRegionOptions" :key="o.value" :label="o.value">{{ o.label }}</el-checkbox>
                        </el-checkbox-group>
                    </el-form-item>
                    <el-form-item label="未识别 IP / 内网">
                        <el-select v-model="cfg.geo.unknown" size="small" style="width:150px">
                            <el-option v-for="o in geoUnknownOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="拦截状态码">
                        <el-select v-model="cfg.geo.status" size="small" style="width:150px">
                            <el-option v-for="v in blockStatusOptions" :key="v" :label="String(v)" :value="v"></el-option>
                        </el-select>
                    </el-form-item>
                </el-form>
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
                        <el-input v-model="trustedText" type="textarea" :rows="4" class="waf-mono" placeholder="一行一个 IP / CIDR / IP 范围，用于获取真实客户端 IP"></el-input>
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

    WAF.tpl.rules = `
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
                <el-select v-model="ruleScope" size="small" style="width:110px" @change="ruleScopeChange">
                    <el-option label="全局" value="global"></el-option>
                    <el-option label="站点" value="site"></el-option>
                </el-select>
                <el-select v-if="ruleScope === 'site'" v-model="ruleSite" size="small" style="width:190px" @change="ruleScopeChange">
                    <el-option v-for="s in siteNames" :key="s" :label="s" :value="s"></el-option>
                </el-select>
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
                <el-table-column label="响应码" width="120">
                    <template #default="s">
                        <el-select :model-value="s.row.status_override || 0" size="small" style="width:100px" @change="setRuleStatus(s.row, $event)">
                            <el-option v-for="o in ruleStatusOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
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

})(window);
