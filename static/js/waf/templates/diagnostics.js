/*! btwaf_ce 控制台模板：diagnostics */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.tpl = WAF.tpl || {};

    WAF.tpl.diagnostics = `
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
                <el-descriptions-item label="Web 服务器">{{ status.nginx.name || 'Nginx' }} {{ status.nginx.version || '' }}<br><span class="waf-sub">{{ status.nginx.bin || '-' }}</span></el-descriptions-item>
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
</section>
`;

    WAF.tpl.dialogs = `
    </main>
</div>

<el-dialog v-model="siteLogVisible" :title="siteLogSite ? siteLogSite + ' 日志' : '站点日志'" width="900px" append-to-body class="waf-dialog">
    <div class="waf-teleport waf-dialog-body">
        <div class="waf-filters">
            <el-select v-model="siteLogDate" size="small" style="width:160px" @change="siteLogDateChange">
                <el-option v-for="d in siteLogDates" :key="d" :label="d" :value="d"></el-option>
            </el-select>
            <el-button size="small" :loading="siteLogLoading" @click="loadSiteLogs">刷新</el-button>
        </div>
        <div class="waf-error" v-if="siteLogError">
            <span>{{ siteLogError }}</span>
            <el-button link type="primary" size="small" @click="loadSiteLogs">重试</el-button>
        </div>
        <el-table :data="siteLogList" size="small" border stripe v-loading="siteLogLoading" empty-text="暂无日志" @row-click="openLogDetail" class="waf-clickable-table">
            <el-table-column label="时间" width="150">
                <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
            </el-table-column>
            <el-table-column label="IP / 归属" min-width="160">
                <template #default="s">
                    <div class="waf-cell-stack">
                        <span class="waf-mono">{{ s.row.ip }}</span>
                        <span class="waf-sub waf-ellipsis">{{ s.row.area || '-' }}</span>
                    </div>
                </template>
            </el-table-column>
            <el-table-column label="请求" min-width="220">
                <template #default="s"><span class="waf-mono waf-ellipsis">{{ (s.row.method || '') + ' ' + (s.row.uri || '') }}</span></template>
            </el-table-column>
            <el-table-column label="命中规则" min-width="180">
                <template #default="s"><span class="waf-sub waf-ellipsis">{{ hitsText(s.row.hits) }}</span></template>
            </el-table-column>
            <el-table-column label="动作" width="88">
                <template #default="s"><el-tag size="small" :type="actionTag(s.row.action)">{{ actionLabel(s.row.action) }}</el-tag></template>
            </el-table-column>
        </el-table>
        <div class="waf-pager">
            <el-pagination background small layout="total, sizes, prev, pager, next" :total="siteLogTotal" :page-size="siteLogRows" :current-page="siteLogPage" :page-sizes="[10, 20, 50, 100]" @current-change="onSiteLogPageChange" @size-change="onSiteLogSizeChange"></el-pagination>
        </div>
    </div>
</el-dialog>

<el-dialog v-model="logDetailVisible" title="命中详情" width="760px" append-to-body class="waf-dialog">
    <div v-if="logDetail" class="waf-detail waf-teleport waf-dialog-body">
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
            <el-descriptions-item label="地区">{{ countryLabel(logDetail.country) }}</el-descriptions-item>
            <el-descriptions-item label="原因">{{ logDetail.reason || (logDetail.action === 'geo' ? '地区限制' : '-') }}</el-descriptions-item>
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
    </div>
    <template #footer>
        <div v-if="logDetail" class="waf-dialog-actions">
            <el-button size="small" type="danger" plain @click="addIpToList(logDetail, 'ip_black')">加入 IP 黑名单</el-button>
            <el-button size="small" type="warning" plain @click="addIpToList(logDetail, 'ip_white')">加入 IP 白名单</el-button>
            <el-button size="small" @click="unbanLogIp(logDetail)">解封该 IP</el-button>
        </div>
    </template>
</el-dialog>

<el-dialog v-model="siteDialog.visible" :title="'站点防护配置 · ' + siteDialog.site_name" width="900px" append-to-body class="waf-dialog" :before-close="beforeCloseSite">
    <div v-loading="siteDialog.loading" class="waf-site-dialog waf-teleport waf-dialog-body waf-dialog-body-tall">
        <el-tabs v-model="siteDialog.tab" class="waf-tabs">
            <el-tab-pane lazy label="基础" name="basic">
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
                    <el-form-item label="拦截状态码（0=继承）">
                        <el-input-number v-model="siteDialog.config.block.status" :min="0" :max="599" size="small" controls-position="right"></el-input-number>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane lazy label="模块" name="modules">
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

            <el-tab-pane lazy label="地区访问" name="geo">
                <el-form label-width="150px" size="small" class="waf-form">
                    <el-form-item label="本站点地区控制">
                        <el-select v-model="siteTri.geo_open" size="small" style="width:170px">
                            <el-option v-for="o in triOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="模式">
                        <el-select v-model="siteTri.geo_mode" size="small" style="width:220px">
                            <el-option label="继承全局" value="inherit"></el-option>
                            <el-option v-for="o in geoModeOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="地区">
                        <el-checkbox-group v-model="siteDialog.config.geo.regions">
                            <el-checkbox v-for="o in geoRegionOptions" :key="o.value" :label="o.value">{{ o.label }}</el-checkbox>
                        </el-checkbox-group>
                    </el-form-item>
                    <el-form-item label="未识别 IP / 内网">
                        <el-select v-model="siteTri.geo_unknown" size="small" style="width:170px">
                            <el-option label="继承全局" value="inherit"></el-option>
                            <el-option v-for="o in geoUnknownOptions" :key="o.value" :label="o.label" :value="o.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="拦截状态码">
                        <el-select v-model="siteDialog.config.geo.status" size="small" style="width:150px">
                            <el-option label="继承全局" :value="0"></el-option>
                            <el-option v-for="v in blockStatusOptions" :key="v" :label="String(v)" :value="v"></el-option>
                        </el-select>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane lazy label="CC / 攻击拦截" name="cc">
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

            <el-tab-pane lazy label="CDN" name="cdn">
                <el-alert v-if="panelCdnOpen()" type="warning" :closable="false" show-icon
                    :title="'面板已开启 CDN 真实 IP 解析（' + (siteDialog.panelCdn.scope === 'site' ? '站点' : '全局') + '，Header=' + (siteDialog.panelCdn.header || '-') + '），插件站点 CDN 设置暂不生效'"></el-alert>
                <el-form label-width="130px" size="small" class="waf-form">
                    <el-form-item label="CDN 预设">
                        <el-select v-model="siteDialog.cdnPreset" size="small" style="width:220px" :disabled="panelCdnOpen()" @change="applyCdnPreset">
                            <el-option v-for="p in cdnPresets" :key="p.value" :label="p.label" :value="p.value"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="CDN 模式"><el-switch v-model="siteDialog.config.cdn.open" :disabled="panelCdnOpen()"></el-switch></el-form-item>
                    <el-form-item label="真实 IP 头">
                        <el-input v-model="siteText.cdn_headers" type="textarea" :rows="4" class="waf-mono" :disabled="panelCdnOpen()" placeholder="一行一个请求头，如 cf-connecting-ip"></el-input>
                    </el-form-item>
                    <el-form-item label="可信代理 IP">
                        <el-input v-model="siteText.cdn_trusted" type="textarea" :rows="4" class="waf-mono" :disabled="panelCdnOpen()" placeholder="一行一个 IP / CIDR / IP 范围"></el-input>
                    </el-form-item>
                </el-form>
            </el-tab-pane>

            <el-tab-pane lazy label="黑白名单" name="lists">
                <div class="waf-list-editor">
                    <el-select v-model="siteListType" size="small" style="width:180px">
                        <el-option v-for="m in listMeta" :key="m.key" :label="m.label" :value="m.key"></el-option>
                    </el-select>
                    <el-upload v-if="isIpList(siteListType)" :auto-upload="false" :show-file-list="false" accept=".txt,text/plain" :on-change="onImportSiteList">
                        <el-button size="small" :loading="listImporting">导入</el-button>
                    </el-upload>
                    <el-button v-if="isIpList(siteListType)" size="small" @click="exportSiteList">导出</el-button>
                </div>
                <el-input v-model="siteText[siteListType]" type="textarea" :rows="10" class="waf-mono" placeholder="一行一条"></el-input>
            </el-tab-pane>

            <el-tab-pane lazy label="敏感路径 / 后缀" name="paths">
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

            <el-tab-pane lazy label="绑定自定义规则" name="custom">
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
        <div class="waf-dialog-footer-actions">
            <el-button size="small" @click="closeSiteDialog">取消</el-button>
            <el-button size="small" type="primary" :disabled="!siteDialogDirty" :loading="siteDialog.saving" @click="saveSiteConfig">保存站点配置</el-button>
        </div>
    </template>
</el-dialog>

<el-dialog v-model="customDialogVisible" :title="customForm.id ? '编辑自定义规则' : '新增自定义规则'" width="660px" append-to-body class="waf-dialog">
  <div class="waf-teleport waf-dialog-body">
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

<el-dialog v-model="blockPagePreviewVisible" title="拦截页面预览（后端已过滤危险标签）" width="720px" append-to-body class="waf-dialog">
    <div class="waf-teleport waf-dialog-body waf-dialog-body-flush">
        
        <iframe class="waf-preview-frame" sandbox="" :srcdoc="blockPagePreview"></iframe>
    </div>
</el-dialog>

<el-dialog v-model="confirmDialog.visible" :title="confirmDialog.title" width="420px" append-to-body class="waf-dialog" @closed="onConfirmClosed">
    <div class="waf-teleport waf-dialog-body">
        <div class="waf-confirm-text">{{ confirmDialog.content }}</div>
        <el-checkbox v-if="confirmDialog.checkbox" v-model="confirmDialog.checked" style="margin-top:12px">{{ confirmDialog.checkboxLabel }}</el-checkbox>
    </div>
    <template #footer>
        <el-button size="small" @click="onConfirmCancel">取消</el-button>
        <el-button size="small" type="primary" @click="onConfirmOk">确定</el-button>
    </template>
</el-dialog>
`;

})(window);
