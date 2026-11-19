/*! btwaf_ce 控制台模板：monitor */
(function (window) {
    'use strict';
    var WAF = window.WAF = window.WAF || {};
    WAF.tpl = WAF.tpl || {};

    WAF.tpl.top = `
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

    WAF.tpl.overview = `
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

    WAF.tpl.logs = `
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

    WAF.tpl.blocks = `
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

    WAF.tpl.oplogs = `
<section class="waf-view" v-show="view === 'oplogs'">
    <div class="waf-view-head">
        <div class="waf-view-title">操作日志</div>
        <div class="waf-view-tools">
            <el-button size="small" :loading="opLogLoading" @click="loadOpLogs">刷新</el-button>
            <el-button link type="danger" size="small" @click="clearOpLogs">清空</el-button>
        </div>
    </div>
    <div class="waf-error" v-if="errors.oplogs">
        <span>{{ errors.oplogs }}</span>
        <el-button link type="primary" size="small" @click="loadOpLogs">重试</el-button>
    </div>
    <div class="waf-filters">
        <el-date-picker v-model="opLogFilter.date" type="date" value-format="YYYY-MM-DD" size="small" clearable popper-class="waf-popper" style="width:150px"></el-date-picker>
        <el-input v-model="opLogFilter.keyword" placeholder="操作内容关键字" size="small" clearable style="width:220px" @keyup.enter="opLogSearch"></el-input>
        <el-button size="small" type="primary" @click="opLogSearch">查询</el-button>
        <el-button size="small" @click="opLogReset">重置</el-button>
    </div>
    <el-table :data="opLogs" size="small" border v-loading="opLogLoading" empty-text="暂无操作日志">
        <el-table-column label="时间" width="170">
            <template #default="s"><span class="waf-mono">{{ fmtTime(s.row.time) }}</span></template>
        </el-table-column>
        <el-table-column label="操作内容" min-width="420">
            <template #default="s"><span class="waf-sub">{{ s.row.content }}</span></template>
        </el-table-column>
    </el-table>
    <div class="waf-pager">
        <el-pagination background small layout="total, sizes, prev, pager, next" :total="opLogTotal" :page-size="opLogRows" :current-page="opLogPage" :page-sizes="[10, 20, 50, 100]" @current-change="onOpLogPageChange" @size-change="onOpLogSizeChange"></el-pagination>
    </div>
</section>
`;

})(window);
