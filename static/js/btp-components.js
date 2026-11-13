/*!
 * BTP.js 组件库  btp-components.js  v3
 * =====================================================================
 * 对齐宝塔面板自定义组件(BtButton/BtInput/BtTable/...)的 Vue 组件库。
 * 底层为 Element Plus 2.14.x(与面板同源,本地 vendor 引入),DOM 与面板一致。
 *
 * 组件名与面板 Bt* 组件一一对应(去掉 Bt 前缀、转 kebab-case):
 *   <bt-button type="success">保存</bt-button>
 *   <bt-input v-model="form.name" placeholder="名称"/>
 *   <bt-select v-model="form.env" :options="envs"/>
 *   <bt-table :data="rows" :columns="cols"/>
 *   <bt-dialog v-model="visible" title="标题">...</bt-dialog>
 *
 * 说明:
 *  - 透传组件(bt-button/bt-card/bt-alert/bt-switch/...)= el-* 组件别名,零差异
 *  - 定制组件(bt-input/bt-select/bt-checkbox/bt-radio/bt-table/bt-dialog/bt-tabs...)
 *    对齐面板 props/行为,并附加面板差异类(bt-dialog / bt-tabs / bt-multiple-select)
 * ===================================================================== */
(function (window) {
    'use strict';

    BTP.ready(function () {
        var comps = {};

        /* ---------- 工具:生成 el-* 别名组件(透传 attrs + 所有插槽,可选附加 bt- 类) ---------- */
        function passthrough(name, elTag, extraClass) {
            var cls = extraClass ? ' :class="' + extraClass + '"' : '';
            return {
                name: name,
                inheritAttrs: false,
                template: '<' + elTag + ' v-bind="$attrs"' + cls +
                    '><template v-for="(_, s) in $slots" #[s]="scope"><slot :name="s" v-bind="scope || {}"></slot></template></' + elTag + '>'
            };
        }

        /* ---------- 1. 直接透传组件(面板 BtXxx = el-xxx 别名) ---------- */
        var passthroughs = {
            'bt-button': 'el-button',
            'bt-button-group': 'el-button-group',
            'bt-btn-group': 'el-button-group',
            'bt-card': 'el-card',
            'bt-alert': 'el-alert',
            'bt-tag': 'el-tag',
            'bt-switch': 'el-switch',
            'bt-link': 'el-link',
            'bt-divider': 'el-divider',
            'bt-empty': 'el-empty',
            'bt-avatar': 'el-avatar',
            'bt-badge': 'el-badge',
            'bt-skeleton': 'el-skeleton',
            'bt-skeleton-item': 'el-skeleton-item',
            'bt-progress': 'el-progress',
            'bt-rate': 'el-rate',
            'bt-slider': 'el-slider',
            'bt-steps': 'el-steps',
            'bt-step': 'el-step',
            'bt-carousel': 'el-carousel',
            'bt-carousel-item': 'el-carousel-item',
            'bt-collapse': 'el-collapse',
            'bt-collapse-item': 'el-collapse-item',
            'bt-descriptions': 'el-descriptions',
            'bt-descriptions-item': 'el-descriptions-item',
            'bt-timeline': 'el-timeline',
            'bt-timeline-item': 'el-timeline-item',
            'bt-scrollbar': 'el-scrollbar',
            'bt-image': 'el-image',
            'bt-tooltip': 'el-tooltip',
            'bt-popover': 'el-popover',
            'bt-dropdown': 'el-dropdown',
            'bt-container': 'el-container',
            'bt-header': 'el-header',
            'bt-aside': 'el-aside',
            'bt-main': 'el-main',
            'bt-footer': 'el-footer',
            'bt-pagination': 'el-pagination',
            'bt-tree': 'el-tree',
            'bt-autocomplete': 'el-autocomplete',
            'bt-cascader': 'el-cascader',
            'bt-cascader-panel': 'el-cascader-panel',
            'bt-date-picker': 'el-date-picker',
            'bt-time-picker': 'el-time-picker',
            'bt-time-select': 'el-time-select',
            'bt-tree-select': 'el-tree-select',
            'bt-select-v2': 'el-select-v2',
            'bt-upload': 'el-upload',
            'bt-input-number': 'el-input-number',
            'bt-form': 'el-form',
            'bt-form-item': 'el-form-item',
            'bt-tab-pane': 'el-tab-pane',
            'bt-table-column': 'el-table-column',
            'bt-radio-group': 'el-radio-group',
            'bt-checkbox-group': 'el-checkbox-group',
            'bt-option': 'el-option',
            'bt-option-group': 'el-option-group',
            'bt-radio-button': 'el-radio-button',
            'bt-checkbox-button': 'el-checkbox-button'
        };
        Object.keys(passthroughs).forEach(function (name) {
            comps[name] = passthrough(name, passthroughs[name]);
        });

        // 带面板差异类的透传组件
        comps['bt-tabs'] = passthrough('bt-tabs', 'el-tabs', "{'bt-tabs': true}");
        comps['bt-popover'] = passthrough('bt-popover', 'el-popover', "{'bt-popover': true}");

        /* ---------- 2. bt-input(对齐面板 BtInput:width/icon + el-input) ---------- */
        comps['bt-input'] = {
            name: 'bt-input',
            inheritAttrs: false,
            props: {
                modelValue: { type: [String, Number], default: '' },
                width: { type: [String, Number], default: '100%' }
            },
            emits: ['update:modelValue', 'input', 'change', 'focus', 'blur'],
            computed: {
                val: {
                    get() { return this.modelValue; },
                    set(v) { this.$emit('update:modelValue', v); this.$emit('input', v); }
                }
            },
            template: '<el-input v-model="val" :style="{width: width}" v-bind="$attrs" @focus="$emit(\'focus\', $event)" @blur="$emit(\'blur\', $event)" @change="$emit(\'change\', $event)"></el-input>'
        };

        /* ---------- 3. bt-input-search(对齐面板 BtInputSearch:回车/清空触发 search) ---------- */
        comps['bt-input-search'] = {
            name: 'bt-input-search',
            inheritAttrs: false,
            props: {
                modelValue: { type: [String, Number], default: '' },
                clearable: { type: Boolean, default: true },
                placeholder: { type: String, default: '' },
                width: { type: [String, Number], default: '240px' }
            },
            emits: ['update:modelValue', 'search'],
            computed: {
                val: {
                    get() { return this.modelValue; },
                    set(v) { this.$emit('update:modelValue', v); }
                }
            },
            template: '<el-input v-model="val" :placeholder="placeholder" :clearable="clearable" :style="{width: width}" v-bind="$attrs" @keyup.enter="$emit(\'search\', val)" @clear="$emit(\'search\', \'\')"><template #append><el-button @click="$emit(\'search\', val)"><i class="el-icon"><svg viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg" width="14" height="14"><path fill="currentColor" d="m795.904 750.72 124.992 124.928a32 32 0 0 1-45.248 45.248L750.72 795.904a416 416 0 1 1 45.248-45.248zM480 832a352 352 0 1 0 0-704 352 352 0 0 0 0 704z"/></svg></i></el-button></template></el-input>'
        };

        /* ---------- 4. bt-select(对齐面板 BtSelect:多选加 bt-multiple-select,支持 options) ---------- */
        comps['bt-select'] = {
            name: 'bt-select',
            inheritAttrs: false,
            props: {
                modelValue: { default: null },
                options: { type: Array, default: function () { return []; } },
                placeholder: { type: String, default: '请选择' },
                multiple: { type: Boolean, default: false },
                clearable: { type: Boolean, default: false },
                disabled: { type: Boolean, default: false },
                width: { type: [String, Number], default: '' }
            },
            emits: ['update:modelValue', 'change'],
            computed: {
                val: {
                    get() { return this.modelValue; },
                    set(v) { this.$emit('update:modelValue', v); this.$emit('change', v); }
                }
            },
            template: '<el-select :class="{\'bt-multiple-select\': multiple}" :style="width ? {width: width} : {}" v-model="val" :placeholder="placeholder" :multiple="multiple" :clearable="clearable" :disabled="disabled" v-bind="$attrs"><el-option v-for="(o, i) in options" :key="typeof o === \'object\' ? o.value : o" :label="typeof o === \'object\' ? o.label : o" :value="typeof o === \'object\' ? o.value : o" :disabled="typeof o === \'object\' ? o.disabled : false"></el-option><slot></slot></el-select>'
        };

        /* ---------- 5. bt-checkbox(对齐面板 BtCheckbox:options 数组) ---------- */
        comps['bt-checkbox'] = {
            name: 'bt-checkbox',
            inheritAttrs: false,
            props: {
                modelValue: { type: Array, default: function () { return []; } },
                options: { type: Array, default: function () { return []; } }
            },
            emits: ['update:modelValue', 'change'],
            computed: {
                val: {
                    get() { return this.modelValue; },
                    set(v) { this.$emit('update:modelValue', v); this.$emit('change', v); }
                }
            },
            template: '<el-checkbox-group v-model="val" v-bind="$attrs"><el-checkbox v-for="(o, i) in options" :key="i" :value="typeof o === \'object\' ? o.value : o" :disabled="typeof o === \'object\' ? !!o.disabled : false">{{ typeof o === \'object\' ? o.label : o }}</el-checkbox><slot></slot></el-checkbox-group>'
        };

        /* ---------- 6. bt-radio(对齐面板 BtRadio:options 数组) ---------- */
        comps['bt-radio'] = {
            name: 'bt-radio',
            inheritAttrs: false,
            props: {
                modelValue: { default: null },
                options: { type: Array, default: function () { return []; } }
            },
            emits: ['update:modelValue', 'change'],
            computed: {
                val: {
                    get() { return this.modelValue; },
                    set(v) { this.$emit('update:modelValue', v); this.$emit('change', v); }
                }
            },
            template: '<el-radio-group v-model="val" v-bind="$attrs"><el-radio v-for="(o, i) in options" :key="i" :value="typeof o === \'object\' ? o.value : o" :disabled="typeof o === \'object\' ? !!o.disabled : false">{{ typeof o === \'object\' ? o.label : o }}</el-radio><slot></slot></el-radio-group>'
        };

        /* ---------- 7. bt-table(对齐面板 BtTable:columns 配置) ---------- */
        comps['bt-table'] = {
            name: 'bt-table',
            inheritAttrs: false,
            props: {
                data: { type: Array, default: function () { return []; } },
                columns: { type: Array, default: function () { return []; } },
                border: { type: Boolean, default: false },
                stripe: { type: Boolean, default: false },
                size: { type: String, default: '' }
            },
            template: '<el-table :data="data" :border="border" :stripe="stripe" :size="size" v-bind="$attrs"><el-table-column v-for="(c, i) in columns" :key="c.prop || i" :prop="c.prop" :label="c.label" :width="c.width" :min-width="c.minWidth" :align="c.align" :fixed="c.fixed"><template v-if="c.slot" #default="scope"><slot :name="c.slot" :row="scope.row" :index="scope.$index"></slot></template></el-table-column><slot></slot></el-table>'
        };

        /* ---------- 8. bt-dialog(对齐面板 BtDialog:el-dialog + bt-dialog + 默认 footer) ---------- */
        comps['bt-dialog'] = {
            name: 'bt-dialog',
            inheritAttrs: false,
            props: {
                modelValue: { type: Boolean, default: false },
                title: { type: String, default: '' },
                width: { type: String, default: '520px' },
                footer: { type: Boolean, default: true },
                confirmText: { type: String, default: '确定' },
                cancelText: { type: String, default: '取消' }
            },
            emits: ['update:modelValue', 'open', 'close', 'closed', 'confirm', 'cancel'],
            computed: {
                val: {
                    get() { return this.modelValue; },
                    set(v) { this.$emit('update:modelValue', v); }
                }
            },
            template: '<el-dialog class="bt-dialog" :title="title" :width="width" v-model="val" v-bind="$attrs" @open="$emit(\'open\')" @close="$emit(\'close\')" @closed="$emit(\'closed\')"><slot></slot><template v-if="footer" #footer><slot name="footer"><el-button @click="val=false; $emit(\'cancel\')">{{ cancelText }}</el-button><el-button type="primary" @click="$emit(\'confirm\')">{{ confirmText }}</el-button></slot></template></el-dialog>'
        };

        /* ---------- 9. bt-help(对齐面板 BtHelp:ul/li 帮助列表) ---------- */
        comps['bt-help'] = {
            name: 'bt-help',
            inheritAttrs: false,
            props: {
                options: { type: Array, default: function () { return []; } },
                listStyle: { type: String, default: 'disc' }
            },
            template: '<ul class="bt-help-list" :style="{\'list-style-type\': listStyle}"><li v-for="(o, i) in options" :key="i"><span v-if="o.isHtml" v-html="o.content"></span><template v-else>{{ o.content || o }}</template></li><slot></slot></ul>'
        };

        /* ---------- 10. bt-page-text(对齐面板 BtPageText:文本分页提示) ---------- */
        comps['bt-page-text'] = {
            name: 'bt-page-text',
            inheritAttrs: false,
            props: { total: { type: Number, default: 0 }, page: { type: Number, default: 1 }, size: { type: Number, default: 10 } },
            template: '<span class="bt-page-text" v-bind="$attrs">共 {{ total }} 条 / 第 {{ page }} 页 / 每页 {{ size }} 条</span>'
        };

        // 注册到 BTP,供 createApp 自动安装
        BTP.__components = comps;
        window.BTPComponents = comps;
    });
})(window);
