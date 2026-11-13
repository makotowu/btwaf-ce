#!/usr/bin/env node
/**
 * btwaf_ce 面板内 E2E 冒烟（需要真实宝塔面板）
 *
 * 环境变量：
 *   BTWAF_PANEL_URL   面板地址，如 http://127.0.0.1:8888/<安全入口>
 *   BTWAF_PANEL_USER  面板账号
 *   BTWAF_PANEL_PASS  面板密码
 *   CHROME_BIN        Chrome/Chromium 可执行文件（缺省尝试常见路径）
 *   BTWAF_CE_VERSION  期望版本（默认 0.1.0）
 *
 * 说明：脚本使用 CDP，不依赖 puppeteer；缺少环境变量或 Chrome 时以 0 退出（跳过）。
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const URL = process.env.BTWAF_PANEL_URL || '';
const USER = process.env.BTWAF_PANEL_USER || '';
const PASS = process.env.BTWAF_PANEL_PASS || '';
const VERSION = process.env.BTWAF_CE_VERSION || '0.1.0';
const CHROME_CANDIDATES = [
  process.env.CHROME_BIN,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].filter(Boolean);
const chrome = CHROME_CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch (e) { return false; } });
if (!URL || !USER || !PASS) {
  console.log('SKIP panel_ui: 未设置 BTWAF_PANEL_URL/USER/PASS');
  process.exit(0);
}
if (!chrome) {
  console.log('SKIP panel_ui: 未找到 Chrome（可设置 CHROME_BIN）');
  process.exit(0);
}

const port = 9333 + Math.floor(Math.random() * 200);
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'btwaf-e2e-'));
const proc = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-sandbox',
  '--remote-debugging-port=' + port, '--user-data-dir=' + profile,
  '--window-size=1600,1000', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function wsUrl() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((x) => x.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch (e) { /* retry */ }
    await sleep(200);
  }
  throw new Error('Chrome CDP 未就绪');
}

const ws = new WebSocket(await wsUrl());
let seq = 0;
const pending = new Map();
let consoleErrors = [];
let failedRequests = [];
const send = (method, params) => new Promise((resolve) => {
  const id = ++seq;
  pending.set(id, resolve);
  ws.send(JSON.stringify({ id, method, params }));
});
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.exceptionThrown') {
    consoleErrors.push((msg.params.exceptionDetails.exception || {}).description || msg.params.exceptionDetails.text);
  }
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
    consoleErrors.push(msg.params.args.map((a) => a.value || a.description || '').join(' '));
  }
  if (msg.method === 'Network.responseReceived' && msg.params.response.status >= 400) {
    failedRequests.push([msg.params.response.status, msg.params.response.url]);
  }
};
await new Promise((r) => (ws.onopen = r));
await send('Page.enable');
await send('Runtime.enable');
await send('Network.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false });

const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  return r.result ? r.result.value : undefined;
};
const failures = [];
const ok = (cond, message) => { if (!cond) failures.push(message); };

try {
  await send('Page.navigate', { url: URL });
  await sleep(5500);
  await evaluate(`(function(){
    const set=(s,v)=>{const e=document.querySelector(s);if(!e)return;const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');d.set.call(e,v);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
    set('input[name=username]', ${JSON.stringify(USER)});
    set('input[name=password]', ${JSON.stringify(PASS)});
    const b=[...document.querySelectorAll('button')].find(x=>x.innerText.trim()==='登录'); if(b)b.click();
  })()`);
  await sleep(7000);

  // 打开旧版软件商店页，调用其 plugin_view 打开插件（与面板真实 layer 流程一致）
  await send('Page.navigate', { url: new globalThis.URL('/software', new globalThis.URL(URL).origin).toString() });
  await sleep(5000);
  const hasView = await evaluate('typeof window.plugin_view');
  ok(hasView === 'object', 'software 页未加载 plugin_view（登录态/页面结构变化）');
  await evaluate(`window.plugin_view.renderPlugin({pluginTitle:'宝塔WAF社区版',pluginName:'btwaf_ce',pluginBuilt:0})`);
  await sleep(9000);

  const state = JSON.parse(await evaluate(`JSON.stringify((()=>{
    const app=document.querySelector('#app'); const layer=document.querySelector('.layui-layer-page.waf-layer-page');
    const main=document.querySelector('#btwaf-ce-app .waf-main'); const nav=document.querySelector('#btwaf-ce-app .waf-nav');
    return {text: app?app.innerText:'', layer: layer?layer.getBoundingClientRect().toJSON():null,
      main: main?{clientH:main.clientHeight,scrollH:main.scrollHeight}:null,
      navTop: nav?nav.getBoundingClientRect().top:null};
  })())`));
  ok(new RegExp('v?' + VERSION.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).test(state.text), `页面版本不是 ${VERSION}`);
  const brand = await evaluate(`(()=>{const e=document.querySelector('#btwaf-ce-app .waf-brand-name');return e?e.innerText.trim():''})()`);
  ok(brand === '宝塔WAF社区版', '品牌名不是 宝塔WAF社区版');
  ok(!!state.layer, '插件 layer 未打开');
  ok(!!state.main && state.main.scrollH >= state.main.clientH, '主内容区不可滚动');
  ok(failedRequests.filter((x) => /btwaf_ce|ico-btwaf_ce/.test(x[1])).length === 0, '存在插件静态资源 404');

  // 主内容滚动时左侧导航不应移动
  const navTopBefore = state.navTop;
  const scroll = JSON.parse(await evaluate(`(()=>{const m=document.querySelector('#btwaf-ce-app .waf-main');m.scrollTop=m.scrollHeight;return JSON.stringify({scrollTop:m.scrollTop,navTop:document.querySelector('#btwaf-ce-app .waf-nav').getBoundingClientRect().top})})()`));
  ok(scroll.scrollTop > 0, '主内容区未产生滚动');
  ok(Math.abs(scroll.navTop - navTopBefore) < 1, '滚动主内容时左侧导航发生了移动');

  // 拦截记录：默认 10 条/页、无开发跳过清单、无 ARGS_ERR
  await evaluate(`(()=>{const el=[...document.querySelectorAll('#btwaf-ce-app .el-menu-item')].find(e=>e.innerText.trim()==='拦截记录');if(el)el.click();})()`);
  await sleep(2600);
  const logs = await evaluate(`(()=>{const a=document.querySelector('#app');return a?a.innerText:''})()`);
  ok(!/指定参数无效|ARGS_ERR/.test(logs), '拦截记录仍出现参数错误');
  ok(/10\s*条\/页/.test(logs), '表格默认不是 10 条/页');
  const noDev = await evaluate(`!document.querySelector('#btwaf-ce-app .waf-skips') && (document.querySelector('#app') ? document.querySelector('#app').innerText : '').indexOf('未移植 / 跳过规则清单') < 0`);
  ok(noDev, '仍存在开发期跳过规则清单');
  const adv = await evaluate(`(()=>{const el=document.querySelector('#btwaf-ce-app .waf-advanced');return !!(el && el.querySelector('.el-collapse-item__header'))})()`);
  ok(adv, '缺少高级信息折叠区');
  const siteText = await evaluate(`(()=>{const el=[...document.querySelectorAll('#btwaf-ce-app .el-menu-item')].find(e=>e.innerText.trim()==='网站防护');if(!el)return '';el.click();return 'ok'})()`);
  ok(siteText === 'ok', '缺少「网站防护」入口');

  // 系统诊断：横幅与检测项状态一致
  await evaluate(`(()=>{const el=[...document.querySelectorAll('#btwaf-ce-app .el-menu-item')].find(e=>e.innerText.trim()==='系统诊断');if(el)el.click();})()`);
  await sleep(2200);
  const diag = await evaluate(`(()=>{const b=document.querySelector('#btwaf-ce-app .waf-env-banner');const rows=[...document.querySelectorAll('#btwaf-ce-app .el-table__row')];return JSON.stringify({banner:b?b.innerText:'',rows:rows.length})})()`);
  const d = JSON.parse(diag || '{}');
  ok(!!d.banner, '系统诊断缺少状态横幅');

  if (consoleErrors.length) failures.push('控制台错误：' + consoleErrors.slice(0, 3).join(' | '));
} catch (e) {
  failures.push('E2E 异常：' + (e && e.stack ? e.stack : e));
} finally {
  try { ws.close(); } catch (e) { }
  try { proc.kill(); } catch (e) { }
  try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { }
}

if (failures.length) {
  console.error('FAIL panel_ui');
  failures.forEach((f) => console.error(' - ' + f));
  process.exit(1);
}
console.log('PASS panel_ui: 打开/滚动/导航固定/拦截记录/诊断均正常');
