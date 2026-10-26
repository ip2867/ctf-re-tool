// 运行期加固（40 题实测的三类吞吐/浪费问题）：
//   ① 日志面板与工具步骤条 DOM 无上限增长 → 长会话渲染层负担递增（上限+批量裁剪）
//   ② 杀软短暂持锁（CrackMe4 blocked-by-av）→ 同路径延迟重试一次
//   ③ 本地枚举候选全部无效（17 连"候选无效"后整轮放弃）→ 聚合原因生成定向重试提示
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r/g, '');

console.log('[1] 日志面板 DOM 上限');
{
  ok(/const LOG_DOM_LIMIT = 1500/.test(appSrc), '上限常量 1500');
  ok(/const LOG_DOM_TRIM_BATCH = 300/.test(appSrc), '批量裁剪 300（摊销成本）');
  ok(/logOutput\.children\.length > LOG_DOM_LIMIT/.test(appSrc) && /removeChild\(logOutput\.firstChild\)/.test(appSrc), '超限批量移除最旧行');
  ok(/timeline\.jsonl/.test(appSrc) && appSrc.indexOf('timeline.jsonl') < appSrc.indexOf('LOG_DOM_LIMIT') + 2000, 'DOM 裁剪不影响 timeline.jsonl 全量落盘');
}
console.log('\n[2] 工具步骤条 DOM 上限');
{
  const i = appSrc.indexOf("if (container.children.length > 400)");
  ok(i > 0, '上限 400 存在');
  const seg = appSrc.slice(i, i + 500);
  ok(/tool-step-running/.test(seg) && /break/.test(seg), '运行中的行不裁');
  ok(/removeChild\(first\)/.test(seg), '裁已完成行');
}
console.log('\n[3] 行为验证：日志裁剪逻辑（迷你 DOM）');
{
  // 抽取 addLog（依赖 document/state/window），用 mock DOM 跑 1600 次
  const start = appSrc.search(/^function addLog\(type, message\) \{/m);
  const lines = appSrc.slice(start).split('\n');
  const out = []; let depth = 0, st = false;
  for (const l of lines) { out.push(l); for (const c of l) { if (c === '{') { depth++; st = true; } else if (c === '}') depth--; } if (st && depth === 0) break; }
  const src = out.join('\n');
  const grabConst = (n) => { const m = appSrc.match(new RegExp('const ' + n + ' = (\\d+)')); return m ? m[1] : null; };
  const LIMIT = Number(grabConst('LOG_DOM_LIMIT')), BATCH = Number(grabConst('LOG_DOM_TRIM_BATCH'));
  const decls = ['const LOG_DOM_LIMIT = ' + LIMIT + ';', 'const LOG_DOM_TRIM_BATCH = ' + BATCH + ';'].join('\n');
  const mkEl = () => {
    const el = {
      children: [], className: '', innerHTML: '', textContent: '',
      appendChild(c) { this.children.push(c); c.parentNode = this; },
      removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; },
      get firstChild() { return this.children[0]; },
      querySelector() { if (!this._textTarget) this._textTarget = { textContent: '' }; return this._textTarget; },
    };
    return el;
  };
  const logPanel = mkEl();
  const docMock = { createElement: mkEl, getElementById: (id) => (id === 'category-log' ? logPanel : null) };
  const stateMock = { caseDir: '' };
  const winMock = {};
  const followScroll = () => { };
  const mod = { exports: null };
  new Function('document', 'state', 'window', 'followScroll', 'module',
    decls + '\n' + src + '\nmodule.exports = addLog;')(docMock, stateMock, winMock, followScroll, mod);
  const addLogFn = mod.exports;
  for (let i = 0; i < 1600; i++) addLogFn('info', 'line-' + i);
  ok(logPanel.children.length <= LIMIT, `1600 行后不超过上限（实际 ${logPanel.children.length}）`);
  const last = logPanel.children[logPanel.children.length - 1];
  ok(last && last._textTarget && last._textTarget.textContent === 'line-1599', '最新行保留在面板内（裁的是旧行）');
}
console.log('\n[4] 杀软持锁重试');
{
  const i = appSrc.indexOf('const typeResult = await window.electronAPI.detectFileType(filePath)');
  const seg = appSrc.slice(appSrc.indexOf('let typeResult = await window.electronAPI.detectFileType(filePath)'), appSrc.indexOf('let typeResult = await window.electronAPI.detectFileType(filePath)') + 900);
  ok(/let typeResult/.test(appSrc), 'detect 结果改为 let（可重试覆盖）');
  ok(/typeResult\.blocked && !opts\.noAvRetry/.test(seg), '仅 blocked 且未禁用重试时触发');
  ok(/setTimeout\(r, 2500\)/.test(seg), '延迟 2.5s 后重读');
  ok(/重试读取成功/.test(seg), '成功有可观察日志');
}
console.log('\n[5] 枚举全灭 → 定向重试');
{
  ok(/state\.lastEnumFeedback = '';\s*\/\/ 每次枚举重置/.test(appSrc) || /state\.lastEnumFeedback = '';/.test(appSrc), '每轮重置反馈');
  {
    const finHead = appSrc.slice(appSrc.indexOf('async function finalizeSolve'), appSrc.indexOf('async function finalizeSolve') + 700);
    ok(/state\.lastEnumFeedback = '';/.test(finHead), 'finalizeSolve 入口复位（防上一题反馈跨题泄漏）');
  }
  ok(/缺少真实密文[\s\S]{0,120}请从代码\/数据里取出被校验的密文常量/.test(appSrc), '缺密文类别给出具体动作');
  ok(/输入非空但输出为空[\s\S]{0,200}key\/密文配错/.test(appSrc), '空输出类别给出排查方向');
  ok(/retryPrompt: enumFb, enumFeedback: true/.test(appSrc), 'finalizeSolve 把枚举反馈作为 retryPrompt 返回');
  ok(/\|\| retryFin\.enumFeedback/.test(appSrc), '重试循环允许枚举反馈触发');
  ok(/本地枚举候选全部无效（缺密文\/空输出）/.test(appSrc), '重试原因有可观察文案');
  // 契约失败证据优先于枚举反馈
  const i = appSrc.indexOf("state.lastEnumFeedback = '';   // 已有更强的契约失败证据");
  ok(i > 0, '契约失败证据存在时清掉枚举反馈（不重复注入）');
}
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
