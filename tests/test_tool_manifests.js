// 工具清单一致性回归（本次全面审查的核心产出）
//
// 背景：main.js 里同一份"工具集合"被维护了 6 份清单：
//   schema 定义 / dispatch case / toolLabel / KNOWN 文本解析 / MAP 参数映射 / precheck
// 只要有一处漏更新，就会出现"工具存在但 AI 调不到""参数传了读不到"这类
// 只在实战中才暴露的故障——而且**测试全绿**（因为没人把清单彼此比对）。
//
// 实测已发生的故障：
//   · ida_dbg 的 precheck 白名单漏了 status/suspend/clear_remote/snapshot_diff，
//     而 schema 写着、工具描述还重点推荐 → 四个动作 100% 调不到
//   · browser_js 有 dispatch 但 schema 缺失 → skills 教 AI 用它，但 tools/list 里没有
//   · wiki_read 在 MAP 里映射成 'name'，schema/dispatch 都是 'path' → 裸参数丢失
//   · KNOWN 缺 8 个工具 → 文本形态调用被整条丢弃
//
// 这个测试把这些清单两两比对，任何一处不一致都会红。
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const mainLines = mainSrc.split('\n');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// ---- 抽取各类清单 ----
// 注意：不能用 indexOf('function ') 找函数边界——函数体里的字符串含 "function" 字样会截断。
// 统一用「花括号配平」取整个函数体。
function fnBody(name) {
  const i = mainSrc.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('未找到 function ' + name);
  let j = mainSrc.indexOf('{', i), depth = 0, inS = null, esc = false, inRe = false, inReCls = false;
  const prevSig = (k) => { let x = k - 1; while (x >= 0 && /\s/.test(mainSrc[x])) x--; return x >= 0 ? mainSrc[x] : ''; };
  for (let k = j; k < mainSrc.length; k++) {
    const c = mainSrc[k];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (inRe) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === '[') { inReCls = true; continue; }
      if (c === ']') { inReCls = false; continue; }
      if (c === '/' && !inReCls) inRe = false;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '/') {
      const p = prevSig(k);
      if (p === '' || /[([{,;:=!&|?+\-*%<>~^]/.test(p)) { inRe = true; continue; }
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return mainSrc.slice(i, k + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

function extractSchemaTools() {
  const body = fnBody('getToolDefinitions');
  return [...body.matchAll(/^\s*name:\s*"([a-z_0-9]+)"/gm)].map(m => m[1]);
}

function extractDispatchCases() {
  const body = fnBody('executeToolCall');
  return [...body.matchAll(/case\s+'([a-z_0-9]+)'\s*:/g)].map(m => m[1]);
}

function extractToolLabels() {
  const body = fnBody('toolLabel');
  return [...body.matchAll(/case\s+'([a-z_0-9]+)'\s*:/g)].map(m => m[1]);
}

function extractKnown() {
  const start = mainSrc.indexOf('function parseTextToolCalls');
  const end = mainSrc.indexOf('const MAP =', start);
  return [...mainSrc.slice(start, end).matchAll(/'([a-z_0-9]+)'/g)].map(m => m[1]);
}

function extractMapKeys() {
  const start = mainSrc.indexOf('const MAP = {', mainSrc.indexOf('function parseTextToolCalls'));
  const end = mainSrc.indexOf('};', start);
  const out = {};
  for (const m of mainSrc.slice(start, end).matchAll(/([a-z_0-9]+)\s*:\s*'([a-z_0-9]+)'/g)) out[m[1]] = m[2];
  return out;
}

const SCHEMA = [...new Set(extractSchemaTools())];
const DISPATCH = [...new Set(extractDispatchCases())];
const LABELS = new Set(extractToolLabels());
const KNOWN = new Set(extractKnown());
const MAP = extractMapKeys();

console.log('[0] 清单规模');
console.log('  schema=' + SCHEMA.length + ' dispatch=' + DISPATCH.length +
  ' labels=' + LABELS.size + ' known=' + KNOWN.size + ' map=' + Object.keys(MAP).length);
ok(SCHEMA.length > 40, 'schema 抽取成功（' + SCHEMA.length + ' 个工具）');
ok(DISPATCH.length > 40, 'dispatch 抽取成功（' + DISPATCH.length + ' 个工具）');

console.log('\n[1] schema ↔ dispatch 必须一一对应');
{
  const noCase = SCHEMA.filter(t => !DISPATCH.includes(t));
  const noSchema = DISPATCH.filter(t => !SCHEMA.includes(t));
  ok(noCase.length === 0, 'schema 里声明的工具都有 dispatch 实现', noCase.join(', '));
  ok(noSchema.length === 0, 'dispatch 里的工具都在 schema 里声明（否则 AI 发现不了）', noSchema.join(', '));
}

console.log('\n[2] 每个可调用工具都要有中文标签（否则 UI 显示英文名）');
{
  const missing = SCHEMA.filter(t => !LABELS.has(t));
  ok(missing.length === 0, 'schema 工具都有 toolLabel', missing.join(', '));
}

console.log('\n[3] KNOWN（文本形态调用解析）必须覆盖 schema 全部工具');
{
  // 历史 bug：KNOWN 漏 8 个 → 模型用文本格式调这些工具时，调用直接消失
  const missing = SCHEMA.filter(t => !KNOWN.has(t));
  ok(missing.length === 0, 'KNOWN 覆盖全部 schema 工具', missing.join(', '));
}

console.log('\n[4] MAP 的参数名必须与 schema 的 properties / dispatch 读取一致');
{
  const bad = [];
  const dBody = fnBody('executeToolCall');
  const schemaBody = fnBody('getToolDefinitions');
  for (const [tool, param] of Object.entries(MAP)) {
    // 该工具在 schema 里的属性块
    const ni = schemaBody.indexOf('name: "' + tool + '"');
    if (ni < 0) { bad.push(tool + '（schema 里没有这个工具）'); continue; }
    const propsEnd = schemaBody.indexOf('required:', ni);
    const propsBlock = schemaBody.slice(ni, propsEnd > ni ? propsEnd : ni + 2000);
    const hasProp = new RegExp('\\b' + param + '\\s*:').test(propsBlock);
    // dispatch 侧是否读 input.<param>
    const caseIdx = dBody.indexOf("case '" + tool + "'");
    let reads = false;
    if (caseIdx >= 0) {
      const nextCase = dBody.indexOf("case '", caseIdx + 5);
      const caseBody = dBody.slice(caseIdx, nextCase > caseIdx ? nextCase : undefined);
      reads = new RegExp('input\\.' + param + '\\b').test(caseBody) || /input\[/.test(caseBody);
    }
    if (!hasProp && !reads) bad.push(tool + '→' + param + '（schema 无此属性且 dispatch 不读）');
  }
  ok(bad.length === 0, 'MAP 映射的参数名都能被正确消费', bad.slice(0, 6).join(' | '));
  ok(MAP.wiki_read === 'path', 'wiki_read 映射到 path（不是 name）', 'got ' + MAP.wiki_read);
}

console.log('\n[5] ida_dbg 的 precheck 白名单必须与 schema enum 一致');
{
  const enumIdx = mainSrc.indexOf('enum: ["start", "exit", "continue", "run_to", "step_into", "step_over",');
  ok(enumIdx > 0, '找到 ida_dbg 的 action enum');
  const enumBlock = mainSrc.slice(enumIdx, enumIdx + 400);
  const enumActions = [...enumBlock.matchAll(/"([a-z_]+)"/g)].map(m => m[1]);

  const preIdx = mainSrc.indexOf('const DBG_ACTIONS = [');
  ok(preIdx > 0, '找到 precheck 里的 DBG_ACTIONS 白名单');
  const preBlock = mainSrc.slice(preIdx, mainSrc.indexOf('];', preIdx));
  const preActions = [...preBlock.matchAll(/'([a-z_]+)'/g)].map(m => m[1]);

  const missing = enumActions.filter(a => !preActions.includes(a));
  const extra = preActions.filter(a => !enumActions.includes(a));
  ok(missing.length === 0, 'schema 里的动作都能通过 precheck（不再误拦）', missing.join(', '));
  ok(extra.length === 0, 'precheck 里没有 schema 之外的动作', extra.join(', '));

  // 结构性断言：precheck 里只允许有一处 ida_dbg 的**动作白名单校验**。
  // 用 `const DBG_ACTIONS = [` 作为标志（这正是当初分叉出来的那个数组）。
  const dupCount = (mainSrc.match(/const DBG_ACTIONS = \[/g) || []).length;
  ok(dupCount === 1, 'ida_dbg 的动作白名单只有一处（两处必然不同步）', '发现 ' + dupCount + ' 处');
  // 不允许再出现旧的裸 allowed 数组写法
  ok(!/const allowed = \['start', 'exit', 'continue'/.test(mainSrc), '旧的 allowed 数组已移除');
}

console.log('\n[6] 实际执行 precheck：12 个 ida_dbg 动作全部放行');
{
  const i = mainSrc.indexOf('function precheckToolCall(');
  let j = mainSrc.indexOf('{', i), depth = 0, inS = null, esc = false, fnSrc = null;
  for (let k = j; k < mainSrc.length; k++) {
    const c = mainSrc[k];
    if (inS) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === inS) inS = null; continue; }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { fnSrc = mainSrc.slice(i, k + 1); break; } }
  }
  let fn = null;
  try { fn = new Function(fnSrc + '\nreturn precheckToolCall;')(); } catch (e) { /* 下面报错 */ }
  ok(typeof fn === 'function', 'precheckToolCall 可独立执行');
  if (typeof fn === 'function') {
    const acts = ['start', 'exit', 'continue', 'run_to', 'step_into', 'step_over',
      'status', 'suspend', 'clear_remote', 'regs', 'regs_named', 'stack',
      'bp_list', 'bp_add', 'bp_del', 'bp_toggle',
      'snapshot_diff', 'force_continue', 'global_reads'];
    const blocked = [];
    for (const a of acts) {
      const r = fn('ida_dbg', {
        action: a, addr: '0x401000', addrs: '0x401000', reg: 'eax',
        regions: [{ addr: '0x1', size: 16 }], set: [{ reg: 'eax', value: 1 }], func: 'main',
      });
      if (typeof r === 'string' && /未知的调试 action/.test(r)) blocked.push(a);
    }
    ok(blocked.length === 0, '全部 ' + acts.length + ' 个动作都不被"未知 action"拦下', blocked.join(', '));
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
