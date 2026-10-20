// 关键函数选择单测：
//   ① DialogFunc 类命名必须 +5 才能进 top10（fixture 30 个 sub_*）；
//   ② 入口/Dialog 的 1 跳 callee 走独立强制通道（不占 6 个名额）；
//   ③ 强制通道必须调插件的 callees（decompile 的 refs 只含数据引用，不含函数调用）。
const fs = require('fs');
const path = require('path');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

function grab(name) {
  const startIdx = appSrc.search(new RegExp('^(?:async\\s+)?function\\s+' + name + '\\s*\\(', 'm'));
  if (startIdx < 0) throw new Error('未找到函数 ' + name);
  const lines = appSrc.slice(startIdx).split(/\r?\n/);
  const out = [];
  let depth = 0, started = false;
  for (const line of lines) {
    out.push(line);
    for (const ch of line) {
      if (ch === '{') { depth++; started = true; }
      else if (ch === '}') depth--;
    }
    if (started && depth === 0) break;
  }
  return out.join('\n');
}

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const mod = { exports: {} };
new Function('module', 'exports', 'addLog',
  'const log = () => {};\n'
  + grab('selectKeyFunctions') + '\n'
  + grab('collectForcedFuncs') + '\n'
  + 'module.exports = { selectKeyFunctions, collectForcedFuncs };'
)(mod, mod.exports, () => {});
const { selectKeyFunctions, collectForcedFuncs } = mod.exports;

async function main() {
  console.log('[1] fixture：30 个 sub_*(0x150) + DialogFunc(0xa9) → top10 必须含 DialogFunc');
  const funcs = [];
  for (let i = 0; i < 30; i++) {
    funcs.push({ name: 'sub_' + (0x401000 + i * 0x200).toString(16), size: '0x150', address: '0x' + (0x401000 + i * 0x200).toString(16) });
  }
  funcs.push({ name: 'DialogFunc', size: '0xa9', address: '0x401420' });

  const top10 = selectKeyFunctions(funcs, 10);
  const names10 = top10.map(f => f.name);
  ok(names10.includes('DialogFunc'), `top10 含 DialogFunc（实际: ${names10.slice(0, 3).join(',')}...）`);

  console.log('\n[2] 强制通道：main→CheckIt 必须出现在 forced，且不占 6 个名额');
  const funcs2 = funcs.concat([
    { name: 'main', size: '0x200', address: '0x401000' },
    { name: 'CheckIt', size: '0x100', address: '0x402000' },
  ]);
  const calls = [];
  const callMcp = async (tool, args) => {
    calls.push({ tool, args });
    if (tool === 'callees') return { success: true, result: [{ addr: args.addrs[0], callees: ['CheckIt'] }] };
    return { success: true, result: [] };
  };
  const forced = await collectForcedFuncs(funcs2, callMcp, 12);
  ok(forced.includes('CheckIt'), `forced 含 CheckIt（实际 ${forced.join(',')}）`);
  ok(forced.includes('main') && forced.includes('DialogFunc'), `forced 含种子本身（${forced.join(',')}）`);

  console.log('\n[3] 强制通道调用的工具名必须是 callees');
  ok(calls.length > 0, `有调用（${calls.length} 次）`);
  ok(calls.every(c => c.tool === 'callees'), `全部是 callees（实际 ${[...new Set(calls.map(c => c.tool))].join(',')}）`);
  ok(calls.every(c => Array.isArray(c.args.addrs)), 'addrs 为字符串数组');

  console.log('\n[4] 日志文本：强制加入入口/Dialog 邻接函数');
  // 用与实现相同的模板渲染实际日志，证明文案逐字匹配
  const tpl = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8')
    .match(/addLog\('info', `(\[采集\] 强制加入入口\/Dialog 邻接函数: \$\{forced\.join\(', '\)\})`\)/);
  ok(!!tpl, '采集阶段使用该日志模板');
  const rendered = tpl ? tpl[1].replace('${forced.join(\', \')}', forced.join(', ')) : '';
  ok(rendered.startsWith('[采集] 强制加入入口/Dialog 邻接函数: DialogFunc, CheckIt'),
    `渲染后日志含 "DialogFunc, CheckIt"（${rendered}）`);

  console.log('\n[5] 采集阶段：forced 先入队、再 selectKeyFunctions(6)、dedupe');
  ok(/forced = await collectForcedFuncs\(analysisData\.functions/.test(appSrc), '调用 collectForcedFuncs');
  ok(/const picked = selectKeyFunctions\(analysisData\.functions, 6\)/.test(appSrc), 'selectKeyFunctions(funcs, 6)');
  ok(/\[\.\.\.forced, \.\.\.picked\]/.test(appSrc), 'dedupe 顺序为 [...forced, ...picked]');
  ok(!/const keyFuncs = selectKeyFunctions\(analysisData\.functions, 6\);\s*\n\s*\/\/ thunk/.test(appSrc),
    '旧的一行式 keyFuncs = selectKeyFunctions(6) 已替换');

  console.log('\n[6] 评分规则：Dialog 类命名 +5');
  const body = grab('selectKeyFunctions');
  ok(/DialogFunc\|DlgProc\|DialogProc\|WndProc\|WinProc\|WindowProc\|MainWndProc/.test(body), '含对话框过程命名表');
  ok(/\)\s*s \+= 5;/.test(body), '对话框命名计 +5');

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
