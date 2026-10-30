// 抽取 app.js 里的 jsonCandidates / parseHypotheses 真实实现并跑边界用例
const fs = require('fs');
const path = require('path');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

function extractFn(name) {
  const i = appSrc.indexOf('function ' + name);
  if (i < 0) throw new Error('not found: ' + name);
  // 从函数头扫到配对大括号结束
  let depth = 0, started = false;
  for (let k = i; k < appSrc.length; k++) {
    const c = appSrc[k];
    if (c === '{') { depth++; started = true; }
    else if (c === '}') { depth--; if (started && depth === 0) return appSrc.slice(i, k + 1); }
  }
  throw new Error('unbalanced: ' + name);
}

const src = extractFn('jsonCandidates') + '\n' + extractFn('parseHypotheses') +
  '\nmodule.exports = { jsonCandidates, parseHypotheses };';

const mod = { exports: {} };
new Function('module', 'exports', src)(mod, mod.exports);
const { parseHypotheses, jsonCandidates } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, d) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); } };

console.log('[1] 实测场景：中间夹了裸 "json" 语言标记行');
{
  const text = `[HYPOTHESES]
json
[
  {"algo":"custom","note":"A","next":"x"},
  {"algo":"custom","note":"B","next":"y"}
]

[/HYPOTHESES]`;
  const r = parseHypotheses(text);
  ok(r.length === 2, '解析出 2 条假设', String(r.length));
  ok(r[0].note === 'A' && r[1].note === 'B', '内容正确');
}

console.log('\n[2] 带 ```json 围栏');
{
  const text = '```json\n[HYPOTHESES]\n```json\n[{"a":1},{"a":2}]\n```\n[/HYPOTHESES]';
  const r = parseHypotheses('[HYPOTHESES]```json\n[{"a":1},{"a":2}]\n```[/HYPOTHESES]');
  ok(r.length === 2, 'markdown 围栏内可解析', String(r.length));
}

console.log('\n[3] 正常格式仍然工作（回归）');
{
  const r = parseHypotheses('[HYPOTHESES][{"algo":"aes_ecb","key":"0011"}][/HYPOTHESES]');
  ok(r.length === 1 && r[0].algo === 'aes_ecb', '原始格式不受影响');
}

console.log('\n[4] 多个块');
{
  const r = parseHypotheses('[HYPOTHESES][{"a":1}][/HYPOTHESES] 中间文字 [HYPOTHESES]\njson\n[{"b":2}]\n[/HYPOTHESES]');
  ok(r.length === 2, '两个块都解析', String(r.length));
}

console.log('\n[5] 坏 JSON 不应崩溃、也不应静默给空');
{
  const r = parseHypotheses('[HYPOTHESES]{不是json}[/HYPOTHESES]');
  ok(Array.isArray(r) && r.length === 0, '坏 JSON 返回空数组而不抛');
  const r2 = parseHypotheses('');
  ok(Array.isArray(r2) && r2.length === 0, '空输入返回空数组');
  const r3 = parseHypotheses('没有标记的普通文本');
  ok(r3.length === 0, '无标记返回空');
}

console.log('\n[6] jsonCandidates 顺序：原文优先');
{
  const c = jsonCandidates('[{"a":1}]');
  ok(c[0] === '[{"a":1}]', '首个候选是原文');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
