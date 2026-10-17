// 作用域安全单测：防止"函数引用了别处的局部变量"这类运行时 ReferenceError。
//
// 背景（真实事故）：`runNegativeAssertionCheck` 里写了 `analysisData && analysisData.algScan`，
// 但 `analysisData` 只是 `autoSolveBinaryFlag` 的局部变量。结果在真机跑 Disguise 时抛
// `ReferenceError: analysisData is not defined`，把整轮 AI 的结果（且是正确的"本层是 loader"结论）吞掉。
// 同一个 bug 在 `buildStageSummary` / `runHypotheses` 里也有——因为它们是**同类函数**，被复制粘贴出来的。
//
// 本测试的做法：静态扫描 app.js，找出"在某个函数体里引用了 analysisData"但该函数
// **不在** autoSolveBinaryFlag/autoAnalyze 的局部作用域内的位置，直接判定为潜在缺陷。
// 这是一条通用的静态护栏，不针对任何一道题。
const fs = require('fs'), p = require('path');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const lines = src.split('\n');

// 允许访问 analysisData 的函数（它是它们的参数或局部变量）
const SAFE_FUNCS = new Set([
  'autoSolveBinaryFlag', 'autoAnalyze', 'toolUseDeepSolveBinary',
  'detailedAnalysis', 'detailedBinaryAnalysis', 'analyzePE', 'analyzeELF',
  'toolUseDeepSolve', 'extractHookTargets', 'buildAnalysisPrompt',
]);

// 找到每个顶层 function 的起止行。
// 解析要点：模板字符串里含 `${...}` 和裸 `{`，正则字面量里含 `{}`——都会干扰大括号配平。
// 这里用一个小状态机：跟踪字符串/模板/注释/正则的粗略状态。
function functionRanges(text) {
  const out = [];
  // 只认**顶格**函数声明（顶层函数），嵌套函数会随外层一起被包含，不影响判定。
  const re = /^(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    const startIdx = text.indexOf('{', m.index);
    if (startIdx < 0) continue;
    let depth = 0, i = startIdx;
    let mode = 'code';
    let templateDepth = 0;
    for (; i < text.length; i++) {
      const ch = text[i], nx = text[i + 1];
      if (mode === 'line-comment') { if (ch === '\n') mode = 'code'; continue; }
      if (mode === 'block-comment') { if (ch === '*' && nx === '/') { i++; mode = 'code'; } continue; }
      if (mode === 'single') { if (ch === '\\') { i++; continue; } if (ch === "'") mode = 'code'; continue; }
      if (mode === 'double') { if (ch === '\\') { i++; continue; } if (ch === '"') mode = 'code'; continue; }
      if (mode === 'template') {
        if (ch === '\\') { i++; continue; }
        if (ch === '`' && templateDepth === 0) { mode = 'code'; continue; }
        if (ch === '$' && nx === '{') { templateDepth++; i++; continue; }
        if (ch === '}' && templateDepth > 0) { templateDepth--; continue; }
        continue;
      }
      if (ch === '/' && nx === '/') { i++; mode = 'line-comment'; continue; }
      if (ch === '/' && nx === '*') { i++; mode = 'block-comment'; continue; }
      if (ch === "'") { mode = 'single'; continue; }
      if (ch === '"') { mode = 'double'; continue; }
      if (ch === '`') { mode = 'template'; templateDepth = 0; continue; }
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) { i++; break; } }
    }
    out.push({
      name, start: m.index, end: i,
      startLine: text.slice(0, m.index).split('\n').length,
      endLine: text.slice(0, i).split('\n').length,
    });
  }
  return out;
}

// 判定某函数体里是否**真的**在运行时引用 analysisData（而不是声明它或有参数）
function usesUndeclaredAnalysisData(body) {
  // 去掉注释行
  const code = body.split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  // 该函数自己声明了/作为参数接收了 → 合法
  if (/(?:function\s*[A-Za-z0-9_$]*\s*\([^)]*\banalysisData\b)|(?:let|const|var)\s+analysisData\b/.test(code)) {
    return false;
  }
  return /\banalysisData\b/.test(code);
}

console.log('A) 静态扫描：函数体内引用 analysisData 但不在安全函数内');
{
  const fns = functionRanges(src);
  const offenders = [];
  for (const fn of fns) {
    if (SAFE_FUNCS.has(fn.name)) continue;
    const body = src.slice(fn.start, fn.end);
    if (usesUndeclaredAnalysisData(body)) {
      offenders.push(`${fn.name} (行 ${fn.startLine}-${fn.endLine})`);
    }
  }
  ok(offenders.length === 0, offenders.length ? `发现 ${offenders.length} 处越界引用：${offenders.join(', ')}` : '无越界引用');
}

console.log('\nB) 已知的三处历史缺陷点必须已改为 state');
{
  // runNegativeAssertionCheck / buildStageSummary / runHypotheses 都应读 state.lastAlgScan
  const checks = [
    ['runNegativeAssertionCheck', /const\s+algScan\s*=\s*opts\.algScan\s*\|\|\s*\(state\.lastAlgScan/],
    ['buildStageSummary', /const\s+sc\s*=\s*state\.lastAlgScan\s*\|\|\s*\{\}/],
    ['runHypotheses', /state\.lastAlgScan\s*&&\s*state\.lastAlgScan\.summary/],
  ];
  for (const [fn, re] of checks) {
    ok(re.test(src), `${fn} 已通过 state.lastAlgScan 读取扫描结果`);
  }
}

console.log('\nC) state.lastAlgScan 有写入点与清理点');
{
  ok(/state\.lastAlgScan\s*=\s*\(sc\s*&&\s*sc\.success\)\s*\?\s*sc\s*:\s*null/.test(src), '采集阶段写入');
  ok(/if\s*\(sc\s*&&\s*sc\.success\)\s*state\.lastAlgScan\s*=\s*sc/.test(src), '深度求解阶段写入');
  ok(/state\.lastAlgScan\s*=\s*null/.test(src), '换题时清空（防跨题串数据）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
