// 验证"loader 层判定"逻辑：模拟不同扫描结果，确认自动接力/跳过静态分析的判据正确
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

// 抽取判据关键常量与正则
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

// 复刻判据（与 app.js 同源正则）
const PAYLOAD_RE = /内嵌\s*(PE|ELF|DEX|载荷)|编码存储/i;
function classify(scan) {
  const sums = (scan && Array.isArray(scan.summary)) ? scan.summary : [];
  const algoSignals = sums.filter(s => !PAYLOAD_RE.test(String(s.algo || ''))
    && (s.confidence === 'high' || s.confidence === 'medium'));
  const hasPayload = !!(scan && ((scan.payloads || []).length || (scan.embeddedPE || []).length));
  return {
    hasPayload,
    hasAlgo: algoSignals.length > 0,
    // 自动接力条件
    autoHandoff: hasPayload && !algoSignals.length,
    // 跳过静态分析条件（只看载荷与算法）
    skipStatic: hasPayload && !algoSignals.length,
  };
}

console.log('A) Disguise 第一层（真实扫描结果形态）→ 必须自动接力');
{
  const cls = classify({
    summary: [{ algo: '内嵌 PE（编码存储，已定位）', confidence: 'high', evidence: '@0xa200' }],
    payloads: [{ type: 'pe', offset: 0xa200, length: 86016, encode: { kind: 'xor', key: 7, stride: 4 } }],
  });
  ok(cls.hasPayload === true, '识别为有载荷');
  ok(cls.hasAlgo === false, '载荷结论**不**被误判为算法指纹（这次真机 bug 的核心）');
  ok(cls.autoHandoff === true, '触发自动接力');
  ok(cls.skipStatic === true, '跳过静态分析（避免"请用户提供 stage2"）');
}

console.log('\nB) 正常算法题（Challenge：SM4）→ 不接力');
{
  const cls = classify({
    summary: [{ algo: 'SM4', confidence: 'high', evidence: 'FK+S盒' }],
    payloads: [],
  });
  ok(cls.hasPayload === false, '无载荷');
  ok(cls.hasAlgo === true, '识别到算法');
  ok(cls.autoHandoff === false, '不触发接力');
  ok(cls.skipStatic === false, '不跳过静态分析');
}

console.log('\nC) 既有载荷又有算法 → 交 AI 判断（不自动接力）');
{
  const cls = classify({
    summary: [
      { algo: '内嵌 PE（编码存储，已定位）', confidence: 'high' },
      { algo: 'AES', confidence: 'high' },
    ],
    payloads: [{ type: 'pe', offset: 0x100, length: 0x1000, encode: { kind: 'none' } }],
  });
  ok(cls.hasPayload === true && cls.hasAlgo === true, '两类都识别');
  ok(cls.autoHandoff === false, '不自动接力（避免把主逻辑层当壳跳过）');
}

console.log('\nD) 零指纹无载荷 → 不接力、不跳过');
{
  const cls = classify({ summary: [{ algo: '(未发现算法指纹)', confidence: 'n/a' }], payloads: [] });
  ok(cls.hasPayload === false && cls.hasAlgo === false, '都没有');
  ok(cls.autoHandoff === false, '不接力');
}

console.log('\nE) 源码一致性：判据正则必须同时存在于两处');
{
  const occurrences = (src.match(/内嵌\\s\*\(PE\|ELF\|DEX\|载荷\)\|编码存储/g) || []).length;
  ok(occurrences >= 3, `正则出现 ${occurrences} 次（自动接力/跳过静态/runHypotheses 各一）`);
  ok(!src.includes("hasPayload && !hasStrongAlgo && !state._inStageHandoff"), '已移除阻断多层接力的 _inStageHandoff 条件');
}

console.log('\nF) 路径拼接：不能出现 scripts/scripts（真实脏目录事故）');
{
  // getScriptsDir() 返回的已经是 .../scripts；若再拼 /scripts 会生成 scripts/scripts/xxx.py。
  // 断言：不得出现 `${baseDir}/scripts/` 或 `${baseDir}/extracted` 这类"二次拼接"模式。
  ok(!/\$\{baseDir\}\/scripts\//.test(src), '不再拼 `${baseDir}/scripts/`');
  ok(!/\$\{baseDir\}\/extracted/.test(src), '不再拼 `${baseDir}/extracted`');
  ok(/scriptsBase\s*=\s*caseDir\s*\?\s*`\$\{caseDir\}\/scripts`\s*:\s*await\s+getScriptsDir\(\)/.test(src),
    '有 CASE 时用 CASE/scripts，否则直接用 getScriptsDir() 的返回值');
}

console.log('\nG) 探针/测试不得调用会写 UI 的函数（防再次污染界面）');
{
  // 这是一个约定性检查：tests/ 下不允许调用 runNegativeAssertionCheck（它会 addSystemMessage）。
  const testsDir = p.join(__dirname);
  const offenders = [];
  for (const f of fs.readdirSync(testsDir)) {
    if (!/\.js$/.test(f) || f === 'test_scope_safety.js' || f === 'test_loader_classification.js') continue;
    const t = fs.readFileSync(p.join(testsDir, f), 'utf8');
    if (/runNegativeAssertionCheck\s*\(/.test(t) || /addSystemMessage\s*\(/.test(t)) offenders.push(f);
  }
  ok(offenders.length === 0, offenders.length ? `这些测试会写 UI：${offenders.join(', ')}` : '无测试调用写 UI 的函数');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
