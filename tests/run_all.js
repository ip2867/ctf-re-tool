// 轻量测试运行器：node tests/run_all.js
// 依次跑全部单测；任一失败则退出码非 0（便于 CI / 发布前把关）。
const { spawnSync } = require('child_process'), p = require('path'), fs = require('fs');

const tests = fs.readdirSync(__dirname)
  .filter(f => /^test_.*\.js$/.test(f))
  .sort();

let failed = 0;
const results = [];
for (const t of tests) {
  process.stdout.write('\n========== ' + t + ' ==========\n');
  const r = spawnSync(process.execPath, [p.join(__dirname, t)], { stdio: 'inherit' });
  const ok = r.status === 0;
  if (!ok) failed++;
  results.push((ok ? '✅ ' : '❌ ') + t);
}
console.log('\n================ 汇总 ================');
results.forEach(r => console.log(r));
console.log(`\n${tests.length - failed}/${tests.length} 个测试文件通过`);

// 回归题集（真实题多题实测）：单测证明"机制通用"，回归题集证明"在多道真题上不误报/不失效"。
// 两者缺一不可——单测全绿但真题误报，等于把 AI 引向错误结论。
console.log('\n========== 回归题集（真实题目） ==========');
const rr = spawnSync(process.execPath, [p.join(__dirname, 'run_regression.js')], { stdio: 'inherit' });
if (rr.status !== 0) { failed++; results.push('❌ 回归题集'); } else results.push('✅ 回归题集');

console.log('\n================ 最终汇总 ================');
results.forEach(r => console.log(r));
console.log(`\n单元测试 ${tests.length - (failed - (rr.status !== 0 ? 1 : 0))}/${tests.length} 通过` +
  ` ｜ 回归题集 ${rr.status === 0 ? '通过' : '失败'}`);
process.exit(failed ? 1 : 0);
