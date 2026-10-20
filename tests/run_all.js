// 全量单元回归：逐个跑 tests/test_*.js，统计通过数。失败项打印尾部输出。
// 跑法：node tests/run_all.js
// 注意：manual_dbg_*.js 不在里面——它们需要真实 IDA / Kali，属手工验收。
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const files = fs.readdirSync(dir).filter(f => /^test_.*\.js$/.test(f)).sort();
let pass = 0, fail = 0;
const failed = [];

for (const f of files) {
  try {
    execFileSync(process.execPath, [path.join(dir, f)], { cwd: path.join(dir, '..'), stdio: 'pipe', timeout: 120000 });
    pass++;
    console.log('PASS ' + f);
  } catch (e) {
    fail++;
    failed.push(f);
    const out = String((e.stdout || '') + (e.stderr || '')).trim().split('\n').slice(-6).join('\n');
    console.log('FAIL ' + f);
    if (out) console.log('     ' + out.replace(/\n/g, '\n     '));
  }
}
console.log('\n==== ' + pass + '/' + (pass + fail) + ' passed ====');
if (failed.length) console.log('failed: ' + failed.join(', '));
process.exit(fail ? 1 : 0);
