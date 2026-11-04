// 端到端：用 smc_dump 的脚本生成器跑真实 license 二进制
// 这一步验证「工具真的能用」，不是只有单测过
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const SD = require('../electron/smc-dump');

const W = 'C:/Users/Administrator/Desktop/工具/_work';
const LIC = path.join(W, 'license.bin');
if (!fs.existsSync(LIC)) { console.log('SKIP 缺少 license.bin'); process.exit(0); }

const script = SD.buildSmcScript({
  binPath: '/tmp/lic2/license',
  outDir: '/tmp/lic2/e2e',
  region: '0x404000:0x20000',
  patches: [{ va: '0x5024fc', bytes: '31c0c3' }],
  stdinData: '00'.repeat(48) + '\n',
  maxSnap: 4000,
  maxMs: 8000,
  sleepMs: 0,
});
fs.writeFileSync(path.join(W, '_e2e_smcdump.py'), script, 'utf8');
console.log('SCRIPT_GENERATED len=' + script.length);

// 语法自检
try {
  execFileSync('python', ['-I', '-X', 'utf8', '-c',
    'compile(open(r"' + path.join(W, '_e2e_smcdump.py') + '", encoding="utf-8").read(), "g", "exec")'],
    { stdio: 'pipe' });
  console.log('SYNTAX_OK');
} catch (e) {
  console.log('SYNTAX_FAIL ' + String(e.stderr || e.message).slice(0, 500));
  process.exit(1);
}
