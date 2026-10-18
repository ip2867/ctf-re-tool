// 验证 detect-file-type 能区分"杀软拦截"与"文件不存在"。
// 场景来自实测（CrackMe4）：解压成功、文件在盘上，但 Defender 实时保护让
// fs.openSync 抛 UNKNOWN: unknown error。旧实现把整题当"检测失败"静默跳过。
const fs = require('fs');
const os = require('os');
const path = require('path');

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? ' → ' + extra : '')); }
}

// 复刻 main.js 里的拦截判定分支（与实现保持同步）
function classify(openErr, filePath) {
  const msg = String(openErr && openErr.message || '');
  const blocked = /UNKNOWN|EPERM|EACCES|operation not permitted/i.test(msg) | (openErr && openErr.code === 'UNKNOWN');
  if (blocked && fs.existsSync(filePath)) return 'blocked';
  return 'other';
}

const tmp = path.join(os.tmpdir(), 'ctf_av_test_' + Date.now());
fs.mkdirSync(tmp, { recursive: true });
const real = path.join(tmp, 'sample.bin');
fs.writeFileSync(real, Buffer.from('4d5a9000', 'hex'));

console.log('[拦截识别]');
const errUnk = Object.assign(new Error("UNKNOWN: unknown error, open '" + real + "'"), { code: 'UNKNOWN' });
ok('UNKNOWN + 文件存在 → blocked', classify(errUnk, real) === 'blocked');
const errPerm = Object.assign(new Error('EPERM: operation not permitted, open'), { code: 'EPERM' });
ok('EPERM + 文件存在 → blocked', classify(errPerm, real) === 'blocked');
const errNoent = Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
ok('ENOENT（真缺失）→ 不归为 blocked', classify(errNoent, path.join(tmp, 'nope.bin')) === 'other');
ok('UNKNOWN + 文件不存在 → 不归为 blocked', classify(errUnk, path.join(tmp, 'nope.bin')) === 'other');

console.log('[正常文件不受影响]');
const fd = fs.openSync(real, 'r');
const buf = Buffer.alloc(4);
fs.readSync(fd, buf, 0, 4, 0);
fs.closeSync(fd);
ok('普通文件仍可正常读取', buf.toString('hex') === '4d5a9000');

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
