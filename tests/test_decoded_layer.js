// 验证 looksLikeMachineCode / findDecodedLayer：直接抽取 app.js 里的实现，
// 用 CrackMe3 的真实求解输出（AI 的自定义 RC4 解出的 x86 函数）做回归。
const fs = require('fs');
const p = require('path');
const appSrc = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const start = appSrc.indexOf('function looksLikeMachineCode');
const end = appSrc.indexOf('// 解析求解脚本的结构化失败输出');
if (start < 0 || end < 0) throw new Error('未能定位 looksLikeMachineCode / findDecodedLayer');
const body = appSrc.slice(start, end);
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports = { looksLikeMachineCode, findDecodedLayer };')(mod, mod.exports);
const { looksLikeMachineCode, findDecodedLayer } = mod.exports;

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? ' → ' + extra : '')); }
}

console.log('[正样本：CrackMe3 真实解出的 x86 函数]');
const real = '83ec18b065b163884424048844240d88442410884424128d442400b273884c2402884c2403884c240e8b4c241c5088542404885424098854240a6a00b2726a0c51c644241175c644241721c644241879c64424196fc644241a75c644241b618854241cc644241f6cc64424217688542423c644242400ff54243083c418c39090';
ok('识别为机器码', looksLikeMachineCode(real));
ok('同类（不同寄存器序言）也识别', looksLikeMachineCode('55' + '89e5' + '83ec10' + '8b4508'.repeat(8) + 'c9c3'));
ok('64 位序言 48 89 e5', looksLikeMachineCode('4889e54883ec20' + '488b45f8'.repeat(8) + 'c3'));

console.log('[负样本：正常明文 / 随机串]');
ok('flag 明文不算机器码', !looksLikeMachineCode('flag{this_Is_a_EaSyRe}'));
ok('中文明文不算机器码', !looksLikeMachineCode('恭喜你答对了，flag是flag{abc}'));
ok('短 hex 不算', !looksLikeMachineCode('83ec18b065b16388'));
ok('随机 hex（无 prologue/epilogue）不算', !looksLikeMachineCode('a1b2c3d4e5f60718' .repeat(8)));

console.log('[findDecodedLayer 端到端]');
const out = [
  '[MISS] attempt=0 algo=custom keyenc=ascii stage=verify result=no-flag preview=' + real.slice(0, 100),
  '[OUT] attempt=0 keyenc=ascii: ' + real,
].join('\n');
const dl = findDecodedLayer(out);
ok('从 [OUT] 行检出', dl.count >= 1, JSON.stringify(dl));
const out2 = '[MISS] attempt=0 algo=aes_cbc keyenc=ascii stage=verify result=garbage preview=9f3a2b1c';
ok('garbage 不误报', findDecodedLayer(out2).count === 0);

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
