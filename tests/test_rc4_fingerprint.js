// 验证 RC4 指纹修复：直接调用 main.js 里真实的 scanCryptoFingerprints。
// 旧判据（出现 "00 01 02 .. 09" 即报 RC4）在实测 20 题里误报 12 题；
// 新判据要求完整 0..255 表（或 dword 步长的完整表）才报。
const fs = require('fs');
const path = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader');

const cases = [
  ['CrackMe2/CrackMe.exe', 'E:/ctf/pratice/ai/CrackMe2/19248a41-b7fc-440d-ad52-d3fcf287cab9_x/CrackMe/CrackMe.exe'],
  ['CrackMe3/CrackMe.exe', 'E:/ctf/pratice/ai/CrackMe3/02da357b-0bce-4ff2-b2b3-d1c7e4e73fe8_x/CrackMe3/CrackMe.exe'],
  ['Crackme7/CrackMe.exe', 'E:/ctf/pratice/ai/Crackme7/5ca3eeb0-dbfc-41d4-b1e8-057a24021496_x/Crackme7/CrackMe.exe'],
  ['Crackme6/Crackme.exe', 'E:/ctf/pratice/ai/Crackme6/0cfb1bc3-31b3-44f9-b08c-75740775da61_x/Crackme/Crackme.exe'],
  ['CrackMe5/CrackMe.exe', 'E:/ctf/pratice/ai/CrackMe5/0aca6176-2145-4217-9a36-b4e124192460_x/CrackMe5/CrackMe.exe'],
];

let rc4 = 0, scanned = 0;
for (const [label, p] of cases) {
  if (!fs.existsSync(p)) { console.log('SKIP(missing)', label); continue; }
  let r;
  try { r = scanCryptoFingerprints(p); } catch (e) { console.log('SKIP(error)', label, e.message); continue; }
  if (!r || !r.success) { console.log('SCAN FAIL', label, r && r.error); continue; }
  scanned++;
  const algos = (r.summary || []).map(s => s.algo);
  const hasRc4 = algos.some(a => /RC4/.test(a));
  if (hasRc4) rc4++;
  console.log(`${label}: ${algos.join(' | ') || '(无指纹)'}`);
}

console.log(`\n扫描 ${scanned} 个样本，RC4 判定 ${rc4} 次`);
// 这些样本都不是 RC4；旧实现会给出 2/4 误报。新实现应为 0。
if (scanned > 0 && rc4 === 0) { console.log('✅ RC4 误报已消除'); process.exit(0); }
console.log('❌ 仍有 RC4 误报'); process.exit(1);
