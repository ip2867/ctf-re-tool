// 验证 RC4 指纹修复：直接调用 main.js 里真实的 scanCryptoFingerprints。
// 旧判据（出现 "00 01 02 .. 09" 即报 RC4）在实测 20 题里误报 12 题；
// 新判据要求完整 0..255 表（或 dword 步长的完整表）才报。
//
// 真样本校验改为可选：node tests/test_rc4_fingerprint.js --real <path1> [<path2> ...]
// CI 只用合成样本（干净 checkout 没有 E: 盘）。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const tmp = (name, buf) => {
  const f = path.join(os.tmpdir(), `rc4_${Date.now()}_${name}`);
  fs.writeFileSync(f, buf);
  return f;
};
const hasRc4 = (r) => (r.summary || []).some(s => /RC4/.test(s.algo));

console.log('[1] 只有 00 01 02..09 前缀（不是完整表）→ 不得报 RC4');
{
  const f = tmp('prefix.bin', Buffer.concat([
    Buffer.alloc(64, 0x90), Buffer.from('00010203040506070809', 'hex'), Buffer.alloc(1024, 0x41),
  ]));
  const r = scanCryptoFingerprints(f);
  ok(!hasRc4(r), `不误报（summary: ${(r.summary || []).map(s => s.algo).join(', ')}）`);
  try { fs.unlinkSync(f); } catch (e) {}
}

console.log('\n[2] 完整 0..255 连续表 → 报 RC4（stride=1）');
{
  const tbl = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) tbl[i] = i;
  const f = tmp('full.bin', Buffer.concat([Buffer.alloc(64, 0xCC), tbl, Buffer.alloc(64, 0xCC)]));
  const r = scanCryptoFingerprints(f);
  ok(hasRc4(r), `报 RC4（summary: ${(r.summary || []).map(s => s.algo).join(', ')}）`);
  const hit = (r.fingerprints || []).find(x => x.fp === 'RC4-ID');
  ok(hit && /stride=1/.test(hit.desc || ''), `证据标记 stride=1（${hit && hit.desc}）`);
  try { fs.unlinkSync(f); } catch (e) {}
}

console.log('\n[3] dword 步长的完整表 → 报 RC4（stride=4）');
{
  const tbl = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) tbl.writeUInt32LE(i, i * 4);
  const f = tmp('full4.bin', Buffer.concat([Buffer.alloc(64, 0xCC), tbl, Buffer.alloc(64, 0xCC)]));
  const r = scanCryptoFingerprints(f);
  ok(hasRc4(r), '报 RC4');
  const hit = (r.fingerprints || []).find(x => x.fp === 'RC4-ID');
  ok(hit && /stride=4/.test(hit.desc || ''), `证据标记 stride=4（${hit && hit.desc}）`);
  try { fs.unlinkSync(f); } catch (e) {}
}

console.log('\n[4] 可选真样本（--real）');
{
  const idx = process.argv.indexOf('--real');
  const reals = idx >= 0 ? process.argv.slice(idx + 1).filter(Boolean) : [];
  if (!reals.length) {
    console.log('  SKIP 未提供 --real <path...>（CI 不依赖本机样本）');
  } else {
    let scanned = 0, rc4 = 0;
    for (const p of reals) {
      if (!fs.existsSync(p)) { console.log('  SKIP(missing) ' + p); continue; }
      const r = scanCryptoFingerprints(p);
      if (!r || !r.success) { console.log('  SKIP(error) ' + p); continue; }
      scanned++;
      if (hasRc4(r)) rc4++;
      console.log(`  ${path.basename(p)}: ${(r.summary || []).map(s => s.algo).join(' | ') || '(无指纹)'}`);
    }
    ok(scanned > 0, `扫描 ${scanned} 个真样本`);
    ok(rc4 === 0, `无 RC4 误报（${rc4}）`);
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
