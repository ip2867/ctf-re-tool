// 实测：对真实 Disguise.exe 跑算法指纹扫描器（含第一层与解出的 stage2）
const fs = require('fs'), p = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

function show(label, file) {
  console.log('\n===== ' + label + ' =====');
  console.log('file: ' + file + '  (' + (fs.existsSync(file) ? fs.statSync(file).size + 'B' : 'MISSING') + ')');
  if (!fs.existsSync(file)) return null;
  const r = scanCryptoFingerprints(file);
  console.log('扫描字节数: ' + r.size);
  console.log('主结论:');
  (r.summary || []).forEach(s => console.log('  - [' + s.algo + '] 置信度=' + s.confidence + '\n      证据: ' + s.evidence + '\n      建议: ' + s.note));
  console.log('原始命中: ' + JSON.stringify((r.fingerprints || []).map(f => (f.fp || f.algo) + '@' + f.offset + (f.stride ? '(stride' + f.stride + ')' : ''))));
  console.log('高熵常量: ' + JSON.stringify((r.highEntropy || []).map(h => '@' + h.offset + '(' + h.len + 'B)')));
  return r;
}

// 可选真样本诊断脚本：node tests/test_scan_disguise.js --real <Disguise.exe>
// 默认不跑（CI 不依赖本机样本目录）。仓库内的同类样本见
// tests/regression/disguise-loader-xor-dword/Disguise.exe。
const realIdx = process.argv.indexOf('--real');
const d = realIdx >= 0 ? String(process.argv[realIdx + 1] || '') : '';
if (!d) {
  console.log('SKIP 未提供 --real <Disguise.exe>（本脚本是真样本诊断工具，不参与 CI 判定）');
  process.exit(0);
}
show('第一层 Disguise.exe', d);

// 解出 stage2 后再扫（复现题解的释放逻辑：.data 0x41C000 每 dword 取低字节 XOR 7）
if (!fs.existsSync(d)) { console.log('（样本缺失，跳过 stage2 复现）'); process.exit(0); }
try {
  const pe = require('fs').readFileSync(d);
  // 用 PE 头算 0x41C000 的文件偏移
  const e_lfanew = pe.readUInt32LE(0x3c);
  const nsec = pe.readUInt16LE(e_lfanew + 6);
  const optSize = pe.readUInt16LE(e_lfanew + 20);
  const secTbl = e_lfanew + 24 + optSize;
  let off = null, size = null;
  const imgBase = pe.readUInt32LE(e_lfanew + 24 + 28);
  for (let i = 0; i < nsec; i++) {
    const s = secTbl + i * 40;
    const vsize = pe.readUInt32LE(s + 8);
    const vaddr = pe.readUInt32LE(s + 12) + imgBase;
    const rawSize = pe.readUInt32LE(s + 16);
    const rawPtr = pe.readUInt32LE(s + 20);
    const va = 0x41C000;
    if (va >= vaddr && va < vaddr + Math.max(vsize, rawSize)) {
      off = rawPtr + (va - vaddr); size = Math.max(vsize, rawSize);
      console.log('\n[定位] 0x41C000 → 文件偏移 0x' + off.toString(16) + ' (段rawPtr=0x' + rawPtr.toString(16) + ')');
    }
  }
  if (off !== null) {
    const n = pe.readUInt32LE(off - 0x41C000 + 0x470000); // 段内相对 0x41C000 → 0x470000 的长度
    console.log('[长度字段] n = ' + n);
    const cnt = (n > 0 && n < 0x200000) ? n : 0x15000;
    const out = Buffer.alloc(cnt);
    for (let i = 0; i < cnt; i++) out[i] = (pe.readUInt32LE(off + i * 4) ^ 7) & 0xff;
    const sp = p.join(require('os').tmpdir(), 'ctf_test_stage2.bin');
    fs.writeFileSync(sp, out);
    console.log('[释放] stage2 → ' + sp + '  首2字节=' + out.slice(0, 2).toString('hex') + (out[0] === 0x4d && out[1] === 0x5a ? '  (MZ ✓)' : '  (非MZ ✗)'));
    show('第二层 stage2', sp);
  }
} catch (e) { console.log('stage2 释放失败: ' + e.message); }
