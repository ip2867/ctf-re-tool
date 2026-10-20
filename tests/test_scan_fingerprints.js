// 算法指纹扫描器综合单测：
//  A) 标准常量命中（SM4/AES/SM3/TEA/CRC32）
//  B) 步长 S 盒（Disguise 的 dword 数组形态）
//  C) 零指纹 → 正确判定为"壳/decoy"（不再误报）
//  D) 误报安全：对真实系统大二进制不得报出"自定义分组密码"
const fs = require('fs'), p = require('path'), os = require('os');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const check = (n, c, x) => { if (c) { pass++; console.log('  ✅ ' + n); } else { fail++; console.log('  ❌ ' + n + (x ? '  → ' + x : '')); } };
const tmp = (name, buf) => { const f = p.join(os.tmpdir(), name); fs.writeFileSync(f, buf); return f; };
const has = (r, re) => (r.summary || []).some(s => re.test(s.algo));
const sumText = (r) => (r.summary || []).map(s => s.algo + '/' + s.confidence).join(', ');

console.log('A) 标准常量命中');
{
  const f = tmp('t_sm4fk.bin', Buffer.concat([Buffer.alloc(64), Buffer.from('a3b1bac656aa3350677d9197b27022dc', 'hex'), Buffer.alloc(64)]));
  const r = scanCryptoFingerprints(f);
  check('SM4 FK → 判定 SM4', has(r, /SM4/), sumText(r));
}
{
  const f = tmp('t_aessbox.bin', Buffer.concat([Buffer.alloc(32), Buffer.from('637c777bf26b6fc5', 'hex'), Buffer.alloc(64)]));
  const r = scanCryptoFingerprints(f);
  check('AES S 盒 → 判定 AES', has(r, /AES/), sumText(r));
}
{
  const f = tmp('t_sm3iv.bin', Buffer.concat([Buffer.alloc(16), Buffer.from('7380166f4914b2b9172442d7', 'hex'), Buffer.alloc(32)]));
  const r = scanCryptoFingerprints(f);
  check('SM3 IV → 判定 SM3', has(r, /SM3/), sumText(r));
}
{
  const f = tmp('t_tea.bin', Buffer.concat([Buffer.alloc(16), Buffer.from('b979379e', 'hex'), Buffer.alloc(32)]));
  const r = scanCryptoFingerprints(f);
  check('TEA delta → 判定 TEA', has(r, /TEA/), sumText(r));
}

console.log('\nB) 步长 S 盒（dword 数组，Disguise 形态）');
{
  // 真实感的自定义双射：伪随机置换（非仿射/非恒等），按 4 字节步长、低字节存值
  const perm = Array.from({ length: 256 }, (_, i) => i);
  let s = 20261016 >>> 0;
  const rnd = () => (s = (s * 1664525 + 1013904223) >>> 0) / 4294967296;
  for (let i = 255; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }
  const box = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) box.writeUInt32LE(perm[i], i * 4);
  const f = tmp('t_sbox4.bin', Buffer.concat([Buffer.alloc(16), box, Buffer.alloc(16)]));
  const r = scanCryptoFingerprints(f);
  check('dword 双射表 → 自定义分组密码 high', has(r, /自定义分组密码/) && r.summary.find(s => /自定义分组密码/.test(s.algo)).confidence === 'high', sumText(r));
  const hit = (r.fingerprints || []).find(x => x.fp === 'SBOX-256');
  check('步长被识别为 4', hit && hit.stride === 4, hit ? 'stride=' + hit.stride : 'no hit');
}
{
  // 标准 SM4 S 盒按 dword 步长存放 → 应判 SM4（步长形态的标准盒）
  const sm4 = Buffer.from('d690e9fecce13db716b614c228fb2c05', 'hex');   // 标准 SM4 sbox 前 16 字节
  const box = Buffer.alloc(256 * 4);
  for (let i = 0; i < 16; i++) box.writeUInt32LE(sm4[i], i * 4);
  for (let i = 16; i < 256; i++) box.writeUInt32LE((i * 37 + 11) & 0xff, i * 4);
  // 注意：该表未必严格双射，只验证"步长表能被发现"（SM4 判定需完整标准表，这里不强制）
  const f = tmp('t_sm4sbox4.bin', Buffer.concat([Buffer.alloc(16), box, Buffer.alloc(16)]));
  const r = scanCryptoFingerprints(f);
  console.log('     （步长表发现能力）' + sumText(r));
}

console.log('\nC) 零指纹 → 中性结论（不再断言"是壳"）');
{
  // 用真正"无规律"的字节（非置换），且长度为 4096 无 256 项双射
  const rand = Buffer.alloc(4096);
  for (let i = 0; i < rand.length; i++) rand[i] = (i * i * 7 + i * 3 + 5) & 0xff;   // 非双射循环
  const f = tmp('t_none.bin', rand);
  const r = scanCryptoFingerprints(f);
  check('无指纹 → 报"未发现算法指纹"', has(r, /未发现算法指纹/), sumText(r));
  const s0 = (r.summary || [])[0] || {};
  check('note 为中性措辞（含"未识别到已知算法常量"）', /未识别到已知算法常量/.test(s0.note || ''), s0.note);
  check('note 不把零指纹断言成壳', !/极可能/.test(s0.note || '') && !/本层是壳/.test(s0.note || ''), s0.note);
  check('标记 noPayload=true（本层无内嵌载荷）', s0.noPayload === true, 'noPayload=' + s0.noPayload);
}
{
  // 恒等表（00 01 02 …）是偏移/跳转表，不是 S 盒 → 必须不报"分组密码"
  const idt = Buffer.alloc(256); for (let i = 0; i < 256; i++) idt[i] = i;
  const f1 = tmp('t_ident.bin', Buffer.concat([Buffer.alloc(32), idt, Buffer.alloc(32)]));
  const r1 = scanCryptoFingerprints(f1);
  check('恒等表(字节) 不报分组密码', !has(r1, /自定义分组密码/), sumText(r1));
  const idt2 = Buffer.alloc(512); for (let i = 0; i < 256; i++) idt2.writeUInt16LE(i, i * 2);
  const f2 = tmp('t_ident2.bin', Buffer.concat([Buffer.alloc(32), idt2, Buffer.alloc(32)]));
  const r2 = scanCryptoFingerprints(f2);
  check('恒等表(word) 不报分组密码', !has(r2, /自定义分组密码/), sumText(r2));
}

console.log('\nD) 散落 MD5 K 轮常量（CrackMe2 布局）');
{
  const { MD5_K } = require('../electron/crypto-detect.js');
  // 按真实的"散落"形态写：每两个 K 之间插入 8/36/64 字节噪声
  const parts = [Buffer.alloc(64, 0x90)];
  for (let i = 0; i < MD5_K.length; i++) {
    const k = Buffer.alloc(4); k.writeUInt32LE(MD5_K[i] >>> 0, 0);
    parts.push(k, Buffer.alloc(1 + ((i * 7) % 13), 0x05));
  }
  const scattered = Buffer.concat(parts);
  check('散落布局的连续匹配命中数为 0（旧判据必然漏报）',
    !scattered.includes(Buffer.from('d76aa478e8c7b756', 'hex')), '不应出现连续两个 K');

  const f = tmp('t_md5_scatter.bin', scattered);
  const r = scanCryptoFingerprints(f);
  check('散落 K 表 → summary 含 MD5', has(r, /MD5/), sumText(r));
  const md5 = (r.summary || []).find(s => s.algo === 'MD5') || {};
  check('MD5 置信度为 high', md5.confidence === 'high', md5.confidence);
  check('证据写出 K 命中数/IV 命中数', /K 常量命中 64\/64/.test(md5.evidence || '') && /IV 0\/4/.test(md5.evidence || ''), md5.evidence);
  check('fingerprints 含 MD5-K 条目', (r.fingerprints || []).some(x => x.fp === 'MD5-K'));

  // 反例：K 表 + 4 个标准 IV（LE 连续）= 链接了标准实现（ntoskrnl/ntdll 形态）
  const withIv = Buffer.concat([scattered, Buffer.from('0123456789abcdef', 'hex')]);
  const r2 = scanCryptoFingerprints(tmp('t_md5_lib.bin', withIv));
  check('K 表 + 标准 IV → 不判为"内联 MD5"', !(r2.summary || []).some(s => s.algo === 'MD5' && /内联/.test(s.evidence || '')), sumText(r2));
}

console.log('\nE) 多 lane 双射表（cnbragon 的真实 `00 v v v` 布局）');
{
  const perm = Array.from({ length: 256 }, (_, i) => i);
  let s = 987654321 >>> 0;
  const rnd = () => (s = (s * 1664525 + 1013904223) >>> 0) / 4294967296;
  for (let i = 255; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }

  // 布局 1：`00 v v v` —— lane0 恒 0，lane1-3 逐项相等（cnbragon）
  const b1 = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) {
    b1[i * 4] = 0; b1[i * 4 + 1] = perm[i]; b1[i * 4 + 2] = perm[i]; b1[i * 4 + 3] = perm[i];
  }
  const r1 = scanCryptoFingerprints(tmp('t_lane_cn.bin', Buffer.concat([Buffer.alloc(64, 0x90), b1, Buffer.alloc(64, 0x90)])));
  const h1 = (r1.fingerprints || []).find(x => x.fp === 'SBOX-256' && x.algo === 'CUSTOM-BLOCK');
  check('`00 v v v` → 识别为 CUSTOM-BLOCK', !!h1, sumText(r1));
  check('stride=4 且 valueLane=1', h1 && h1.stride === 4 && h1.valueLane === 1, h1 ? `stride=${h1.stride} lane=${h1.valueLane}` : 'no hit');
  check('dword 偏移 (0x40) 被正确报出', h1 && parseInt(h1.offset, 16) === 64, h1 && h1.offset);
  check('常量差分分析用的是值 lane 起点', h1 && h1.constantAnalysis && parseInt(h1.constantAnalysis.sboxFileOffset, 16) === 65,
    h1 && h1.constantAnalysis && h1.constantAnalysis.sboxFileOffset);

  // 布局 2：`v 0 0 0` —— 值在低字节（Disguise 的 dword 数组）
  const b2 = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) b2.writeUInt32LE(perm[i], i * 4);
  const r2 = scanCryptoFingerprints(tmp('t_lane_le.bin', Buffer.concat([Buffer.alloc(64, 0x90), b2, Buffer.alloc(64, 0x90)])));
  const h2 = (r2.fingerprints || []).find(x => x.fp === 'SBOX-256' && x.algo === 'CUSTOM-BLOCK');
  check('`v 00 00 00` → 同样识别（valueLane=0）', h2 && h2.valueLane === 0 && h2.stride === 4, h2 ? `lane=${h2.valueLane}` : 'no hit');

  // 排除项：恒等表 / 仿射表都不应产生 CUSTOM-BLOCK
  const ident = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) { ident[i * 4] = i; ident[i * 4 + 1] = i; ident[i * 4 + 2] = i; }
  const rId = scanCryptoFingerprints(tmp('t_lane_ident.bin', Buffer.concat([Buffer.alloc(64, 0x90), ident, Buffer.alloc(64, 0x90)])));
  check('恒等表（lane 镜像）不报 CUSTOM-BLOCK', !(rId.fingerprints || []).some(x => x.algo === 'CUSTOM-BLOCK'), sumText(rId));

  const aff = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) { const v = (i * 37 + 11) & 0xff; aff[i * 4] = v; aff[i * 4 + 1] = v; aff[i * 4 + 2] = v; }
  const rAf = scanCryptoFingerprints(tmp('t_lane_affine.bin', Buffer.concat([Buffer.alloc(64, 0x90), aff, Buffer.alloc(64, 0x90)])));
  check('仿射表（a*i+b）不报 CUSTOM-BLOCK', !(rAf.fingerprints || []).some(x => x.algo === 'CUSTOM-BLOCK'), sumText(rAf));
}

console.log('\nF) 误报安全（真实系统大二进制）');
{
  const cands = [
    'C:/Windows/System32/ntdll.dll',
    'C:/Windows/System32/kernel32.dll',
    'C:/Windows/System32/msvcrt.dll',
    p.join(__dirname, '..', 'node_modules/electron/dist/electron.exe'),
    p.join(__dirname, '..', 'src/js/app.js'),
  ];
  let tested = 0, falsePos = 0;
  for (const c of cands) {
    if (!fs.existsSync(c)) continue;
    tested++;
    const r = scanCryptoFingerprints(c);
    const fpText = sumText(r);
    // 误报判据：任何置信度（含 medium）的 CUSTOM-BLOCK 都不应出现在通用二进制上，
    // 也不得给出 high 置信度的分组密码判定。
    // 旧断言只看 high 与"疑似非 low"，新增的 medium 条目会整段漏检。
    const customHits = (r.fingerprints || []).filter(x => x.fp === 'SBOX-256' && x.algo === 'CUSTOM-BLOCK');
    // electron.exe 属超大体量通用程序：>16MB 时 summary 已降级为 low，但 fingerprints 里仍会有
    // 真实存在的置换表（其自带密码库）。对这类文件只断言"不产生 high 判定"。
    const isGenericHuge = (r.size || 0) > 16 * 1024 * 1024;
    const bad = (r.summary || []).some(s => /自定义分组密码/.test(s.algo) && s.confidence === 'high')
      || (r.summary || []).some(s => /疑似自定义分组密码/.test(s.algo) && s.confidence !== 'low')
      || (!isGenericHuge && customHits.length > 0);
    if (bad) { falsePos++; console.log('     ⚠️ ' + p.basename(c) + ' → ' + fpText + ' | CUSTOM-BLOCK=' + customHits.length); }
    else console.log('     ✓ ' + p.basename(c) + ' (' + (r.size / 1024 | 0) + 'KB) → ' + fpText);
  }
  check(`测试了 ${tested} 个真实二进制，无 high 置信度误报`, tested > 0 && falsePos === 0, `误报 ${falsePos} 个`);
}

console.log('\nG) 真实样本回归（--real <crackme2> <cnbragon>，缺省跳过）');
{
  // 真样本不入库（体积/版权），CI 不依赖本机样本目录。
  const realArgs = process.argv.reduce((acc, a, i, arr) => (a === '--real' ? arr.slice(i + 1).filter(Boolean) : acc), []);
  const crackme2 = realArgs[0] || '';
  const cnbragon = realArgs[1] || '';
  if (!crackme2) console.log('     （未提供 --real，跳过真样本校验）');
  if (crackme2 && fs.existsSync(crackme2)) {
    const r = scanCryptoFingerprints(crackme2);
    check('CrackMe2 → summary 含 MD5（散落 K 表）', has(r, /^MD5$/), sumText(r));
    const md5 = (r.summary || []).find(s => s.algo === 'MD5') || {};
    check('CrackMe2 → MD5 置信度 high 且证据含 64/64', md5.confidence === 'high' && /64\/64/.test(md5.evidence || ''), md5.evidence);
    check('CrackMe2 → 结论不再含"极可能…壳"', !(r.summary || []).some(s => /极可能/.test(s.note || '')));
  } else {
    console.log('     （跳过 CrackMe2：样本不存在）');
  }

  const cnbragonPath = cnbragon;
  if (cnbragonPath && fs.existsSync(cnbragonPath)) {
    const r = scanCryptoFingerprints(cnbragonPath);
    check('cnbragon → summary 含自定义分组密码', has(r, /自定义分组密码/), sumText(r));
    // 真实布局是 `00 v v v`：只保留 valueLane=1 的那条（0x1fb98）
    const h = (r.fingerprints || []).find(x => x.fp === 'SBOX-256' && x.algo === 'CUSTOM-BLOCK' && x.valueLane === 1);
    check('cnbragon → 0x1fb98 条目 stride=4 / valueLane=1',
      h && h.stride === 4 && parseInt(h.offset, 16) === 0x1fb98, h ? `${h.offset} stride=${h.stride} lane=${h.valueLane}` : 'no hit');
    check('cnbragon → 该条分析笔记写明 lane 1',
      h && h.constantAnalysis && h.constantAnalysis.notes.some(n => /lane 1/.test(n)),
      h && h.constantAnalysis && h.constantAnalysis.notes.find(n => /lane/.test(n)));
  } else {
    console.log('     （跳过 cnbragon：样本不存在）');
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
