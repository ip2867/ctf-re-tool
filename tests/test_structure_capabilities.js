#!/usr/bin/env node
'use strict';

/**
 * 本轮新增的 4 个能力模块的契约测试（全部带负向断言）。
 *
 *   elf-anomaly.js       ELF 结构级异常（段尾缝隙/重定位矛盾/TEXTREL/空壳函数）
 *   blob-decrypt.js      加密 blob 的自解密器推断（多家族试解 + 可判读性打分）
 *   arx-solve.js         GF(2) 线性映射反解 / 矩阵求逆 / 三轮 Feistel 化简
 *   firmware-package.js  固件/OTA 包结构解析（魔数/描述符/尾部标记/摘要匹配）
 *
 * 设计原则：**不针对具体题目**。这里用随机生成的结构做断言，判据来自
 * "正常编译器/正常打包器不会这么干" 的事实，因此对任意样本成立。
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const E = require(path.join(ROOT, 'electron', 'elf-anomaly.js'));
const B = require(path.join(ROOT, 'electron', 'blob-decrypt.js'));
const A = require(path.join(ROOT, 'electron', 'arx-solve.js'));
const F = require(path.join(ROOT, 'electron', 'firmware-package.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

// ═══════════════ elf-anomaly ═══════════════
console.log('=== elf-anomaly：ELF 结构级异常 ===');

/** 造一个最小 ELF64 LE 头 */
function buildElfHeader({ phoff = 0x40, phnum = 0, shoff = 0, shnum = 0, shstrndx = 0, type = 3, machine = 62, entry = 0x1000 } = {}) {
  const b = Buffer.alloc(64);
  b[0] = 0x7f; b[1] = 0x45; b[2] = 0x4c; b[3] = 0x46;
  b[4] = 2;            // 64 位
  b[5] = 1;            // LE
  b[6] = 1;            // version
  b.writeUInt16LE(type, 16);
  b.writeUInt16LE(machine, 18);
  b.writeBigUInt64LE(BigInt(entry), 24);
  b.writeBigUInt64LE(BigInt(phoff), 32);
  b.writeBigUInt64LE(BigInt(shoff), 40);
  b.writeUInt16LE(64, 52);           // ehsize
  b.writeUInt16LE(56, 54);           // phentsize
  b.writeUInt16LE(phnum, 56);
  b.writeUInt16LE(64, 58);           // shentsize
  b.writeUInt16LE(shnum, 60);
  b.writeUInt16LE(shstrndx, 62);
  return b;
}
function buildPhdr64({ type, flags = 4, offset, vaddr, filesz, memsz, align = 0x1000 }) {
  const b = Buffer.alloc(56);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(flags, 4);
  b.writeBigUInt64LE(BigInt(offset), 8);
  b.writeBigUInt64LE(BigInt(vaddr), 16);
  b.writeBigUInt64LE(BigInt(vaddr), 24);
  b.writeBigUInt64LE(BigInt(filesz), 32);
  b.writeBigUInt64LE(BigInt(memsz), 40);
  b.writeBigUInt64LE(BigInt(align), 48);
  return b;
}

t('非 ELF 返回 null（不能把任意文件当 ELF 分析）', () => {
  assert.strictEqual(E.analyzeElfAnomalies(Buffer.from('not an elf at all')), null);
  assert.strictEqual(E.analyzeElfAnomalies(Buffer.alloc(0)), null);
});

t('正常 ELF（无页尾数据、无 TEXTREL）不得报高危', () => {
  // 1 个 LOAD，filesz 正好填满页，页尾无数据
  const hdr = buildElfHeader({ phoff: 0x40, phnum: 1, shoff: 0, shnum: 0 });
  const ph = buildPhdr64({ type: 1, offset: 0, vaddr: 0, filesz: 0x1000, memsz: 0x1000 });
  const buf = Buffer.concat([hdr, ph, Buffer.alloc(0x1000 - 0x40 - 56)]);
  const r = E.analyzeElfAnomalies(buf);
  assert.ok(r, '应识别为 ELF');
  const hi = r.findings.filter((x) => x.severity === 'high');
  assert.deepStrictEqual(hi.map((x) => x.kind), [], '正常 ELF 不该有高危项：' + JSON.stringify(hi));
});

t('段尾缝隙藏数据必须检出（零填充 + 中间夹真数据也要检出）', () => {
  // LOAD filesz=0x100，页对齐到 0x1000 → 页尾 0xf00 字节；在 0x800 处塞 128 字节高熵数据
  const hdr = buildElfHeader({ phoff: 0x40, phnum: 1, shoff: 0, shnum: 0 });
  const ph = buildPhdr64({ type: 1, offset: 0, vaddr: 0, filesz: 0x100, memsz: 0x100 });
  const body = Buffer.alloc(0x1000);
  // 用确定性伪随机填充页尾中段
  let s = 0x12345678;
  for (let i = 0x800; i < 0x880; i++) { s = (s * 1664525 + 1013904223) >>> 0; body[i] = s & 0xff; }
  const buf = Buffer.concat([hdr, ph]).length < 0x1000
    ? Buffer.concat([Buffer.concat([hdr, ph]), body.slice(0x40 + 56, 0x1000)])
    : body;
  const full = Buffer.alloc(0x1000);
  hdr.copy(full, 0);
  ph.copy(full, 0x40);
  for (let i = 0x800; i < 0x880; i++) full[i] = body[i];
  const r = E.analyzeElfAnomalies(full);
  const hit = r.findings.find((x) => x.kind === 'segment-slack-data');
  assert.ok(hit, '页尾藏数据未检出：' + JSON.stringify(r.findings.map((x) => x.kind)));
  const offs = (hit.detail || []).map((d) => d.fileOffset);
  assert.ok(offs.some((o) => parseInt(o, 16) >= 0x800 && parseInt(o, 16) < 0x880),
    '未定位到 0x800 附近的数据块：' + JSON.stringify(offs));
});

t('负向断言：页尾全是 0 时不得报 segment-slack-data', () => {
  const hdr = buildElfHeader({ phoff: 0x40, phnum: 1, shoff: 0, shnum: 0 });
  const ph = buildPhdr64({ type: 1, offset: 0, vaddr: 0, filesz: 0x100, memsz: 0x100 });
  const full = Buffer.alloc(0x1000);
  hdr.copy(full, 0); ph.copy(full, 0x40);
  const r = E.analyzeElfAnomalies(full);
  const hit = r.findings.find((x) => x.kind === 'segment-slack-data');
  assert.ok(!hit, '全 0 页尾被误报：' + (hit && JSON.stringify(hit.detail)));
});

t('findDataBlocks：滑窗能跳过零填充找到真数据', () => {
  const buf = Buffer.alloc(4096);
  let s = 0xdeadbeef;
  for (let i = 1000; i < 1200; i++) { s = (s * 1664525 + 1013904223) >>> 0; buf[i] = s & 0xff; }
  const blocks = E.findDataBlocks(buf);
  assert.ok(blocks.length > 0, '未找到数据块');
  const b0 = blocks[0];
  assert.ok(b0.start <= 1000 && b0.end >= 1200, `块边界不准：${b0.start}..${b0.end}`);
});

// ═══════════════ blob-decrypt ═══════════════
console.log('\n=== blob-decrypt：自解密器推断 ===');

t('xor-chain-word：对**手工构造**的密文能精确还原（不做自逆假设）', () => {
  // 链式 XOR 不是自逆的：解密是 "key 累加上一个**明文** word"，
  // 所以不能拿解密函数当加密函数用（早期测试在这里错了）。
  // 正确做法：按正向定义手工造密文 C[i] = P[i] ^ key，key = (key + P[i]) & mask。
  const plain = Buffer.alloc(256);
  let s = 0xabcdef01;
  for (let i = 0; i < plain.length; i++) { s = (s * 1664525 + 1013904223) >>> 0; plain[i] = s & 0xff; }
  const W = 4, N = plain.length / W;
  const cipher = Buffer.from(plain);
  let key = 0n;
  const mask = 0xffffffffn;
  for (let i = N - 1; i >= 1; i--) {
    const pv = BigInt(plain.readUInt32LE(i * W));
    cipher.writeUInt32LE(Number((pv ^ key) & mask), i * W);
    key = (key + pv) & mask;
  }
  const back = B.xorChainWords(cipher, { width: W, direction: 'down', key0: 0 });
  assert.deepStrictEqual(back, plain, '链式 XOR 未还原明文');
});

t('autoDecrypt：对链式 XOR 加密的代码块，正确答案必须排第一', () => {
  // 造一段"看起来像 x86 代码"的明文（NOP 滑板 + endbr64 + ret 模式）
  const plain = Buffer.alloc(512);
  for (let i = 0; i < 256; i++) plain[i] = 0x90;
  plain[256] = 0xf3; plain[257] = 0x0f; plain[258] = 0x1e; plain[259] = 0xfa;
  for (let i = 260; i < 496; i++) plain[i] = 0x90;
  plain[496] = 0xc3;
  // 按正向定义手工加密（不能拿解密函数当加密用）
  const W = 4, N = plain.length / W, mask = 0xffffffffn;
  const cipher = Buffer.from(plain);
  let key = 0n;
  for (let i = N - 1; i >= 1; i--) {
    const pv = BigInt(plain.readUInt32LE(i * W));
    cipher.writeUInt32LE(Number((pv ^ key) & mask), i * W);
    key = (key + pv) & mask;
  }
  const r = B.autoDecrypt(cipher, { kind: 'code', single: false, limit: 4 });
  assert.strictEqual(r.best.algo, 'xor-chain-word',
    '正确答案没排第一：' + JSON.stringify(r.top.map((x) => [x.algo, x.params, x.score])));
  assert.deepStrictEqual(r.best._out, plain, '第一名解出的明文不对');
});

t('负向断言：错误算法（rolling-xor）解出的结果必须与明文不同', () => {
  const plain = Buffer.alloc(256, 0x90);
  plain[0] = 0xf3; plain[1] = 0x0f; plain[2] = 0x1e; plain[3] = 0xfa;
  const W = 4, N = plain.length / W, mask = 0xffffffffn;
  const cipher = Buffer.from(plain);
  let key = 0n;
  for (let i = N - 1; i >= 1; i--) {
    const pv = BigInt(plain.readUInt32LE(i * W));
    cipher.writeUInt32LE(Number((pv ^ key) & mask), i * W);
    key = (key + pv) & mask;
  }
  const wrong = B.rollingXor(cipher, { reverse: false });
  assert.notDeepStrictEqual(wrong, plain, '错误算法竟解出正确明文 —— 测试失效');
});

t('scoreResult：可打印文本比随机字节分高', () => {
  const text = Buffer.from('hello world this is plain text 12345', 'latin1');
  const rand = Buffer.alloc(text.length);
  let s = 7;
  for (let i = 0; i < rand.length; i++) { s = (s * 1664525 + 1013904223) >>> 0; rand[i] = s & 0xff; }
  const st = B.scoreResult(text, 'text');
  const sr = B.scoreResult(rand, 'text');
  assert.ok(st.score > sr.score, `文本应得分更高：text=${st.score} rand=${sr.score}`);
});

t('parseStubParams：能从 elfstudy 形态的 stub 抽出参数', () => {
  const asm = [
    'lea rdi, [rbx + 0x71]',
    'mov ecx, 0xcb',
    'xor eax, eax',
    'xor dword ptr [rdi + rcx*4], eax',
    'add eax, [rdi + rcx*4]',
    'loop 0x7364',
  ].join('\n');
  const p = B.parseStubParams(asm);
  assert.strictEqual(p.width, 4, '宽度应为 4');
  assert.strictEqual(p.count, 0xcb, '计数应为 0xcb');
  assert.strictEqual(p.direction, 'down', '方向应为 down');
  assert.strictEqual(p.accumulate, true, '应识别 key 累加');
  assert.strictEqual(p.key0, 0, '应识别 key 初值 0');
  assert.ok(p.evidence.length >= 4, '应给出证据列表');
});

t('负向断言：给一段无关汇编，不得编造参数', () => {
  const p = B.parseStubParams('mov rax, rbx\nret');
  assert.strictEqual(p.width, null, '不应凭空空想宽度');
  assert.strictEqual(p.count, null, '不应凭空想计数');
});

// ═══════════════ arx-solve ═══════════════
console.log('\n=== arx-solve：GF(2) 与 Feistel ===');

function randInvMatrix(n, seed) {
  let s = seed >>> 0;
  const rnd = () => (s = (s * 1664525 + 1013904223) >>> 0) / 4294967296;
  for (let k = 0; k < 1000; k++) {
    const M = [];
    for (let i = 0; i < n; i++) M.push(Array.from({ length: n }, () => (rnd() < 0.5 ? 1 : 0)));
    if (A.invertMatrix(M, n).ok) return M;
  }
  return [...Array(n)].map((_, i) => [...Array(n)].map((_, j) => (i === j ? 1 : 0)));
}

t('linearMap：从单位向量样本反解，必须精确还原随机可逆矩阵', () => {
  for (const n of [4, 8, 12]) {
    const M = randInvMatrix(n, 42 + n);
    const pairs = [];
    for (let k = 0; k < n; k++) {
      const x = new Array(n).fill(0); x[k] = 1;
      pairs.push({ in: x, out: A.matVec(M, x) });
    }
    const r = A.linearMap(pairs, n, n);
    assert.ok(r.ok, `n=${n} 反解失败：${r.reason}`);
    assert.deepStrictEqual(r.M, M, `n=${n} 反解矩阵与真值不符`);
  }
});

t('invertMatrix：M⁻¹·(M·x) == x', () => {
  for (const n of [4, 8, 16]) {
    const M = randInvMatrix(n, 99 + n);
    const inv = A.invertMatrix(M, n);
    assert.ok(inv.ok, `n=${n} 求逆失败`);
    const x = Array.from({ length: n }, (_, i) => i % 2);
    assert.deepStrictEqual(A.matVec(inv.inv, A.matVec(M, x)), x, `n=${n} 逆矩阵不对`);
  }
});

t('负向断言：奇异矩阵必须报失败（不能编一个逆矩阵）', () => {
  const singular = [[1, 1, 0, 0], [1, 1, 0, 0], [0, 0, 1, 1], [0, 0, 1, 1]];
  const r = A.invertMatrix(singular, 4);
  assert.strictEqual(r.ok, false, '奇异矩阵竟求出了逆');
});

t('负向断言：样本不足时 linearMap 必须失败（不能给出一个解）', () => {
  const M = randInvMatrix(8, 5);
  const pairs = [{ in: [1, 0, 0, 0, 0, 0, 0, 0], out: A.matVec(M, [1, 0, 0, 0, 0, 0, 0, 0]) }];
  const r = A.linearMap(pairs, 8, 8);
  assert.strictEqual(r.ok, false, '样本不足却给出解：' + JSON.stringify(r));
  assert.ok(/不足|秩/.test(r.reason), '失败原因应说明样本不足：' + r.reason);
});

t('apply4x4：字节向量上的 GF(2) 矩阵是线性的', () => {
  const P = [[1, 0, 1, 0], [0, 1, 0, 1], [1, 1, 0, 0], [0, 1, 1, 1]];
  const a = [0x12, 0x34, 0x56, 0x78];
  const b = [0xff, 0x00, 0xaa, 0x55];
  const pa = A.apply4x4(P, a);
  const pb = A.apply4x4(P, b);
  const pab = A.apply4x4(P, a.map((v, i) => v ^ b[i]));
  assert.deepStrictEqual(pab, pa.map((v, i) => v ^ pb[i]), 'apply4x4 不是线性的');
});

t('feistel3Invert：判据在真值 t 上必须成立（U^V^W^t==0）', () => {
  const SBOX = Array.from({ length: 256 }, (_, i) => (i * 167 + 13) & 0xff);
  const SINV = new Array(256);
  for (let i = 0; i < 256; i++) SINV[SBOX[i]] = i;
  const mk = (P, Q, k) => {
    const Pi = A.invertMatrix(P, 4).inv, Qi = A.invertMatrix(Q, 4).inv;
    return {
      g: (x) => A.apply4x4(Q, A.apply4x4(P, x.map((v, i) => v ^ k[i])).map((v) => SBOX[v])),
      gInv: (z) => A.apply4x4(Pi, A.apply4x4(Qi, z).map((v) => SINV[v])).map((v, i) => v ^ k[i]),
    };
  };
  const R = [
    mk(randInvMatrix(4, 1), randInvMatrix(4, 2), [1, 2, 3, 4]),
    mk(randInvMatrix(4, 3), randInvMatrix(4, 4), [5, 6, 7, 8]),
    mk(randInvMatrix(4, 5), randInvMatrix(4, 6), [9, 10, 11, 12]),
  ];
  const F1 = (x) => x.map((v, i) => v ^ R[0].g(x)[i]);
  const F2 = (x) => x.map((v, i) => v ^ R[1].g(x)[i]);
  const F3 = (x) => x.map((v, i) => v ^ R[2].g(x)[i]);
  const xor4 = (a, b) => a.map((v, i) => v ^ b[i]);
  const L = [0x01, 0x23, 0x45, 0x67], Rr = [0x89, 0xab, 0xcd, 0xef];
  const U = Rr;
  const V = xor4(L, F1(U));
  const W = xor4(U, F2(V));
  const L3 = W, R3 = xor4(V, F3(W));
  const yL = xor4(L3, L), yR = xor4(R3, Rr);
  const tt = xor4(xor4(U, V), W);
  // 判据
  const lhs = xor4(xor4(R[0].gInv(xor4(tt, yL)), R[1].gInv(tt)), xor4(R[2].gInv(xor4(tt, yR)), tt));
  assert.deepStrictEqual(lhs, [0, 0, 0, 0], '判据不成立：' + JSON.stringify(lhs));
  // 重建
  assert.deepStrictEqual(R[1].gInv(tt), V, 'g2⁻¹(t) 未还原 V');
});

t('buildFeistelC：生成的 C 源码结构完整（含 main/SINV 初始化/2^32 循环）', () => {
  const SBOX = Array.from({ length: 256 }, (_, i) => (i * 7 + 1) & 0xff);
  const mkP = () => [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]];
  const rounds = [0, 1, 2].map((i) => ({ P: mkP(), Q: mkP(), k: [i, i, i, i], Pinv: mkP(), Qinv: mkP() }));
  const src = A.buildFeistelC({ sbox: SBOX, rounds, yL: [1, 2, 3, 4], yR: [5, 6, 7, 8] });
  for (const kw of ['#include <stdio.h>', 'int main(void)', 'SINV[SBOX[i]]', 'for (uint32_t a = 0; a < 256; a++)', 'HIT L=']) {
    assert.ok(src.includes(kw), 'C 源码缺关键片段：' + kw);
  }
  assert.ok(src.length > 2000 && src.length < 20000, '源码长度异常：' + src.length);
});

t('负向断言：rounds 不足 3 轮时 buildFeistelC 必须报错', () => {
  assert.throws(() => A.buildFeistelC({ sbox: new Array(256).fill(0), rounds: [], yL: [0, 0, 0, 0], yR: [0, 0, 0, 0] }),
    /3 轮/, '未报错');
});

// ═══════════════ firmware-package ═══════════════
console.log('\n=== firmware-package：固件/OTA 包解析 ===');

t('findMagics：能认出常见固件魔数', () => {
  const buf = Buffer.concat([
    Buffer.from('QWBP', 'latin1'), Buffer.alloc(16),
    Buffer.from('hsqs', 'latin1'), Buffer.alloc(16),
    Buffer.from('_CPI', 'latin1'), Buffer.alloc(16),
  ]);
  const hits = F.findMagics(buf);
  const names = hits.map((h) => h.name);
  assert.ok(names.includes('QWBP') && names.includes('squashfs') && names.includes('CPIO'),
    '魔数识别不全：' + JSON.stringify(names));
});

t('尾部标记块：识别 `<标记><u32 LE 长度><数据>` 结构', () => {
  const marker = Buffer.from('TESTFLAG', 'latin1');
  const body = Buffer.from('0123456789abcdef', 'latin1');
  const len = Buffer.alloc(4); len.writeUInt32LE(body.length, 0);
  const buf = Buffer.concat([Buffer.alloc(32), marker, len, body]);
  const r = F.analyzePackage(buf);
  const hit = r.trailers.find((x) => x.marker === 'TESTFLAG');
  assert.ok(hit, '未识别尾部标记块：' + JSON.stringify(r.trailers));
  assert.strictEqual(hit.offset, 32, '标记偏移不对');
  assert.strictEqual(hit.length, body.length, '长度不对');
  assert.strictEqual(hit.bodyOffset, 32 + 8 + 4, '数据起点不对');
});

t('负向断言：长度字段越界时不得当成尾部块（防误报）', () => {
  const marker = Buffer.from('BADMARK', 'latin1');
  const len = Buffer.alloc(4); len.writeUInt32LE(0x7fffffff, 0);   // 远超文件大小
  const buf = Buffer.concat([Buffer.alloc(16), marker, len, Buffer.alloc(8)]);
  const r = F.analyzePackage(buf);
  assert.strictEqual(r.trailers.length, 0, '越界长度被误报为尾部块：' + JSON.stringify(r.trailers));
});

t('findDescriptorTable + assembleByDescriptors：分段拼回正确', () => {
  // 造 3 段：放在文件不同位置，描述符表给出 (off, len)
  const seg1 = Buffer.from('AAAAAAAAAA', 'latin1');
  const seg2 = Buffer.from('BBBBBBBB', 'latin1');
  const seg3 = Buffer.from('CCCCCCCCC', 'latin1');
  const parts = [];
  parts.push(Buffer.alloc(8));                     // 0..8 头部
  // 描述符表放 8..（3×8 字节）
  const tbl = Buffer.alloc(24);
  const dOff = 8 + 24 + 16;
  // 布局：头(8) + 表(24) + 填充(16) + seg1 + seg2 + seg3
  const o1 = dOff, o2 = o1 + seg1.length, o3 = o2 + seg2.length;
  tbl.writeUInt32LE(o1, 0); tbl.writeUInt32LE(seg1.length, 4);
  tbl.writeUInt32LE(o2, 8); tbl.writeUInt32LE(seg2.length, 12);
  tbl.writeUInt32LE(o3, 16); tbl.writeUInt32LE(seg3.length, 20);
  const buf = Buffer.concat([Buffer.alloc(8), tbl, Buffer.alloc(16), seg1, seg2, seg3]);
  const tables = F.findDescriptorTable(buf);
  assert.ok(tables.length > 0, '未找到描述符表');
  const best = tables.find((x) => x.count === 3 && x.tableOffset === 8);
  assert.ok(best, '未找到 3 段的描述符表：' + JSON.stringify(tables.map((x) => [x.tableOffset, x.count])));
  const asm = F.assembleByDescriptors(buf, best.entries);
  assert.strictEqual(asm.toString('latin1'), 'AAAAAAAAAABBBBBBBBCCCCCCCCC', '拼回内容不对');
});

t('analyzePackage：QWBP 容器（模拟题 2 形态）能定位到尾部 flag 段', () => {
  // 构造成题 2 的真实布局：QWBP 头 + 摘要 + 描述符 + 数据 + QWBPFLAG + u32 len + 密文
  const head = Buffer.concat([Buffer.from('QWBP', 'latin1'), Buffer.alloc(4),
    Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]), Buffer.from([3, 0, 0, 0])]);
  const digest = Buffer.alloc(32, 0xaa);
  const descs = Buffer.alloc(36);
  const dataStart = 0x60;
  const segs = [Buffer.from('1111111111111', 'latin1'), Buffer.from('222222222222', 'latin1'), Buffer.from('3333333333333', 'latin1')];
  let o = dataStart;
  for (let i = 0; i < 3; i++) {
    descs.writeUInt32LE(o, i * 12); descs.writeUInt32LE(segs[i].length, i * 12 + 4);
    descs.writeUInt32LE(0, i * 12 + 8);
    o += segs[i].length;
  }
  const payload = Buffer.concat(segs);
  const trailer = Buffer.concat([Buffer.from('QWBPFLAG', 'latin1'), (() => { const b = Buffer.alloc(4); b.writeUInt32LE(30, 0); return b; })(), Buffer.alloc(30, 0x5c)]);
  const buf = Buffer.concat([head, digest, descs, payload, trailer]);
  const r = F.analyzePackage(buf);
  assert.ok(r.magics.some((m) => m.name === 'QWBP'), '未识别 QWBP 魔数');
  const fl = r.trailers.find((x) => x.marker === 'QWBPFLAG');
  assert.ok(fl, '未识别 QWBPFLAG：' + JSON.stringify(r.trailers.map((x) => x.marker)));
  assert.strictEqual(fl.length, 30, 'flag 段长度不对');
  assert.strictEqual(fl.bodyOffset, buf.length - 30, 'flag 数据起点不对');
});

t('负向断言：纯随机数据不得报出 QWBP/描述符（防误报）', () => {
  let s = 0x11223344;
  const buf = Buffer.alloc(512);
  for (let i = 0; i < buf.length; i++) { s = (s * 1664525 + 1013904223) >>> 0; buf[i] = s & 0xff; }
  const r = F.analyzePackage(buf);
  assert.ok(!r.magics.some((m) => m.name === 'QWBP'), '随机数据被误报 QWBP');
  assert.strictEqual(r.trailers.length, 0, '随机数据被误报尾部块：' + JSON.stringify(r.trailers));
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
