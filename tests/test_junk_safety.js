// 花指令修复的**安全性**回归（2026-10-26 代码审查后补齐）
//
// 这批用例锁定的都是"工具会静默改坏正常程序"的真实缺陷——
// 每一条都对应一次实测复现的 bug，删掉任何断言都会让同类问题重新溜进去。
const { decodeInsn } = require('../electron/junk-code.js');
const { scanJunkFeatures, applyRepair } = require('../electron/junk-repair.js');
const { buildBoundaryMap } = require('../electron/boundary-map.js');
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const hex = b => b.toString('hex');
const scan = (arr, opts) => scanJunkFeatures(Buffer.from(arr), Object.assign({ start: 0, end: arr.length, decodeInsn }, opts || {}));

console.log('[1] jcc32 必须带 rel（否则 boundary 崩溃 + 8 字节误删）');
{
  const d = decodeInsn(Buffer.from([0x0f, 0x85, 0x1d, 0x00, 0x00, 0x00]), 0);
  ok(d && d.kind === 'jcc32', 'kind=jcc32', d && d.kind);
  ok(d && d.rel === 29, 'rel=29（不是 null）', d && String(d.rel));
  ok(d && d.len === 6, 'len=6', d && String(d.len));
  // boundary 模式不应对含 jcc32 的输入崩溃
  let threw = null;
  try {
    buildBoundaryMap(Buffer.from([0x0f, 0x85, 0x02, 0x00, 0x00, 0x00, 0x90, 0x90, 0xc3]), { start: 0, end: 9, decodeInsn });
  } catch (e) { threw = e.message; }
  ok(threw === null, 'buildBoundaryMap 不抛异常', threw);
}

console.log('\n[2] test/cmp/and 不是"恒定标志位"，绝不能改字节');
{
  const cases = [
    ['test eax,eax; jz +2', [0x85, 0xc0, 0x74, 0x02, 0xb0, 0x01, 0xc3]],
    ['cmp eax,5; jz +2', [0x83, 0xf8, 0x05, 0x74, 0x02, 0xb0, 0x01, 0xc3]],
    ['add eax,5; jz +2', [0x83, 0xc0, 0x05, 0x74, 0x02, 0xb0, 0x01, 0xc3]],
    ['and eax,eax; jz +2', [0x21, 0xc0, 0x74, 0x02, 0xb0, 0x01, 0xc3]],
  ];
  for (const [name, arr] of cases) {
    const r = scan(arr);
    const ap = applyRepair(Buffer.from(arr), r.candidates);
    ok(hex(ap.buffer) === hex(Buffer.from(arr)), name + ' → 字节不变', hex(ap.buffer));
    ok(r.candidates.filter(c => c.safe).length === 0, name + ' → 无 safe 候选',
      String(r.candidates.filter(c => c.safe).length));
  }
}

console.log('\n[3] xor r,r 得到的恒定条件必须按**方向**处理');
{
  // xor eax,eax → ZF=1；jnz 永不跳 → 应 nop 掉 jnz，mov al,1 仍在执行路径
  const arr = [0x31, 0xc0, 0x75, 0x02, 0xb0, 0x01, 0xc3];
  const r = scan(arr);
  const ap = applyRepair(Buffer.from(arr), r.candidates);
  const out = hex(ap.buffer);
  ok(!out.includes('eb02'), 'jnz 没被改成 jmp +2（会跳过 mov al,1）', out);
  ok(out === '31c09090b001c3', 'jnz 换成等长 NOP，mov al,1 仍可达', out);
}
{
  // xor eax,eax; jz -2 → 条件恒真且是反向跳；绝不能产出 EB FE（死循环）
  const arr = [0x31, 0xc0, 0x74, 0xfe, 0xc3];
  const r = scan(arr);
  const ap = applyRepair(Buffer.from(arr), r.candidates);
  ok(!hex(ap.buffer).includes('ebfe'), '没有产出 0xEB 0xFE 死循环', hex(ap.buffer));
}

console.log('\n[4] jmp 跳 1~4 字节不能 nop（会让执行落入被跳过的字节）');
{
  // jmp +2 跳过 e8；nop 后 e8 会被当 call 执行
  const arr = [0xeb, 0x02, 0xe8, 0x5b, 0xc3];
  const r = scan(arr);
  const ap = applyRepair(Buffer.from(arr), r.candidates);
  ok(hex(ap.buffer) === hex(Buffer.from(arr)), 'jmp short 不被自动 nop', hex(ap.buffer));
  ok(r.candidates.filter(c => c.safe && c.feature === 'F05_jmp_chain').length === 0,
    'F05 短 jmp 只报告不改', String(r.candidates.filter(c => c.safe).length));
}

console.log('\n[5] 互补跳转对只在"两侧同目标"时才报告（不同目标绝不能动）');
{
  // jz +10 ; jnz +10 —— 两侧同目标，是恒跳构造；只报告
  const arr = [0x74, 0x0a, 0x75, 0x0a, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3];
  const r = scan(arr);
  const ap = applyRepair(Buffer.from(arr), r.candidates);
  ok(hex(ap.buffer) === hex(Buffer.from(arr)), '同目标互补对不改字节', hex(ap.buffer));
}

console.log('\n[6] end 超出文件长度必须被夹住（否则主进程 OOM）');
{
  const small = Buffer.alloc(4096, 0x90);
  const r = scanJunkFeatures(small, { start: 0, end: 69632, decodeInsn });
  ok(r.ok === true, 'ok=true（不崩不 OOM）', String(r.ok));
  ok(r.codeRange.end === 4096, 'end 夹到 buf.length', String(r.codeRange.end));
  ok(r.stats.insnCount <= 4096, '指令数不超过文件长度', String(r.stats.insnCount));
  ok(Array.isArray(r.warnings) && r.warnings.length > 0, 'warnings 说明已夹', JSON.stringify(r.warnings));
  // start 越界应明确失败而不是扫 0 长度
  const r2 = scanJunkFeatures(small, { start: 99999, end: 100000, decodeInsn });
  ok(r2.ok === false, 'start 越界 → ok:false', JSON.stringify(r2).slice(0, 80));
}

console.log('\n[7] features 允许 schema 宣传的短名（否则传了就静默关闭全部检测）');
{
  const arr = [0x31, 0xc0, 0x75, 0x02, 0xb0, 0x01, 0xc3];
  const all = scan(arr);
  const byFull = scan(arr, { features: ['F02_true_false_jcc'] });
  const byShort = scan(arr, { features: ['true_false_jcc'] });
  const byAlias = scan(arr, { features: ['opaque_pair'] });
  ok(byFull.candidates.length === all.candidates.length, '全名过滤保留 F02', String(byFull.candidates.length));
  ok(byShort.candidates.length === all.candidates.length, '短名 true_false_jcc 生效', String(byShort.candidates.length));
  ok(byAlias.candidates.length === all.candidates.length, '别名 opaque_pair 生效', String(byAlias.candidates.length));
  // 完全认不出的名字 → 回退全开，而不是全关
  const byUnknown = scan(arr, { features: ['nonsense_xyz'] });
  ok(byUnknown.candidates.length === all.candidates.length, '未知名回退全开（不是全关）', String(byUnknown.candidates.length));
  ok(byUnknown.stats.unknownFeatures && byUnknown.stats.unknownFeatures.length === 1, '未知名被记录', JSON.stringify(byUnknown.stats.unknownFeatures));
}

console.log('\n[8] applyRepair 的 to_jmp 分支必须校验负偏移');
{
  const buf = Buffer.from([0x90, 0x90, 0x90, 0x90]);
  const ap = applyRepair(buf, [{
    safe: true, strategy: 'to_jmp', feature: 'X', off: -1, len: 2,
    jmpPatch: { off: -1, bytes: [0xeb, 0x02] },
  }]);
  ok(ap.applied.length === 0, '负偏移被跳过', JSON.stringify(ap.applied));
  ok(hex(ap.buffer) === '90909090', 'buffer 未被写坏', hex(ap.buffer));
  ok(ap.skipped.length === 1, '记录跳过原因', JSON.stringify(ap.skipped));
}

console.log('\n[9] 解码器：32 位下 0x40-0x4F 是 inc/dec，不是 REX 前缀');
{
  const d = decodeInsn(Buffer.from([0x40, 0x40, 0x40, 0xc3]), 0);
  ok(d && d.len === 1, '0x40 单独解码为 1 字节', d && String(d.len));
  ok(d && d.kind === 'incdec', 'kind=incdec', d && d.kind);
  const dx = decodeInsn(Buffer.from([0x40, 0x40, 0x40, 0xc3]), 0, { x64: true });
  ok(dx && dx.len > 1, 'x64 模式下 0x40 当前缀（len>1）', dx && String(dx.len));
}

console.log('\n[10] 解码器：无 ModRM 的 0F xx 不能多吃一字节');
{
  for (const [name, bytes, wantLen] of [
    ['0F 77 emms', [0x0f, 0x77, 0xc3], 2],
    ['0F C8 bswap', [0x0f, 0xc8, 0xc3], 2],
    ['0F A2 cpuid', [0x0f, 0xa2, 0xc3], 2],
    ['66 E9 rel16', [0x66, 0xe9, 0x05, 0x00], 4],
  ]) {
    const d = decodeInsn(Buffer.from(bytes), 0);
    ok(d && d.len === wantLen, name + ' len=' + wantLen, d && String(d.len));
  }
}

console.log('\n[11] 解码器：漏掉的常见 ALU 立即数形式');
{
  for (const [name, bytes, wantLen] of [
    ['25 and eax,imm32', [0x25, 1, 2, 3, 4], 5],
    ['2D sub eax,imm32', [0x2d, 1, 2, 3, 4], 5],
    ['35 xor eax,imm32', [0x35, 1, 2, 3, 4], 5],
    ['3D cmp eax,imm32', [0x3d, 1, 2, 3, 4], 5],
    ['04 add al,imm8', [0x04, 1], 2],
    ['A4 movsb', [0xa4], 1],
    ['91 xchg eax,ecx', [0x91], 1],
    ['C8 enter', [0xc8, 0x10, 0x00, 0x00], 4],
    ['CB retf', [0xcb], 1],
  ]) {
    const d = decodeInsn(Buffer.from(bytes), 0);
    ok(d && d.len === wantLen, name + ' len=' + wantLen, d && String(d.len));
  }
}

console.log('\n[12] 解码器：非法偏移返回 null（不抛错、不越界）');
{
  for (const off of [-1, null, undefined, NaN, 1e9]) {
    let d, err = null;
    try { d = decodeInsn(Buffer.from([0x90, 0xc3]), off); } catch (e) { err = e.message; }
    ok(err === null && d === null, 'off=' + String(off) + ' → null', err || JSON.stringify(d));
  }
}

console.log('\n[13] 修复链路接线（失败不得伪装成功）');
{
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/if \(!rr\.ok\)[\s\S]{0,200}工具调用失败/.test(mainSrc), 'ida_open_file 失败首行是"工具调用失败"');
  ok(/if \(rr\.ok\)[\s\S]{0,300}已指向修补后的库/.test(mainSrc),
    'junk_repair 仅在 rr.ok 时才说"已指向修补后的库"');
  ok(/openTimeoutSec = Math\.min\(waitSec, 55\)/.test(mainSrc), 'open_file 超时夹在 55s 内（避开传输层 60s 硬上限）');
  ok(/if \(wantNewDb\)[\s\S]{0,600}unlinkSync/.test(mainSrc), '只在 new_database=true 时删旧库');
  ok(/opts\.newDatabase === true/.test(mainSrc), '尊重 newDatabase 入参');
  ok(/list_instances/.test(mainSrc) && /select_instance/.test(mainSrc), '多实例兜底仍在');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
