// 指令边界重建（方案 A）
//
// 核心主张：**不修改任何字节**，只重建"哪些地址是指令起点"。
// 依据：花指令的杀伤机制是让反汇编器的边界判断出错；而"跳转目标必须是指令起点"
// 这一事实本身就是纠错依据——把目标强制当起点（MakeCode 语义），
// 而不是把"目标非边界"当成"花指令位置"（那是把症状当病灶，实测会导致越修越乱）。
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const { buildBoundaryMap } = require('../electron/boundary-map.js');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

console.log('[1] 接线');
{
  ok(/require\('\.\/boundary-map'\)/.test(mainSrc), 'main.js require boundary-map');
  ok(/buildBoundaryMap\(buf/.test(mainSrc), 'junk_scan 调用 buildBoundaryMap');
  ok(/mode === 'boundary'/.test(mainSrc), 'junk_scan 支持 mode=boundary');
  ok(/不修改任何字节/.test(mainSrc), '输出明确声明不改字节');
}

console.log('\n[2] 行为：入口 + 控制流展开');
{
  // 构造：entry 处 jmp 到 0x10，0x10 处 ret；中间是"永不被执行"的字节
  const b = Buffer.alloc(64, 0x90);
  b[0] = 0xeb; b[1] = 0x0e;             // jmp +14 → 0x10
  b[16] = 0xc3;                          // ret
  const r = buildBoundaryMap(b, { start: 0, end: b.length, seeds: [0] });
  ok(r.ok === true, '构建成功');
  ok(r.boundaries.includes(0) && r.boundaries.includes(16), '入口与跳转目标都是边界');
  ok(r.unreached.length >= 1, '识别出不可达区间（2..16）', JSON.stringify(r.unreached));
  const gap = r.unreached.find(u => u.from === 2 && u.to === 16);
  ok(!!gap, '不可达区间精确匹配 [2,16)', JSON.stringify(r.unreached));
}

console.log('\n[3] 核心：跳转目标强制对齐（MakeCode 语义）');
{
  // 构造"花指令式错位"：entry 处 jmp 到 0x8，但 0x5 处有 1 字节垃圾
  // 若线性扫描，0x8 会落在某条指令中间；本工具应把 0x8 强制当起点
  const b = Buffer.alloc(48, 0x90);
  b[0] = 0xe9; b.writeInt32LE(3, 1);     // jmp +3 → 0x8
  b[8] = 0x31; b[9] = 0xc0;              // xor eax,eax
  b[10] = 0xc3;                          // ret
  const r = buildBoundaryMap(b, { start: 0, end: b.length, seeds: [0] });
  ok(r.boundaries.includes(8), '跳转目标 0x8 成为边界');
  ok(r.forcedAligns.length >= 1, '记录了强制对齐事件', String(r.forcedAligns.length));
  const fa = r.forcedAligns.find(f => f.target === 8);
  ok(!!fa && fa.from === 0, '强制对齐记录 from=0 target=8', JSON.stringify(fa));
}

console.log('\n[4] 种子：函数序言扫描');
{
  const b = Buffer.alloc(64, 0x90);
  b[0] = 0xc3;                            // entry: ret（避免展开过多）
  b[32] = 0x55; b[33] = 0x89; b[34] = 0xe5;   // push ebp; mov ebp,esp
  b[35] = 0xc3;                            // ret
  const r = buildBoundaryMap(b, { start: 0, end: b.length, seeds: [0] });
  ok(r.seeds.includes(32), '函数序言 (55 89 E5) 被当作种子', JSON.stringify(r.seeds));
  ok(r.boundaries.includes(32), '序言处成为边界');
}

console.log('\n[5] 真实样本：合成花指令 + 不可达垃圾');
{
  // push ebx; xor ebx,ebx; test ebx,ebx; jnz+1; <0xE8 垃圾>; pop ebx; ret
  const b = Buffer.from([
    0x53, 0x31, 0xdb, 0x85, 0xdb, 0x75, 0x01, 0xe8, 0x5b, 0xc3,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  ]);
  const r = buildBoundaryMap(b, { start: 0, end: b.length, seeds: [0] });
  ok(r.ok, '构建成功');
  // jnz+1 目标 = 0x8（落在 0xE8 之后），强制对齐应记录
  ok(r.forcedAligns.some(f => f.target === 8), 'jnz+1 目标 0x8 被强制对齐', JSON.stringify(r.forcedAligns));
  ok(r.boundaries.includes(8), '0x8 成为边界');
}

console.log('\n[6] 统计口径');
{
  const b = Buffer.alloc(100, 0x90);
  b[0] = 0xc3;
  const r = buildBoundaryMap(b, { start: 0, end: b.length, seeds: [0] });
  ok(typeof r.stats.coverage === 'number' && r.stats.coverage >= 0 && r.stats.coverage <= 100, 'coverage 是 0~100 的百分比', String(r.stats.coverage));
  ok(r.stats.unreachableBytes === (r.unreached || []).reduce((s, x) => s + (x.to - x.from), 0), 'unreachableBytes 与 unreached 一致');
  ok(r.mode === 'boundary-map', 'mode 标记正确');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
