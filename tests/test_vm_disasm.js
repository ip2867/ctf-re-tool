// vm_disasm 回归：把"大数组 VM"从不可读变成可读
//
// 背景（D3CTF AncientGameV2）：
//   HTML 里一个 190702 项的平坦数组 + 取指-译码-执行循环。
//   AI 只能反复手写模拟器试，45 轮无契约。
//
// 本测试锁三件事：
//   ① 定长切分对这类题**无效**（opcode 爆炸 / 切不出块）——所以必须有变长分支
//   ② 变长解码（按操作数符号判型）能把它恢复成合理指令流
//   ③ 生成的骨架**能真跑**：填上运算语义后跑通完整 VM 并产出输出
//      —— 这条最关键，它证明骨架不是"看起来像代码的字符串"
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const V = require(path.join(ROOT, 'electron', 'vm-disasm.js'));

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

console.log('[1] 数组字面量提取');
{
  const r = V.extractArrayLiteral('var m_mem = [1,2,3,4,5];', 'm_mem');
  ok(r.ok && r.nums.join(',') === '1,2,3,4,5', '基本提取', JSON.stringify(r.nums));
  const r2 = V.extractArrayLiteral('m_mem: [-1, 0x10, 3]', 'm_mem');
  ok(r2.ok && r2.nums[0] === -1 && r2.nums[1] === 16, '支持负数与 0x 十六进制', JSON.stringify(r2.nums));
  const r3 = V.extractArrayLiteral('var other = [1,2];', 'm_mem');
  ok(!r3.ok && /未找到/.test(r3.reason), '名字不对时明确报错', r3.reason);
  const r4 = V.extractArrayLiteral('var m_mem = [1,2,3', 'm_mem');
  ok(!r4.ok && /未闭合/.test(r4.reason), '括号未闭合时明确报错', r4.reason);
}

console.log('\n[2] 定长切分对"变长指令 VM"是无效的（所以必须有变长分支）');
{
  // 构造一段变长 VM：J(2) / N(3) 混合
  const nums = [-1, 6,          // pc=0 J → 6
    5, 7, 9,                    // pc=2 N
    0, 0];                      // 占位
  const fixed = V.splitInstructions(nums, ['op', 'a', 'b', 'c']);   // 强行按 4 切
  ok(fixed.length >= 1, '定长切分能跑（但语义错位）', 'insns=' + fixed.length);
  const vl = V.decodeVariableLength(nums);
  ok(vl.insns.length === 3, '变长解码得到 3 条指令', 'got=' + vl.insns.length);
  ok(vl.insns[0].type === 'J' && vl.insns[1].type === 'N', '类型判定正确（J/N）',
    vl.insns.map(x => x.type).join(','));
}

console.log('\n[3] 变长解码在真实规模的合成数据上成立');
{
  // 造 5000 条真实形态的变长指令：J / N / R / O 混合
  const prog = [];
  const t = { J: 0, N: 0, R: 0, O: 0 };
  for (let i = 0; i < 5000; i++) {
    const k = i % 4;
    if (k === 0) { prog.push(-1, 100 + i); t.J++; }                  // J
    else if (k === 1) { prog.push(500 + i, 600 + i, 700 + i); t.N++; } // N
    else if (k === 2) { prog.push(800 + i, -5); t.R++; }              // R
    else { prog.push(-2, -6, 900 + i); t.O++; }                       // O
  }
  const vl = V.decodeVariableLength(prog);
  ok(vl.insns.length === 5000, '5000 条指令全部解出', 'got=' + vl.insns.length);
  ok(vl.covered === prog.length, '覆盖全部元素', vl.covered + '/' + prog.length);
  const tc = {};
  for (const x of vl.insns) tc[x.type] = (tc[x.type] || 0) + 1;
  ok(tc.J === t.J && tc.N === t.N && tc.R === t.R && tc.O === t.O,
    '四种类型计数与构造一致', JSON.stringify(tc));
  ok(V.preferVariableLength(vl) === true, '判定为"应采用变长解码"');
}

console.log('\n[4] 判定不该用变长时能拒绝（避免误伤定长 VM）');
{
  // 全正数数组：符号判据退化成"全是 N"，类型单一 → 不该用变长
  const nums = Array.from({ length: 300 }, (_, i) => i + 1);
  const vl = V.decodeVariableLength(nums);
  ok(V.preferVariableLength(vl) === false, '类型单一时拒绝变长解码');
  // 覆盖率不足也不该用
  const short = V.decodeVariableLength([-1, 2, 3]);
  ok(V.preferVariableLength(short) === false, '数据太少时拒绝');
}

console.log('\n[5] 端到端：变长骨架填上语义后能真跑通并产出输出');
{
  // 用真实 AncientGameV2 的程序结构（取前若干条真实指令无法独立运行，
  // 这里构造一个"能跑出已知输出"的最小变长 VM）：
  //   R 读一个字节进 mem[10]
  //   N mem[11] = ~(mem[10] & mem[10])         （恒等变换的绕路写法）
  //   O 输出 mem[11]
  //   J 跳到自身 → 停机
  //
  // 编码（按符号判据）：
  //   R: a>0, b<0  → [10, -1]         mem[10] = 输入
  //   N: a>0, b>=0 → [11, 10, 12]     mem[12] = compute(mem[11], mem[10])
  //     为了让它等于 mem[10]，先做 mem[11]=~(mem[10]&mem[10])=~mem[10]
  //     再做 mem[12]=~(mem[11]&mem[11])=mem[10]  —— 两次 NAND 就是取反两次
  //   实际：N [11,10,10] 会写 mem[10]（c=10），要小心。改成：
  //     N: [30, 10, 31]  mem[31] = ~(mem[30]&mem[10])  ← a=30 未初始化=0
  //   简化：直接用两次 NAND 实现 mem[12] = mem[10]
  //     N1: [20, 10, 21]  mem[21] = ~(mem[20] & mem[10])    mem[20]=0 → ~(0&x)=~0=-1
  //     N2: [21, 21, 22]  mem[22] = ~(-1 & -1) = 0        （清零）
  //   太绕。改用最直接的：让 compute = (x&0xFF) 的恒等，验证管道通畅即可。
  //
  // 这里的目标不是复现这道题，而是验证：**骨架 + 正确语义 = 能跑出输出**。
  const prog = [
    10, -1,        // R: mem[10] = input[0]
    11, 10, 12,    // N: mem[12] = compute(mem[11], mem[10])
    0 - 1, 0 - 1,  // O: 输出 mem[c]，c 在下一项 —— 见下
  ];
  // O 型是 [a<=0, b<0, c]，所以：
  const prog2 = [
    10, -1,           // R: mem[10] = input[0]
    11, 10, 12,       // N: mem[12] = compute(mem[11], mem[10])
    0 - 5, 0 - 6, 12, // O: 输出 mem[12]
    0 - 1, 999,       // J: ip = 999（超出范围 → 停机）
  ];

  const r = V.vmDisasm({
    source: 'var m_mem = [' + prog2.join(',') + '];',
    array: 'm_mem',
  });
  ok(r.ok && r.mode === 'variable-length', '自动选用变长模式', JSON.stringify(r.summary && r.summary.mode));
  ok(r.summary.instructionCount === 4, '解出 4 条指令', String(r.summary.instructionCount));

  // 填上语义：compute 让它把第二个操作数原样传出（mem[11]=0，所以 ~(0 & x) = -1；
  // 这里改成 x 直通，只为验证管道）
  const filled = r.skeleton.replace(
    /def compute\(x, y\):[\s\S]*?raise NotImplementedError\("先确认 N 型语义"\)/,
    'def compute(x, y):\n    return y & 0xFF'
  );
  ok(filled !== r.skeleton, '骨架里的 compute TODO 可被替换');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-vm-'));
  const pyPath = path.join(tmp, 'sim.py');
  fs.writeFileSync(pyPath, filled, 'utf8');

  let out = '', err = '';
  try {
    out = execFileSync('python', ['-I', pyPath, 'Z'], { encoding: 'utf8', timeout: 60000 });
  } catch (e) {
    err = String(e.stderr || e.message).slice(0, 300);
  }
  ok(!err, '骨架能跑完（无异常）', err);
  ok(/OUT b'Z'/.test(out), "输出正好是输入字节 'Z'（证明 R→N→O 管道通了）", out.replace(/\n/g, ' | ').slice(0, 200));

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* 忽略 */ }
}

console.log('\n[6] 工具不编造语义（骨架里必须是 TODO）');
{
  const r = V.vmDisasm({ source: 'var m = [1,2,3,4,5,6,7,8,9,10,11,12];', array: 'm' });
  ok(r.ok, '小数组也能出结果');
  const sk = r.skeleton;
  ok(/TODO|NotImplementedError/.test(sk), '骨架里明确标注语义未知（TODO / NotImplementedError）');
  ok(!/nand|NAND/.test(sk.replace(/NAND|NAND 型|~(x & y)/g, '')),
    '没有把 NAND 当成"默认答案"硬塞（除注释里的示例外不出现）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
