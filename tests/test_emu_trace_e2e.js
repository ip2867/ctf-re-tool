// 端到端：真实 ELF 上的分段 dispatch 还原
//
// 这里用 tests/fixtures/make_dispatch_fixture.py 现场生成一个**结构同型**的 ELF：
//   · 代码切成 92 段，段间用 `jmp rax` 间接跳转
//   · 段号运行期压栈，由 `table[段号]` 算出段地址（静态看不到目标）
//   · 段 1 = 起始，段 0 = 结束
// 然后验证工具链能否自动量出「段号 → 段地址」，并把正向模型与真实执行对拍。
//
// 这锁的是 Obfuscating Macros II 暴露的通用能力：
//   "record a execution trace and set those jump targets"
// 注意：fixture 的常量与真实题目无关，测的是**结构识别能力**，不是某道题的解。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { buildApplyTraceScript, summarizeTrace } = require('../electron/emu-trace.js');

const ROOT = path.join(__dirname, 'fixtures');
const FIX = path.join(ROOT, 'dispatch_fixture');
const TRACE = path.join(ROOT, 'trace.json');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function havePython() {
  try { execFileSync('python', ['-c', 'import keystone,unicorn,capstone,elftools'], { stdio: 'pipe' }); return true; }
  catch (e) { return false; }
}

if (!havePython()) {
  console.log('SKIP: 需要 python + keystone/unicorn/capstone/pyelftools（本机缺依赖）');
  console.log('\n结果：0 通过 / 0 失败（跳过）');
  process.exit(0);
}

console.log('[1] 生成结构同型的分段 dispatch ELF');
try {
  execFileSync('python', [path.join(ROOT, 'make_dispatch_fixture.py'), FIX], { stdio: 'pipe' });
  ok(fs.existsSync(FIX), 'fixture 已生成');
  const fd = fs.openSync(FIX, 'r');
  const magic = Buffer.alloc(4);
  fs.readSync(fd, magic, 0, 4, 0);
  fs.closeSync(fd);
  ok(magic.toString('latin1') === '\x7fELF', 'fixture 是 ELF', magic.toString('hex'));
} catch (e) {
  ok(false, 'fixture 生成失败', String(e.stderr || e.message).slice(0, 300));
  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(1);
}

console.log('\n[2] emu_trace 真跑：量出「段号 → 段地址」');
let tr = null;
try {
  execFileSync('node', [path.join(ROOT, 'gen_trace.js')], { stdio: 'pipe' });
  execFileSync('python', [path.join(ROOT, 'run_trace.py')], { stdio: 'pipe', cwd: ROOT });
  tr = JSON.parse(fs.readFileSync(TRACE, 'utf8'));
  ok(true, 'trace 已产出');
} catch (e) {
  ok(false, 'trace 执行失败', String(e.stderr || e.message).slice(0, 400));
}

if (tr) {
  ok(tr.stop === 'finished', '仿真正常结束（不是撞到未映射内存）', tr.stop);
  ok(tr.insn_count > 500, '执行了足够多指令', String(tr.insn_count));
  ok(Array.isArray(tr.indirect_sites) && tr.indirect_sites.length >= 1, '识别到间接跳转点');
  const site = tr.indirect_sites[0];
  ok(site.distinct >= 80, '一个 dispatch 点量出 80+ 个目标（92 段结构）', String(site.distinct));
  ok(Array.isArray(tr.edges) && tr.edges.length > 100, '记录到控制流边', String(tr.edges.length));
  ok(Array.isArray(tr.exec_ranges) && tr.exec_ranges.length >= 80, '执行区间覆盖各段', String(tr.exec_ranges.length));

  // 跳转目标必须都落在 .text 里（说明不是误把数据当代码）
  const targets = site.targets.map(t => parseInt(t.dst, 16));
  const allInText = targets.every(a => a >= 0x401000 && a < 0x405000);
  ok(allInText, '全部跳转目标落在代码段（未误判数据）');

  // 段地址应当是等距的（每段 0x40）——这是"分段"结构的直接证据
  const sorted = [...targets].sort((a, b) => a - b);
  const strides = new Set();
  for (let i = 1; i < sorted.length; i++) strides.add(sorted[i] - sorted[i - 1]);
  ok(strides.size === 1 && strides.has(0x40), '段地址等距 0x40，确认是分段 dispatch 结构',
    JSON.stringify([...strides]));

  // 摘要必须把映射print成人能读的形式
  const sum = summarizeTrace(tr);
  ok(/间接跳转点: 1 个/.test(sum), '摘要报告跳转点数量');
  ok(/→ 90 个目标/.test(sum) || /→ 8\d 个目标/.test(sum) || /→ 9\d 个目标/.test(sum),
    '摘要报告目标数量', sum.split('\n').find(l => l.includes('个目标')));
  ok(/返回寄存器/.test(sum), '摘要含返回值（可与正向模型对拍）');
}

console.log('\n[3] 正向模型对拍（skill §5.4 的第一步）');
if (tr) {
  try {
    const out = execFileSync('python', [path.join(ROOT, 'verify_model.py'), TRACE],
      { stdio: 'pipe', cwd: ROOT }).toString();
    ok(/RAX MATCH True/.test(out), '正向模型 rax 与真实执行一致', out.trim().split('\n').slice(-3).join(' | '));
    ok(/RDX MATCH True/.test(out), '正向模型 rdx 与真实执行一致');
    ok(/POSITIVE MODEL VERIFIED/.test(out), '对拍通过（可以放心写逆函数）');
  } catch (e) {
    ok(false, '正向模型对拍失败', String(e.stdout || e.stderr || e.message).slice(0, 300));
  }
}

console.log('\n[4] ida_apply_trace 能吃下真实轨迹');
if (tr) {
  const r = buildApplyTraceScript({ trace: tr });
  ok(!r.error, '真实轨迹可直接回填', r.error);
  ok(r.stats.indTargets >= 80, '回填目标数量正确', String(r.stats.indTargets));
  ok(r.stats.edges === tr.edges.length || r.stats.edges > 100, '边数正确', String(r.stats.edges));
  ok(r.stats.truncated.length === 0, '未触发截断', JSON.stringify(r.stats.truncated));
  ok(/IND_TARGETS = \[/.test(r.args.code), '目标地址写进 IDAPython');
  ok(/_exec_seg/.test(r.args.code), '只在可执行段建代码');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
