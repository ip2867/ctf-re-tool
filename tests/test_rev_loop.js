// 可逆循环逆推器回归（rev-loop）
//
// 锁的是 Obfuscating Macros II 暴露的方法论缺口：
// 当时的结论是"雪崩 31.6/64、非仿射 ⇒ 无法反解、只能上 Z3"，
// 实际循环体每步都是双射，从目标值逆序跑一遍就还原了。
//
// 这个测试要保证三件事：
//   1) 算子表的每个逆运算**真的**是逆运算（正逆互逆，随机多组）；
//   2) 生成的脚本能真跑通并回代命中目标；
//   3) 自检**能失败**——故意给错逆运算时必须报错，否则测试是假保护。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { buildRevSolveScript, OPS } = require('../electron/rev-loop.js');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function runPy(code) {
  const tmp = path.join(os.tmpdir(), 'ctf-rev-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.py');
  fs.writeFileSync(tmp, code);
  try {
    return { ok: true, out: execFileSync('python', [tmp], { stdio: 'pipe' }).toString() };
  } catch (e) {
    return {
      ok: false,
      out: String(e.stdout || ''),
      err: String(e.stderr || e.message).slice(0, 400),
      code: e.status,
    };
  } finally {
    try { fs.unlinkSync(tmp); } catch (x) { }
  }
}

console.log('[1] 参数校验');
{
  ok(buildRevSolveScript({}).error, '缺 ops 返回 error');
  ok(/需要 ops/.test(buildRevSolveScript({}).error), '错误信息说明缺 ops');
  ok(buildRevSolveScript({ ops: [{ op: 'xor', dst: 'A', src: 'B' }] }).error, '缺 target/init 返回 error');
  ok(buildRevSolveScript({ ops: [{ op: 'bogus_op', dst: 'X' }], target: ['1'] }).error, '未知算子返回 error');
  ok(/不认识/.test(buildRevSolveScript({ ops: [{ op: 'bogus_op' }], target: ['1'] }).error), '错误信息指出算子名不认识');
  ok(buildRevSolveScript({ ops: [{ op: 'xor', dst: 'X' }], target: ['1', '2'] }).error, '算子缺字段返回 error');
  ok(buildRevSolveScript({ ops: [{ op: 'xor', dst: 'Z', src: 'X' }], regs: ['X', 'Y'], target: ['1', '2'] }).error,
    '寄存器名不在 regs 里返回 error');
  ok(buildRevSolveScript({ ops: [{ op: 'xor', dst: 'X', src: 'Y' }], target: ['1'] }).error,
    'target 数量与 regs 不符返回 error');
  ok(buildRevSolveScript({ ops: [{ op: 'xor', dst: 'X', src: 'Y' }], width: 7, target: ['1', '2'] }).error,
    '非法 width 返回 error');
}

console.log('\n[2] 算子表完整：每个算子都有登记逆运算');
{
  const forward = Object.keys(OPS).filter(k => OPS[k].invOf);
  ok(forward.length >= 12, '可用算子 >= 12 个', String(forward.length));
  let allInverse = true;
  const missing = [];
  for (const k of forward) {
    const inv = OPS[k].invOf;
    if (!OPS[inv]) { allInverse = false; missing.push(`${k}->${inv}`); }
  }
  ok(allInverse, '所有算子的逆运算都已登记', missing.join(', '));

  // 互为逆的两两必须成对
  ok(OPS[OPS.add.invOf].invOf === 'add', 'add <-> sub 成对');
  ok(OPS[OPS.rotl_cross.invOf].invOf === 'rotl_cross', 'rotl_cross <-> rotr_cross 成对');
  ok(OPS[OPS.swap_add.invOf].invOf === 'swap_add', 'swap_add <-> unswap_add 成对');
  ok(OPS[OPS.xor.invOf].invOf === 'xor', 'xor 自逆');
  ok(OPS[OPS.not.invOf].invOf === 'not', 'not 自逆');
}

console.log('\n[3] 端到端：生成脚本真跑，正逆互逆 + 回代命中');
{
  const r = buildRevSolveScript({
    regs: ['X', 'Y'], width: 64, rounds: 32,
    ops: [
      { op: 'xor_cond_not', dst: 'Y', src: 'X' },
      { op: 'not', reg: 'X' },
      { op: 'rotl_cross', hi: 'X', lo: 'Y' },
      { op: 'swap_add', a: 'X', b: 'Y' },
      { op: 'rotl_cross', hi: 'X', lo: 'Y' },
    ],
    target: ['0xa1e8895eb916b732', '0x50a2dcc51ed6c4a2'],
  });
  ok(!r.error, '生成成功', r.error);
  const out = runPy(r.script);
  ok(out.ok, 'python 跑通', out.err);
  ok(/SELFCHECK_OK/.test(out.out), '自检通过（正逆互逆）');
  ok(/VERIFY\s+= PASS/.test(out.out), '回代精确命中目标');
  ok(/INPUT_HEX = [0-9a-f]+/.test(out.out), '输出 INPUT_HEX');
  // 小端打包：X0 的最低字节在前
  const m = /INPUT_HEX = ([0-9a-f]+)/.exec(out.out);
  ok(m && m[1].length === 32, '输入 16 字节', m && String(m[1].length));
}

console.log('\n[4] 自检能抓错（不是假保护）');
{
  // 故意把 unswap_add 写错，脚本周边的自检必须失败
  const bad = buildRevSolveScript({
    regs: ['X', 'Y'], width: 64, rounds: 8,
    ops: [{ op: 'swap_add', a: 'X', b: 'Y' }],
    target: ['1', '2'],
  });
  ok(!bad.error, '生成成功');
  // 篡改生成物：把逆向的 unswap_add 换成错的（减反了）
  const tampered = bad.script.replace(
    /_a, _b = \(Y - X\) & MASK, X|X, Y = \(Y - X\) & MASK, X/,
    'X, Y = (Y - X) & MASK, (X + 1) & MASK'
  );
  const out = runPy(tampered);
  ok(!out.ok && out.code === 2, '篡改后自检失败并以 2 退出', String(out.code));
  ok(/SELFCHECK_FAIL|自检失败/.test(out.out), '输出里明确指出自检失败', out.out.split('\n').slice(-3).join(' | '));
}

console.log('\n[5] 各算子单独往返（width/多寄存器组合）');
{
  // target 必须落在 width 内（width=32 就传 32 位值），否则模块按设计报错
  const cases = [
    { name: 'xor 自逆', ops: [{ op: 'xor', dst: 'A', src: 'B' }], regs: ['A', 'B'] },
    { name: 'not 自逆', ops: [{ op: 'not', reg: 'A' }], regs: ['A', 'B'] },
    { name: 'rotl_single', ops: [{ op: 'rotl_single', reg: 'A' }], regs: ['A', 'B'] },
    { name: 'rotl_cross', ops: [{ op: 'rotl_cross', hi: 'A', lo: 'B' }], regs: ['A', 'B'] },
    { name: 'add', ops: [{ op: 'add', dst: 'A', src: 'B' }], regs: ['A', 'B'] },
    { name: 'sub', ops: [{ op: 'sub', dst: 'A', src: 'B' }], regs: ['A', 'B'] },
    { name: 'swap', ops: [{ op: 'swap', a: 'A', b: 'B' }], regs: ['A', 'B'] },
    { name: 'swap_add', ops: [{ op: 'swap_add', a: 'A', b: 'B' }], regs: ['A', 'B'] },
    { name: 'mul_const(奇数)', ops: [{ op: 'mul_const', dst: 'A', value: 0x1234567 }], regs: ['A', 'B'] },
    { name: 'xor_const', ops: [{ op: 'xor_const', dst: 'A', value: 0xdeadbeef }], regs: ['A', 'B'] },
    { name: 'width=32', ops: [{ op: 'rotl_cross', hi: 'A', lo: 'B' }], regs: ['A', 'B'], width: 32,
      target: ['0x12345678', '0x9abcdef0'] },
    { name: 'width=8', ops: [{ op: 'add', dst: 'A', src: 'B' }], regs: ['A', 'B'], width: 8,
      target: ['0x12', '0xef'] },
  ];
  let allOk = true;
  const badNames = [];
  for (const c of cases) {
    const r = buildRevSolveScript({
      regs: c.regs, width: c.width || 64, rounds: 16, ops: c.ops,
      target: c.target || ['0x1234567890abcdef', '0xfedcba0987654321'],
    });
    if (r.error) { allOk = false; badNames.push(c.name + ':gen(' + r.error + ')'); continue; }
    const out = runPy(r.script);
    if (!out.ok || !/VERIFY\s+= PASS/.test(out.out)) { allOk = false; badNames.push(c.name); }
  }
  ok(allOk, `${cases.length} 个算子单独往返全部通过`, badNames.join(', '));
}

console.log('\n[5b] 位宽越界要被明确拒绝（不是静默截断）');
{
  ok(buildRevSolveScript({
    regs: ['A', 'B'], width: 32, ops: [{ op: 'add', dst: 'A', src: 'B' }],
    target: ['0x1234567890abcdef', '1'],
  }).error, 'width=32 传 64 位 target 被拒绝');
  ok(/超出 width/.test(buildRevSolveScript({
    regs: ['A', 'B'], width: 8, ops: [{ op: 'add', dst: 'A', src: 'B' }],
    target: ['0x1234', '1'],
  }).error), '越界错误信息说明超范围');
}

console.log('\n[6] init 模式：跳过反解，只回代');
{
  const r = buildRevSolveScript({
    regs: ['X', 'Y'], rounds: 4,
    ops: [{ op: 'xor', dst: 'X', src: 'Y' }, { op: 'swap_add', a: 'X', b: 'Y' }],
    init: ['0x1111', '0x2222'],
  });
  ok(!r.error, '生成成功', r.error);
  const out = runPy(r.script);
  ok(out.ok && /INIT 模式/.test(out.out), '标识为 init 模式');
  ok(/BACK\s+= 0x/.test(out.out), '输出正向结果（BACK）');
  // init 模式没有 target，脚本不应打印 VERIFY（只做正向展开）
  ok(!/VERIFY/.test(out.out), 'init 模式不做 target 比较');
  ok(/SELFCHECK_OK/.test(out.out), 'init 模式仍做正逆自检');
}

console.log('\n[7] 接线：rev_solve 在 main.js 里可达');
{
  ok(/name: "rev_solve"/.test(mainSrc), 'rev_solve 工具已定义');
  ok(/case 'rev_solve'/.test(mainSrc), '有 dispatch 分支');
  ok(/'rev_solve'/.test(mainSrc), '进 KNOWN 集合');
  ok(/rev_solve: 'ops'/.test(mainSrc), '进 MAP 裸参映射');
  ok(/if \(name === 'rev_solve'\)/.test(mainSrc), 'precheck 有分支');
  ok(/case 'rev_solve': return '可逆逆推'/.test(mainSrc), 'toolLabel 有 rev_solve');
  ok(/require\('\.\/rev-loop'\)/.test(mainSrc), '惰性 require rev-loop');
  // 工具描述必须写清"不可逆就别用"
  ok(/不能逆|含 `& 掩码`|& 掩码/.test(mainSrc), '工具描述说明哪些情形不能逆');
}

console.log('\n[8] 文档/提示词可达性');
{
  const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
  const skill = fs.readFileSync(path.join(__dirname, '..', 'skills', 'ctf-obfuscation', 'SKILL.md'), 'utf8');
  ok(appSrc.includes('rev_solve'), '提示词提及 rev_solve');
  ok(/rev_solve/.test(skill), 'skill 提及 rev_solve');
  // 通解检查：skill 与提示词里不能出现这道题的目标常量
  ok(!/0xA1E8895EB916B732/i.test(skill), 'skill 不含具体题目目标常量');
  ok(!/0xA1E8895EB916B732/i.test(appSrc), '提示词不含具体题目目标常量');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
