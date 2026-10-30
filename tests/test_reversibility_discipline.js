// 方法论回归：可逆校验要先逆推，不要直接上符号执行
//
// Obfuscating Macros II 那一轮我犯的错：
//   测出"雪崩 31.6/64 + 非仿射 + 非可加"，就断定"无法反解"，去上 Z3/angr。
// 实际循环体每步都是双射（^ / ~ / 循环移位 / 交换加法），从目标值逐轮逆序跑一遍
// 就还原了。真正的问题不是数学强度，而是**没有先问"能不能倒着走"**。
//
// 本测试锁三件事：
//   1) 工具的三个入口（skill / 提示词 / 工具描述）都写了这条判据；
//   2) 判据的表述是"看算子集合"，不是"看某道题的常量"（保证是通解不是特解）；
//   3) 可逆化的推理链本身成立：对一组真实形态的算子，正向/逆序必须互相还原。
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const ROOT = path.join(__dirname, '..');
const skill = fs.readFileSync(path.join(ROOT, 'skills', 'ctf-obfuscation', 'SKILL.md'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');

console.log('[1] 三处入口都给了"先判可逆"的判据');
{
  ok(/可逆/.test(skill), 'skill 提到可逆性判断');
  ok(/逆序/.test(skill), 'skill 说明逆序回退');
  ok(/5\.4/.test(skill), 'skill 有独立的 §5.4');
  ok(/可逆/.test(appSrc), '提示词提到可逆性判断');
  ok(/逆序|倒着/.test(appSrc), '提示词说明逆序回退');
  ok(/可逆/.test(mainSrc) || /倒着/.test(mainSrc), '工具描述提到可逆性判断');
}

console.log('\n[2] 判据是"按算子集合"，不是"按某道题"（通解）');
{
  // 必须列出通用算子清单
  ok(/\^=/.test(skill) && /~x/.test(skill), 'skill 列出 XOR / 取反');
  ok(/rol|<<|移位/.test(skill), 'skill 列出循环移位');
  ok(/不可逆|&|\|/.test(skill), 'skill 说明哪些算子不可逆');

  // 不能写成只针对具体题目常量（否则就是特解）
  ok(!/0xA1E8895EB916B732/i.test(skill), 'skill 不含某道题的目标常量');
  ok(!/0x401006/.test(skill), 'skill 不含某道题的函数地址');
  ok(!/Obfuscating Macros II/.test(skill), 'skill 不含具体题名（知识应是通用的）');
}

console.log('\n[3] 推理链自检：正向 / 逆序互还原（真实形态的算子）');
{
  const M = (1n << 64n) - 1n;
  const MSB = 1n << 63n;

  // 与题目同型的 8 条算子（但常量/轮数是测试自造的）
  function fwd(X, Y, rounds) {
    for (let i = 0; i < rounds; i++) {
      Y = (X & 1n) === 0n ? (Y ^ (~X & M)) : (Y ^ X);
      X = ~X & M;
      let XX = X & MSB, YY = Y & MSB;
      X = (X << 1n) & M; Y = (Y << 1n) & M;
      if (YY) X |= 1n;
      if (XX) Y |= 1n;
      const t = Y;
      Y = (Y + X) & M;
      X = t;
      XX = X & MSB; YY = Y & MSB;
      X = (X << 1n) & M; Y = (Y << 1n) & M;
      if (YY) X |= 1n;
      if (XX) Y |= 1n;
    }
    return [X, Y];
  }

  function inv(X, Y, rounds) {
    for (let i = rounds - 1; i >= 0; i--) {
      // 逆 rot: 先看当前最低位是谁带进来的
      let XX = X & 1n, YY = Y & 1n;
      X = (X >> 1n) | (YY ? MSB : 0n);
      Y = (Y >> 1n) | (XX ? MSB : 0n);

      // 逆 "tmp=Y; Y=Y+X; X=tmp"：先 X 是旧 Y，旧 Y = Y - X
      const oldY = (Y - X) & M;
      Y = X;
      X = oldY;

      // 第二轮 rot 逆（注意此处的 rot 与上面同型，位来源同理）
      XX = X & 1n; YY = Y & 1n;
      X = (X >> 1n) | (YY ? MSB : 0n);
      Y = (Y >> 1n) | (XX ? MSB : 0n);

      // 逆 X = ~X
      X = ~X & M;

      // 逆 Y ^= X 或 Y ^= ~X
      // 注意此处 X 已经是"取反前"的值，条件用的是取反前的 X 的最低位
      Y = (X & 1n) === 0n ? (Y ^ (~X & M)) : (Y ^ X);
    }
    return [X, Y];
  }

  const X0 = 0x1122334455667788n, Y0 = 0x99aabbccddeeff00n;
  const [X1, Y1] = fwd(X0, Y0, 64);
  const [X2, Y2] = inv(X1, Y1, 64);
  ok(X2 === X0 && Y2 === Y0, '逆序回退能还原输入（64 轮）',
    `got ${X2.toString(16)} / ${Y2.toString(16)}`);

  // 多组随机输入都要成立（证明不是碰巧）
  let allOk = true;
  let bad = '';
  for (let k = 0; k < 25; k++) {
    const a = BigInt('0x' + Math.floor(Math.random() * 1e16).toString(16).padStart(16, '0').slice(0, 16));
    const b = BigInt('0x' + Math.floor(Math.random() * 1e16).toString(16).padStart(16, '0').slice(0, 16));
    const [u, v] = fwd(a, b, 32);
    const [p, q] = inv(u, v, 32);
    if (p !== a || q !== b) { allOk = false; bad = `${a.toString(16)}/${b.toString(16)}`; break; }
  }
  ok(allOk, '25 组随机输入全部可还原', bad);

  // 反面：若循环体里出现不可逆操作（& 掩码），逆序就不成立
  // —— 用来确认"判据真的能区分"，不是因为我们的逆函数"总能过"
  function fwdLossy(X, Y) {
    Y = (Y & 0x00ffffffffffffffn);   // 高 8 位被抹掉 → 不可逆
    return [X, Y];
  }
  const [, v1] = fwdLossy(1n, 0xffffffffffffffffn);
  ok((v1 & 0xff00000000000000n) === 0n, '含 & 掩码时信息确实丢失（判据能区分不可逆）');
}

console.log('\n[4] 提示词给出了完整的三步执行方式');
{
  ok(/正向函数|写成.*f\(|f\(X, Y\)/.test(appSrc), '提示词要求先写正向函数');
  ok(/对拍|一致|核对/.test(appSrc), '提示词要求用真值对拍校验模型');
  ok(/emu_trace|regs\.rax/.test(appSrc), '提示词指明用 emu_trace 的返回值做真值');
  ok(/不可逆[\s\S]{0,80}angr|angr[\s\S]{0,80}不可逆/.test(appSrc) ||
     /angr_solve/.test(appSrc), '提示词说明不可逆时才转 angr');
}

console.log('\n[5] 工作模式已固化：skills/tool-evolution');
{
  const evoPath = path.join(ROOT, 'skills', 'tool-evolution', 'SKILL.md');
  const has = fs.existsSync(evoPath);
  ok(has, 'tool-evolution skill 存在');
  if (has) {
    const evo = fs.readFileSync(evoPath, 'utf8');
    ok(/^---[\s\S]*?name:\s*tool-evolution/m.test(evo), 'frontmatter 有 name');
    ok(/description:/.test(evo), 'frontmatter 有 description（否则不会自动触发）');
    ok(/不补特解|通解/.test(evo), '写明"只补通解不补特解"的铁律');
    ok(/能力缺口/.test(evo) && /知识缺口/.test(evo), '区分能力缺口与知识缺口');
    ok(/复合原语|一次调用完成/.test(evo), '要求做复合原语而非更细的原子操作');
    ok(/端到端/.test(evo), '要求端到端测试（能真失败的那种）');
    ok(/双仓/.test(evo), '写明双仓交付流程');
    ok(/自检清单/.test(evo), '有结束前自检清单');
    // 不能自己变成特解
    ok(!/0x401006|0xA1E8895E/.test(evo), 'skill 本身不含具体题目地址/常量');
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
