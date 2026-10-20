// 可执行节缺口 / 续块单测（全部合成 imageMap，不依赖真样本）。
//
// 关键约束：
//   · 只在代码节内算缺口：PE 取 .text 且 X 且 !W；ELF 取 PF_X 且 !PF_W。
//     W+X 节（加壳程序的 .WProtec，va=0x42f000、约 117KB、无任何函数）必须排除，
//     否则会产生大量伪缺口并被 disasm 成垃圾。
//   · 单缺口 ≤4096B，超出切段并标 truncated；总数上限 32。
//   · 以无条件 jmp 结尾的函数体 → continuation-missing。
//   · 提示词必须给"间接流/续块"固定块，且不得写死"ret 后到达"的确定性断言。
const fs = require('fs');
const path = require('path');

// 统一 LF：源码文件是 CRLF，而下面按 "\n}\n\n" 切函数体
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r\n/g, '\n');

// 用"顶层函数以 \n}\n\n 分隔"的约定切出函数体（花括号计数会被模板字符串里的 ${...} 干扰）。
function grab(name) {
  const startIdx = appSrc.search(new RegExp('^(?:async\\s+)?function\\s+' + name + '\\s*\\(', 'm'));
  if (startIdx < 0) throw new Error('未找到函数 ' + name);
  const rest = appSrc.slice(startIdx);
  const endRel = rest.indexOf('\n}\n\n');
  const end = endRel >= 0 ? endRel + 2 : rest.length;
  return rest.slice(0, end);
}

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const mod = { exports: {} };
new Function('module', 'exports',
  grab('parseAddrValue') + '\n' + grab('pushGap') + '\n' + grab('computeExecGaps') + '\n'
  + 'const EXEC_GAP_MAX = 4096; const EXEC_GAP_TOTAL = 32;\n'
  + 'module.exports = { computeExecGaps };'
)(mod, mod.exports);
const { computeExecGaps } = mod.exports;

const peMap = {
  format: 'pe', imageBase: 0x400000, sizeOfImage: 0x400000,
  sections: [
    { name: '.text', va: 0x1000, vsize: 0x1000, rawSize: 0x1000, executable: true, writable: false },
    { name: '.rdata', va: 0x2000, vsize: 0x1000, rawSize: 0x1000, executable: false, writable: false },
    // 加壳节：W+X，且没有任何函数
    { name: '.WProtec', va: 0x2f000, vsize: 0x1cd66, rawSize: 0x1cd66, executable: true, writable: true },
  ],
};

console.log('[1] 缺口只落在 .text 内，不含 0x42f000，单缺口 ≤4096');
{
  // .text 绝对地址 = 0x400000 + 0x1000 = 0x401000 .. 0x402000
  const funcs = [
    { name: 'f1', address: '0x401000', size: 0x200 },
    { name: 'f2', address: '0x401e00', size: 0x200 },   // 覆盖到 .text 末端
  ];
  const r = computeExecGaps(funcs, peMap, {});
  ok(r.gaps.length >= 1, `有缺口（${r.gaps.length}）`);
  const inText = r.gaps.every(g => {
    const a = parseInt(g.addr, 16);
    return a >= 0x401000 && a + g.size <= 0x402000;
  });
  ok(inText, '缺口全部落在 .text 内');
  ok(!r.gaps.some(g => parseInt(g.addr, 16) === 0x42f000), '不含 0x42f000（W+X 节被排除）');
  ok(r.gaps.every(g => g.size <= 4096), '单缺口 ≤4096');
}

console.log('\n[2] 5000B 缺口被切成 2 段且标记 truncated');
{
  // .text 0x401000..0x402000（4096B）；只覆盖首 100 字节 → 缺口 3996B，不切。
  // 用更大的 .text 制造 5000B 缺口。
  const bigMap = {
    format: 'pe', imageBase: 0x400000, sizeOfImage: 0x400000,
    sections: [{ name: '.text', va: 0x1000, vsize: 0x2000, rawSize: 0x2000, executable: true, writable: false }],
  };
  const funcs = [
    { name: 'head', address: '0x401000', size: 0x100 },
    { name: 'tail', address: '0x401000 + 0x100 + 5000', size: 0 },   // 占位，下面替换
  ];
  // 精确构造：覆盖 [0x401000, 0x401100) 与 [0x402484, 0x403000)（.text = 0x401000..0x403000）
  const start2 = 0x401100 + 5000;
  funcs[1] = { name: 'tail', address: '0x' + start2.toString(16), size: 0x403000 - start2 };
  const r = computeExecGaps(funcs, bigMap, {});
  ok(r.gaps.length === 2, `切成 2 段（实际 ${r.gaps.length}）`);
  ok(r.gaps[0].size === 4096 && r.gaps[1].size === 904, `4096 + 904（实际 ${r.gaps.map(g => g.size).join('+')}）`);
  ok(r.gaps[0].truncated === true, '首段标记 truncated');
}

console.log('\n[3] jmp 结尾的函数体 → continuation-missing');
{
  const funcs = [
    { name: 'f1', address: '0x401000', size: 0x100, code: 'int f1(){ x = 1;\n  jmp loc_402500;\n}' },
  ];
  const r = computeExecGaps(funcs, peMap, {});
  const cont = r.continuation.find(c => c.addr === '0x402500');
  ok(!!cont, `产生 continuation-missing（${JSON.stringify(r.continuation)}）`);
  ok(cont && cont.reason === 'continuation-missing', 'reason = continuation-missing');
}

console.log('\n[4] 提示词固定块 + 不写死"ret 后到达"');
{
  ok(appSrc.includes('## 间接流/续块（不得当死代码）'), '提示词含「## 间接流/续块（不得当死代码）」');
  ok(!/0x42f779/.test(appSrc) && !/0x4015c0/.test(appSrc), '源码不含具体地址（无题目特判）');
  ok(!/ret 后到达/.test(appSrc), '不含确定性的"ret 后到达"断言句');
  ok(/可能由间接跳转\/VM 尾声到达/.test(appSrc), '改为未验证推论措辞');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
