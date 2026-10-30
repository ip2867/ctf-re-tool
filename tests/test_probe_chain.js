// 探测式多命令（cmd `&` 串联）回归
//
// 实测（DancingKeys.sys 一轮）：AI 写
//   where idat64.exe idat.exe 2>nul & dir /b "C:\Program Files\IDA*" 2>nul
// 这是**探测式**写法：逐条试、哪条有输出算哪条。但 cmd 里 `&` 串联时整体退出码
// 只取最后一条，只要某条失败且无 stdout，exec 就带非零码回来 → 被渲染成
// "命令执行失败"，即使后面的 dir 明明成功了。AI 于是误判"本机没装 IDA"，改走手工静态分析。
//
// 这条断言的靶子是"工具对命令结果的判定"，不是某道题：
// 只要 AI 用 `2>nul` 明确表达了"这条失败我不在乎"，逐条执行就不会再把成功的结果吞掉。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec } = require('child_process');
const { runBash, splitProbeChain } = require('../electron/tool-result.js');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-probe-'));
const marker = 'PROBE_MARKER_' + Date.now();
fs.writeFileSync(path.join(probeDir, marker + '.txt'), 'x');
const deps = { exec, tempDir: os.tmpdir(), cwd: probeDir, timeoutMs: 30000 };

(async () => {
  console.log('[1] 拆分规则：只拆"探测式"，不拆"逻辑链"');
  {
    const a = splitProbeChain('where idat64.exe idat.exe 2>nul & dir /b "C:\\Program Files\\IDA*" 2>nul');
    ok(Array.isArray(a) && a.length === 2, '`A 2>nul & B 2>nul` 拆成 2 条', JSON.stringify(a));
    ok(Array.isArray(a) && /^where idat64/.test(a[0]) && /^dir \/b/.test(a[1]), '拆分保留原命令顺序与内容');

    ok(splitProbeChain('cd /d C:\\x && dir') === null, '`&&` 逻辑链不拆（有依赖关系）');
    ok(splitProbeChain('cmd1 2>nul & cmd2') === null, '有一段缺 2>nul 就不拆（沉默失败信号不明确）');
    ok(splitProbeChain('where python') === null, '单条命令不拆');
    ok(splitProbeChain('echo a | head -2') === null, '管道不吃 & 拆分');
    const big = Array.from({ length: 8 }, (_, i) => 'x' + i + ' 2>nul').join(' & ');
    ok(splitProbeChain(big) === null, '超过 6 段不拆（避免变成长脚本）');
  }

  console.log('\n[2] 实测：前面那条失败、后面那条成功，不得判为"执行失败"');
  {
    const cmd = `where definitely_not_here_xyz 2>nul & dir /b "${probeDir}" 2>nul`;
    const r = await runBash(deps, cmd);
    ok(!/命令执行失败/.test(r), '不再报"命令执行失败"', r.slice(0, 160));
    ok(r.includes(marker), '后面的 dir 输出被保留下来', r.slice(0, 200));
    ok(/已适配/.test(r), '标注这是逐条执行的结果', r.slice(0, 100));
  }

  console.log('\n[3] 实测：前面成功、后面失败，同样保留成功结果');
  {
    const cmd = `dir /b "${probeDir}" 2>nul & where definitely_not_here_xyz 2>nul`;
    const r = await runBash(deps, cmd);
    ok(!/命令执行失败/.test(r), '退出码不再是整链判定', r.slice(0, 160));
    ok(r.includes(marker), '成功那条的输出保留', r.slice(0, 200));
  }

  console.log('\n[4] 全都没输出 = 有效结论，不是"命令执行失败"');
  {
    const cmd = 'where definitely_not_here_a 2>nul & where definitely_not_here_b 2>nul';
    const r = await runBash(deps, cmd);
    ok(!/命令执行失败/.test(r), '不报执行失败', r.slice(0, 160));
    ok(/没有一条命令产生输出/.test(r), '明确告诉 AI"都没有"（这本身是结论）', r.slice(0, 200));
    ok(/definitely_not_here_a/.test(r) && /definitely_not_here_b/.test(r), '逐条列出查了什么', r.slice(0, 300));
  }

  console.log('\n[5] 不误伤：普通命令 / 逻辑链行为不变');
  {
    const r1 = await runBash(deps, 'dir /b "' + probeDir + '" 2>nul');
    ok(r1.includes(marker) && !/已适配/.test(r1), '单条命令不触发探测链适配', r1.slice(0, 120));

    const r2 = await runBash(deps, 'cd /d "' + probeDir + '" && dir /b');
    ok(r2.includes(marker) && !/已适配/.test(r2), '`&&` 逻辑链原样执行', r2.slice(0, 120));

    const r3 = await runBash(deps, 'dir /b "Z:\\definitely\\missing\\path"');
    ok(/命令执行失败/.test(r3), '真正的失败仍然如实报失败（不掩盖错误）', r3.slice(0, 120));
  }

  try { fs.rmSync(probeDir, { recursive: true, force: true }); } catch (e) { /* 清理失败不影响结论 */ }
  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})();
