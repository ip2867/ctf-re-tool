// bash 在 Windows 上的 POSIX 管道适配（Obfuscating Macros II 一轮实测：
// run_command 失败 7 次，全是 `| head -5` / `| grep x` 这类 cmd.exe 不认的写法，
// AI 误判"环境缺失"后绕圈重试，烧掉大量预算）。
const path = require('path');
const { exec } = require('child_process');
const os = require('os');
const { runBash } = require('../electron/tool-result.js');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};
const ROOT = path.join(__dirname, '..');
const deps = { exec, tempDir: os.tmpdir(), cwd: ROOT, timeoutMs: 30000 };

(async () => {
  console.log('[1] head / tail 适配');
  {
    const r1 = await runBash(deps, 'echo AAA | head -1');
    ok(/已适配/.test(r1), 'head 命中适配提示', r1.slice(0, 80));
    ok(/AAA/.test(r1), 'head 保留输出', r1.slice(0, 80));
    ok(!/不是内部或外部命令|not recognized/.test(r1), 'head 不再报"命令不存在"', r1.slice(0, 120));

    // echo BBB 在 cmd 下只有一行且无尾换行，tail -1 会得到空串；用 python 造多行更可靠
    const r2 = await runBash(deps, 'python -c "print(111);print(222)" | tail -1');
    ok(/已适配/.test(r2) && /222/.test(r2), 'tail 适配并保留末行', r2.slice(0, 100));
  }

  console.log('\n[2] grep / wc 适配');
  {
    const r3 = await runBash(deps, 'python -c "print(chr(102)+chr(111)+chr(111));print(chr(98)+chr(97)+chr(114))" | grep foo');
    ok(/已适配/.test(r3), 'grep 命中适配提示', r3.slice(0, 80));
    ok(/foo/.test(r3) && !/\bbar\b/.test(r3), 'grep 只保留匹配行', r3.slice(0, 120));

    const r4 = await runBash(deps, 'python -c "print(1);print(2)" | wc -l');
    ok(/已适配/.test(r4) && /\b2\b/.test(r4), 'wc -l 统计行数', r4.slice(0, 80));
  }

  console.log('\n[3] 2>&1 位置兼容');
  {
    const r5 = await runBash(deps, 'echo CCC 2>&1 | head -1');
    ok(/已适配/.test(r5) && /CCC/.test(r5), 'cmd 风格的 2>&1 | head 也能适配', r5.slice(0, 100));
  }

  console.log('\n[4] 不误伤：非 POSIX / 复杂管道原样执行');
  {
    const r6 = await runBash(deps, 'python -c "print(123)"');
    ok(/123/.test(r6) && !/已适配/.test(r6), '普通命令不加适配提示', r6.slice(0, 60));

    const r7 = await runBash(deps, 'echo A | findstr A | findstr A');
    ok(!/已适配/.test(r7), '多重管道不强行改写（避免语义错误）', r7.slice(0, 80));
  }

  console.log('\n[5] 超时可注入（长计算不被 120s 误杀）');
  {
    const t0 = Date.now();
    const r8 = await runBash({ exec, tempDir: os.tmpdir(), cwd: ROOT, timeoutMs: 1500 }, 'python -c "import time;time.sleep(5)"');
    const dt = Date.now() - t0;
    ok(/超时/.test(r8), '超时信息明确', r8.slice(0, 80));
    ok(dt < 6000, '按注入的 1.5s 超时终止（而非默认更久）', dt + 'ms');
    ok(/1s 上限|2s 上限/.test(r8), '提示里带上实际超时值', r8.slice(0, 80));
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})();
