// bash 多行 python -c 的真实执行契约：
// cmd.exe 下多行 -c 会让换行被当成命令分隔，结果是退出码 0、stdout 空、stderr 空——
// 模型看到"成功但无输出"，只能重复同一条命令。这里钉住改写与实际执行结果。
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os'), p = require('path');
const { rewriteMultilinePython, runBash } = require('../electron/tool-result.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

const ev = (command) => runBash({ exec, tempDir: os.tmpdir() }, command);

(async () => {
  console.log('T8a) rewriteMultilinePython 拆出 cd 前缀并切到 file 模式');
  {
    const cmd = 'cd /d C:\\Windows\\Temp && python -c "\nimport os\nprint(os.getcwd())\nprint(111)\n"';
    const r = rewriteMultilinePython(cmd);
    ok(r.mode === 'file', `mode=${r.mode}`);
    ok(r.cwdPrefix === 'cd /d C:\\Windows\\Temp && ', `cwdPrefix 精确保留：${JSON.stringify(r.cwdPrefix)}`);
    ok(/import os/.test(r.script || ''), '脚本正文已抽出');
  }

  console.log('\nT8b) 带 cd 前缀的多行脚本：真实 cwd 与输出都正确');
  {
    const out = await ev('cd /d C:\\Windows\\Temp && python -c "\nimport os\nprint(os.getcwd())\nprint(111)\n"');
    ok(/C:\\Windows\\Temp/i.test(out), `输出含 C:\\Windows\\Temp：${out.split('\n')[0]}`);
    ok(/\b111\b/.test(out), '输出含 111');
  }

  console.log('\nT8c) 裸多行脚本：必须真的执行');
  {
    const out = await ev('python -c "\nprint(111)\n"');
    ok(/\b111\b/.test(out), `输出 111：${out.trim()}`);
    ok(!/无输出/.test(out), '不出现"无输出"文案');
  }

  console.log('\nT8d) 单行脚本保持 shell 模式');
  {
    const out = await ev('python -c "print(222)"');
    ok(/\b222\b/.test(out), `输出 222：${out.trim()}`);
  }

  console.log('\nT8e) 空输出文案带 exit 码，且不谎称成功');
  {
    const out = await ev('python -c "pass"');
    ok(/exit=0/.test(out), `含 exit=0：${out.trim()}`);
    ok(!/成功/.test(out), '不含"成功"');
  }

  // ── 复核问题 1：改写不得静默丢弃引号之后的命令尾部 ──
  // 早期实现用"首个引号到末个引号"截取脚本体，于是 && / 重定向 / 位置参数全部消失，
  // 却仍报成功，模型会以为文件已写出、参数已传入。
  console.log('\nT8f) 引号后的尾部（&&、重定向、位置参数）必须原样保留');
  {
    const r1 = rewriteMultilinePython('python -c "\nprint(111)\n" && echo DONE');
    ok(r1.mode === 'file', '&& 复合命令仍改写为 file 模式');
    ok(/&&\s*echo DONE/.test(r1.tail || ''), `tail 保留 && echo DONE：${JSON.stringify(r1.tail)}`);

    const r2 = rewriteMultilinePython('python -c "\nprint(111)\n" > out.txt');
    ok(/>\s*out\.txt/.test(r2.tail || ''), `tail 保留重定向：${JSON.stringify(r2.tail)}`);

    const r3 = rewriteMultilinePython('python -c "\nimport sys\nprint(sys.argv[1:])\n" alpha beta');
    ok(/alpha beta/.test(r3.tail || ''), `tail 保留位置参数：${JSON.stringify(r3.tail)}`);

    // 内嵌的引号不能被当成脚本体结束（旧实现 lastIndexOf 会取到最后一个引号）
    const r4 = rewriteMultilinePython('python -c "\nprint(\'a\')\nprint(1)\n"');
    ok(/print\('a'\)/.test(r4.script || '') && /print\(1\)/.test(r4.script || ''),
      `脚本正文完整（含内层引号）：${JSON.stringify(r4.script)}`);
  }

  console.log('\nT8g) 尾部确实被执行（重定向写出文件、位置参数到达 sys.argv）');
  {
    const outFile = p.join(os.tmpdir(), `bash_tail_${Date.now()}.txt`);
    const out1 = await ev(`python -c "\nprint(111)\n" > "${outFile}"`);
    const exists = fs.existsSync(outFile);
    const body = exists ? fs.readFileSync(outFile, 'utf8') : '';
    ok(exists, '重定向目标文件被创建');
    ok(/111/.test(body), `文件内容含 111：${JSON.stringify(body)}`);
    ok(!/111/.test(out1), 'stdout 不再误报 111（输出已进文件）');
    try { fs.unlinkSync(outFile); } catch (e) { /* 清理 */ }

    const out2 = await ev('python -c "\nimport sys\nprint(sys.argv[1:])\n" alpha beta');
    ok(/alpha/.test(out2) && /beta/.test(out2), `位置参数到达 sys.argv：${out2.trim()}`);
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
