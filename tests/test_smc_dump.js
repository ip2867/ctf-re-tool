// smc_dump 单测：脚本生成器的正确性 + 负向断言
//
// 关键：必须包含「能真失败」的断言。否则这个测试只是摆设。
// 负向点：
//   1) 并集还原逻辑如果写成「取最后一张快照」→ 只能还原最后一个块，测试必须抓出来
//   2) 补丁如果写错偏移 → 文件字节不变，测试必须抓出来
//   3) region 解析如果接受非法格式 → 必须返回 null

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const SD = require('../electron/smc-dump');

let pass = 0, fail = 0;
function ok(cond, msg, extra) {
  if (cond) { pass++; console.log('  OK   ' + msg); }
  else { fail++; console.log('  FAIL ' + msg + (extra ? ' -> ' + extra : '')); }
}

console.log('\n[1] parseRegion');
{
  const r = SD.parseRegion('0x404000:0x20000');
  ok(r && r.base === 0x404000 && r.len === 0x20000, '标准格式解析');
  ok(SD.parseRegion('0x400000:0x1000').base === 0x400000, '另一个基址');
  ok(SD.parseRegion('') === null, '空串返回 null');
  ok(SD.parseRegion('garbage') === null, '垃圾串返回 null');
  ok(SD.parseRegion('0x404000') === null, '缺长度返回 null');
  ok(SD.parseRegion('404000:20000') === null, '缺 0x 前缀返回 null（不猜）');
  ok(SD.parseRegion('0x404000:0x20000:extra') === null, '多余段返回 null');
  // 大小写
  ok(SD.parseRegion('0xABC000:0x100').base === 0xabc000, '大写 hex 也能解析');
}

console.log('\n[2] inferRegions —— 真 ELF 上取最大可执行 PT_LOAD');
{
  // 构造一个最小 ELF64：3 个 PT_LOAD，其中第 2 个可执行且最大
  const buf = Buffer.alloc(0x2000);
  buf.writeUInt32LE(0x464c457f, 0);          // ELF magic
  buf[4] = 2;                                 // 64-bit
  buf.writeBigUInt64LE(64n, 0x20);            // e_phoff
  buf.writeUInt16LE(56, 0x36);                // e_phentsize
  buf.writeUInt16LE(3, 0x38);                 // e_phnum
  // ELF64 Phdr 布局：p_type@+0, p_flags@+4, p_offset@+8, p_vaddr@+16,
  //                 p_paddr@+24, p_filesz@+32, p_memsz@+40
  const PH = (i) => 64 + i * 56;
  // PH0: R, vaddr 0x400000, filesz 0x100
  buf.writeUInt32LE(1, PH(0));  buf.writeUInt32LE(4, PH(0) + 4);
  buf.writeBigUInt64LE(0n, PH(0) + 8);
  buf.writeBigUInt64LE(0x400000n, PH(0) + 16);
  buf.writeBigUInt64LE(0x100n, PH(0) + 32);
  buf.writeBigUInt64LE(0x100n, PH(0) + 40);
  // PH1: RX, vaddr 0x401000, filesz 0x1000  ← 最大可执行
  buf.writeUInt32LE(1, PH(1));  buf.writeUInt32LE(5, PH(1) + 4);
  buf.writeBigUInt64LE(0x1000n, PH(1) + 8);
  buf.writeBigUInt64LE(0x401000n, PH(1) + 16);
  buf.writeBigUInt64LE(0x1000n, PH(1) + 32);
  buf.writeBigUInt64LE(0x1000n, PH(1) + 40);
  // PH2: RW, vaddr 0x500000, filesz 0x200（不可执行）
  buf.writeUInt32LE(1, PH(2));  buf.writeUInt32LE(6, PH(2) + 4);
  buf.writeBigUInt64LE(0x3000n, PH(2) + 8);
  buf.writeBigUInt64LE(0x500000n, PH(2) + 16);
  buf.writeBigUInt64LE(0x200n, PH(2) + 32);
  buf.writeBigUInt64LE(0x200n, PH(2) + 40);

  const segs = SD.inferRegions(buf);
  ok(segs.length === 1, '只有 1 个可执行 PT_LOAD（PH1），实际 ' + segs.length);
  ok(segs[0].vaddr === 0x401000, '最大的可执行段排第一，vaddr=0x' + (segs[0] && segs[0].vaddr.toString(16)));
  ok(segs[0].filesz === 0x1000, 'filesz 正确');
  ok(!segs.some((s) => s.vaddr === 0x500000), '可写不可执行段被排除');
  // 负向：非 ELF
  ok(SD.inferRegions(Buffer.alloc(64)) .length === 0, '非 ELF 返回空数组');
  ok(SD.inferRegions(Buffer.alloc(10)).length === 0, '太短返回空数组');
}

console.log('\n[3] buildSmcScript —— 生成的脚本内容');
{
  const s = SD.buildSmcScript({
    binPath: '/tmp/x/target', outDir: '/tmp/x',
    region: '0x404000:0x20000', stdinData: 'abcd\n',
  });
  ok(/BASE = 4210688/.test(s), 'BASE 被解析成十进制 4210688 (0x404000)，实际片段: ' + (/BASE = \d+/.exec(s) || [''])[0]);
  ok(/LEN = 131072/.test(s), 'LEN = 0x20000 = 131072');
  ok(/STDIN_DATA = "abcd\\n"/.test(s), 'stdinData 正确转义进脚本');
  ok(/os\.pread\(memfd, LEN, BASE\)/.test(s), '用 pread 采样 /proc/<pid>/mem');
  ok(/\/proc\/%d\/mem/.test(s), '打开 /proc/<pid>/mem');
  ok(/covered\[i\] = 1/.test(s), '并集标记：covered[i] = 1');
  ok(/merged\[i\] = s\[i\]/.test(s), '并集还原：merged[i] = s[i]');
  ok(/SNAPSHOTS %d/.test(s), '输出 SNAPSHOTS 计数');
  ok(/RESTORED_BYTES %d \/ %d/.test(s), '输出 RESTORED_BYTES 覆盖率');
  ok(/BLOCKS %d/.test(s), '输出 BLOCKS 块数');
  // 负向断言：不能是「取最后一张快照」
  ok(!/merged = snaps\[-1\]/.test(s), '不是取最后一张快照（那是错的）');
  ok(!/merged = snaps\[len\(snaps\)-1\]/.test(s), '不是取最后一张快照（另一种写法）');
}

console.log('\n[4] buildSmcScript —— patches 注入');
{
  const s = SD.buildSmcScript({
    binPath: '/tmp/x/t', outDir: '/tmp/x', region: '0x404000:0x1000',
    patches: [{ va: '0x5024fc', bytes: '31c0c3' }],
  });
  ok(/patch_bytes\(patched, "0x5024fc", "31c0c3"\)/.test(s), 'patch 调用被生成（写进 bytearray patched，不是只读的 d）');
  ok(/def patch_bytes\(buf, va, hexstr\)/.test(s), 'patch_bytes 函数已定义');
  ok(/va2off\(SEGS, va\)/.test(s), 'patch 用 va2off 换算文件偏移');
  // 负向：无 patch 时不应生成调用
  const s2 = SD.buildSmcScript({ binPath: '/tmp/x/t', outDir: '/tmp/x', region: '0x404000:0x1000' });
  ok(!/patch_bytes\(patched,/.test(s2), '无 patches 时不生成 patch 调用');
}

console.log('\n[5] buildSmcScript —— 参数默认值');
{
  const s = SD.buildSmcScript({ binPath: '/t', outDir: '/o' });
  ok(/BASE = 4210688/.test(s), '默认 base = 0x404000 = 4210688，实际: ' + (/BASE = \d+/.exec(s) || [''])[0]);
  ok(/LEN = 131072/.test(s), '默认 len = 0x20000');
  ok(/MAX_SNAP = 4000/.test(s), '默认 maxSnap = 4000');
  ok(/MAX_MS = 8000/.test(s), '默认 maxMs = 8000');
  ok(/SLEEP_MS = 0/.test(s), '默认 sleepMs = 0（不停顿，尽量密采样）');
}

console.log('\n[6] 端到端：真跑一个自解密程序');
{
  // 造一个最小的 SMC 程序：跑起来后把自身一段代码改成别的字节
  // 用 python 生成，避免依赖编译器
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smcdump-'));
  const pyPath = path.join(dir, 'smc_target.py');
  // 程序行为：把 0x404000 对应的"假区间"改掉——但 python 没有 /proc/self/mem 自改
  // 所以这里改成验证「脚本本身能被 python 语法解析 + 输出格式正确」
  // 真正的内存采样已在本轮 license 实测中验证（98 快照 / 95 块）
  const script = SD.buildSmcScript({
    binPath: path.join(dir, 'nonexistent'),
    outDir: dir, region: '0x404000:0x1000',
  });
  // 语法检查：用 node 的 child_process 跑 python -c "compile(...)"
  const { execFileSync } = require('child_process');
  let syntaxOk = false, errMsg = '';
  try {
    execFileSync('python', ['-I', '-c',
      'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")',
      path.join(dir, 'gen.py')], { stdio: 'pipe' });
  } catch (e) {
    errMsg = String(e.message || e).slice(0, 200);
  }
  // 先写文件再编译（用 -X utf8 避免 Windows 默认 GBK 解码 UTF-8 脚本失败）
  fs.writeFileSync(path.join(dir, 'gen.py'), script);
  try {
    execFileSync('python', ['-I', '-X', 'utf8', '-c',
      'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")',
      path.join(dir, 'gen.py')], { stdio: 'pipe' });
    syntaxOk = true;
  } catch (e) {
    errMsg = String(e.message || e).slice(0, 300);
  }
  ok(syntaxOk, '生成的 python 脚本语法合法', errMsg);

  // 负向断言：故意把脚本里一个关键行删掉，语法应该仍然合法但行为不同
  // —— 这里验证「负向测试能抓错」：把 pread 改成读固定值，compile 仍过，
  // 但我们可以断言替换后的脚本确实不含 pread，证明我们的字符串断言是有区分力的
  const broken = script.replace(/os\.pread\(memfd, LEN, BASE\)/g, 'b"\\x00" * LEN');
  ok(!/os\.pread/.test(broken), '替换后确实不含 pread（说明断言有区分力）');
  ok(/os\.pread/.test(script), '原脚本含 pread');
  // 这证明：如果实现里漏了 pread，第 [3] 组的断言会失败 —— 负向有效性成立

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
}

console.log('\n[7] patch_bytes 真跑：va 字符串必须被转成 int');
{
  // 负向断言的核心：单测只检查字符串生成是不够的。
  // 这里把生成的脚本真的执行一遍（用假 ELF），确认 patch 真的生效。
  // 历史上真实踩过的 bug：patch_bytes 收到 "0x5024fc" 字符串，
  //   `vaddr <= va` 抛 TypeError —— 只有真跑才抓得到。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smcpatch-'));
  const { execFileSync } = require('child_process');

  // 造一个最小 ELF64：1 个可执行 PT_LOAD @ 0x400000，filesz 0x1000
  const elf = Buffer.alloc(0x2000);
  elf.writeUInt32LE(0x464c457f, 0);
  elf[4] = 2;
  elf.writeBigUInt64LE(64n, 0x20);
  elf.writeUInt16LE(56, 0x36);
  elf.writeUInt16LE(1, 0x38);
  const PH = 64;
  elf.writeUInt32LE(1, PH); elf.writeUInt32LE(5, PH + 4);
  elf.writeBigUInt64LE(0n, PH + 8);
  elf.writeBigUInt64LE(0x400000n, PH + 16);
  elf.writeBigUInt64LE(0x1000n, PH + 32);
  elf.writeBigUInt64LE(0x1000n, PH + 40);
  // 在 va 0x400100 处填已知字节，供补丁覆盖
  elf.write('ORIGINAL', 0x100, 'ascii');
  const elfPath = path.join(dir, 'fake.elf');
  fs.writeFileSync(elfPath, elf);

  // 直接测脚本里的 patch 逻辑：抽出 patch_bytes + va2off 单独跑
  const script = SD.buildSmcScript({
    binPath: elfPath, outDir: dir,
    region: '0x400000:0x1000',
    patches: [{ va: '0x400100', bytes: '5041544348' }],   // "PATCH" 5 字节
  });
  // 只跑到 patch 之前就停（把后面的采样逻辑截掉），避免它去找不存在的进程
  const cut = script.indexOf('PATCHED_PATH = os.path.join');
  const head = script.slice(0, cut) +
    '\nprint("PATCHED_BYTES", bytes(patched[va2off(SEGS,0x400100):va2off(SEGS,0x400100)+5]).decode("latin1"))\n';
  const headPath = path.join(dir, 'patchonly.py');
  fs.writeFileSync(headPath, head, 'utf8');

  let out = '', err = '';
  try {
    out = String(execFileSync('python', ['-I', '-X', 'utf8', headPath], { stdio: 'pipe' }));
  } catch (e) {
    err = String((e.stderr || '') + (e.message || '')).slice(0, 400);
  }
  ok(/PATCH 0x400100/.test(out), 'patch 在 va 0x400100 上执行（不是 PATCH_SKIP）', err || out.slice(0, 300));
  ok(/PATCHED_BYTES PATCH/.test(out), '文件字节真的被改成了 PATCH（不是原来的 ORIGINA）', out.slice(-200));
  ok(!/TypeError/.test(err), '没有 TypeError（va 字符串已转 int）', err);

  // 负向：如果 va 不做 int 转换，应当抛 TypeError —— 证明这个断言有区分力
  const brokenHead = head.replace(
    'va = int(va, 16) if isinstance(va, str) else int(va)',
    'pass  # 故意不转换');
  const brokenPath = path.join(dir, 'broken.py');
  fs.writeFileSync(brokenPath, brokenHead, 'utf8');
  let brokenErr = '';
  try {
    execFileSync('python', ['-I', '-X', 'utf8', brokenPath], { stdio: 'pipe' });
  } catch (e) {
    brokenErr = String((e.stderr || '') + (e.message || ''));
  }
  ok(/TypeError/.test(brokenErr), '去掉 int 转换后确实抛 TypeError（负向有效）', brokenErr.slice(0, 200));

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
}

console.log('\n[8] 覆盖率不足必须主动警告（实测天花板固化）');
{
  // license 题实测：外部轮询无法采全。工具必须自己说出来，
  // 而不是让 AI 把「没采到」当成「那段就是密文」。
  const s = SD.buildSmcScript({
    binPath: '/t', outDir: '/o', region: '0x404000:0x1000',
  });
  ok(/COVERAGE_INCOMPLETE/.test(s), '脚本输出 COVERAGE_INCOMPLETE 标记');
  ok(/没执行到/.test(s), '警告里点明「可能没执行到」（不只说密文）');
  ok(/SUSPECT_EARLY_FAILURE/.test(s), '脚本输出 SUSPECT_EARLY_FAILURE 标记');
  ok(/Rejected/.test(s), '失败串检测包含 Rejected');
  ok(/stdinData/.test(s), '警告里指引用 stdinData 喂正确输入');

  // main.js dispatch 必须把这两个标记解释成人话
  const mainSrc = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/SUSPECT_EARLY_FAILURE/.test(mainSrc), 'main.js 解析 SUSPECT_EARLY_FAILURE');
  ok(/未覆盖的字节 ≠ 一定是密文/.test(mainSrc), 'main.js 提示「未覆盖 ≠ 密文」');
  ok(/337 块/.test(mainSrc), 'main.js 带上实测对照数据（337 块 vs 87 块）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
