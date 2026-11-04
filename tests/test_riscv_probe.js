#!/usr/bin/env node
'use strict';

/**
 * riscv_probe 的契约测试（含真实 Kali 端到端）。
 *
 * 背景：qwb2026 firmware 题的 keymat 只在内存里——固件启动时把 .selfhash 原地变换，
 * 静态读只能拿到变换前的值。必须用 qemu + gdb 断点读返回点。
 *
 * 本测试锁死三件事：
 *   ① 脚本生成器产出的 bash 结构正确（含关键的 $reg 转义）
 *   ② parseGdbXOutput 能把多个地址块**分开**解析（否则两段会拼成一串）
 *   ③ 真实 Kali 上跑一遍，拿到的 keymat 必须与已知值一致
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const R = require(path.join(ROOT, 'electron', 'riscv-probe.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}
async function ta(name, fn) {
  try { await fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

console.log('=== riscv_probe：脚本生成 ===');

t('find_call 脚本含 gdb-multiarch + riscv:rv32 + 反汇编范围', () => {
  const s = R.buildFindCallSiteScript({ remoteDir: '/tmp/x', binName: 'fw.bin', target: '0x10818', textStart: '0x100b4', textEnd: '0x1090e' });
  assert.ok(/gdb-multiarch/.test(s), '缺 gdb-multiarch');
  assert.ok(/set architecture riscv:rv32/.test(s), '缺 riscv:rv32');
  assert.ok(/0x10818/.test(s), '缺 target');
  assert.ok(/0x100b4,0x1090e/.test(s), '缺反汇编范围');
  assert.ok(/\/tmp\/fwprobe_disasm\.txt/.test(s), '应先把反汇编落盘再 awk（管道里拿不到后续行）');
});

t('probe 脚本启动 qemu 并带 -g 端口', () => {
  const s = R.buildRiscvProbeScript({ remoteDir: '/tmp/x', binName: 'fw.bin', port: 4321, breakAddr: '0x103fc' });
  assert.ok(/qemu-riscv32 -g "\$\{PORT\}"/.test(s), '未以 -g 启动 qemu');
  assert.ok(/PORT=4321/.test(s), '端口未生效');
  assert.ok(/gdb-multiarch/.test(s), '缺 gdb-multiarch');
});

t('probe 脚本里的寄存器引用被转义（否则 bash 会当自己的变量）', () => {
  const s = R.buildRiscvProbeScript({ remoteDir: '/tmp/x', binName: 'fw.bin', bufReg: 's2' });
  // 关键：必须是 \$s2，不能是 $s2 —— 后者在 bash 双引号里会被展开
  assert.ok(/\\\$s2/.test(s), '寄存器引用未转义：bash 会把 $s2 当自己的变量（配合 set -u 直接报错）');
  assert.ok(!/[^\\]\$s2\{?/.test(s.replace(/\\\$s2/g, '')), '仍存在未转义的 $s2');
});

t('probe 脚本会清理残留 qemu（端口占用）', () => {
  const s = R.buildRiscvProbeScript({ remoteDir: '/tmp/x', binName: 'fw.bin', port: 1234 });
  assert.ok(/ss -ltn/.test(s), '未检查端口占用');
  assert.ok(/pkill -f "qemu-riscv32/.test(s), '未清理旧 qemu');
});

t('probe 脚本 kill qemu（不泄漏进程）', () => {
  const s = R.buildRiscvProbeScript({ remoteDir: '/tmp/x', binName: 'fw.bin' });
  assert.ok(/kill "\$\{QEMU_PID\}"/.test(s), '结束时未 kill qemu');
});

console.log('\n=== riscv_probe：gdb 输出解析 ===');

t('单块：正确解析地址与字节', () => {
  const txt = [
    'Breakpoint 1, 0x000103fc in ?? ()',
    '0x2b2abbc0:\t0xdd\t0x97\t0xcb\t0x2d\t0xe2\t0x5c\t0xea\t0x1a',
    '0x2b2abbc8:\t0x8a\t0x9b\t0xc4\t0x9b\t0x81\t0xab\t0xf9\t0xf4',
  ].join('\n');
  const r = R.parseGdbXOutput(txt);
  assert.strictEqual(r.blocks.length, 1, `应只有 1 块，实际 ${r.blocks.length}`);
  assert.strictEqual(r.addr, '0x2b2abbc0');
  assert.strictEqual(r.hex, 'dd97cb2de25cea1a8a9bc49b81abf9f4');
  assert.strictEqual(r.bytes.length, 16);
});

t('多块：按地址不连续切分，不得把两段拼在一起', () => {
  // 真实形态：缓冲区 @0x...bb0 共 4 行，然后 compare @0x10940 共 4 行
  const txt = [
    '=== buffer ===',
    '0x2b2abbb0:\t0xdd\t0x97\t0xcb\t0x2d\t0xe2\t0x5c\t0xea\t0x1a',
    '0x2b2abbb8:\t0x8a\t0x9b\t0xc4\t0x9b\t0x81\t0xab\t0xf9\t0xf4',
    '0x2b2abbc0:\t0x9b\t0x08\t0x56\t0x64\t0xea\t0x73\t0xd2\t0x93',
    '0x2b2abbc8:\t0xd5\t0x8b\t0x92\t0x02\t0x3d\t0xbd\t0x2a\t0xb7',
    '=== compare ===',
    '0x10940:\t0x30\t0x49\t0xe6\t0x79\t0x77\t0xc8\t0xf7\t0x0f',
    '0x10948:\t0x39\t0x65\t0xfd\t0x6c\t0xdd\t0xdb\t0x03\t0x01',
    '0x10950:\t0x64\t0x56\t0x08\t0x9b\t0x93\t0xd2\t0x73\t0xea',
    '0x10958:\t0x02\t0x92\t0x8b\t0xd5\t0xb7\t0x2a\t0xbd\t0x3d',
  ].join('\n');
  const r = R.parseGdbXOutput(txt);
  assert.strictEqual(r.blocks.length, 2, `应切成 2 块，实际 ${r.blocks.length}`);
  assert.strictEqual(r.blocks[0].bytes.length, 32, `第一块应 32 字节，实际 ${r.blocks[0].bytes.length}`);
  assert.strictEqual(r.blocks[0].addr, '0x2b2abbb0');
  assert.strictEqual(r.blocks[0].hex, 'dd97cb2de25cea1a8a9bc49b81abf9f49b085664ea73d293d58b92023dbd2ab7');
  assert.strictEqual(r.blocks[1].addr, '0x10940');
  assert.strictEqual(r.blocks[1].hex, '3049e67977c8f70f3965fd6cdddb03016456089b93d273ea02928bd5b72abd3d');
  // 顶层取第一块（缓冲区），不能取拼接结果
  assert.strictEqual(r.hex, r.blocks[0].hex, '顶层 hex 应取第一块');
  assert.strictEqual(r.bytes.length, 32, '顶层 bytes 不应是 64（两段拼接的错误）');
});

t('负向断言：旧实现（不分块）会得到 64 字节的错误结果', () => {
  const txt = [
    '0x2b2abbb0:\t0xdd\t0x97\t0xcb\t0x2d\t0xe2\t0x5c\t0xea\t0x1a',
    '0x2b2abbb8:\t0x8a\t0x9b\t0xc4\t0x9b\t0x81\t0xab\t0xf9\t0xf4',
  ].join('\n') + '\n' + [
    '0x10940:\t0x30\t0x49\t0xe6\t0x79\t0x77\t0xc8\t0xf7\t0x0f',
    '0x10948:\t0x39\t0x65\t0xfd\t0x6c\t0xdd\t0xdb\t0x03\t0x01',
  ].join('\n');
  // 复刻旧行为：不分块，全 push 到一个数组
  const old = [];
  for (const l of txt.split('\n')) {
    const m = l.match(/^\s*(0x[0-9a-f]+):\s*(.+)$/i);
    if (!m) continue;
    for (const h of (m[2].match(/0x[0-9a-f]{1,2}\b/gi) || [])) old.push(parseInt(h, 16));
  }
  assert.strictEqual(old.length, 32, '前置：旧实现会得到 32 字节（两段 16+16 拼接）');
  assert.notStrictEqual(old.length, 16, '旧实现无法只取第一块 —— 证明这次修复是必要的');
});

t('无 dump 行时返回空块，不崩', () => {
  const r = R.parseGdbXOutput('No symbol table loaded.\nProgram received signal SIGSEGV.');
  assert.strictEqual(r.blocks.length, 0);
  assert.strictEqual(r.hex, '');
  assert.deepStrictEqual(r.bytes, []);
});

console.log('\n=== 六层注册 ===');
{
  const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  t('schema 有 riscv_probe', () => assert.ok(/name:\s*"riscv_probe"/.test(mainSrc)));
  t('dispatch 有 case', () => assert.ok(/case 'riscv_probe':/.test(mainSrc)));
  t('KNOWN 含 riscv_probe', () => {
    const i = mainSrc.indexOf('const KNOWN = new Set([');
    assert.ok(mainSrc.slice(i, i + 1500).includes("'riscv_probe'"));
  });
  t('MAP 映射到 binary', () => assert.ok(/riscv_probe:\s*'binary'/.test(mainSrc)));
  t('toolLabel 有中文标签', () => {
    // 标签实现跨行且字面量末尾带空格（后面拼 binary 名），只匹配前缀
    assert.ok(/case 'riscv_probe':\s*return 'RISC-V 动态取值/.test(mainSrc),
      'toolLabel 缺少 riscv_probe 的中文标签');
  });
  t('precheck 校验 binary / target / breakAddr', () => {
    assert.ok(/name === 'riscv_probe'/.test(mainSrc));
    const i = mainSrc.indexOf("name === 'riscv_probe'");
    const seg = mainSrc.slice(i, i + 800);
    assert.ok(/binary/.test(seg) && /target/.test(seg) && /breakAddr/.test(seg));
  });
}

console.log('\n=== 真实 Kali 端到端（fw_b.bin → keymat）===');
const FW_B = 'C:\\Users\\Administrator\\Desktop\\工具\\_work\\fw\\fw_b.bin';
const EXPECTED_KEYMAT = 'dd97cb2de25cea1a8a9bc49b81abf9f4';   // 题解给的，静态 .selfhash 是 3049e679...

(async () => {
  if (!fs.existsSync(FW_B)) {
    console.log(`  SKIP 固件不存在：${FW_B}`);
    console.log(`\n结果: ${pass} 通过, ${fail} 失败（已跳过端到端）`);
    process.exit(fail > 0 ? 1 : 0);
  }
  // 检查 Kali 是否可达
  let reachable = false;
  try {
    const probe = execFileSync('python', ['-I', '-X', 'utf8', path.join(ROOT, 'tests', 'kali_probe.py'), '--json'],
      { encoding: 'utf8', timeout: 180000 });
    const j = JSON.parse(probe);
    reachable = !j.error && Array.isArray(j.results) && j.results.length > 0;
  } catch (e) {
    const t2 = String(e.stdout || '').trim();
    if (t2) { try { reachable = !!JSON.parse(t2).results; } catch (_) { /* ignore */ } }
  }
  if (!reachable) {
    console.log('  SKIP Kali 不可达');
    console.log(`\n结果: ${pass} 通过, ${fail} 失败（已跳过端到端）`);
    process.exit(fail > 0 ? 1 : 0);
  }

  const Module = require('module');
  const USER_DATA = path.join(process.env.APPDATA || os.homedir(), 'ctf-reverse-tool');
  function mm() {
    const n = () => {};
    const w = function () { return { loadFile: n, on: n, show: n, hide: n, webContents: { on: n, send: n, openDevTools: n, setWindowOpenHandler: n } }; };
    w.getAllWindows = () => []; w.fromWebContents = () => null;
    return {
      app: { whenReady: () => new Promise(() => {}), on: n, once: n, quit: n, exit: n, getPath: () => USER_DATA, getAppPath: () => ROOT, setPath: n, isPackaged: false, getName: () => 't', commandLine: { appendSwitch: n, appendArgument: n }, requestSingleInstanceLock: () => true },
      ipcMain: { handle: n, on: n, removeHandler: n, removeAllListeners: n }, BrowserWindow: w,
      dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }), showSaveDialog: async () => ({ canceled: true }), showMessageBox: async () => ({ response: 0 }) },
      shell: { openPath: async () => '', openExternal: async () => '' }, Menu: { buildFromTemplate: () => ({ popup: n }), setApplicationMenu: n },
      Tray: function () { return { setToolTip: n, setContextMenu: n, on: n }; }, nativeTheme: { on: n, shouldUseDarkColors: false },
      protocol: { registerFileProtocol: n, handle: n }, session: { defaultSession: { webRequest: { onBeforeRequest: n } } },
      Notification: function () { return { show: n }; }, clipboard: { writeText: n, readText: () => '' },
    };
  }
  const ol = Module._load;
  Module._load = function (r, p, i) { if (r === 'electron') return mm(); return ol.call(this, r, p, i); };
  const mp = path.join(ROOT, 'electron', 'main.js');
  const m2 = new Module(mp, module); m2.filename = mp;
  m2.paths = Module._nodeModulePaths(path.dirname(mp));
  m2._compile(fs.readFileSync(mp, 'utf8') + '\n;loadConfig();\n;module.exports.__test={executeToolCall};', mp);
  const T = m2.exports.__test;

  await ta('action=auto 自动 find_call → probe，拿到的 keymat 与题解一致', async () => {
    const r = await T.executeToolCall('riscv_probe', {
      action: 'auto', binary: FW_B, target: '0x10818',
      bufReg: 's2', readBytes: 32, cmpAddr: '0x10940',
    });
    const s = typeof r === 'string' ? r : JSON.stringify(r);
    assert.ok(new RegExp(EXPECTED_KEYMAT).test(s), '输出里没有期望的 keymat：' + s.slice(0, 600));
    assert.ok(/变换前|对照段/.test(s), '未给出变换前/后的对照');
  });

  await ta('负向断言：静态读 .selfhash 得不到 keymat（证明必须动态取）', () => {
    const buf = fs.readFileSync(FW_B);
    const selfhash = buf.slice(0x940, 0x960).toString('hex');
    assert.ok(selfhash.startsWith('3049e679'), '静态 .selfhash 应是 3049e679...，实际 ' + selfhash.slice(0, 8));
    assert.ok(!selfhash.startsWith(EXPECTED_KEYMAT), '静态值居然等于 keymat —— 那就不需要动态取了');
  });

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) process.exit(1);
})();
