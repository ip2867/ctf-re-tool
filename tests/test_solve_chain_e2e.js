#!/usr/bin/env node
'use strict';

/**
 * 端到端**解题链路**验证：从"丢进来一个二进制"到"拿到 flag"。
 *
 * 上一个文件（test_tool_link_e2e.js）验证"每个工具能跑通"。
 * 本文件验证更关键的一件事：**这些工具串起来能不能真解出一道题**。
 *
 * 三道真实形态的合成题（不依赖外部样本，参数随机生成，答案可独立验算）：
 *   ① XOR 链 + 逐字节比较        → scan_crypto 定位 / z3_solve 求解 / 回代验证
 *   ② 魔改 S 盒查表 + 跨字节累加  → lookup_expr 建模 / 解出后回代原始校验函数
 *   ③ 编码存储的内嵌载荷          → scan_crypto 发现 / extract_payload 提取 / 二次扫描
 *
 * 每道题都必须**真的解出 flag 并经原始校验函数复核**，而不是"工具没报错"。
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

const ROOT = path.resolve(__dirname, '..');
let pass = 0, fail = 0;
async function ta(name, fn) {
  try { await fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

// ── 载入 main.js（同 test_tool_link_e2e.js 的做法）──
const USER_DATA = path.join(os.tmpdir(), 'ctf-tool-test-userdata');
fs.mkdirSync(USER_DATA, { recursive: true });
function makeMock() {
  const noop = () => {};
  const fakeWin = function () { return { loadFile: noop, on: noop, show: noop, hide: noop,
    webContents: { on: noop, send: noop, openDevTools: noop, setWindowOpenHandler: noop } }; };
  fakeWin.getAllWindows = () => []; fakeWin.fromWebContents = () => null;
  return {
    app: { whenReady: () => new Promise(() => {}), on: noop, once: noop, quit: noop, exit: noop,
      getPath: () => USER_DATA, getAppPath: () => ROOT, setPath: noop, isPackaged: false,
      getName: () => 'test', commandLine: { appendSwitch: noop, appendArgument: noop },
      requestSingleInstanceLock: () => true },
    ipcMain: { handle: noop, on: noop, removeHandler: noop, removeAllListeners: noop },
    BrowserWindow: fakeWin,
    dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }),
      showSaveDialog: async () => ({ canceled: true }), showMessageBox: async () => ({ response: 0 }) },
    shell: { openPath: async () => '', openExternal: async () => '' },
    Menu: { buildFromTemplate: () => ({ popup: noop }), setApplicationMenu: noop },
    Tray: function () { return { setToolTip: noop, setContextMenu: noop, on: noop }; },
    nativeTheme: { on: noop, shouldUseDarkColors: false },
    protocol: { registerFileProtocol: noop, handle: noop },
    session: { defaultSession: { webRequest: { onBeforeRequest: noop } } },
    Notification: function () { return { show: noop }; },
    clipboard: { writeText: noop, readText: () => '' },
  };
}
const origLoad = Module._load;
Module._load = function (req, parent, isMain) {
  if (req === 'electron') return makeMock();
  return origLoad.call(this, req, parent, isMain);
};
function loadMain() {
  const mp = path.join(ROOT, 'electron', 'main.js');
  const src = fs.readFileSync(mp, 'utf8');
  const m = new Module(mp, module);
  m.filename = mp;
  m.paths = Module._nodeModulePaths(path.dirname(mp));
  m._compile(src + `
;module.exports.__test = {
  executeToolCall: typeof executeToolCall === 'function' ? executeToolCall : null,
  getToolDefinitions: typeof getToolDefinitions === 'function' ? getToolDefinitions : null,
};`, mp);
  return m.exports.__test;
}
const T = loadMain();
const call = async (n, i) => {
  const o = await T.executeToolCall(n, i);
  return typeof o === 'string' ? o : JSON.stringify(o);
};

// ── 确定性伪随机（题面参数可复现，但不写死答案）──
let seed = 0x5EED_1234;
const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
const rndInt = (n) => Math.floor(rnd() * n);

(async () => {
  console.log('=== 端到端解题链路（三道合成题，必须真解出 flag）===');

  // ═══════════ 题 1：XOR 链 + 逐字节比较 ═══════════
  console.log('\n① XOR 链 + 逐字节比较');
  const FLAG1 = 'flag{' + crypto.randomBytes(6).toString('hex') + '}';
  const N1 = FLAG1.length;
  // 校验：expect[i] = flag[i] ^ key[(i*3+1) % keylen] ^ ((i*7)&0xff)
  const KEY1 = Array.from({ length: 5 }, () => 0x20 + rndInt(0x5f));
  const expect1 = [];
  for (let i = 0; i < N1; i++) {
    expect1.push((FLAG1.charCodeAt(i) ^ KEY1[(i * 3 + 1) % KEY1.length] ^ ((i * 7) & 0xff)) & 0xff);
  }
  // 独立的"原始校验函数"——用来回代，与 z3 建模互不依赖
  const verify1 = (cand) => {
    if (cand.length !== N1) return false;
    for (let i = 0; i < N1; i++) {
      if (((cand.charCodeAt(i) ^ KEY1[(i * 3 + 1) % KEY1.length] ^ ((i * 7) & 0xff)) & 0xff) !== expect1[i]) return false;
    }
    return true;
  };
  assert.ok(verify1(FLAG1), '前置：题面自身校验必须通过');

  await ta('z3_solve 解出完整 flag 并逐字节一致', async () => {
    const decl = Array.from({ length: N1 }, (_, i) => `f${i} = BitVec('f${i}', 8)`).join('\n');
    const cons = [];
    for (let i = 0; i < N1; i++) {
      cons.push(`s.add(f${i} >= 0x20, f${i} <= 0x7e)`);
      cons.push(`s.add((f${i} ^ BitVecVal(${KEY1[(i * 3 + 1) % KEY1.length]}, 8) ^ BitVecVal(${(i * 7) & 0xff}, 8)) == ${expect1[i]})`);
    }
    const out = await call('z3_solve', { constraints: decl + '\n' + cons.join('\n') });
    const j = JSON.parse(out.slice(out.indexOf('{')));
    assert.strictEqual(j.status, 'sat', '未解出：' + out.slice(0, 300));
    assert.strictEqual(j.as_text, FLAG1, '解出的明文与真答案不一致：' + j.as_text);
    assert.ok(verify1(j.as_text), '回代原始校验函数失败');
  });

  await ta('负向对照：密钥改一位 → 必须解出不同明文且回代失败', async () => {
    const decl = Array.from({ length: N1 }, (_, i) => `f${i} = BitVec('f${i}', 8)`).join('\n');
    const badKey = KEY1.slice(); badKey[0] ^= 0x01;
    const cons = [];
    for (let i = 0; i < N1; i++) {
      cons.push(`s.add(f${i} >= 0x20, f${i} <= 0x7e)`);
      cons.push(`s.add((f${i} ^ BitVecVal(${badKey[(i * 3 + 1) % badKey.length]}, 8) ^ BitVecVal(${(i * 7) & 0xff}, 8)) == ${expect1[i]})`);
    }
    const out = await call('z3_solve', { constraints: decl + '\n' + cons.join('\n') });
    const j = JSON.parse(out.slice(out.indexOf('{')));
    // 用错密钥要么解出不同的串、要么无解 —— 绝不能解出正确的 flag
    if (j.status === 'sat') {
      assert.notStrictEqual(j.as_text, FLAG1, '用错密钥竟解出了正确 flag —— 测试无法区分对错');
      assert.ok(!verify1(j.as_text), '用错密钥的解竟通过了原始校验 —— 校验函数无效');
    } else {
      assert.strictEqual(j.status, 'unsat', '既非 sat 也非 unsat：' + j.status);
    }
  });

  // ═══════════ 题 2：魔改 S 盒 + 跨字节累加 ═══════════
  console.log('\n② 魔改 S 盒查表 + 跨字节累加');
  const FLAG2 = 'flag{' + crypto.randomBytes(5).toString('hex') + '}';
  const N2 = FLAG2.length;
  // 随机置换 S 盒（非标准、非仿射）
  const SBOX = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) { const j = rndInt(i + 1); [SBOX[i], SBOX[j]] = [SBOX[j], SBOX[i]]; }
  const verify2 = (cand) => {
    if (cand.length !== N2) return false;
    let acc = 0x5a;
    for (let i = 0; i < N2; i++) {
      acc = (acc + SBOX[cand.charCodeAt(i)] + i) & 0xff;     // 跨字节累加
      if (acc !== ((FLAG2.charCodeAt(i) * 3 + i * 11 + 7) & 0xff)) {
        // 注意：这里刻意用"真答案的期望"生成目标，cand 必须自己算出同样的 acc
      }
    }
    return true;
  };
  // 目标序列由真答案跑一遍得到（模拟二进制里的密文常量表）
  const target2 = (() => {
    const t = []; let acc = 0x5a;
    for (let i = 0; i < N2; i++) { acc = (acc + SBOX[FLAG2.charCodeAt(i)] + i) & 0xff; t.push(acc); }
    return t;
  })();
  const verify2b = (cand) => {
    if (cand.length !== N2) return false;
    let acc = 0x5a;
    for (let i = 0; i < N2; i++) { acc = (acc + SBOX[cand.charCodeAt(i)] + i) & 0xff; if (acc !== target2[i]) return false; }
    return true;
  };
  assert.ok(verify2b(FLAG2), '前置：题面自身校验必须通过');

  await ta('lookup_expr 建模魔改 S 盒，解出并回代验证', async () => {
    const table = '[' + SBOX.map((v, i) => `(${i},${v})`).join(',') + ']';
    const decl = Array.from({ length: N2 }, (_, i) => `f${i} = BitVec('f${i}', 8)`).join('\n');
    const cons = [
      `SB = ${table}`,
      'acc = BitVecVal(0x5a, 8)',
    ];
    for (let i = 0; i < N2; i++) {
      cons.push(`s.add(f${i} >= 0x20, f${i} <= 0x7e)`);
      cons.push(`acc = (acc + lookup_expr(f${i}, SB) + BitVecVal(${i}, 8)) & 0xff`);
      cons.push(`s.add(acc == ${target2[i]})`);
    }
    const out = await call('z3_solve', { constraints: decl + '\n' + cons.join('\n'), timeout: 120 });
    const j = JSON.parse(out.slice(out.indexOf('{')));
    assert.strictEqual(j.status, 'sat', '未解出：' + out.slice(0, 400));
    assert.strictEqual(j.as_text, FLAG2, '明文不一致：' + j.as_text);
    assert.ok(verify2b(j.as_text), '回代原始校验函数失败');
  });

  // ═══════════ 题 3：编码存储的内嵌载荷（多阶段）═══════════
  console.log('\n③ 编码存储的内嵌载荷 → 提取 → 二次扫描');
  const INNER_FLAG = 'flag{' + crypto.randomBytes(6).toString('hex') + '}';
  await ta('scan_crypto 发现载荷 → extract_payload 提取 → 魔数正确', async () => {
    // 内层：假 ELF，末尾附 flag 明文（模拟真实多阶段题）
    const inner = Buffer.concat([
      Buffer.from('7f454c46020101000000000000000000', 'hex'),
      Buffer.alloc(200, 0x90),
      Buffer.from(INNER_FLAG, 'ascii'),
    ]);
    const KEY3 = 0x5c;
    const enc = Buffer.alloc(inner.length);
    for (let i = 0; i < inner.length; i++) enc[i] = inner[i] ^ KEY3;
    const carrier = Buffer.concat([Buffer.alloc(128, 0x41), enc, Buffer.alloc(64, 0x00)]);
    const f = path.join(os.tmpdir(), `syn_stage1_${Date.now().toString(36)}.bin`);
    fs.writeFileSync(f, carrier);

    // 第一次扫描：必须发现"编码存储的 ELF"
    const scan1 = await call('scan_crypto', { path: f });
    assert.ok(/载荷|payload/i.test(scan1), 'scan_crypto 没发现内嵌载荷：' + scan1.slice(0, 500));

    // 提取
    const outPath = path.join(os.tmpdir(), `syn_stage2_${Date.now().toString(36)}.bin`);
    const ex = await call('extract_payload',
      { path: f, offset: 128, length: inner.length, kind: 'xor', key: String(KEY3), out: outPath });
    assert.ok(/提取成功|OK/.test(ex), '提取失败：' + ex.slice(0, 400));
    assert.ok(fs.existsSync(outPath), '输出文件不存在');
    const head = fs.readFileSync(outPath).slice(0, 4).toString('hex');
    assert.strictEqual(head, '7f454c46', 'ELF 魔数不对：' + head);

    // 二次扫描新文件：flag 明文应能被 recover_string / read_file 读到
    const inner2 = fs.readFileSync(outPath).toString('latin1');
    assert.ok(inner2.includes(INNER_FLAG), '提取出的内层文件里找不到 flag 明文');

    // 用 read_file 读回（模拟 AI 的取证动作）
    const rd = await call('read_file', { path: outPath });
    assert.ok(rd.includes(INNER_FLAG) || /flag\{/.test(rd), 'read_file 读不到内层 flag');
  });

  // ═══════════ 题 4：TEA 变体（标准算法 + 魔改 delta）═══════════
  console.log('\n④ TEA 变体：delta 被改，靠常量搜索 + 手写逆函数');
  await ta('识别 delta → 手写解密 → 回代验证', async () => {
    const DELTA = 0x9E3779B0;   // 魔改：末位 +1
    const KEY4 = [0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00];
    const PLAIN = Buffer.from('flag{' + crypto.randomBytes(4).toString('hex') + '}', 'ascii');
    const pad = Buffer.alloc((8 - (PLAIN.length % 8)) % 8 || 8, 0);
    const buf = Buffer.concat([PLAIN, pad]);
    // 加密
    const ct = [];
    for (let off = 0; off < buf.length; off += 8) {
      let v0 = buf.readUInt32LE(off), v1 = buf.readUInt32LE(off + 4);
      let sum = 0;
      for (let r = 0; r < 32; r++) {
        sum = (sum + DELTA) >>> 0;
        v0 = (v0 + ((((v1 << 4) >>> 0) + KEY4[0]) ^ (v1 + sum) ^ (((v1 >>> 5) + KEY4[1]) >>> 0))) >>> 0;
        v1 = (v1 + ((((v0 << 4) >>> 0) + KEY4[2]) ^ (v0 + sum) ^ (((v0 >>> 5) + KEY4[3]) >>> 0))) >>> 0;
      }
      ct.push(v0, v1);
    }
    const cipher = Buffer.alloc(ct.length * 4);
    ct.forEach((v, i) => cipher.writeUInt32LE(v, i * 4));

    // 片段：把密文写进一个"二进制"，让 scan_crypto 能找到 TEA 常量
    const fakeBin = Buffer.concat([
      Buffer.alloc(64),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(DELTA, 0); return b; })(),
      Buffer.alloc(64),
      cipher,
      Buffer.alloc(64),
    ]);
    const f = path.join(os.tmpdir(), `syn_tea_${Date.now().toString(36)}.bin`);
    fs.writeFileSync(f, fakeBin);

    const sc = await call('scan_crypto', { path: f });
    assert.ok(/TEA/i.test(sc), 'scan_crypto 没识别 TEA 家族：' + sc.slice(0, 400));

    // 按"魔改 delta"手写解密（这是技能里的正确做法）
    let out = Buffer.alloc(0);
    for (let off = 0; off < cipher.length; off += 8) {
      let v0 = cipher.readUInt32LE(off), v1 = cipher.readUInt32LE(off + 4);
      let sum = (DELTA * 32) >>> 0;
      for (let r = 0; r < 32; r++) {
        v1 = (v1 - ((((v0 << 4) >>> 0) + KEY4[2]) ^ (v0 + sum) ^ (((v0 >>> 5) + KEY4[3]) >>> 0))) >>> 0;
        v0 = (v0 - ((((v1 << 4) >>> 0) + KEY4[0]) ^ (v1 + sum) ^ (((v1 >>> 5) + KEY4[1]) >>> 0))) >>> 0;
        sum = (sum - DELTA) >>> 0;
      }
      const b = Buffer.alloc(8); b.writeUInt32LE(v0, 0); b.writeUInt32LE(v1, 4);
      out = Buffer.concat([out, b]);
    }
    const got = out.toString('latin1').replace(/\x00+$/, '');
    assert.strictEqual(got, PLAIN.toString('latin1'), 'TEA 解密结果不对：' + JSON.stringify(got));
  });

  await ta('负向对照：delta 用标准值解密 → 必须是乱码（证明"搜常量"这步不可省）', async () => {
    const DELTA = 0x9E3779B0;          // 真值（魔改）
    const STD = 0x9E3779B9;            // 标准 TEA delta
    const KEY4 = [0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00];
    const PLAIN = Buffer.from('flag{negativecontrol}', 'ascii');
    const pad = Buffer.alloc((8 - (PLAIN.length % 8)) % 8 || 8, 0);
    const buf = Buffer.concat([PLAIN, pad]);
    const ct = [];
    for (let off = 0; off < buf.length; off += 8) {
      let v0 = buf.readUInt32LE(off), v1 = buf.readUInt32LE(off + 4);
      let sum = 0;
      for (let r = 0; r < 32; r++) {
        sum = (sum + DELTA) >>> 0;
        v0 = (v0 + ((((v1 << 4) >>> 0) + KEY4[0]) ^ (v1 + sum) ^ (((v1 >>> 5) + KEY4[1]) >>> 0))) >>> 0;
        v1 = (v1 + ((((v0 << 4) >>> 0) + KEY4[2]) ^ (v0 + sum) ^ (((v0 >>> 5) + KEY4[3]) >>> 0))) >>> 0;
      }
      ct.push(v0, v1);
    }
    const cipher = Buffer.alloc(ct.length * 4);
    ct.forEach((v, i) => cipher.writeUInt32LE(v, i * 4));

    // 用**标准** delta 解密 → 必须是乱码
    let outBad = Buffer.alloc(0);
    for (let off = 0; off < cipher.length; off += 8) {
      let v0 = cipher.readUInt32LE(off), v1 = cipher.readUInt32LE(off + 4);
      let sum = (STD * 32) >>> 0;
      for (let r = 0; r < 32; r++) {
        v1 = (v1 - ((((v0 << 4) >>> 0) + KEY4[2]) ^ (v0 + sum) ^ (((v0 >>> 5) + KEY4[3]) >>> 0))) >>> 0;
        v0 = (v0 - ((((v1 << 4) >>> 0) + KEY4[0]) ^ (v1 + sum) ^ (((v1 >>> 5) + KEY4[1]) >>> 0))) >>> 0;
        sum = (sum - STD) >>> 0;
      }
      const b = Buffer.alloc(8); b.writeUInt32LE(v0, 0); b.writeUInt32LE(v1, 4);
      outBad = Buffer.concat([outBad, b]);
    }
    const bad = outBad.toString('latin1');
    assert.notStrictEqual(bad.replace(/\x00+$/, ''), PLAIN.toString('latin1'),
      '用标准 delta 竟解出正确明文 —— 该负向断言失效');
    assert.ok(!bad.includes('flag{'), '乱码里仍出现 flag{ —— 断言失效');
  });

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) process.exit(1);
})();
