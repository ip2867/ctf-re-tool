#!/usr/bin/env node
'use strict';

/**
 * 工具**执行链路**契约测试（真正执行 dispatch，不是正则匹配源码）。
 *
 * 为什么必须做这个：此前的 121 项测试全部是"在源码里找 `case 'xxx':`"这种静态检查。
 * 实际结果是 `extract_payload` 因为 `buildPayloadExtractPython` 在主进程未定义，
 * 运行时抛 ReferenceError，被 catch 吞成"工具调用失败"，**测试全绿但工具 100% 不可用**。
 *
 * 本测试的做法：
 *   1. mock 掉 electron 模块，把 main.js 加载进纯 Node（已验证可行）
 *   2. 拿到真实的 executeToolCall / getToolDefinitions / precheckToolCall
 *   3. 对每个工具做"链路三段体检"：
 *        schema 里有定义 → precheck 放行 → dispatch 不抛"未实现/未定义"
 *   4. 对可离线验证的工具（run_python / z3_solve / file_digest / extract_payload …）
 *      真跑一次，断言输出形态正确
 *
 * 断言口径：dispatch 必须返回字符串或结构化结果；**不允许**出现
 * `is not defined` / `is not a function` / `工具调用失败` 这类"链路断了"的迹象。
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

const ROOT = path.resolve(__dirname, '..');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}
async function ta(name, fn) {
  try { await fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

// ────────────── mock electron ──────────────
// userData 目录**必须先建好**：main.js 里 CONFIG_PATH / 脚本临时文件都写在这，
// 目录不存在时所有依赖它的工具都会报 ENOENT——这是测试环境缺陷，不是产品缺陷。
const USER_DATA = path.join(os.tmpdir(), 'ctf-tool-test-userdata');
fs.mkdirSync(USER_DATA, { recursive: true });

function makeMock() {
  const noop = () => {};
  const fakeApp = {
    whenReady: () => new Promise(() => {}),   // 永不 resolve：不触发建窗口
    on: noop, once: noop, quit: noop, exit: noop,
    getPath: () => USER_DATA,
    getAppPath: () => ROOT,
    setPath: noop, isPackaged: false, getName: () => 'test',
    commandLine: { appendSwitch: noop, appendArgument: noop },
    requestSingleInstanceLock: () => true,
  };
  const fakeWin = function () {
    return { loadFile: noop, on: noop, show: noop, hide: noop,
      webContents: { on: noop, send: noop, openDevTools: noop, setWindowOpenHandler: noop } };
  };
  fakeWin.getAllWindows = () => [];
  fakeWin.fromWebContents = () => null;
  return {
    app: fakeApp,
    ipcMain: { handle: noop, on: noop, removeHandler: noop, removeAllListeners: noop },
    BrowserWindow: fakeWin,
    dialog: {
      showOpenDialog: async () => ({ canceled: true, filePaths: [] }),
      showSaveDialog: async () => ({ canceled: true }),
      showMessageBox: async () => ({ response: 0 }),
    },
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
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return makeMock();
  return origLoad.call(this, request, parent, isMain);
};

// ────────────── 加载 main.js 并注入钩子 ──────────────
function loadMain() {
  const mainPath = path.join(ROOT, 'electron', 'main.js');
  const src = fs.readFileSync(mainPath, 'utf8');
  const injected = src + `
;module.exports.__test = {
  executeToolCall: typeof executeToolCall === 'function' ? executeToolCall : null,
  getToolDefinitions: typeof getToolDefinitions === 'function' ? getToolDefinitions : null,
  precheckToolCall: typeof precheckToolCall === 'function' ? precheckToolCall : null,
};
`;
  const m = new Module(mainPath, module);
  m.filename = mainPath;
  m.paths = Module._nodeModulePaths(path.dirname(mainPath));
  m._compile(injected, mainPath);
  return m.exports.__test;
}

let T;
try {
  T = loadMain();
} catch (e) {
  console.log('无法加载 electron/main.js：' + (e && e.message));
  console.log((e && e.stack || '').split('\n').slice(0, 8).join('\n'));
  process.exit(1);
}

// "链路断了"的特征串：这些出现在结果里就说明不是参数问题，是代码没接上
const BROKEN = /is not defined|is not a function|is not defined at|ReferenceError|TypeError: .* is not/;
const isBroken = (s) => BROKEN.test(String(s == null ? '' : s));

const tmpFile = (name, buf) => {
  const f = path.join(os.tmpdir(), `link_${Date.now().toString(36)}_${name}`);
  fs.writeFileSync(f, buf);
  return f;
};

(async () => {
  console.log('=== 工具执行链路契约（真跑 dispatch）===');

  console.log('\nA) 三件套都拿到了');
  t('executeToolCall / getToolDefinitions / precheckToolCall 均为函数', () => {
    assert.strictEqual(typeof T.executeToolCall, 'function', 'executeToolCall 缺失');
    assert.strictEqual(typeof T.getToolDefinitions, 'function', 'getToolDefinitions 缺失');
    assert.strictEqual(typeof T.precheckToolCall, 'function', 'precheckToolCall 缺失');
  });

  const defs = T.getToolDefinitions();
  const names = (defs || []).map((d) => d.name).filter(Boolean);
  console.log(`     共 ${names.length} 个工具：${names.join(' ')}`);

  console.log('\nB) 每个工具都能被 dispatch 分派（不落到 default 的"未知工具"）');
  // 用一份"最小合法参数"喂进去：目的是触发 case 分支，而不是跑出正确结果。
  // 若落到 default，返回里会含"未知工具" —— 说明 schema 注册了但 dispatch 没接。
  const MIN_PARAMS = {
    read_file: { path: tmpFile('r.txt', 'hi') },
    list_dir: { path: os.tmpdir() },
    glob: { pattern: '*.md', path: ROOT },
    grep: { pattern: 'zzz_no_match', path: ROOT },
    file_digest: { paths: [tmpFile('d.txt', 'hi')] },
    run_python: { script: 'print(1)' },
    run_command: { command: 'echo hi' },
    bash: { command: 'echo hi' },
    z3_solve: { constraints: "x = BitVec('x', 8)\ns.add(x == 1)" },
    scan_crypto: { path: tmpFile('c.bin', Buffer.from('a3b1bac6', 'hex')) },
  };
  const unknownTool = [];
  for (const n of names) {
    if (n.startsWith('ida_') || n.startsWith('jeb_') || n.startsWith('burp_') ||
        n === 'browser_open' || n === 'browser_search' || n === 'browser_js' ||
        n === 'adb_command' || n === 'frida_hook' || n === 'gui_input' ||
        n === 'remote_exec' || n === 'traffic_extract' || n === 'pcap' ||
        n === 'switch_to_next_stage') continue;   // 需要外部服务/交互，另测
    let out;
    try { out = await T.executeToolCall(n, MIN_PARAMS[n] || {}); }
    catch (e) { out = 'THREW: ' + (e && e.message); }
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    if (/未知工具|unknown tool|未实现的工具/i.test(s)) unknownTool.push(n);
    if (isBroken(s)) unknownTool.push(n + '(断链: ' + s.slice(0, 90) + ')');
  }
  t('没有工具落到"未知工具"/断链分支', () => {
    assert.deepStrictEqual(unknownTool, [], '这些问题工具：\n      ' + unknownTool.join('\n      '));
  });

  console.log('\nC) 可离线验证的工具：真跑一次，断言输出形态');
  await ta('run_python 返回真实 stdout', async () => {
    const out = await T.executeToolCall('run_python', { script: 'print("LINK_OK")' });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(s.includes('LINK_OK'), '输出里没有 LINK_OK：' + s.slice(0, 300));
  });
  await ta('z3_solve 能真解出 sat', async () => {
    const out = await T.executeToolCall('z3_solve',
      { constraints: "f0 = BitVec('f0', 8)\ns.add(f0 == 0x66)" });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(/"status"\s*:\s*"sat"/.test(s) || /sat/.test(s), 'z3 未返回 sat：' + s.slice(0, 300));
  });
  await ta('file_digest 返回真实内容', async () => {
    const f = tmpFile('dg.txt', 'abc');
    const out = await T.executeToolCall('file_digest', { paths: [f] });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(/abc/.test(s), '没读到文件内容：' + s.slice(0, 300));
    assert.ok(/3 ?字节|3B/.test(s), '没报告大小：' + s.slice(0, 300));
  });
  await ta('extract_payload（历史上最典型的断链工具）能真跑', async () => {
    // 构造：MZ 头用 XOR 0x17 编码，工具应能解出含 4d5a 的载荷
    const plain = Buffer.alloc(256);
    plain[0] = 0x4d; plain[1] = 0x5a;
    const enc = Buffer.alloc(plain.length);
    for (let i = 0; i < plain.length; i++) enc[i] = plain[i] ^ 0x17;
    const carrier = Buffer.concat([Buffer.alloc(64), enc, Buffer.alloc(64)]);
    const f = tmpFile('ep.bin', carrier);
    const outPath = path.join(os.tmpdir(), `link_ep_out_${Date.now().toString(36)}.bin`);
    const out = await T.executeToolCall('extract_payload',
      { path: f, offset: 64, length: 256, kind: 'xor', key: '23', out: outPath });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(!isBroken(s), '断链：' + s.slice(0, 300));
    assert.ok(/提取成功|已写出|OK/.test(s), '未成功提取：' + s.slice(0, 400));
    assert.ok(fs.existsSync(outPath), '输出文件不存在');
    const head = fs.readFileSync(outPath).slice(0, 2).toString('hex');
    assert.strictEqual(head, '4d5a', '魔数不对：' + head);
  });
  await ta('scan_crypto 能真扫到 SM4 FK', async () => {
    const f = tmpFile('fk.bin', Buffer.concat([
      Buffer.alloc(32), Buffer.from('c6bab1a35033aa5697917d67dc2270b2', 'hex'), Buffer.alloc(32)]));
    const out = await T.executeToolCall('scan_crypto', { path: f });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(/SM4/.test(s), '未识别 SM4：' + s.slice(0, 400));
    assert.ok(!isBroken(s), '断链：' + s.slice(0, 300));
  });
  await ta('read_file 返回文件内容', async () => {
    const f = tmpFile('rf.txt', 'READ_ME_123');
    const out = await T.executeToolCall('read_file', { path: f });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(s.includes('READ_ME_123'), '内容不符：' + s.slice(0, 200));
  });

  console.log('\nD) precheck：缺必填参数必须被拦下（契约 = 返回非空字符串即拦截）');
  // precheckToolCall 的契约是「返回错误文案字符串 = 拦截」，不是返回 {ok:false}。
  // 调用方（agent 循环 main.js:7666）判断的是 `if (precheck)`。
  const precheckMsg = (n, i) => T.precheckToolCall(n, i);
  await ta('z3_solve 缺 constraints 被拦', () => {
    const msg = precheckMsg('z3_solve', {});
    assert.ok(typeof msg === 'string' && msg.length > 0, '空 constraints 没被 precheck 拦');
    assert.ok(/constraints/.test(msg), '报错没点名缺的是 constraints：' + msg);
  });
  await ta('run_python 缺 script 被拦', () => {
    const msg = precheckMsg('run_python', {});
    assert.ok(typeof msg === 'string' && /script/.test(msg), 'run_python 空参数未拦：' + msg);
  });
  await ta('scan_crypto 缺 path 被拦', () => {
    const msg = precheckMsg('scan_crypto', {});
    assert.ok(typeof msg === 'string' && /path/.test(msg), 'scan_crypto 空参数未拦：' + msg);
  });
  await ta('参数齐全时 precheck 放行（返回 falsy）', () => {
    const msg = precheckMsg('z3_solve', { constraints: "x = BitVec('x',8)" });
    assert.ok(!msg, '合法参数却被拦：' + msg);
  });
  await ta('负向断言：文件不存在时 precheck 给出"相近文件"提示', () => {
    const dir = path.join(os.tmpdir(), 'link_near_' + Date.now().toString(36));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'target_challenge.bin'), 'x');
    const msg = precheckMsg('scan_crypto', { path: path.join(dir, 'target_challeng.bin') });
    assert.ok(typeof msg === 'string', '不存在的文件未被拦');
    assert.ok(/相近文件|不存在/.test(msg), '错误信息不可操作：' + msg);
  });

  console.log('\nE) 负向断言：故意喂错参数，必须返回可读错误而不是抛未捕获异常');
  await ta('不存在的文件路径 → 可读错误', async () => {
    const out = await T.executeToolCall('read_file', { path: 'Z:/definitely/not/here.bin' });
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(/不存在|not found|ENOENT|读取失败/i.test(s), '没有给可读错误：' + s.slice(0, 200));
  });

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) process.exit(1);
})();
