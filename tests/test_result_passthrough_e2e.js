#!/usr/bin/env node
'use strict';

/**
 * 工具结果**回传**链路：dispatch 输出 → toToolResult → 给 AI 的 content + is_error。
 *
 * 断链风险：工具实际成功，但 toToolResult 把它判成 isError=true，
 * AI 就会以为失败、反复重试或换路——表现为"工具明明能用却解不出题"。
 * 反向风险同样严重：真失败被判成成功，AI 拿着空结果继续往下走。
 *
 * 做法：对每个可离线工具真跑一次，断言 (a) 输出能被 toToolResult 正确解析，
 * (b) 成功场景 isError=false，(c) 失败场景 isError=true。
 */

const assert = require('assert');
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

const { toToolResult, ToolCallError } = require(path.join(ROOT, 'electron', 'tool-result.js'));

function loadMain() {
  const mp = path.join(ROOT, 'electron', 'main.js');
  const src = fs.readFileSync(mp, 'utf8');
  const m = new Module(mp, module);
  m.filename = mp;
  m.paths = Module._nodeModulePaths(path.dirname(mp));
  m._compile(src + `
;module.exports.__test = {
  executeToolCall: typeof executeToolCall === 'function' ? executeToolCall : null,
};`, mp);
  return m.exports.__test;
}
const T = loadMain();
const run = (n, i) => T.executeToolCall(n, i);

const tmp = (name, buf) => {
  const f = path.join(os.tmpdir(), `tr_${Date.now().toString(36)}_${name}`);
  fs.writeFileSync(f, buf); return f;
};

(async () => {
  console.log('=== 工具结果回传链路（dispatch → toToolResult → AI）===');

  console.log('\nA) toToolResult 契约本身');
  await ta('字符串 → {text, isError:false}（普通输出不该被判成错误）', () => {
    const r = toToolResult('一切正常：解出 flag{abc}');
    assert.strictEqual(typeof r.text, 'string');
    assert.strictEqual(r.isError, false, '正常字符串被判成错误');
    assert.ok(r.text.includes('flag{abc}'));
  });
  await ta('null/undefined 不崩且文本非空', () => {
    for (const v of [null, undefined]) {
      const r = toToolResult(v);
      assert.strictEqual(typeof r.text, 'string', 'text 必须是字符串');
      assert.ok(r.text.length > 0, '空输入应给出占位说明，不能是空串');
    }
  });
  await ta('对象 → JSON 字符串化（结构化结果不丢字段）', () => {
    const r = toToolResult({ status: 'sat', model: { x: 1 } });
    assert.ok(r.text.includes('"status"') && r.text.includes('sat'), '对象未正确序列化：' + r.text);
  });
  await ta('ToolCallError → isError:true', () => {
    const r = toToolResult(new ToolCallError('文件不存在'));
    assert.strictEqual(r.isError, true, 'ToolCallError 必须判成错误');
    assert.ok(/文件不存在/.test(r.text), '错误信息丢失：' + r.text);
  });
  await ta('普通 Error → 不抛未捕获异常', () => {
    const r = toToolResult(new Error('boom'));
    assert.strictEqual(typeof r.text, 'string');
    assert.ok(/boom/.test(r.text), '错误信息丢失');
  });

  console.log('\nB) 真实工具：成功场景不得被判成 isError');
  const okCases = [
    ['run_python 正常脚本', 'run_python', { script: 'print("OK_MARK")' }, /OK_MARK/],
    ['z3_solve sat', 'z3_solve', { constraints: "x = BitVec('x',8)\ns.add(x == 0x41)" }, /sat/],
    ['z3_solve unsat（有效负结果，不是错误）', 'z3_solve',
      { constraints: "x = BitVec('x',8)\ns.add(x == 1)\ns.add(x == 2)" }, /unsat/],
    ['read_file', 'read_file', { path: tmp('ok.txt', 'HELLO_LINK') }, /HELLO_LINK/],
    ['scan_crypto', 'scan_crypto',
      { path: tmp('ok.bin', Buffer.concat([Buffer.alloc(16), Buffer.from('c6bab1a35033aa5697917d67dc2270b2', 'hex'), Buffer.alloc(16)])) }, /SM4/],
  ];
  for (const [label, tool, input, re] of okCases) {
    await ta(label, async () => {
      const raw = await run(tool, input);
      const r = toToolResult(raw);
      assert.ok(re.test(r.text), '输出里没找到期望内容 ' + re + '：' + r.text.slice(0, 250));
      assert.strictEqual(r.isError, false, '成功结果被判成 isError=true，AI 会误以为失败');
    });
  }

  console.log('\nC) 真实工具：失败场景必须被判成 isError（AI 才会换路）');
  const badCases = [
    ['read_file 路径不存在', 'read_file', { path: 'Z:/nope/xyz.bin' }],
    ['scan_crypto 路径不存在', 'scan_crypto', { path: 'Z:/nope/xyz.bin' }],
    ['run_python 语法错误', 'run_python', { script: 'def f(:\n  pass' }],
  ];
  for (const [label, tool, input] of badCases) {
    await ta(label, async () => {
      const raw = await run(tool, input);
      const r = toToolResult(raw);
      assert.ok(r.isError === true || /失败|错误|不存在|Error|Traceback/i.test(r.text),
        '失败场景既没标 isError 也没有可读错误：' + r.text.slice(0, 250));
    });
  }

  console.log('\nD) 负向断言：不能把一切都判成错误');
  await ta('成功样本里 isError 为 true 的比例必须为 0', async () => {
    const samples = [
      await run('run_python', { script: 'print(1)' }),
      await run('read_file', { path: tmp('ok2.txt', 'x') }),
      await run('z3_solve', { constraints: "x = BitVec('x',8)\ns.add(x == 1)" }),
    ];
    const wrong = samples.filter((s) => toToolResult(s).isError).length;
    assert.strictEqual(wrong, 0, `${wrong}/${samples.length} 个成功结果被误判成错误`);
  });

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) process.exit(1);
})();
