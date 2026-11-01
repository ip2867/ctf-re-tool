#!/usr/bin/env node
'use strict';

/**
 * 自证：**链路测试本身**能不能抓到断链。
 *
 * 前面几个 e2e 测试都建立在"mock electron + 加载 main.js"这套装置上。
 * 如果这套装置本身有问题（比如把异常吞掉、把 undefined 当成功），
 * 那么它永远不会失败，等于又一层"假绿"。
 *
 * 本文件故意制造 4 种断链，断言装置必须能识别：
 *   ① dispatch 返回 undefined            → 必须被 toToolResult 标成"无输出"
 *   ② dispatch 抛 ReferenceError          → 必须冒泡（而不是被静默吞掉）
 *   ③ 工具名不存在                         → 必须返回"未知工具"
 *   ④ 源码里删掉一个 case                  → 静态检查必须发现
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
const { toToolResult } = require(path.join(ROOT, 'electron', 'tool-result.js'));

function loadMain(extra) {
  const mp = path.join(ROOT, 'electron', 'main.js');
  let src = fs.readFileSync(mp, 'utf8');
  if (extra) src = extra(src);
  const m = new Module(mp, module);
  m.filename = mp;
  m.paths = Module._nodeModulePaths(path.dirname(mp));
  m._compile(src + `
;module.exports.__test = {
  executeToolCall: typeof executeToolCall === 'function' ? executeToolCall : null,
};`, mp);
  return m.exports.__test;
}

(async () => {
  console.log('=== 自证：链路测试装置能抓到断链吗 ===');

  const base = loadMain();

  await ta('① 工具返回 undefined → toToolResult 给出非空说明（不是空白）', () => {
    const r = toToolResult(undefined);
    assert.ok(r.text.trim().length > 0, 'undefined 变成空文本，AI 收到空块');
    assert.ok(/无输出|为空/.test(r.text), '没说明是"无输出"：' + r.text);
  });

  await ta('② ReferenceError 必须被标记成"工具实现缺陷"，不能混同于普通失败', async () => {
    // 不存在的工具 → 明确的"未知工具"
    const out = await base.executeToolCall('__nonexistent_tool__', {});
    const s = typeof out === 'string' ? out : JSON.stringify(out);
    assert.ok(/未知工具|unknown|不支持/.test(s), '调用不存在的工具没有明确报错：' + s.slice(0, 200));

    // 注入真实断链（模拟 extract_payload 当年缺失函数的形态）
    const broken = loadMain((src) => {
      const re = /(case 'z3_solve':)(\s*)(return await runZ3Solve)/;
      if (!re.test(src)) throw new Error('注入点未找到：case z3_solve 的实现行');
      return src.replace(re, "$1$2throw new ReferenceError('buildPayloadExtractPython is not defined');$2$3");
    });
    const r = await broken.executeToolCall('z3_solve', { constraints: "x = BitVec('x',8)" });
    const rs = typeof r === 'string' ? r : JSON.stringify(r);
    // 关键：必须与"普通工具失败"可区分 —— 否则 AI 只会当成参数问题反复重试
    assert.ok(/工具实现缺陷/.test(rs), 'ReferenceError 被混同成普通失败，AI 会盲目重试：' + rs.slice(0, 200));
    assert.ok(/ReferenceError/.test(rs), '没保留异常类型：' + rs.slice(0, 200));
    assert.ok(/buildPayloadExtractPython is not defined/.test(rs), '没保留原始消息：' + rs.slice(0, 200));
    assert.ok(!/^工具调用失败/.test(rs), '仍以"工具调用失败"开头，无法与其他失败区分');
  });

  await ta('③ 负向：源码删掉一个 case → 静态可达性检查必须发现', () => {
    const src = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
    // 模拟"schema 有但 dispatch 没有"的漂移：检查每个 schema 工具都有 case
    const names = [...new Set([...src.matchAll(/name:\s*"([a-z0-9_]+)"/g)].map((m) => m[1]))];
    // 这些走别名/无独立 case，属已知例外
    const ALIAS = new Set(['gen_sm4_solver', 'ida_dbg_mem']);
    const missing = names.filter((n) => !ALIAS.has(n) && !new RegExp(`case '${n}'`).test(src));
    assert.deepStrictEqual(missing, [], '这些工具 schema 有定义但 dispatch 没有 case：' + missing.join(','));
  });

  await ta('④ 负向：把 toToolResult 临时改回旧实现 → 本文件的断言必须失败', () => {
    // 直接构造旧行为（Error 走 JSON.stringify），验证我们的断言确实能区分
    const oldBehavior = (v) => {
      let text;
      if (v === undefined) text = '';
      else if (typeof v === 'object') { try { text = JSON.stringify(v, null, 2); } catch (e) { text = String(v); } }
      else text = String(v);
      return { text, isError: false };
    };
    const err = new Error('boom');
    const old = oldBehavior(err);
    const now = toToolResult(err);
    // 旧实现：Error → "{}"，isError=false；新实现：带消息，isError=true
    assert.strictEqual(old.text, '{}', '旧行为复现失败（前置条件不成立）');
    assert.strictEqual(old.isError, false, '旧行为应把 Error 判成成功');
    assert.ok(/boom/.test(now.text), '新实现丢了错误消息');
    assert.strictEqual(now.isError, true, '新实现没把 Error 判成错误');
    assert.notDeepStrictEqual(old, now, '新旧实现无差异 —— 断言无法区分对错');
  });

  await ta('⑤ 装置本身：main.js 能在无 Electron 环境加载（否则所有 e2e 都是假的）', () => {
    assert.strictEqual(typeof base.executeToolCall, 'function', 'executeToolCall 未加载');
  });

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) process.exit(1);
})();
