#!/usr/bin/env node
'use strict';

/**
 * Kali 远程执行链路：AI 真的能让远端跑命令并拿回输出吗。
 *
 * 这是"工具能用但解不出题"的另一个高发区：SSH 配置在，但 remote_exec 的
 * 参数形态/返回形态与 AI 的预期不符，表现为"远端明明装了 gdb 却总说用不了"。
 *
 * 断言：
 *   ① 远端命令能真跑并回传 stdout
 *   ② 失败命令返回非零与 stderr（AI 才能据此换路）
 *   ③ 不可达时给出可操作的错误（而不是挂死或空返回）
 * 若 Kali 不可达则整体跳过（不算失败）。
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

// userData 必须指向**真实**目录：remote_exec 依赖 config.json 里的 kali 配置，
// 用临时目录 mock 会让它永远报 REMOTE_UNCONFIGURED —— 那是测试环境缺陷。
// Electron 的 userData 在 Windows 上是 %APPDATA%\<productName>，与 kali_probe.py 读的同一份。
const USER_DATA = path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'),
  'ctf-reverse-tool');
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
const { execFileSync } = require('child_process');

(async () => {
  console.log('=== Kali 远程执行链路 ===');

  // 先用 probe 判断可达性（它已实测过 SSH）
  let probeJson = null;
  try {
    const out = execFileSync('python', ['-I', '-X', 'utf8', path.join(ROOT, 'tests', 'kali_probe.py'), '--json'],
      { encoding: 'utf8', timeout: 180000 });
    probeJson = JSON.parse(out);
  } catch (e) {
    const t = String(e.stdout || '').trim();
    if (t) { try { probeJson = JSON.parse(t); } catch (_) { /* ignore */ } }
  }
  if (!probeJson || probeJson.ok !== true) {
    console.log('  SKIP —— Kali 不可达（probe.ok !== true），远程链路本次不验证');
    console.log(`\n结果: ${pass} 通过, ${fail} 失败（已跳过）`);
    process.exit(fail > 0 ? 1 : 0);
  }
  console.log(`  Kali 可达：${probeJson.host}`);

  const T = (() => {
    const mp = path.join(ROOT, 'electron', 'main.js');
    const src = fs.readFileSync(mp, 'utf8');
    const m = new Module(mp, module);
    m.filename = mp;
    m.paths = Module._nodeModulePaths(path.dirname(mp));
    // 生产环境里 loadConfig() 在 app.whenReady() 的回调里执行；
    // 测试 mock 的 whenReady 永不 resolve，所以必须显式调一次，
    // 否则 config.kali 恒为默认值 → 所有远程工具都报 REMOTE_UNCONFIGURED。
    m._compile(src + `
;loadConfig();
;module.exports.__test = {
  executeToolCall: typeof executeToolCall === 'function' ? executeToolCall : null,
  getConfig: () => config,
};`, mp);
    return m.exports.__test;
  })();
  const call = async (n, i) => {
    const o = await T.executeToolCall(n, i);
    return typeof o === 'string' ? o : JSON.stringify(o);
  };

  await ta('config 已加载到真实的 kali 配置（前置条件）', async () => {
    const cfg = T.getConfig();
    assert.ok(cfg && cfg.kali && cfg.kali.sshHost, 'config.kali.sshHost 为空 —— 后续远程测试无意义');
    console.log(`     config.kali → ${cfg.kali.sshUser}@${cfg.kali.sshHost}:${cfg.kali.sshPort}`);
  });

  await ta('remote_exec 能真跑命令并回传 stdout', async () => {
    const out = await call('remote_exec', { host: 'kali', command: 'echo KALI_LINK_OK && uname -m' });
    assert.ok(/KALI_LINK_OK/.test(out), '没拿到远端 stdout：' + out.slice(0, 400));
    assert.ok(/x86_64|aarch64/.test(out), '没拿到 uname 输出：' + out.slice(0, 400));
  });

  await ta('远端能跑到 gdb / python3（动调前提）', async () => {
    const out = await call('remote_exec', { host: 'kali',
      command: 'command -v gdb; python3 -c "import sys;print(sys.version_info[0])"' });
    assert.ok(/gdb/.test(out), 'gdb 路径没回传：' + out.slice(0, 400));
    assert.ok(/\b3\b/.test(out), 'python3 版本没回传：' + out.slice(0, 400));
  });

  // remote_exec 失败时**抛** ToolCallError（__toolError=true），由主循环捕获后
  // 转成 is_error 的 tool_result —— 这是设计如此。测试要把两种情况都归一成文本，
  // 否则"抛错"会被误读成测试装置问题。
  const callText = async (n, i) => {
    try {
      const o = await T.executeToolCall(n, i);
      return typeof o === 'string' ? o : JSON.stringify(o);
    } catch (e) {
      return String((e && e.message) || e);
    }
  };

  await ta('失败命令必须归为"命令失败"而不是"连不上"（否则 AI 会去查网络）', async () => {
    const out = await callText('remote_exec', { host: 'kali', command: 'ls /definitely/not/here_xyz' });
    // 首行是分类前缀；只看第一行，避免"正文里恰好出现别的词"干扰
    const head = String(out).split('\n')[0];
    assert.ok(/REMOTE_CMD_FAILED/.test(head), '命令失败被误归类：' + head.slice(0, 300));
    assert.ok(!/REMOTE_REFUSED|REMOTE_AUTH|REMOTE_TIMEOUT/.test(head),
      '把"命令写错"报成了连接类故障：' + head.slice(0, 300));
    // 保留远端原始报错（中文/英文 locale 都覆盖）
    assert.ok(/无法访问|No such file|not found|no such/i.test(out), '缺少远端原始报错：' + out.slice(0, 300));
  });

  await ta('负向断言：命令失败必须被判成 is_error（抛错或前缀，两条路都算）', async () => {
    const { toToolResult } = require(path.join(ROOT, 'electron', 'tool-result.js'));
    let raw, threw = null;
    try { raw = await T.executeToolCall('remote_exec', { host: 'kali', command: 'ls /nope_xyz_123' }); }
    catch (e) { threw = e; }
    // 设计：__toolError 的异常上抛给主循环 → 主循环用 toToolResult 转 is_error
    const r = threw ? toToolResult(threw) : toToolResult(raw);
    assert.strictEqual(r.isError, true, '远端命令失败却没标 is_error：' + r.text.slice(0, 200));
    assert.ok(/REMOTE_CMD_FAILED/.test(r.text), '前缀不对：' + r.text.slice(0, 200));
  });

  await ta('负向断言：不可达主机必须快速返回可操作错误（不挂死）', async () => {
    const t0 = Date.now();
    const out = await call('remote_exec', { host: 'kali', command: 'echo x', port: 1 });
    const ms = Date.now() - t0;
    // 允许它回落到别的入口，但必须有可读信息且不能耗时过久
    assert.ok(out.length > 0, '空返回');
    console.log(`     耗时 ${ms}ms，输出前 100 字：${out.slice(0, 100).replace(/\n/g, ' ')}`);
    assert.ok(ms < 120000, '耗时过长（' + ms + 'ms），会拖垮解题预算');
  });

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  if (fail > 0) process.exit(1);
})();
