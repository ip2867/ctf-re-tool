// IDA 自动拉起回归（工具循环路径）
//
// 实测（DancingKeys.sys，用户直接在对话里下指令，没点界面的"自动分析"）：
//   ida_open_file → "工具调用失败: IDA 未能切换到目标文件"
// 根因不是 .sys 难打开，而是**这条路径从来不检查 IDA 有没有在跑**：
// 界面按钮走 launchTool('ida') 会先拉起 IDA，工具循环里的 ida_open_file 直接调 open_file，
// IDA 没运行时必然失败，模型据此判定"本机没有 IDA"转去手工分析。
//
// 这里锁两件事：
//   ① ensureIdaProcessForTool 的三条分支（已在跑 / 未配置 / 拉起后等端口）
//   ② idaReloadAndWait 里 ensure 必须发生在 open_file 之前（顺序错了等于没修）
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// 从 main.js 抽出这两个函数（它们依赖模块作用域的 config/spawnArgv/hardenEditorConfigs，
// 用 new Function 把依赖当参数注入，避免为了测试把 main.js 拆开）
function grabFn(name) {
  let idx = mainSrc.indexOf('function ' + name + '(');
  if (idx < 0) throw new Error('未找到 function ' + name);
  // async 前缀在 "function" 之前，丢掉会得到 Unexpected identifier（awaits 只能出现在 async 里）
  if (mainSrc.slice(Math.max(0, idx - 6), idx) === 'async ') idx -= 6;
  let i = mainSrc.indexOf('{', idx);
  let depth = 0, inS = null, esc = false;
  for (let j = i; j < mainSrc.length; j++) {
    const c = mainSrc[j];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return mainSrc.slice(idx, j + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

const code = grabFn('probeTcpPort') + '\n' + grabFn('ensureIdaProcessForTool');
const make = (config, spawnArgv, hardenEditorConfigs) => new Function(
  'config', 'spawnArgv', 'hardenEditorConfigs', 'fs', 'path', 'require',
  code + '\nreturn { probeTcpPort, ensureIdaProcessForTool };'
)(config, spawnArgv, hardenEditorConfigs || (() => {}), fs, path, require);

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

(async () => {
  console.log('[1] probeTcpPort 能真实分辨"在监听 / 没监听"');
  {
    const srv = net.createServer();
    await new Promise(r => srv.listen(0, '127.0.0.1', r));
    const livePort = srv.address().port;
    const deadPort = await freePort();
    const { probeTcpPort } = make({ tools: {}, mcp: {} }, async () => ({ success: true }));

    ok(await probeTcpPort('127.0.0.1', livePort, 800) === true, '监听中的端口 → true');
    ok(await probeTcpPort('127.0.0.1', deadPort, 800) === false, '未监听的端口 → false');
    await new Promise(r => srv.close(r));
  }

  console.log('\n[2] IDA 已在跑 → 不重复拉起');
  {
    const srv = net.createServer();
    await new Promise(r => srv.listen(0, '127.0.0.1', r));
    const livePort = srv.address().port;
    let spawns = 0;
    const { ensureIdaProcessForTool } = make(
      { tools: { ida: 'C:\\fake\\ida64.exe' }, mcp: { ida: `http://127.0.0.1:${livePort}/mcp` } },
      async () => { spawns++; return { success: true }; }
    );
    const r = await ensureIdaProcessForTool('C:\\t\\a.sys', 20000);
    ok(r.ok === true && r.already === true, '判为"已在运行"', JSON.stringify(r).slice(0, 120));
    ok(spawns === 0, '没有重复启动 IDA');
    await new Promise(r2 => srv.close(r2));
  }

  console.log('\n[3] IDA 没配路径 → 明确说清"去设置里填"，而不是含糊失败');
  {
    const deadPort = await freePort();
    const { ensureIdaProcessForTool } = make(
      { tools: { ida: '' }, mcp: { ida: `http://127.0.0.1:${deadPort}/mcp` } },
      async () => { throw new Error('不该走到启动'); }
    );
    const r = await ensureIdaProcessForTool('C:\\t\\a.sys', 15000);
    ok(r.ok === false, '如实报失败');
    const text = r.lines.join('\n');
    ok(/设置/.test(text) && /ida64\.exe/i.test(text), '告诉用户去设置页填 IDA 路径', text.slice(0, 200));
    ok(/未监听/.test(text), '说清是端口没起来（不是文件打不开）', text.slice(0, 200));
  }

  console.log('\n[4] IDA 没在跑 → 自动拉起，并等到端口就绪');
  {
    const deadPort = await freePort();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-ida-'));
    const fakeExe = path.join(tmpDir, 'ida64.exe');
    fs.writeFileSync(fakeExe, 'x');
    let seenArgv = null;
    let srv = null;
    const { ensureIdaProcessForTool } = make(
      { tools: { ida: fakeExe }, mcp: { ida: `http://127.0.0.1:${deadPort}/mcp` } },
      async (argv, opts) => {
        seenArgv = { argv, opts };
        // 模拟 IDA 冷启动后 MCP 端口开始监听
        setTimeout(() => {
          srv = net.createServer();
          srv.listen(deadPort, '127.0.0.1');
        }, 300);
        return { success: true };
      }
    );
    const r = await ensureIdaProcessForTool('C:\\t\\a.sys', 20000);
    ok(r.ok === true && r.launched === true, '拉起后等到端口就绪', JSON.stringify(r).slice(0, 160));
    ok(!!seenArgv, '确实启动了进程');
    ok(seenArgv && seenArgv.argv[0] === fakeExe, '启动的是设置里的 IDA 路径', JSON.stringify(seenArgv && seenArgv.argv));
    ok(seenArgv && seenArgv.argv.includes('-A'), '带 -A 自主模式（否则冷启动弹框挡住插件自启）');
    ok(seenArgv && seenArgv.argv.includes('C:\\t\\a.sys'), '把目标文件一起传进去');
    ok(seenArgv && seenArgv.opts && seenArgv.opts.gui === true, '以 GUI 方式启动（需要可见窗口）');
    ok(/已自动启动/.test(r.lines.join('\n')), '日志里说明"是自动启动的"', r.lines.join('\n').slice(0, 160));
    if (srv) await new Promise(r2 => srv.close(r2));
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { /* 清理失败不影响结论 */ }
  }

  console.log('\n[5] 拉起后端口一直不起来 → 说清可能原因（不让模型瞎猜）');
  {
    const deadPort = await freePort();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-ida2-'));
    const fakeExe = path.join(tmpDir, 'ida64.exe');
    fs.writeFileSync(fakeExe, 'x');
    const { ensureIdaProcessForTool } = make(
      { tools: { ida: fakeExe }, mcp: { ida: `http://127.0.0.1:${deadPort}/mcp` } },
      async () => ({ success: true })
    );
    const r = await ensureIdaProcessForTool('C:\\t\\a.sys', 15000);
    ok(r.ok === false, '超时如实报失败');
    const text = r.lines.join('\n');
    ok(/插件/.test(text), '点出"MCP 插件未加载"这个最常见原因', text.slice(0, 240));
    ok(/仍未监听/.test(text), '说清是端口没起来');
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { /* 同上 */ }
  }

  console.log('\n[6] 结构性断言：ensure 必须发生在 open_file 之前');
  {
    const iEnsure = mainSrc.indexOf("ensureIdaProcessForTool(filePath");
    const iOpen = mainSrc.indexOf("idaMcpCallTool('open_file'");
    ok(iEnsure > 0, 'idaReloadAndWait 里调用了 ensureIdaProcessForTool');
    ok(iOpen > iEnsure && iEnsure > 0, 'ensure 在 open_file 之前（顺序错了等于没修）', `${iEnsure} vs ${iOpen}`);
    ok(!/请先启动 IDA（并确认 MCP 端口可达）/.test(mainSrc.split('ensureIdaProcessForTool(filePath')[0].slice(-2000)),
      '失败提示不再默认要求用户手动启动 IDA');
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})();
