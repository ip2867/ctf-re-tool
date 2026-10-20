// 手工验收：本地 PE 动态调试（需本机 IDA 9.x）。
// 覆盖：start 幂等 / 真暂停 / status / 单步 / run_to / continue 异步轮询 /
//       suspend / 暂停态写内存 / exit。期望 RESULT=PASS (10/10)。
// 跑法：node tests/manual_dbg_local.js
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

const SAMPLE = 'E:\\ctf\\pratice\\ai\\CrackMe3\\02da357b-0bce-4ff2-b2b3-d1c7e4e73fe8_x\\CrackMe3\\CrackMe.exe';
const IDA = 'E:\\ctf\\tools\\1-Reverse\\IDA9.1\\ida.exe';
const PORT = 13337;
const log = [];
const say = (s) => { log.push(s); console.log(s); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let sessionId = null;
const hdr = () => (sessionId ? { 'Mcp-Session-Id': sessionId } : {});

function post(method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || {} });
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/mcp?ext=dbg', method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Content-Length': Buffer.byteLength(body) }, hdr()), timeout: 90000 },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => {
        const lines = d.split('\n').filter(l => l.startsWith('data: '));
        const payload = lines.length ? lines.map(l => l.slice(6)).join('') : d;
        let j; try { j = JSON.parse(payload); } catch (e) { j = { _raw: d }; }
        resolve({ json: j, headers: res.headers }); }); });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject); req.write(body); req.end();
  });
}
function portOpen() { return new Promise((resolve) => { const req = http.get(`http://127.0.0.1:${PORT}/`, () => { req.destroy(); resolve(true); }); req.setTimeout(1200, () => { req.destroy(); resolve(false); }); req.on('error', () => resolve(false)); }); }
async function raw(name, args) {
  const r = await post('tools/call', { name, arguments: args || {} });
  const res = (r.json && r.json.result) || {};
  const text = Array.isArray(res.content) ? res.content.map(c => c.text || '').join('\n') : '';
  if (res.isError) throw new Error('[' + name + '] ' + text.slice(0, 300));
  // py_eval 返回 {result, stdout, stderr}，其它工具返回裸 JSON
  try { return JSON.parse(text); } catch (e) { return text; }
}
async function initSession() {
  const r = await post('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'ctf-tool', version: '1.0' } });
  sessionId = (r.headers && r.headers['mcp-session-id']) || null;
  const body = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' });
  await new Promise((resolve) => { const req = http.request({ host: '127.0.0.1', port: PORT, path: '/mcp?ext=dbg', method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, hdr()) }, (res) => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.write(body); req.end(); });
}

const { buildDbgCall, dbgStateName } = require('../electron/ida-dbg');

async function readState() {
  const r = await raw('py_eval', { code: 'import idaapi, ida_dbg\nprint("ON", ida_dbg.is_debugger_on())\nprint("STATE", idaapi.get_process_state())' });
  const t = String((r && r.stdout) || '');
  const m = /STATE\s+(-?\d+)/.exec(t);
  return { on: /ON\s+True/.test(t), state: m ? +m[1] : null };
}
async function waitStop(timeoutMs, intervalMs = 250, startupGraceMs = 0) {
  const t0 = Date.now(); let last = null;
  while (Date.now() - t0 < timeoutMs) {
    const cur = await readState(); last = cur;
    if (!cur.on) {
      if (Date.now() - t0 < startupGraceMs) { await sleep(intervalMs); continue; }
      return { stopped: true, state: 0, reason: 'no-process', waitedMs: Date.now() - t0 };
    }
    if (cur.state === -1) return { stopped: true, state: -1, reason: 'suspended', waitedMs: Date.now() - t0 };
    if (cur.state === 2) return { stopped: true, state: 2, reason: 'exited', waitedMs: Date.now() - t0 };
    await sleep(intervalMs);
  }
  return { stopped: false, state: last && last.state, reason: 'still-running', waitedMs: Date.now() - t0 };
}
async function ip() {
  try { const r = await raw('dbg_regs', {}); const a = (r && r.registers) || []; const h = a.find(x => /^(eip|rip)$/i.test(x.name)); return h ? h.value : null; } catch (e) { return null; }
}
async function prod(action, input) {
  const call = buildDbgCall(action, Object.assign({ action }, input || {}), {
    targetKind: 'PE', remoteAvailable: true, remoteHost: '192.168.230.129', remotePort: 23946, remotePass: '200512',
  });
  if (call.error) return { __paramError: call.error };
  const r = await raw(call.tool, call.args);
  return { call, r };
}

(async () => {
  const R = [];
  const mark = (n, ok, d) => { R.push({ n, ok }); say((ok ? '  ✅ ' : '  ❌ ') + n + (d ? ' — ' + d : '')); };
  try {
    try { execSync('powershell -NoProfile -Command "Stop-Process -Name ida -Force -ErrorAction SilentlyContinue"', { stdio: 'ignore' }); } catch (e) { }
    await sleep(2000);
    spawn(IDA, ['-A', SAMPLE], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
    const dl = Date.now() + 180000;
    let up = false;
    while (Date.now() < dl) { await sleep(3000); if (await portOpen()) { up = true; break; } }
    say('MCP 就绪=' + up);
    if (!up) { say('RESULT=FAIL'); return; }
    await initSession();
    await sleep(10000);

    say('\n=== 1. start + 等真暂停（新逻辑）===');
    const s1 = await prod('start', {});
    const out1 = String((s1.r && s1.r.stdout) || '');
    const already1 = /ALREADY_RUNNING True/.test(out1);
    say('  stdout=' + JSON.stringify(out1));
    const w1 = await waitStop(already1 ? 3000 : 20000, 250, 1500);
    const ip1 = await ip();
    say('  wait=' + JSON.stringify(w1) + ' ip=' + ip1);
    mark('start 后确实进入暂停态', w1.reason === 'suspended', 'reason=' + w1.reason + ' state=' + w1.state);
    mark('暂停在用户代码入口区', !!ip1 && parseInt(ip1, 16) >= 0x400000 && parseInt(ip1, 16) < 0x410000, 'EIP=' + ip1);

    say('\n=== 2. 幂等 start ===');
    const s2 = await prod('start', {});
    const out2 = String((s2.r && s2.r.stdout) || '');
    say('  stdout=' + JSON.stringify(out2));
    mark('重复 start 识别为 ALREADY_RUNNING', /ALREADY_RUNNING True/.test(out2));

    say('\n=== 3. status py 代码可解析 ===');
    const s3 = await prod('status', {});
    const t3 = String((s3.r && s3.r.stdout) || '');
    say('  stdout=' + JSON.stringify(t3));
    const m3 = /STATE\s+(-?\d+)/.exec(t3);
    mark('status 输出含 STATE 与 IP', !!m3 && /IP\s+0x/.test(t3),
      'state=' + (m3 ? m3[1] : 'n/a') + ' → ' + (m3 ? dbgStateName(+m3[1]) : 'n/a'));

    say('\n=== 4. 单步 ===');
    const a0 = await ip();
    const so = await prod('step_over', {}).catch(e => ({ err: e.message }));
    if (so.err) say('  step_over 报错: ' + so.err.slice(0, 100));
    else say('  step_over → ' + JSON.stringify(so.r).slice(0, 150));
    await sleep(300);
    const a1 = await ip();
    mark('单步后 IP 前进', !!a0 && !!a1 && a0 !== a1, a0 + ' → ' + a1);

    say('\n=== 5. run_to 到指令边界 ===');
    // 0x4012d3 是 0x4012d1 那条 mov 之后的真实指令边界（已实测可达）；
    // 0x4012d6 落在指令中间，run_to 会跑飞，不能用。
    const rt = await prod('run_to', { addr: '0x4012d3' });
    say('  ' + JSON.stringify(rt.r).slice(0, 200));
    const w5 = await waitStop(6000);
    const ip5 = await ip();
    say('  wait=' + JSON.stringify(w5) + ' ip=' + ip5);
    mark('run_to 后停在目标地址', w5.reason === 'suspended' && String(ip5).toLowerCase() === '0x4012d3', 'EIP=' + ip5);

    say('\n=== 6. continue → GUI 消息循环（预期 running，非报错）===');
    const ct = await prod('continue', {}).catch(e => ({ err: e.message }));
    if (ct.err) say('  continue 报错: ' + ct.err.slice(0, 80));
    const w6 = await waitStop(3000);
    say('  wait=' + JSON.stringify(w6) + ' ip=' + await ip());
    mark('continue 后能识别 running/still-running', w6.reason === 'still-running' || w6.reason === 'exited',
      'reason=' + w6.reason);

    say('\n=== 7. suspend 拉回暂停态 ===');
    const sp = await prod('suspend', {});
    const t7 = String((sp.r && sp.r.stdout) || '');
    say('  stdout=' + JSON.stringify(t7));
    const w7 = await waitStop(5000);
    const ip7 = await ip();
    say('  wait=' + JSON.stringify(w7) + ' ip=' + ip7);
    mark('suspend 后进入暂停态', w7.reason === 'suspended', 'state=' + w7.state + ' EIP=' + ip7);

    say('\n=== 8. 暂停态写内存 ===');
    if (w7.reason === 'suspended') {
      const regs = await raw('dbg_regs', {});
      const arr = (regs && regs.registers) || [];
      const esp = (arr.find(x => /^esp$/i.test(x.name)) || {}).value;
      if (esp) {
        const target = '0x' + (parseInt(esp, 16) - 0x200).toString(16);
        const payload = '4142434445464748494a4b4c4d4e4f50';
        const w = await prod('mem_write', { regions: [{ addr: target, data: payload }] });
        const rd = await prod('mem_read', { regions: [{ addr: target, size: 16 }] });
        const got = String(JSON.stringify(rd.r)).match(/[0-9a-f]{32}/i);
        say('  write=' + JSON.stringify(w.r).slice(0, 140));
        mark('写内存并精确读回', !!got && got[0].toLowerCase() === payload.toLowerCase(), target + ' → ' + (got && got[0]));
      }
    }

    say('\n=== 9. exit ===');
    try { await prod('exit', {}); } catch (e) { }
    await sleep(500);
    const s9 = await readState();
    say('  ' + JSON.stringify(s9));
    mark('exit 后调试器关闭', !s9.on);

    const okCount = R.filter(x => x.ok).length;
    say('\nRESULT=' + (okCount === R.length ? 'PASS' : 'PARTIAL') + ' (' + okCount + '/' + R.length + ')');
  } catch (e) {
    say('RESULT=FAIL ' + e.message);
  } finally {
    try { await raw('dbg_exit', {}); } catch (e) { }
    try { execSync('powershell -NoProfile -Command "Stop-Process -Name ida -Force -ErrorAction SilentlyContinue"', { stdio: 'ignore', timeout: 15000 }); } catch (e) { }
    fs.writeFileSync(path.join(__dirname, '_dbg_semantics.txt'), log.join('\n'), 'utf8');
    process.exit(0);
  }
})();
