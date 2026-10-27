// 手工验收：Kali linux_server 远程调试（需 Kali 可达、有可执行的 linux_server）。
// 覆盖：编译/下载 PIE 目标 → 等 23946 LISTEN → start(remote) → 自动 suspend →
//       重定位符号 → idaapi.add_bpt → continue 命中 main → 单步 →
//       continue 命中 check → 读写内存。期望 RESULT=PASS (11/11)。
// 跑法：node tests/manual_dbg_remote.js
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { Client } = require('ssh2');

const IDA = 'E:\\ctf\\tools\\1-Reverse\\IDA9.1\\ida.exe';
const PORT = 13337;
// 凭据一律从环境变量读，绝不写进仓库（历史版本曾硬编码，已清理）。
const HOST = process.env.KALI_HOST || '127.0.0.1';
const SSH_PORT = Number(process.env.KALI_PORT) || 22;
const USER = process.env.KALI_USER || '';
const PASS = process.env.KALI_PASS || '';
if (!USER || !PASS) {
  console.error('缺少凭据：请先设置 KALI_HOST / KALI_USER / KALI_PASS 环境变量');
  process.exit(2);
}
const log = [];
const say = (s) => { log.push(s); console.log(s); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let sessionId = null;
const hdr = () => (sessionId ? { 'Mcp-Session-Id': sessionId } : {});
function post(method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || {} });
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/mcp?ext=dbg', method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Content-Length': Buffer.byteLength(body) }, hdr()), timeout: 120000 },
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
  try { return JSON.parse(text); } catch (e) { return text; }
}
async function initSession() {
  const r = await post('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'ctf-tool', version: '1.0' } });
  sessionId = (r.headers && r.headers['mcp-session-id']) || null;
  const body = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' });
  await new Promise((resolve) => { const req = http.request({ host: '127.0.0.1', port: PORT, path: '/mcp?ext=dbg', method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, hdr()) }, (res) => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.write(body); req.end(); });
}
function ssh(cmd, timeout = 90000) {
  return new Promise((resolve) => {
    const c = new Client();
    let out = '', err = '';
    const t = setTimeout(() => { try { c.end(); } catch (e) { } resolve({ ok: false, code: -1, out, err, error: 'timeout' }); }, timeout);
    c.on('ready', () => { c.exec(cmd, (e, s) => { if (e) { clearTimeout(t); c.end(); return resolve({ ok: false, code: -1, out, err, error: e.message }); }
      s.on('data', d => out += d); s.stderr.on('data', d => err += d);
      s.on('close', (code) => { clearTimeout(t); c.end(); resolve({ ok: code === 0, code, out, err }); }); }); });
    c.on('error', (e) => { clearTimeout(t); resolve({ ok: false, code: -1, out, err, error: e.message }); });
    c.connect({ host: HOST, port: SSH_PORT, username: USER, password: PASS, readyTimeout: 20000, hostVerifier: () => true });
  });
}
function sftpGet(remote, local) {
  return new Promise((resolve) => {
    const c = new Client();
    c.on('ready', () => { c.sftp((e, sftp) => { if (e) { c.end(); return resolve({ ok: false, error: e.message }); }
      sftp.fastGet(remote, local, (e2) => { c.end(); resolve(e2 ? { ok: false, error: e2.message } : { ok: true }); }); }); });
    c.on('error', (e) => resolve({ ok: false, error: e.message }));
    c.connect({ host: HOST, port: SSH_PORT, username: USER, password: PASS, readyTimeout: 20000, hostVerifier: () => true });
  });
}
async function killIda() {
  try { execSync('powershell -NoProfile -Command "Stop-Process -Name ida -Force -ErrorAction SilentlyContinue"', { stdio: 'ignore', windowsHide: true, timeout: 30000 }); } catch (e) { }
  const dl = Date.now() + 60000;
  while (Date.now() < dl) { if (!(await portOpen())) return true; await sleep(1000); }
  return false;
}
async function state() {
  try {
    const r = await raw('py_eval', { code: 'import idaapi, ida_dbg\nprint("ON", ida_dbg.is_debugger_on())\nprint("STATE", idaapi.get_process_state())' });
    const t = String((r && r.stdout) || '');
    const m = /STATE (-?\d+)/.exec(t);
    return { on: /ON True/.test(t), state: m ? +m[1] : null };
  } catch (e) { return { on: false, state: null }; }
}
async function regsIp() {
  try { const r = await raw('dbg_regs', {}); const a = (r && r.registers) || []; const h = a.find(x => /^(rip|eip)$/i.test(x.name)); return h ? h.value : null; }
  catch (e) { return null; }
}
async function waitState(want, timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) { const s = await state(); if (s.state === want) return true; await sleep(250); }
  return false;
}
async function ensureServer() {
  // 反复确认端口 LISTEN：只 sleep 一次不够（实测 RC=0 就是连太早）
  for (let i = 0; i < 10; i++) {
    const r = await ssh("ss -ln 2>/dev/null | grep -c 23946 || echo 0", 15000);
    if (String(r.out || '').trim() !== '0') return true;
    await sleep(700);
  }
  return false;
}

(async () => {
  const R = [];
  const mark = (n, ok, d) => { R.push({ n, ok }); say((ok ? '  ✅ ' : '  ❌ ') + n + (d ? ' — ' + d : '')); };
  const tag = Date.now();
  const remoteElf = '/tmp/st_' + tag;
  try {
    say('=== 1. 编译 + 下载 ===');
    // 关键设计：main 先 sleep(4) 再调 check。
    // 这样调试器有 ~4 秒窗口完成 attach → suspend → 下断点 → continue，
    // 断点才可能在 check 真正被调用时命中。
    // （之前 usleep(1.5s) 的目标在设断点前就跑过了 check，表现为
    //   read_regs => -1 / continue 失败，很容易误判成"远程断点不可用"。）
    const src = '#include <unistd.h>\n#include <stdio.h>\n__attribute__((noinline)) int check(int v){ volatile int r=v*3+7; return r; }\nint main(void){ volatile int x=0x1234; sleep(4); int y=check(x); printf("Y %d\\n",y); fflush(stdout); sleep(120); return 0; }\n';
    const b64 = Buffer.from(src, 'utf8').toString('base64');
    const cc = await ssh(`echo ${b64} | base64 -d > ${remoteElf}.c && gcc -g -O0 -o ${remoteElf} ${remoteElf}.c && echo COMPILED`, 90000);
    mark('编译', /COMPILED/.test(cc.out || ''));
    const localElf = path.join(os.tmpdir(), 'st_' + tag);
    const got = await sftpGet(remoteElf, localElf);
    mark('下载', got.ok, got.error || path.basename(localElf));

    say('\n=== 2. linux_server（等 LISTEN）===');
    await ssh("pkill -f linux_server 2>/dev/null; sleep 1; echo ok", 15000);
    await ssh(`setsid /tmp/linux_server -P${PASS} -v > /tmp/ls6.log 2>&1 < /dev/null & echo SPAWNED`, 20000);
    const listenOk = await ensureServer();
    mark('linux_server 就绪', listenOk);

    say('\n=== 3. 打开 ELF ===');
    await killIda();
    spawn(IDA, ['-A', localElf], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
    const dl = Date.now() + 180000;
    let up = false;
    while (Date.now() < dl) { await sleep(3000); if (await portOpen()) { up = true; break; } }
    if (!up) { say('RESULT=FAIL no-mcp'); return; }
    await initSession();
    await sleep(9000);

    say('\n=== 4. 连接远程 + start ===');
    let rc = null;
    for (let attempt = 0; attempt < 3 && rc !== 1; attempt++) {
      if (attempt > 0) { say('  重试 ' + attempt); await sleep(1500); }
      const conn = await raw('py_eval', { code: [
        'import ida_dbg, idaapi',
        'try: ida_dbg.set_remote_debugger("","",-1)',
        'except Exception: pass',
        'print("LOAD", ida_dbg.load_debugger("linux", True))',
        `ida_dbg.set_remote_debugger(${JSON.stringify(HOST)}, ${JSON.stringify(PASS)}, 23946)`,
        `print("RC", idaapi.start_process(${JSON.stringify(remoteElf)}, "", ""))`,
      ].join('\n') });
      const co = String((conn && conn.stdout) || '');
      say('  ' + co.trim().replace(/\n/g, ' | '));
      rc = Number((/RC\s+(-?\d+)/.exec(co) || [])[1]);
      if (rc !== 1) await ensureServer();
    }
    mark('远程 start（RC=1）', rc === 1, 'RC=' + rc);

    say('\n=== 5. 立刻 suspend（此时 main 正在 sleep(4)）===');
    // 不要 sleep 后再 suspend：目标要尽快固定住，否则 4 秒窗口会被浪费掉
    try { await raw('py_eval', { code: 'import ida_dbg\nprint("SUSP", ida_dbg.suspend_process())' }); } catch (e) { }
    const paused = await waitState(-1, 10000);
    const s0 = await state();
    mark('进入暂停态', paused, 'state=' + s0.state + ' on=' + s0.on);

    say('\n=== 6. 重定位符号 + 下断点（idaapi.add_bpt）===');
    const sym = await raw('py_eval', { code: [
      'import idaapi',
      'print("IMAGEBASE", hex(idaapi.get_imagebase()))',
      'for n in ("main","check"):',
      '    print("SYM", n, hex(idaapi.get_name_ea(idaapi.BADADDR, n)))',
    ].join('\n') });
    const so = String((sym && sym.stdout) || '');
    say('  ' + so.trim().replace(/\n/g, ' | '));
    const mainEa = (/SYM main (0x[0-9a-fA-F]+)/.exec(so) || [])[1];
    const checkEa = (/SYM check (0x[0-9a-fA-F]+)/.exec(so) || [])[1];

    const bps = await raw('py_eval', { code: [
      'import idaapi',
      `print("BP_MAIN", idaapi.add_bpt(${mainEa}, 0, idaapi.BPT_SOFT))`,
      `print("BP_CHECK", idaapi.add_bpt(${checkEa}, 0, idaapi.BPT_SOFT))`,
      'print("QTY", idaapi.get_bpt_qty())',
    ].join('\n') });
    const bo = String((bps && bps.stdout) || '');
    say('  ' + bo.trim().replace(/\n/g, ' | '));
    mark('断点已设置', /QTY 2/.test(bo), 'main=' + mainEa + ' check=' + checkEa);

    say('\n=== 7. continue → 命中 main ===');
    try { await raw('dbg_continue', {}); } catch (e) { say('  ' + e.message.slice(0, 70)); }
    const hitA = await waitState(-1, 10000);
    const ripA = await regsIp();
    mark('命中 main', hitA && String(ripA).toLowerCase() === String(mainEa).toLowerCase(), 'RIP=' + ripA);

    if (hitA) {
      say('\n=== 8. 单步 ===');
      try { await raw('dbg_step_over', {}); } catch (e) { say('  ' + e.message.slice(0, 70)); }
      await sleep(700);
      const ripB = await regsIp();
      mark('单步 IP 前进', !!ripB && ripA !== ripB, ripA + ' → ' + ripB);

      say('\n=== 9. continue → 命中 check ===');
      try { await raw('dbg_continue', {}); } catch (e) { say('  ' + e.message.slice(0, 70)); }
      const hitB = await waitState(-1, 10000);
      const ripC = await regsIp();
      mark('命中 check', hitB && String(ripC).toLowerCase() === String(checkEa).toLowerCase(), 'RIP=' + ripC);

      say('\n=== 10. 读写内存 ===');
      try {
        const rd = await raw('dbg_read', { regions: [{ addr: ripC || ripA, size: 16 }] });
        const hex = String(JSON.stringify(rd)).match(/[0-9a-f]{32}/i);
        mark('读内存', !!hex, (hex && hex[0]) || '');
      } catch (e) { mark('读内存', false, e.message.slice(0, 80)); }
      try {
        const regs = await raw('dbg_regs', {});
        const arr = (regs && regs.registers) || [];
        const rsp = (arr.find(x => /^rsp$/i.test(x.name)) || {}).value;
        const target = '0x' + (parseInt(rsp, 16) - 0x100).toString(16);
        const payload = '4142434445464748494a4b4c4d4e4f50';
        await raw('dbg_write', { regions: [{ addr: target, data: payload }] });
        const rd = await raw('dbg_read', { regions: [{ addr: target, size: 16 }] });
        const got = String(JSON.stringify(rd)).match(/[0-9a-f]{32}/i);
        mark('写内存并读回', !!got && got[0].toLowerCase() === payload.toLowerCase(), target + ' → ' + (got && got[0]));
      } catch (e) { mark('写内存', false, e.message.slice(0, 80)); }
    }

    say('\n=== 11. 服务器日志 ===');
    const lg = await ssh('tail -15 /tmp/ls6.log', 15000);
    say((lg.out || '').trim().split('\n').slice(-10).join('\n'));

    const okCount = R.filter(x => x.ok).length;
    say('\nRESULT=' + (okCount === R.length ? 'PASS' : 'PARTIAL') + ' (' + okCount + '/' + R.length + ')');
  } catch (e) { say('RESULT=FAIL ' + e.message); }
  finally {
    try { await raw('dbg_exit', {}); } catch (e) { }
    await killIda();
    try { await ssh(`pkill -f linux_server 2>/dev/null; pkill -f st_${tag} 2>/dev/null; rm -f ${remoteElf} ${remoteElf}.c; echo cleaned`, 15000); } catch (e) { }
    fs.writeFileSync(path.join(__dirname, '_remote_stable.txt'), log.join('\n'), 'utf8');
    process.exit(0);
  }
})();
