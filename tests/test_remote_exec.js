// 远程执行工具单测：错误分类必须可操作，且失败必须是错误（空 stdout 不是成功）。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { classifyRemoteError, REMOTE_PREFIXES } = require('../electron/remote-exec.js');
const { toToolResult } = require('../electron/tool-result.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] classifyRemoteError');
{
  const t = classifyRemoteError({
    success: false, error: 'Timed out while waiting for handshake', host: '192.168.230.129', port: 22,
  });
  ok(t.code === 'REMOTE_TIMEOUT', `握手超时 → REMOTE_TIMEOUT（${t.code}）`);
  ok(t.message.includes('192.168.230.129:22'), `消息含 host:port（${t.message}）`);
  ok(t.isError === true, 'isError=true');

  const a = classifyRemoteError({ success: false, error: 'All configured authentication methods failed', host: 'h', port: 22 });
  ok(a.code === 'REMOTE_AUTH', `认证失败 → REMOTE_AUTH（${a.code}）`);

  const r = classifyRemoteError({ success: false, error: 'connect ECONNREFUSED 127.0.0.1:22', host: '127.0.0.1', port: 22 });
  ok(r.code === 'REMOTE_REFUSED', `ECONNREFUSED → REMOTE_REFUSED（${r.code}）`);

  const u = classifyRemoteError({ host: '' });
  ok(u.code === 'REMOTE_UNCONFIGURED', `空 host → REMOTE_UNCONFIGURED（${u.code}）`);
  ok(u.isError === true, '未配置也是错误');

  // 空 stdout + 非零退出码必须是错误
  const e = classifyRemoteError({ success: true, stdout: '', exitCode: 1, host: 'h', port: 22 });
  ok(e.isError === true, 'exitCode≠0 即使 success=true 也是错误');
  const okr = classifyRemoteError({ success: true, stdout: 'ok', exitCode: 0, host: 'h', port: 22 });
  ok(okr.isError === false, '正常退出 → 非错误');
}

console.log('\n[2] 固定前缀被 tool-result 识别为失败');
{
  for (const p of ['REMOTE_TIMEOUT', 'REMOTE_AUTH', 'REMOTE_REFUSED', 'REMOTE_UNCONFIGURED']) {
    const msg = classifyRemoteError({
      host: 'h', port: 22, success: false,
      error: p === 'REMOTE_TIMEOUT' ? 'Timed out while waiting for handshake'
        : p === 'REMOTE_AUTH' ? 'All configured authentication methods failed'
          : 'connect ECONNREFUSED',
    }).message;
    const tr = toToolResult(msg);
    ok(tr.isError === true, `${p} 被识别为 isError（${JSON.stringify(tr).slice(0, 120)}）`);
  }
}

console.log('\n[3] 源码接线：schema / dispatch / KNOWN / MAP / toolLabel / precheck');
{
  const def = mainSrc.slice(mainSrc.indexOf('name: "remote_exec"'), mainSrc.indexOf('name: "remote_exec"') + 900);
  ok(/name: "remote_exec"/.test(def), 'schema 存在');
  ok(/host: \{ type: "string", enum: \["kali", "local"\]/.test(def), 'host 枚举 kali/local');
  ok(/timeout_ms/.test(def), 'schema 含 timeout_ms');
  ok(/case 'remote_exec':/.test(mainSrc), "dispatch 含 case 'remote_exec'");
  const known = mainSrc.slice(mainSrc.indexOf('const KNOWN = new Set(['), mainSrc.indexOf('const KNOWN = new Set([') + 1400);
  ok(/'remote_exec'/.test(known), 'KNOWN 含 remote_exec');
  const map = mainSrc.slice(mainSrc.indexOf('const MAP = {'), mainSrc.indexOf('const MAP = {') + 1000);
  ok(/remote_exec: 'command'/.test(map), "MAP 含 remote_exec → 'command'");
  const label = mainSrc.slice(mainSrc.indexOf('function toolLabel'), mainSrc.indexOf('// 执行命令（渲染层'));
  ok(/case 'remote_exec'/.test(label), 'toolLabel 含 remote_exec');
  const pre = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'), mainSrc.indexOf('function levenshtein'));
  ok(/name === 'remote_exec'/.test(pre), 'precheck 含 remote_exec');
  ok(/缺少必填参数 command/.test(pre), 'precheck 给出 command 必填提示');
  ok(/async function remoteExecTool\(input\)/.test(mainSrc), 'remoteExecTool 存在');
  ok(/execCommandAsync\(/.test(mainSrc.slice(mainSrc.indexOf('async function remoteExecTool'), mainSrc.indexOf('async function remoteExecTool') + 2500))
    || /exec\(cmd, \{ timeout: timeoutMs/.test(mainSrc), 'local 走本地 shell');
  ok(/sshExec\(cmd, timeoutMs\)/.test(mainSrc), 'kali 走 sshExec');
}

console.log('\n[4] 真实 local 调用 echo ok');
{
  const r = spawnSync(process.platform === 'win32' ? 'cmd' : 'sh',
    process.platform === 'win32' ? ['/c', 'echo ok'] : ['-c', 'echo ok'], { encoding: 'utf8' });
  ok(r.status === 0 && /ok/.test(r.stdout), `本地 echo ok 可用（${String(r.stdout).trim()}）`);
  // remoteExecTool 的 local 分支走 exec；这里只验证等价命令能返回 ok（不启动 Electron）
  ok(/if \(host === 'local'\)/.test(mainSrc), 'local 分支存在');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
