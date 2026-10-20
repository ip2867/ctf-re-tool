// linux_server 启动命令与日志分类的单测
const { buildLinuxServerCommand, classifyLinuxServerLog } = require('../electron/remote-exec.js');
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8').replace(/\r\n/g, '\n');
const dbgSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'ida-dbg.js'), 'utf8').replace(/\r\n/g, '\n');

console.log('[1] linux_server 启动命令');
{
  const r = buildLinuxServerCommand({ path: '/tmp/linux_server', password: 'ctf123' });
  ok(!r.error, '生成命令成功', r.error);
  // 必须 setsid：普通 nohup/& 会随 SSH 会话关闭被杀（实测）
  ok(/^setsid /.test(r.command), '以 setsid 开头（脱离 SSH 会话）', r.command);
  ok(/< \/dev\/null/.test(r.command), 'stdin 重定向到 /dev/null');
  ok(/& echo LINUX_SERVER_SPAWNED/.test(r.command), '后台执行并回显标记');
  // IDA 的密码参数是紧贴形式 -P<pw>
  ok(/ -Pctf123/.test(r.command), 'password 用 -P<pass> 紧贴形式', r.command);
  ok(!/ -P ctf123/.test(r.command), '不是 -P <pass> 分离形式');

  const noPass = buildLinuxServerCommand({ path: '/tmp/linux_server' });
  ok(!noPass.error && !/-P/.test(noPass.command), '无密码时不加 -P');

  ok(/ss -ln/.test(r.verifyCommand) && /23946/.test(r.verifyCommand), 'verifyCommand 检查 23946');
  ok(/netstat/.test(r.verifyCommand), 'verifyCommand 兼容 netstat');
  ok(/pkill -f 'linux_server'/.test(r.stopCommand), 'stopCommand 用 pkill');
}

console.log('\n[2] 命令注入防护');
{
  ok(!!buildLinuxServerCommand({ path: '/tmp/x; rm -rf /' }).error, '路径含分号被拒');
  ok(!!buildLinuxServerCommand({ path: '/tmp/x$(id)' }).error, '路径含 $() 被拒');
  ok(!!buildLinuxServerCommand({ path: '/tmp/a b' }).error, '路径含空格被拒');
  ok(!!buildLinuxServerCommand({ path: '/tmp/x', password: 'a;b' }).error, '密码含分号被拒');
  ok(!buildLinuxServerCommand({ path: '/tmp/x', password: 'a@b#c%+.-' }).error, '安全字符集允许');
}

console.log('\n[3] 日志状态分类');
{
  ok(classifyLinuxServerLog('Listening on :::23946 (my ip 1.2.3.4)...').state === 'listening', 'listening');
  ok(classifyLinuxServerLog('Accepting connection from ::ffff:1.2.3.4...').state === 'connected', 'connected');
  ok(classifyLinuxServerLog('bind: Address already in use').state === 'port-in-use', 'port-in-use');
  ok(classifyLinuxServerLog('bash: /tmp/linux_server: Permission denied').state === 'cannot-start', 'cannot-start');
  ok(classifyLinuxServerLog('').state === 'unknown', 'unknown');
  ok(classifyLinuxServerLog('Listening on :::23946').ready === true, 'ready 标记');
  ok(classifyLinuxServerLog('Address already in use').ready === false, '失败时 ready=false');
}

console.log('\n[4] 远程调试器名必须是 linux（不是 gdb）');
{
  // Linux 远程调试用 IDA 自带的 dbgsrv/linux_server，调试器名为 "linux"
  ok(/load_debugger\("linux", True\)/.test(dbgSrc), 'ida-dbg.js 用 load_debugger("linux", True)');
  ok(!/load_debugger\("gdb"/.test(dbgSrc), '不再使用 gdb 调试器');
  const prelude = require('../electron/ida-dbg.js').buildStartPrelude('remote', { path: '/tmp/target' }, { remoteHost: '1.2.3.4', remotePass: 'pw' });
  ok(/load_debugger\("linux", True\)/.test(prelude.args.code), '生成代码含 linux 调试器');
  ok(/set_remote_debugger\("1\.2\.3\.4", "pw", 23946\)/.test(prelude.args.code), 'host/pass/port 正确');
  ok(/_p = "\/tmp\/target"/.test(prelude.args.code) && /start_process\(_p,/.test(prelude.args.code),
    '目标用远端路径（经 _p 变量，不是空串）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
