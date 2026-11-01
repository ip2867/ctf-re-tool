'use strict';
// 远程执行结果分类（纯函数）。
//
// 为什么：AI 侧此前完全看不到 Kali——工具表里没有 remote_exec，失败时也只有
// "连接超时"这类无信息文案。远程失败必须给出可操作的固定前缀，且**默认必须判为错误**
// （空 stdout 不是成功）。前缀同时要登记到 tool-result.js 的 FAILURE_PREFIXES，
// 否则字符串失败不会被标 is_error。

const PREFIXES = {
  REMOTE_TIMEOUT: 'REMOTE_TIMEOUT',
  REMOTE_AUTH: 'REMOTE_AUTH',
  REMOTE_REFUSED: 'REMOTE_REFUSED',
  REMOTE_UNCONFIGURED: 'REMOTE_UNCONFIGURED',
  // 命令本身在远端跑失败（找不到文件、非零退出）——与"连不上"是两回事。
  // 历史上这两类都归 REMOTE_REFUSED，AI 看到"命令失败"会去查 SSH/网络，
  // 而真正的原因是命令写错了。实测：`ls /nonexistent` 报 REMOTE_REFUSED。
  REMOTE_CMD_FAILED: 'REMOTE_CMD_FAILED',
  OK: 'OK',
};

// input: {success, error, stdout, exitCode, host, port}
// 返回 {code, message, isError}
function classifyRemoteError(input) {
  const i = input || {};
  const host = String(i.host == null ? '' : i.host).trim();
  const port = i.port == null || i.port === '' ? 22 : i.port;
  const target = `${host || '(未配置)'}:${port}`;
  const raw = String(i.error == null ? '' : i.error);

  if (!host) {
    return {
      code: PREFIXES.REMOTE_UNCONFIGURED,
      message: `${PREFIXES.REMOTE_UNCONFIGURED} ${target}（未配置 sshHost/sshPort，请先在设置里填写 Kali 地址）`,
      isError: true,
    };
  }

  if (/timed out while waiting for handshake|handshake.*time(d)? ?out|ETIMEDOUT|timeout|超时/i.test(raw)) {
    return {
      code: PREFIXES.REMOTE_TIMEOUT,
      message: `${PREFIXES.REMOTE_TIMEOUT} ${target}（SSH 握手超时）；可改用本地兜底命令或检查 Kali 是否启动/可达`,
      isError: true,
    };
  }
  if (/all configured authentication methods failed|authentication failed|permission denied|bad password/i.test(raw)) {
    return {
      code: PREFIXES.REMOTE_AUTH,
      message: `${PREFIXES.REMOTE_AUTH} ${target}（认证失败）；检查用户名/密码/密钥配置`,
      isError: true,
    };
  }
  if (/ECONNREFUSED|connection refused|connect ECONNREFUSED/i.test(raw)) {
    return {
      code: PREFIXES.REMOTE_REFUSED,
      message: `${PREFIXES.REMOTE_REFUSED} ${target}（端口拒绝连接）；SSH 服务可能未启动`,
      isError: true,
    };
  }

  if (i.success === false) {
    // 区分"连不上"与"命令跑失败"：
    //   sshExec 在连接层失败时 stdout/stderr 都为空，只有 error 文案；
    //   命令层失败时 exitCode 有值，错误原文在 stderr（ls 的报错就走 stderr）。
    // 混为一谈会让 AI 看到"命令写错"却去排查 SSH/网络。
    const hasStderr = !!(i.stderr && String(i.stderr).trim());
    const hasOut = !!(i.stdout && String(i.stdout).trim());
    const ranOnRemote = hasStderr || hasOut || Number.isFinite(Number(i.exitCode));
    if (ranOnRemote && !/ECONNREFUSED|connection refused|handshake|authentication failed|permission denied/i.test(raw)) {
      const detail = (hasStderr ? String(i.stderr) : (hasOut ? String(i.stdout) : raw)).trim().slice(0, 400);
      return {
        code: PREFIXES.REMOTE_CMD_FAILED,
        message: `${PREFIXES.REMOTE_CMD_FAILED} ${target}（命令在远端执行失败，连接正常）：${detail}`,
        isError: true,
      };
    }
    return {
      code: PREFIXES.REMOTE_REFUSED,
      message: `${PREFIXES.REMOTE_REFUSED} ${target}（${raw || '命令执行失败'}）`,
      isError: true,
    };
  }

  const code = i.exitCode == null ? 0 : Number(i.exitCode);
  if (Number.isFinite(code) && code !== 0) {
    // 非零退出码是"命令本身失败"（ls 找不到文件、grep 无匹配），不是连接问题。
    // 保留 stderr/stdout 原文便于 AI 直接看到远端报错。
    const detail = String(i.stderr && String(i.stderr).trim() ? i.stderr : (i.stdout || raw)).trim().slice(0, 400);
    return {
      code: PREFIXES.REMOTE_CMD_FAILED,
      message: `${PREFIXES.REMOTE_CMD_FAILED} ${target}（退出码 ${code}，连接正常）：${detail}`,
      isError: true,
    };
  }

  return { code: PREFIXES.OK, message: '', isError: false };
}

// remote_exec 的补充能力：IDB 的 Linux 远程调试服务端（dbgsrv/linux_server）。
//
// 为什么单独写：Linux 远程调试不是 gdbserver，而是 IDA 自带的 linux_server。
// 启动它有固定套路，且必须 setsid（否则 SSH 会话一断就被杀，实测两次失败）：
//   setsid <path>/linux_server -P<password> > <log> 2>&1 < /dev/null &
//
// 传入 password 时拼 `-P<pw>`（IDA 的格式是紧贴的，不是 `-P <pw>`）。
function buildLinuxServerCommand(opts) {
  const o = opts || {};
  const bin = String(o.path || '/tmp/linux_server');
  const pass = String(o.password == null ? '' : o.password);
  const log = String(o.log || '/tmp/linux_server.log');
  if (!bin) return { error: 'path 不能为空' };
  // 只允许常规路径字符，避免命令注入（这是拼给远端 shell 的字符串）
  if (!/^[A-Za-z0-9_./-]+$/.test(bin)) return { error: 'path 含非法字符' };
  if (pass && !/^[A-Za-z0-9_@#%+.-]*$/.test(pass)) return { error: 'password 含非法字符' };
  const passArg = pass ? ` -P${pass}` : '';
  return {
    command: `setsid ${bin}${passArg} > ${log} 2>&1 < /dev/null & echo LINUX_SERVER_SPAWNED`,
    password: pass,
    // 校验是否起来了：ss/netstat 看端口；两条命令都给，兼容不同发行版
    verifyCommand: `sleep 1; (ss -ln 2>/dev/null || netstat -ln 2>/dev/null) | grep -E '23946|:23946' || echo NOT_LISTENING`,
    stopCommand: "pkill -f 'linux_server' 2>/dev/null; echo STOPPED",
  };
}

// linux_server 的启动日志里能判断状态的几个标志
function classifyLinuxServerLog(text) {
  const s = String(text || '');
  if (/Listening on .*23946/i.test(s)) return { ready: true, state: 'listening' };
  if (/Accepting connection/i.test(s)) return { ready: true, state: 'connected' };
  if (/Address already in use|bind.*failed/i.test(s)) return { ready: false, state: 'port-in-use' };
  if (/Permission denied|not found|No such file/i.test(s)) return { ready: false, state: 'cannot-start' };
  return { ready: false, state: 'unknown' };
}

module.exports = {
  classifyRemoteError, REMOTE_PREFIXES: PREFIXES,
  buildLinuxServerCommand, classifyLinuxServerLog,
};
