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
    return {
      code: PREFIXES.REMOTE_REFUSED,
      message: `${PREFIXES.REMOTE_REFUSED} ${target}（${raw || '命令执行失败'}）`,
      isError: true,
    };
  }

  const code = i.exitCode == null ? 0 : Number(i.exitCode);
  if (Number.isFinite(code) && code !== 0) {
    return {
      code: PREFIXES.REMOTE_REFUSED,
      message: `${PREFIXES.REMOTE_REFUSED} ${target}（退出码 ${code}）：${String(i.stdout || raw).slice(0, 400)}`,
      isError: true,
    };
  }

  return { code: PREFIXES.OK, message: '', isError: false };
}

module.exports = { classifyRemoteError, REMOTE_PREFIXES: PREFIXES };
