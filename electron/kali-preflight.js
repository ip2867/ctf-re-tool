'use strict';
// Kali 远程预检决策（纯函数）。
//
// 实测：Kali 不可达（ping 2/2 丢包、SSH 22 timeout、无 vmware-vmx），而 analyzeBIN
// 仍会依次跑 file/binwalk/strings，每条 60s 超时 —— 白等 3 分钟。
// 因此探活必须在发任何远程命令之前完成，并缓存 120s（同一轮里不重复探）。
//
// 注意：只测"远程预检阶段"的耗时；skip 之后的 localFirmwareProbe 会 spawn Python，
// 不属于预检区间。

const DEFAULT_TTL_MS = 120000;

// input: {reachable, cacheAgeMs, ttlMs, host, port}
// 返回 {action:'remote'|'skip', reason, log, probe}
function decideKaliPreflight(input) {
  const i = input || {};
  const ttl = Number(i.ttlMs) > 0 ? Number(i.ttlMs) : DEFAULT_TTL_MS;
  const host = String(i.host == null ? '' : i.host).trim();
  const port = i.port == null || i.port === '' ? 22 : i.port;
  const age = i.cacheAgeMs;

  // 缓存新鲜：不再探活，直接沿用上次结论
  if (age != null && Number.isFinite(Number(age)) && Number(age) < ttl && typeof i.reachable === 'boolean') {
    return i.reachable
      ? { action: 'remote', reason: 'cache-hit-reachable', log: `[Kali] 缓存命中（${Math.round(Number(age) / 1000)}s 前探活成功）`, probe: false }
      : { action: 'skip', reason: 'cache-hit-unreachable', log: `[Kali] ${port}/TIMEOUT → 跳过远程命令，使用本地兜底`, probe: false };
  }

  if (i.reachable === true) {
    return { action: 'remote', reason: 'reachable', log: `[Kali] ${host || 'kali'}:${port} 可达 → 远程命令`, probe: true };
  }
  return {
    action: 'skip',
    reason: 'unreachable',
    log: `[Kali] ${port}/TIMEOUT → 跳过远程命令，使用本地兜底`,
    probe: true,
  };
}

// 可达时才按 file → binwalk → strings 执行；不可达时一条都不发。
// 本地兜底能力边界必须显式写进 AI 上下文：只能给 magic/strings/熵，不能解包。
function decideKaliRemotePlan(input) {
  const i = input || {};
  const reachable = i.reachable === true;
  if (!reachable) {
    return {
      reachable: false,
      commands: [],
      note: '本地兜底只能给 magic/strings/熵，不能解包（无 binwalk/file 语义）；'
        + '需要解包时先确认 Kali 可用或人工提供已解出的内容。',
    };
  }
  const plan = ['file', 'binwalk', 'strings'];
  const cap = i.capabilities || {};
  // 纯文本/已知容器不必跑 binwalk：解包由本地能力处理
  if (cap.textual || cap.archive) plan.splice(1, 1);
  return { reachable: true, commands: plan, note: '' };
}

module.exports = { decideKaliPreflight, decideKaliRemotePlan, DEFAULT_TTL_MS };
