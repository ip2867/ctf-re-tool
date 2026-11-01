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

// ─── 动态调试能力预检 ───
// 为什么需要：SSH 通 ≠ 能动态调试。实测 Kali 上曾同时存在三种"看着通却调不了"：
//   ① yama ptrace_scope=1 → 非父进程 attach 被拒（PTRACE_ATTACH EPERM）
//   ② 没有 gdb / gdbserver → 只能干瞪眼
//   ③ 自检程序写法不对（TRACEME 后直接 CONT，抢在 stop 之前）→ 假报失败
// 因此动调前必须确认：ptrace 实测放行 + gdb 存在。
//
// input: {
//   reachable: bool,            // SSH 是否可达
//   ptraceScope: '0'|'1'|...,   // /proc/sys/kernel/yama/ptrace_scope
//   hasGdb: bool,
//   hasGdbserver: bool,
//   ptraceWorks: bool|null,     // 实跑 TRACEME+GETREGS 的结果；null=未测
//   probeTimedOut: bool,
// }
// 返回 {ok, blockers[], warns[], guidance}
function decideDynDebugReadiness(input) {
  const i = input || {};
  const blockers = [];
  const warns = [];

  if (i.reachable !== true) {
    blockers.push('SSH 不可达：先确认虚拟机已开机（vmrun start）且 IP 未变');
  }
  // ptrace 实测最有说服力：能 attach+读寄存器才算数
  if (i.ptraceWorks === false) {
    blockers.push('ptrace 实测失败：内核拒绝 attach（检查 yama / 容器 seccomp）');
  } else if (i.ptraceWorks == null) {
    const scope = String(i.ptraceScope == null ? '' : i.ptraceScope).trim();
    if (scope === '1') {
      blockers.push('yama ptrace_scope=1：只能 attach 子进程，需 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`');
    } else if (scope === '2') {
      blockers.push('yama ptrace_scope=2：仅 root 可 attach（用 sudo 或改用 gdbserver 由程序自己启动）');
    } else if (scope === '3') {
      blockers.push('yama ptrace_scope=3：完全禁止 ptrace');
    }
    warns.push('ptrace 未实测：建议跑一次 TRACEME+GETREGS 确认，而不是只看 ptrace_scope');
  }

  if (i.hasGdb === false && i.hasGdbserver === false) {
    blockers.push('既无 gdb 也无 gdbserver：无法下断点/读寄存器');
  } else if (i.hasGdb === false) {
    warns.push('无 gdb，但有 gdbserver：可远程调试但要用客户端连接，脚本化更难');
  }

  if (i.probeTimedOut) {
    warns.push('能力探测超时：按"不可用"处理，不要假设远端具备调试工具');
  }

  const ok = blockers.length === 0;
  let guidance = '';
  if (!ok) {
    guidance = '先解决阻塞项再动调；否则会用"断点没命中/attach 失败"消耗预算，'
      + '且无法区分是环境问题还是分析假设错。';
  } else if (warns.length) {
    guidance = '可动调，但有降级项：注意上面的 warn，必要时先用 strace/gdbserver 兜底。';
  } else {
    guidance = '动态调试链路就绪：可 attach、可下断点、可读寄存器。';
  }
  return { ok, blockers, warns, guidance };
}

module.exports = { decideKaliPreflight, decideKaliRemotePlan, decideDynDebugReadiness, DEFAULT_TTL_MS };
