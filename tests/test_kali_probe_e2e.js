#!/usr/bin/env node
'use strict';

/**
 * kali_probe.py 实测结果 → decideDynDebugReadiness() 判定 的**端到端**一致性。
 *
 * 背景：测试单测 decideDynDebugReadiness 的每个分支（11 项），但从未验证
 * "真机探到的值喂进去会得出什么结论"。这两者脱节时，预检可能对一台
 * 明明可用的机器报 blocker（或反过来），而单测全绿。
 *
 * 做法：真跑 kali_probe.py --json，把 results 映射成 decideDynDebugReadiness 的入参，
 * 断言：探测 ok=true 时判定必须 ok，且 blockers 为空。
 * 若 SSH 不通（退出码 2）则跳过，不算失败。
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const { decideDynDebugReadiness } = require(path.join(ROOT, 'electron', 'kali-preflight.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}
const skip = (name, why) => console.log('  SKIP ' + name + ' —— ' + why);

/** 跑探测并解析 JSON；返回 null 表示环境不可达 */
function probe() {
  try {
    const out = execFileSync('python', ['-I', '-X', 'utf8', path.join(ROOT, 'tests', 'kali_probe.py'), '--json'],
      { encoding: 'utf8', timeout: 180000 });
    return JSON.parse(out);
  } catch (e) {
    // 退出码 2 = 未配置/不可达，stdout 里仍可能有 JSON
    const txt = String((e.stdout || '')).trim();
    if (txt) { try { return JSON.parse(txt); } catch (_) { /* fall through */ } }
    return null;
  }
}

const r = probe();
// probe 有三种"不可用"形态，都必须跳过而不是硬跑断言：
//   ① 完全没有输出（解析失败）
//   ② 顶层 error 字段（SSH 端口不可达 / 未配置）——形如 {ok:false, error:"REFUSED"}
//   ③ results 为空（探测没跑起来）
// 早期实现只判了 ①，于是 Kali 关机时 ② 被当成"探测成功"，用空 results 造出入参，
// 得出 ok=true，再断言"与 probe.ok 一致"必然失败——这是测试自身的缺陷。
const probeUnusable = !r || r.error || !Array.isArray(r.results) || r.results.length === 0;
if (probeUnusable) {
  const why = !r ? '探测无输出（SSH 不通或未配置）'
    : (r.error ? `探测失败：${r.error} ${r.detail || ''}`.trim() : '探测未返回 results');
  skip('Kali 实测映射', why);
  console.log(`\n结果: ${pass} 通过, ${fail} 失败（已跳过）`);
  if (fail > 0) process.exit(1);
  process.exit(0);
}

const byName = {};
for (const it of (r.results || [])) byName[it.name] = it;

console.log('=== Kali 实测 → 预检判定 一致性 ===');
console.log(`  host=${r.host}  probe.ok=${r.ok}  失败项=${(r.failed || []).join(',') || '(无)'}`);

// probe 的 results → decideDynDebugReadiness 的入参
const input = {
  reachable: true,
  ptraceWorks: byName.ptrace_attach ? byName.ptrace_attach.ok === true : undefined,
  ptraceScope: byName.ptrace_scope ? byName.ptrace_scope.value : undefined,
  hasGdb: byName.gdb ? byName.gdb.ok === true : undefined,
  hasGdbserver: byName.gdbserver ? byName.gdbserver.ok === true : undefined,
  probeTimedOut: false,
};
const d = decideDynDebugReadiness(input);

console.log('  映射入参: ' + JSON.stringify(input));
console.log('  判定结果: ok=' + d.ok + ' blockers=' + JSON.stringify(d.blockers) + ' warns=' + JSON.stringify(d.warns));

t('探测可用的机器 → 预检不得报 blocker', () => {
  if (r.ok !== true) { console.log('     （probe.ok 非 true，跳过该断言）'); return; }
  assert.strictEqual(d.ok, true, 'probe 说可用，预检却说不可用：' + JSON.stringify(d.blockers));
  assert.deepStrictEqual(d.blockers, [], 'blockers 必须为空');
});
t('ptrace 实测通过 → 不得因 scope 值误报', () => {
  if (!(byName.ptrace_attach && byName.ptrace_attach.ok)) { console.log('     （ptrace 未实测通过，跳过）'); return; }
  const noScope = decideDynDebugReadiness({ ...input, ptraceScope: undefined });
  assert.strictEqual(noScope.ok, true, 'scope 未知但 ptrace 实测通过时不应报 blocker');
  const badScope = decideDynDebugReadiness({ ...input, ptraceScope: '3' });
  assert.strictEqual(badScope.ok, true, 'ptrace 实测通过时，scope=3 也只应提示不应阻塞（实测优先）');
});
t('负向断言：把 ptrace 实测改成失败 → 判定必须翻转', () => {
  assert.strictEqual(d.ok, true, '前置条件：真机基线应判可用');
  const flipped = decideDynDebugReadiness({ ...input, ptraceWorks: false });
  assert.strictEqual(flipped.ok, false, 'ptrace 实测失败时 ok 必须为 false');
  assert.ok(flipped.blockers.length > 0, '必须有 blocker 说明');
});
t('负向断言：既无 gdb 也无 gdbserver → 必须报 blocker', () => {
  const noDbg = decideDynDebugReadiness({ ...input, hasGdb: false, hasGdbserver: false });
  assert.strictEqual(noDbg.ok, false, '两者都没有时不该判可用');
  assert.ok(noDbg.blockers.some((b) => /gdb/i.test(b)), 'blocker 应点名 gdb');
});
t('guidance 非空且可操作', () => {
  assert.ok(typeof d.guidance === 'string' || Array.isArray(d.guidance), 'guidance 缺失');
  const txt = Array.isArray(d.guidance) ? d.guidance.join('\n') : d.guidance;
  assert.ok(txt.trim().length > 0, 'guidance 为空');
});

// 两套判据口径不同，不能简单要求 ok 相等：
//   · probe.ok = 「所有非可选探测项都通过」（含 arch/kernel 等**环境信息**项）
//   · 预检.ok  = 「**能不能调试**」（只看 ptrace / gdb 这类硬条件）
// SSH 通道抖动时 probe 的单项探测会拿到 "Timeout opening channel"，
// probe.ok 变 false，但只要 ptrace 实测通过，预检仍应判可用 —— 这是**功能正确**。
// 因此断言改为：两套判据不得「一个说完全不可用、另一个也说可用」这种方向性矛盾。
t('probe 与预检的结论不得方向性矛盾', () => {
  const probeOk = r.ok === true;
  const preOk = d.ok === true;
  if (!probeOk && preOk) {
    // 允许：probe 因**非决定性**项失败，而真正决定"能不能调"的条件都过了。
    // 决定性项只有两个：ptrace 实测（ptrace_attach）、以及"有 gdb 或 gdbserver"。
    // arch/kernel/ptrace_scope 等只是**环境信息**——SSH 通道抖动时读不到，
    // 不代表调试不可用（实测：channel 超时导致 ptrace_scope 读失败，但 ptrace 实测通过）。
    const failed = r.failed || [];
    const ptraceFailed = failed.some((x) => x === 'ptrace_attach' || x === 'ptrace');
    const noDebugger = failed.includes('gdb') && failed.includes('gdbserver');
    assert.ok(!ptraceFailed, `probe 的 ptrace 实测失败，预检却判可用 —— 真矛盾：${JSON.stringify(failed)}`);
    assert.ok(!noDebugger, `probe 报 gdb 与 gdbserver 都不可用，预检却判可用 —— 真矛盾：${JSON.stringify(failed)}`);
    console.log(`     （probe.ok=false 但失败项 ${JSON.stringify(failed)} 均非决定性条件 → 预检判可用合理）`);
    return;
  }
  assert.strictEqual(preOk, probeOk,
    `两套判据方向矛盾：probe.ok=${probeOk} 预检.ok=${preOk}（blockers=${JSON.stringify(d.blockers)}）`);
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
