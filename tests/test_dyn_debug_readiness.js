#!/usr/bin/env node
'use strict';

/**
 * test_dyn_debug_readiness.js — 动态调试能力预检的契约测试
 *
 * 背景（实测）：SSH 通 ≠ 能动态调试。Kali 上曾同时存在：
 *   · yama ptrace_scope=1 → 非父进程 attach 被 EPERM 拒绝
 *   · 没有 gdb/gdbserver → 无法下断点
 *   · 自检程序写法错（TRACEME 后直接 CONT，抢在 SIGSTOP 前）→ 假报 "No such process"
 * 这些如果不在动调前判掉，AI 会把预算烧在"断点没命中"，且分不清是环境问题还是假设错。
 */

const assert = require('assert');
const path = require('path');
const { decideDynDebugReadiness } = require(path.join(__dirname, '..', 'electron', 'kali-preflight.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}

console.log('=== 动态调试能力预检 ===');

t('全绿：可达 + ptrace 实测通过 + 有 gdb → ok', () => {
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: true, hasGdb: true, hasGdbserver: true, ptraceScope: '0',
  });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.deepStrictEqual(r.blockers, []);
});

t('SSH 不可达 → 阻塞，且提示开虚拟机', () => {
  const r = decideDynDebugReadiness({ reachable: false, hasGdb: true, ptraceWorks: true });
  assert.strictEqual(r.ok, false);
  assert.ok(r.blockers.some(b => /SSH 不可达/.test(b)), JSON.stringify(r.blockers));
  assert.ok(r.blockers.some(b => /vmrun/.test(b)), '应提示用 vmrun 开机');
});

t('ptrace_scope=1 且未实测 → 阻塞并给出修法', () => {
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: null, ptraceScope: '1', hasGdb: true, hasGdbserver: true,
  });
  assert.strictEqual(r.ok, false);
  assert.ok(r.blockers.some(b => /ptrace_scope=1/.test(b)), JSON.stringify(r.blockers));
  assert.ok(r.blockers.some(b => /tee \/proc\/sys\/kernel\/yama\/ptrace_scope/.test(b)), '要给具体命令');
});

t('ptrace_scope=0 但未实测 → 不阻塞，但 warn 要求实测', () => {
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: null, ptraceScope: '0', hasGdb: true, hasGdbserver: true,
  });
  assert.strictEqual(r.ok, true, 'scope=0 不该硬阻塞');
  assert.ok(r.warns.some(w => /未实测/.test(w)), '必须提醒实测，而不是只看 scope 值');
});

t('ptrace 实测失败优先于 scope 值 → 阻塞', () => {
  // 关键：scope 写着 0，但实测 attach 失败（容器 seccomp 等）→ 必须信实测
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: false, ptraceScope: '0', hasGdb: true, hasGdbserver: true,
  });
  assert.strictEqual(r.ok, false, '实测失败必须阻塞，不能因为 scope=0 就放行');
  assert.ok(r.blockers.some(b => /ptrace 实测失败/.test(b)));
});

t('既无 gdb 也无 gdbserver → 阻塞', () => {
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: true, hasGdb: false, hasGdbserver: false, ptraceScope: '0',
  });
  assert.strictEqual(r.ok, false);
  assert.ok(r.blockers.some(b => /既无 gdb 也无 gdbserver/.test(b)));
});

t('无 gdb 但有 gdbserver → 只 warn 不阻塞', () => {
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: true, hasGdb: false, hasGdbserver: true, ptraceScope: '0',
  });
  assert.strictEqual(r.ok, true);
  assert.ok(r.warns.some(w => /gdbserver/.test(w)));
});

// ── 负向断言：证明判定真的会随输入翻转 ──
t('负向断言：同一组输入去掉 ptrace 实测通过后必须从 ok 翻成阻塞', () => {
  const good = decideDynDebugReadiness({
    reachable: true, ptraceWorks: true, hasGdb: true, hasGdbserver: true, ptraceScope: '0',
  });
  const bad = decideDynDebugReadiness({
    reachable: true, ptraceWorks: false, hasGdb: true, hasGdbserver: true, ptraceScope: '0',
  });
  assert.strictEqual(good.ok, true);
  assert.strictEqual(bad.ok, false);
  assert.notStrictEqual(good.ok, bad.ok, 'ok 必须翻转，否则测试无效');
});

t('负向断言：探测超时必须进 warn（不能当成"一切正常"）', () => {
  const r = decideDynDebugReadiness({
    reachable: true, ptraceWorks: null, ptraceScope: '0', hasGdb: true, hasGdbserver: true, probeTimedOut: true,
  });
  assert.ok(r.warns.some(w => /超时/.test(w)), JSON.stringify(r.warns));
});

t('返回结构完整（ok/blockers/warns/guidance）', () => {
  const r = decideDynDebugReadiness({ reachable: false });
  for (const k of ['ok', 'blockers', 'warns', 'guidance']) {
    assert.ok(k in r, '缺少字段 ' + k);
  }
  assert.ok(Array.isArray(r.blockers) && Array.isArray(r.warns));
  assert.ok(typeof r.guidance === 'string' && r.guidance.length > 0);
});

t('空输入不抛异常', () => {
  const r = decideDynDebugReadiness();
  assert.strictEqual(r.ok, false, '空输入应判不可用，而不是崩');
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
