#!/usr/bin/env node
'use strict';

/**
 * 花指令告警阈值回归测试。
 *
 * 背景（真实事故，2026-10-31）：旧判据 `bad >= 20 || ratio > 0.002` 的信噪比为 0——
 * 实测微软官方 ntdll/kernel32/user32/msvcrt/notepad 的"非对齐跳转"占比是
 * 0.033%~0.131%，**全部**被判"高度可疑"。elfstudy 题在 0.52% 触发这条告警，
 * AI 得到「花指令高度可疑（必须处理）」这条唯一可执行的指令，花 2 小时去修
 * 根本不存在的问题（该题实际是 ELF 加载期自解密）。零 flag。
 *
 * 本测试锁死两件事：
 *   ① 阈值必须用双条件（绝对量 + 比例），单条件任一都会误报
 *   ② 用实测基线数据验证：系统二进制不得被判可疑，题目量级必须能检出
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

// ── 从 main.js 抽出实际阈值表达式，保证测的是实现而不是复刻 ──
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const m = mainSrc.match(/suspicious:\s*(bad\s*>=\s*\d+\s*&&\s*ratio\s*>\s*[\d.]+)/);
assert.ok(m, 'main.js 里找不到 suspicious 的双条件阈值');
const expr = m[1];
console.log(`  实际阈值表达式: ${expr}`);

const BAD_MIN = Number(expr.match(/bad\s*>=\s*(\d+)/)[1]);
const RATIO_MIN = Number(expr.match(/ratio\s*>\s*([\d.]+)/)[1]);
const suspicious = (bad, insn) => bad >= BAD_MIN && bad / Math.max(1, insn) > RATIO_MIN;

console.log(`  解析出: bad >= ${BAD_MIN} && ratio > ${RATIO_MIN}（即 ${(RATIO_MIN * 100).toFixed(2)}%）`);

// ── 实测基线（2026-11-04 用 scanJunkFeatures 量得，见 _work/JUNK_BASELINE.txt）──
const SYSTEM_BINARIES = [
  ['ntdll.dll', 378, 628063],
  ['kernel32.dll', 77, 234802],
  ['user32.dll', 264, 319301],
  ['msvcrt.dll', 290, 221919],
  ['notepad.exe', 23, 68524],
];
const CHALLENGE_BINARIES = [
  ['elfstudy', 39, 7530],
  ['fw_a', 1865, 249983],
  ['license', 4451, 386519],
];

console.log('\nA) 系统二进制不得被判"高度可疑"（这是旧阈值的致命误报）');
t(`${SYSTEM_BINARIES.length} 个微软官方二进制全部不触发`, () => {
  const bad = [];
  for (const [name, badT, insn] of SYSTEM_BINARIES) {
    const ratio = badT / insn;
    if (suspicious(badT, insn)) bad.push(`${name}(${badT}/${insn}=${(ratio * 100).toFixed(3)}%)`);
  }
  assert.deepStrictEqual(bad, [], '这些系统二进制被误判为高度可疑：' + bad.join(', '));
});

t('负向断言：旧阈值确实会误报这些系统二进制（证明这次修复是必要的）', () => {
  const oldSuspicious = (bad, insn) => bad >= 20 || (bad / Math.max(1, insn)) > 0.002;
  const hits = SYSTEM_BINARIES.filter(([, b, i]) => oldSuspicious(b, i)).map((x) => x[0]);
  assert.strictEqual(hits.length, SYSTEM_BINARIES.length,
    `旧阈值应误报全部 ${SYSTEM_BINARIES.length} 个，实际只误报 ${hits.length} 个：${hits.join(',')}`);
  console.log(`     旧阈值误报: ${hits.join(', ')}`);
});

console.log('\nB) 题目量级样本仍必须能检出（修复不能矫枉过正）');
t('elfstudy（0.52%，题目里最弱的那个）仍被判可疑', () => {
  const [, b, i] = CHALLENGE_BINARIES[0];
  assert.ok(suspicious(b, i), `elfstudy ${b}/${i} 应被判可疑，实际没有`);
});
t('license / fw_a（0.75% / 1.15%）仍被判可疑', () => {
  for (const [name, b, i] of CHALLENGE_BINARIES.slice(1)) {
    assert.ok(suspicious(b, i), `${name} ${b}/${i} 应被判可疑`);
  }
});

console.log('\nC) 双条件缺一不可（单条件各有失效场景）');
t('负向断言：只有比例没有绝对量 → 小文件几个异常就误报', () => {
  // 小文件：10 条指令里 3 个非对齐 = 30%，比例极高但绝对量很小
  assert.ok(!suspicious(3, 10), '小文件 3/10 不该被判可疑（绝对量不足）');
});
t('负向断言：只有绝对量没有比例 → 大文件天然堆积就误报', () => {
  // 大文件：60 万个指令里 100 个非对齐 = 0.017%，绝对量过了但比例低
  assert.ok(!suspicious(100, 600000), '大文件 100/600000 不该被判可疑（比例过低）');
});
t('两个条件同时满足才触发', () => {
  // 构造：bad 刚好等于阈值，insn 取一个让 ratio 明显超过阈值的值
  const insn = Math.round(BAD_MIN / (RATIO_MIN * 2));   // ratio ≈ 2×阈值
  assert.ok(suspicious(BAD_MIN, insn),
    `bad=${BAD_MIN} insn=${insn}（ratio=${(BAD_MIN / insn * 100).toFixed(2)}%）应触发`);
  // 同样 bad，但 insn 放大 10 倍 → ratio 掉到阈值以下 → 不该触发
  assert.ok(!suspicious(BAD_MIN, insn * 10),
    `bad=${BAD_MIN} insn=${insn * 10}（ratio 低于阈值）不该触发`);
});

console.log('\nD) 阈值合理性边界');
t('阈值高于所有系统二进制的上界', () => {
  const maxSysRatio = Math.max(...SYSTEM_BINARIES.map(([, b, i]) => b / i));
  assert.ok(RATIO_MIN > maxSysRatio,
    `阈值 ${(RATIO_MIN * 100).toFixed(3)}% 必须高于系统二进制上界 ${(maxSysRatio * 100).toFixed(3)}%`);
  console.log(`     系统上界 ${(maxSysRatio * 100).toFixed(3)}% < 阈值 ${(RATIO_MIN * 100).toFixed(2)}%`);
});
t('阈值低于题目样本的下界', () => {
  const minChRatio = Math.min(...CHALLENGE_BINARIES.map(([, b, i]) => b / i));
  assert.ok(RATIO_MIN < minChRatio,
    `阈值 ${(RATIO_MIN * 100).toFixed(3)}% 必须低于题目下界 ${(minChRatio * 100).toFixed(3)}%`);
  console.log(`     题目下界 ${(minChRatio * 100).toFixed(3)}% > 阈值 ${(RATIO_MIN * 100).toFixed(2)}%`);
});
t('BAD_MIN 单独兜底小样本噪声（比例再高也不触发）', () => {
  // notepad 的绝对值 23 个本身不构成问题——真正挡住它的是**比例**（0.034%）。
  // 这条断言验证的是：绝对量门槛对小文件起兜底作用。
  // 构造：小文件 15 条指令里 10 个非对齐 = 67%（比例爆表，但绝对量不足）
  const insn = 15, bad = 10;
  assert.ok(bad / insn > RATIO_MIN, '前置：该样本比例应远超阈值');
  assert.ok(!suspicious(bad, insn), `小样本 ${bad}/${insn} 不该触发（绝对量 < ${BAD_MIN}）`);
  // 反向：同样比例但样本量够大 → 应触发
  const bigInsn = 1000, bigBad = 200;    // 20%
  assert.ok(suspicious(bigBad, bigInsn), `大样本 ${bigBad}/${bigInsn} 应触发`);
});

console.log('\nE) 文案不得再出现"必须处理"式的强制指令');
t('app.js 的花指令注入段已改成"先确认"口径', () => {
  const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');
  const i = appSrc.indexOf('花指令检测：统计上可疑');
  assert.ok(i > 0, '找不到新的花指令提示标题');
  const seg = appSrc.slice(i, i + 3000);
  assert.ok(!/必须处理/.test(seg), '仍含"必须处理"这类强制指令：会让 AI 无条件动手');
  assert.ok(/先确认|排除这两种|判读基线/.test(seg), '缺少"先确认"的判读指引');
  assert.ok(/0\.0?3%|0\.03|基线/.test(seg), '缺少实测基线数字（AI 需要参照物才能判断 0.52% 是否异常）');
});

console.log('\nF) 零指纹分支必须给出具体下一步（不能只说"可能是什么"）');
t('scan_crypto 的零命中 note 点名了 elf_anomaly 与 blob_decrypt', () => {
  const i = mainSrc.indexOf("algo: '(未发现算法指纹)'");
  assert.ok(i > 0, '找不到零指纹分支');
  const seg = mainSrc.slice(i, i + 2200);
  assert.ok(/elf_anomaly/.test(seg), '零命中 note 未点名 elf_anomaly —— AI 会自己抓一条错误的行动');
  assert.ok(/blob_decrypt/.test(seg), '零命中 note 未点名 blob_decrypt');
  assert.ok(/切勿.*花指令|不是.*花指令|与.*花指令/.test(seg), '未明确排除"去修花指令"这个错误方向');
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
