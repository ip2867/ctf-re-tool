#!/usr/bin/env node
'use strict';

/**
 * P1/P2 修复的回归测试：把"数据坏了"和"告警重复"变成工具必须处理的信号。
 *
 * 背景（elfstudy 真实事故，2026-10-31，2 小时零 flag）：
 *   P1: `[IDA] 越界地址 44/159`（27.7%）只打了一行 warning，AI 仍把残缺函数表
 *       当成完整事实基础推理了 2 小时。根因：没有"数据可信度"闸门。
 *   P2: `越界地址` 与 `花指令 0.52%` 各出现 **6 次**，AI 每次都以为"环境还没准备好"，
 *       反复重开分析。根因：FailureLoopGuard 只覆盖工具调用失败，覆盖不到日志级告警。
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

const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

// ═══════════ P1：函数表可信度闸门 ═══════════
console.log('=== P1：IDA 函数表可信度闸门 ===');

t('存在按越界比例分级的三档判定（ok / suspect / unusable）', () => {
  const i = appSrc.indexOf('const trust = dropRatio > 0.20');
  assert.ok(i > 0, '找不到 dropRatio 分级代码');
  const seg = appSrc.slice(i, i + 400);
  assert.ok(/'unusable'/.test(seg), '缺 unusable 档');
  assert.ok(/'suspect'/.test(seg), '缺 suspect 档');
  assert.ok(/0\.20/.test(seg), 'unusable 阈值应为 20%');
  assert.ok(/0\.05/.test(seg), 'suspect 阈值应为 5%');
});

t('不可信时把标记写进 analysisData（否则提示词拿不到）', () => {
  assert.ok(/analysisData\.funcTableTrust\s*=\s*trust/.test(appSrc), '未记录 funcTableTrust');
  assert.ok(/analysisData\.funcTableDropRatio\s*=/.test(appSrc), '未记录 dropRatio');
});

t('提示词里对 unusable 有明确禁令（不能只说"可能不完整"）', () => {
  const i = appSrc.indexOf("analysisData.funcTableTrust === 'unusable'");
  assert.ok(i > 0, '找不到 unusable 的提示词分支');
  const seg = appSrc.slice(i, i + 900);
  assert.ok(/函数表整体不可信/.test(seg), '缺"整体不可信"的明确措辞');
  assert.ok(/不要.*当作完整函数清单|不要.*当完整/.test(seg), '未禁止当成完整清单');
  assert.ok(/任何"没有某函数"的结论都不成立|没有某函数/.test(seg), '未说明"找不到"不可信');
  assert.ok(/elf_anomaly/.test(seg), '未给出替代取证手段 elf_anomaly');
  assert.ok(/ida_open_file|重开/.test(seg), '未给出 IDA 重建的出路');
});

t('ImageBase=0 被识别为 PIE 典型解析错误（而不是当成正常情况）', () => {
  assert.ok(/im\.map\.imageBase === 0/.test(appSrc), '未检查 ImageBase=0');
  const i = appSrc.indexOf('im.map.imageBase === 0');
  const seg = appSrc.slice(i, i + 300);
  assert.ok(/PIE/.test(seg), '未说明这是 PIE 文件的典型问题');
});

t('负向断言：低越界率（<5%）不得标记为不可信', () => {
  // 复刻分级逻辑，验证边界
  const classify = (dropped, total) => {
    const r = dropped / Math.max(1, total);
    return r > 0.20 ? 'unusable' : (r > 0.05 ? 'suspect' : 'ok');
  };
  assert.strictEqual(classify(1, 100), 'ok', '1% 应为 ok');
  assert.strictEqual(classify(4, 100), 'ok', '4% 应为 ok');
  assert.strictEqual(classify(10, 100), 'suspect', '10% 应为 suspect');
  assert.strictEqual(classify(21, 100), 'unusable', '21% 应为 unusable');
  assert.strictEqual(classify(44, 159), 'unusable', 'elfstudy 的 44/159=27.7% 应为 unusable');
});

// ═══════════ P2：告警重复升级 ═══════════
console.log('\n=== P2：同类告警重复升级 ===');

// 主进程模块可直接 require
const { WarningRepeatGuard, normalizeWarningKey } = require(path.join(ROOT, 'electron', 'warning-repeat-guard.js'));

t('告警文本归一：数字/地址/路径被抹掉，同一条告警得到同一 key', () => {
  const a = normalizeWarningKey('[IDA] 越界地址 44/159 个不在映像内（ImageBase=0x0, SizeOfImage=0x1b330）');
  const b = normalizeWarningKey('[IDA] 越界地址 43/43 个不在映像内（ImageBase=0x0, SizeOfImage=0x1b330）');
  assert.strictEqual(a, b, '同一个告警类别的不同实例应归一到同一 key');
  assert.ok(!/\d/.test(a.replace(/\[\]\/?/g, '')), 'key 里不该残留具体数字：' + a);
});

t('负向断言：不同类别告警不得被归一成同一 key', () => {
  const a = normalizeWarningKey('[IDA] 越界地址 44/159 个不在映像内');
  const b = normalizeWarningKey('[花指令探测] 跳转目标非对齐 39/7530');
  assert.notStrictEqual(a, b, '不同告警被错误合并 —— 会导致误升级');
});

t('第 2 次出现 → advisory（提醒，不强制）', () => {
  const g = new WarningRepeatGuard();
  const msg = '[IDA] 越界地址 44/159 个不在映像内';
  const r1 = g.record('warning', msg);
  assert.strictEqual(r1.repeat, 1);
  assert.ok(!r1.advisory, '第 1 次不该有 advisory');
  const r2 = g.record('warning', '[IDA] 越界地址 43/43 个不在映像内');
  assert.strictEqual(r2.repeat, 2, '不同数字应归一到同类');
  assert.ok(r2.advisory && /第 2 次/.test(r2.advisory), '第 2 次应给 advisory');
  assert.ok(!r2.tripped, '第 2 次不该 tripped');
});

t('第 3 次出现 → tripped（强制换前提）', () => {
  const g = new WarningRepeatGuard();
  const msg = '[花指令探测] 跳转目标非对齐 39/7530（0.52%）';
  g.record('warning', msg);
  g.record('warning', msg);
  const r3 = g.record('warning', msg);
  assert.strictEqual(r3.repeat, 3);
  assert.strictEqual(r3.tripped, true, '第 3 次必须 tripped');
  assert.ok(/停止重试/.test(r3.advisory), 'advisory 应明确说停止重试');
  assert.ok(/换前提|换一类工具/.test(r3.advisory), 'advisory 应要求换前提');
  assert.ok(/elf_anomaly|scan_crypto|blob_decrypt/.test(r3.advisory), '应给出具体的替代工具');
});

t('负向断言：只统计 warning/error，info/success 不参与（否则正常日志会误升级）', () => {
  const g = new WarningRepeatGuard();
  for (let i = 0; i < 10; i++) {
    const r = g.record('info', '[采集] 已获取函数列表 100 个');
    assert.strictEqual(r.repeat, 0, 'info 级不该被计数');
  }
  for (let i = 0; i < 10; i++) {
    const r = g.record('success', '✅ 已搜索关键字符串');
    assert.strictEqual(r.repeat, 0, 'success 级不该被计数');
  }
  assert.strictEqual(g.topRepeats(2).length, 0, '不该有任何重复项');
});

t('负向断言：tripped 只报一次（不刷屏）', () => {
  const g = new WarningRepeatGuard();
  const msg = '[IDA] 越界地址 1/10 个不在映像内';
  const rs = [];
  for (let i = 0; i < 6; i++) rs.push(g.record('warning', msg));
  const trippedCount = rs.filter((r) => r.tripped).length;
  assert.strictEqual(trippedCount, 1, `tripped 应只触发 1 次，实际 ${trippedCount} 次`);
  assert.strictEqual(g.takeAdvisories().length, 2, '总计应有 2 条 advisory（第 2 次 + 第 3 次）');
});

t('elfstudy 的真实场景：两条告警各 6 次 → 两条 tripped', () => {
  const g = new WarningRepeatGuard();
  const seq = [
    '[IDA] 越界地址 44/159 个不在映像内（ImageBase=0x0, SizeOfImage=0x1b330）',
    '[花指令探测] 跳转目标非对齐 39/7530（0.52%）',
    '[IDA] 越界地址 44/159 个不在映像内（ImageBase=0x0, SizeOfImage=0x1b330）',
    '[花指令探测] 跳转目标非对齐 39/7530（0.52%）',
    '[IDA] 越界地址 43/43 个不在映像内',
    '[花指令探测] 跳转目标非对齐 39/7530（0.52%）',
  ];
  const trips = seq.map((s) => g.record('warning', s)).filter((r) => r.tripped);
  assert.strictEqual(trips.length, 2, `应触发 2 次升级，实际 ${trips.length}`);
  const top = g.topRepeats(3).map((x) => x.count);
  assert.deepStrictEqual(top, [3, 3], '两个类别各应计数 3');
});

// ═══════════ 接入检查 ═══════════
console.log('\n=== 接入：告警升级必须真的能到达 AI ===');

t('addLog 里调用了 guard，并把 advisory 存进 state', () => {
  assert.ok(/ensureWarningRepeatGuard\(\)/.test(appSrc), 'addLog 未调用 ensureWarningRepeatGuard');
  assert.ok(/state\.pendingWarningAdvisories\.push/.test(appSrc), 'advisory 未存入 pendingWarningAdvisories');
});

t('提示词把 pendingWarningAdvisories 放在最前面（优先级最高）', () => {
  const i = appSrc.indexOf('repeatWarnSection');
  assert.ok(i > 0, '找不到 repeatWarnSection');
  const promptIdx = appSrc.indexOf('${repeatWarnSection}', i);
  assert.ok(promptIdx > 0, '提示词未插入 repeatWarnSection');
  // 必须在"文件路径"之前（即最顶部）
  const promptStart = appSrc.lastIndexOf('const analysisPrompt =', promptIdx);
  const seg = appSrc.slice(promptStart, promptIdx);
  assert.ok(/我正在分析一个CTF/.test(seg), 'repeatWarnSection 应紧跟提示词开头');
  assert.ok(!/文件路径/.test(seg), 'repeatWarnSection 必须在"文件路径"之前（更高优先级）');
});

t('消费后清空（避免同一 advisory 反复注入）', () => {
  const i = appSrc.indexOf('repeatWarnSection');
  const seg = appSrc.slice(i, i + 600);
  assert.ok(/state\.pendingWarningAdvisories = \[\]/.test(seg), '注入后未清空，会重复注入');
});

t('渲染层内联实现与主进程模块规则一致（adviseAt=2 / tripAt=3）', () => {
  assert.ok(/adviseAt:\s*2/.test(appSrc), '渲染层 adviseAt 应为 2');
  assert.ok(/tripAt:\s*3/.test(appSrc), '渲染层 tripAt 应为 3');
  const g = new WarningRepeatGuard();
  assert.strictEqual(g.adviseAt, 2, '主进程 adviseAt 应为 2');
  assert.strictEqual(g.tripAt, 3, '主进程 tripAt 应为 3');
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
