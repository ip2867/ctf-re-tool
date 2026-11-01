#!/usr/bin/env node
'use strict';

/**
 * 长结果截断链路：工具输出 > 24000 字符时，flag 还在不在 AI 能看到的部分里。
 *
 * 断链风险：AI 用 run_python 打了一堆调试输出，真正的 flag 在末尾；
 * 若截断只保留"开头 N 字符"，flag 就被切掉，AI 看到"没有 flag"从而放弃或重复劳动。
 * 这是"工具能用但解不出题"的典型形态之一。
 *
 * 断言：落盘 + 首尾预览的形态下，**尾部内容必须可见**（flag 通常在最后一行）。
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const { persistToolResult } = require(path.join(ROOT, 'electron', 'agent-runtime.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

const DIR = path.join(os.tmpdir(), 'ctf-persist-test');

console.log('=== 长结果截断：flag 必须仍可见 ===');

// 构造：大量调试输出 + 末尾 flag
const FLAG = 'flag{truncation_keeps_me}';
const noise = Array.from({ length: 3000 }, (_, i) => `[dbg] line ${i} ` + 'x'.repeat(20)).join('\n');
const big = noise + '\n' + FLAG;

t('输出超过 maxChars 时被落盘（不是直接丢弃）', () => {
  const out = persistToolResult(big, { maxChars: 2000, dir: DIR, id: 'trunc1' });
  assert.ok(out.length < big.length, '没有截断');
  assert.ok(/落盘|read_file|\.txt/i.test(out), '没提示落盘路径：' + out.slice(0, 200));
});

t('尾部 flag 必须出现在返回文本里（不能被截断吃掉）', () => {
  const out = persistToolResult(big, { maxChars: 2000, dir: DIR, id: 'trunc2' });
  assert.ok(out.includes(FLAG), 'flag 被截掉了，AI 会误以为没解出来。返回文本末尾：' + out.slice(-300));
});

t('落盘文件内容完整（AI 可按路径回读）', () => {
  const out = persistToolResult(big, { maxChars: 2000, dir: DIR, id: 'trunc3' });
  const m = out.match(/([A-Za-z]:[\\/][^\s`'"]+\.txt)/);
  assert.ok(m, '返回文本里找不到落盘路径：' + out.slice(0, 300));
  const p = m[1];
  assert.ok(fs.existsSync(p), '落盘文件不存在：' + p);
  const full = fs.readFileSync(p, 'utf8');
  assert.strictEqual(full.length, big.length, '落盘内容被截断了');
  assert.ok(full.includes(FLAG), '落盘文件里也没有 flag');
});

t('短结果原样返回（不落盘、不改写）', () => {
  const small = 'short output ' + FLAG;
  const out = persistToolResult(small, { maxChars: 24000, dir: DIR, id: 'trunc4' });
  assert.strictEqual(out, small, '短结果被改写了');
});

t('负向断言：maxChars 很小时，中段内容确实会丢（证明"首尾保留"是必要设计）', () => {
  const mid = 'a'.repeat(5000) + 'MIDDLE_MARKER' + 'b'.repeat(5000) + FLAG;
  const out = persistToolResult(mid, { maxChars: 500, dir: DIR, id: 'trunc5' });
  // 中段标记预期被省掉 —— 这正是为什么必须保证"尾部可见"
  const middleVisible = out.includes('MIDDLE_MARKER');
  const tailVisible = out.includes(FLAG);
  assert.strictEqual(tailVisible, true, '尾部必须保留');
  console.log(`     中段可见=${middleVisible}（预期 false 或 true 都可，关键是尾部必须 true）`);
});

t('无 dir 时退化为纯 head+tail 预览，仍保留尾部', () => {
  const out = persistToolResult(big, { maxChars: 1500 });
  assert.ok(out.includes(FLAG), '无 dir 分支把尾部丢了：' + out.slice(-250));
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
