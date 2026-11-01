#!/usr/bin/env node
'use strict';

/**
 * 别名与辅助函数的**运行时**存在性测试。
 *
 * 背景：schema 描述与 skills 都在告诉 AI "可以直接用 lookup_expr / rotl / zext ..."，
 * 但这些名字只有在生成的脚本里真的被注入 `_g` 才可用。文档写了、实现漏了，
 * AI 就会撞 NameError 白跑一轮，而且没有任何测试会发现。
 *
 * 做法：把 buildZ3SolveScript 生成的脚本**真跑一遍**，在约束代码里逐名访问，
 * 任何一个名字不存在都会让 python 抛 NameError → status 变 error。
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const { buildZ3SolveScript } = require(path.join(ROOT, 'electron', 'z3-solve.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}

function solve(constraints, opts) {
  const py = buildZ3SolveScript(constraints, opts || {});
  const tmp = path.join(os.tmpdir(), `zt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
  fs.writeFileSync(tmp, py, 'utf8');
  try {
    return JSON.parse(execFileSync('python', [tmp], { encoding: 'utf8', timeout: 90000 }).trim());
  } finally {
    try { fs.unlinkSync(tmp); } catch (e) { /* ignore */ }
  }
}

// schema 描述与 skills 里承诺可用的小写别名（改这两处时必须同步改这里）
const ALIASES = ['rotl', 'rotr', 'rol', 'ror', 'lshr', 'ashr', 'zext', 'sext', 'extract', 'bswap32'];
// z3 原生名字必须可直达（from z3 import * 的符号被注入 _g）
const NATIVE = ['BitVec', 'BitVecVal', 'If', 'ULT', 'ZeroExt', 'SignExt', 'RotateLeft', 'RotateRight', 'LShR', 'Concat', 'Solver', 'sat', 'unsat'];

console.log('=== z3_solve 注入名字的运行时存在性 ===');

console.log('\nA) schema 描述承诺的小写别名');
t(`${ALIASES.length} 个别名全部可调用`, () => {
  const missing = [];
  for (const name of ALIASES) {
    const r = solve(`${name}   # 仅在名字不存在时抛 NameError`);
    if (r.status === 'error') missing.push(name + ' → ' + (r.error || ''));
  }
  assert.strictEqual(missing.length, 0, '缺失：' + missing.join('; '));
  console.log('     ' + ALIASES.join(', '));
});

console.log('\nB) z3 原生名字必须可直达');
t(`${NATIVE.length} 个原生名字全部可见`, () => {
  const missing = [];
  for (const name of NATIVE) {
    const r = solve(`${name}   # 期望已注入`);
    if (r.status === 'error') missing.push(name);
  }
  assert.strictEqual(missing.length, 0, '缺失：' + missing.join(', '));
});

console.log('\nC) 别名语义正确（不是空壳）');
t('rotl(x,8) 在 8 位下是恒等、在 16 位下把高字节移到低字节', () => {
  const r = solve("a = BitVec('a', 16)\ns.add(a == 0x1234)\ns.add(rotl(a, 8) == 0x3412)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
});
t('lshr 是逻辑右移（高位补 0），不是算术右移', () => {
  // 0x80 逻辑右移 1 = 0x40；算术右移会得 0xC0
  const r = solve("b = BitVec('b', 8)\ns.add(b == 0x80)\ns.add(lshr(b, 1) == 0x40)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  const r2 = solve("b = BitVec('b', 8)\ns.add(b == 0x80)\ns.add(lshr(b, 1) == 0xC0)");
  assert.strictEqual(r2.status, 'unsat', 'lshr 若被实现成算术右移，这条会变 sat');
});
t('ashr 是算术右移（高位补符号位）', () => {
  const r = solve("c = BitVec('c', 8)\ns.add(c == 0x80)\ns.add(ashr(c, 1) == 0xC0)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
});
t('zext 把 8 位扩到 32 位（高位补 0）', () => {
  const r = solve("d = BitVec('d', 8)\ns.add(d == 0xff)\ns.add(zext(d, 24) == 0x000000ff)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
});
t('bswap32 真的反转 4 字节', () => {
  const r = solve("e = BitVec('e', 32)\ns.add(e == 0x11223344)\ns.add(bswap32(e) == 0x44332211)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
});

console.log('\nD) lookup_expr 语义与负向断言（本轮修的核心 bug）');
// 做法：把索引取成**具体常量** BitVecVal(i,8)，再 simplify 求值 —— 直接看查表结果，
// 不必走 solver（solver 只能证明"存在解"，看不出"查错了几项"）。
// 统计量必须装进**命名的**符号变量才会出现在 model 里（BitVecVal 常量不进 model）。
const countBad = (exprLine, label) => {
  const r = solve([
    'TABLE = [(i, (i*7+3) & 0xff) for i in range(256)]',
    '_bad = []',
    'for i in range(256):',
    `    got = simplify(${exprLine}).as_long()`,
    '    if got != ((i*7+3) & 0xff): _bad.append(i)',
    'bad_count = BitVec("bad_count", 32)',
    's.add(bad_count == len(_bad))',
  ].join('\n'));
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  console.log(`     ${label}: 查错 ${r.model.bad_count}/256 项`);
  return r.model.bad_count;
};
t('lookup_expr 在全部 256 个索引上都取到正确的表值', () => {
  const bad = countBad('lookup_expr(BitVecVal(i, 8), TABLE)', 'lookup_expr');
  assert.strictEqual(bad, 0, 'lookup_expr 查错的索引数应为 0，实际 ' + bad);
});
t('负向断言：手写 If(v < K) 的有符号版本必须查错（证明坑真实存在）', () => {
  const r = solve([
    'TABLE = [(i, (i*7+3) & 0xff) for i in range(256)]',
    'def naive(var, table):',
    '    if len(table) == 1: return BitVecVal(table[0][1], 8)',
    '    mid = len(table)//2',
    '    return If(var < table[mid][0], naive(var, table[:mid]), naive(var, table[mid:]))',
    '_bad = []',
    'for i in range(256):',
    '    got = simplify(naive(BitVecVal(i, 8), TABLE)).as_long()',
    '    if got != ((i*7+3) & 0xff): _bad.append(i)',
    'bad_count = BitVec("bad_count", 32)',
    's.add(bad_count == len(_bad))',
  ].join('\n'));
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  assert.ok(r.model.bad_count > 0, '有符号版本竟然全对 —— 该负向断言已失效，需重写');
  console.log(`     有符号版本查错 ${r.model.bad_count}/256 项`);
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
