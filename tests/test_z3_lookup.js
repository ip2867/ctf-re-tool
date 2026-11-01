#!/usr/bin/env node
'use strict';

/**
 * test_z3_lookup.js — z3_solve 的查表辅助（lookup_expr）契约测试
 *
 * 背景（实测踩坑）：把 256 字节 S 盒展开成 z3 的 If 树时，若写
 *     If(v < table[mid][0], left, right)
 * z3 会按**有符号**比较 BitVec 与 int。索引 >= 0x80 被当成负数，
 * 导致前 128 项全部走错分支：实测 128/256 项查错，
 * 外部表现是"约束明明有解却报 unsat"，极难定位。
 * 正确写法是 ULT(v, BitVecVal(k, 8))（无符号比较）。
 */

const assert = require('assert');
const path = require('path');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');

const ROOT = path.join(__dirname, '..');
const { buildZ3SolveScript } = require(path.join(ROOT, 'electron', 'z3-solve.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}

function solve(constraints, opts) {
  const py = buildZ3SolveScript(constraints, opts || {});
  const tmp = path.join(os.tmpdir(), `z3l_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
  fs.writeFileSync(tmp, py, 'utf8');
  try {
    return JSON.parse(execFileSync('python', [tmp], { encoding: 'utf8', timeout: 120000 }).trim());
  } finally {
    try { fs.unlinkSync(tmp); } catch (e) { /* ignore */ }
  }
}

console.log('=== z3 查表辅助 lookup_expr ===');

t('lookup_expr 全索引正确（JSON 输出）', () => {
  const r = solve(`
SBOX = [(i * 37 + 11) % 256 for i in range(256)]
TBL = list(enumerate(SBOX))
bad = 0
for c in range(256):
    if simplify(lookup_expr(BitVecVal(c, 8), TBL)).as_long() != SBOX[c]:
        bad += 1
s.add(BitVecVal(bad, 32) == 0)
`);
  assert.strictEqual(r.status, 'sat', 'lookup_expr 有错误项: ' + JSON.stringify(r).slice(0, 200));
});

t('lookup_expr 能反向求解（已知值反推索引）', () => {
  const r = solve(`
SBOX = [(i * 37 + 11) % 256 for i in range(256)]
TBL = list(enumerate(SBOX))
s.add(lookup_expr(BitVec('x', 8), TBL) == SBOX[0x42])
`);
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  assert.strictEqual(r.model.x, 0x42, '应反解出索引 0x42');
});

// ── 负向断言：证明"有符号比较"确实会错，即坑是真的 ──
t('负向断言：有符号比较 v<int 会导致高位索引查错（坑的真实性）', () => {
  // 同一张表，用有符号写法统计错误数；必须 > 0，否则这个坑根本不存在
  const r = solve(`
SBOX = [(i * 37 + 11) % 256 for i in range(256)]
TBL = list(enumerate(SBOX))
def lk_signed(v, tbl):
    if len(tbl) == 1:
        return BitVecVal(tbl[0][1], 8)
    m = len(tbl) // 2
    return If(v < tbl[m][0], lk_signed(v, tbl[:m]), lk_signed(v, tbl[m:]))
bad = 0
for c in range(256):
    if simplify(lk_signed(BitVecVal(c, 8), TBL)).as_long() != SBOX[c]:
        bad += 1
badn = BitVec('bad_signed', 32)
s.add(badn == bad)
`);
  assert.strictEqual(r.status, 'sat', JSON.stringify(r).slice(0, 200));
  const bad = r.model.bad_signed;
  assert.ok(bad > 0, '有符号版本本应查错若干项，实测 bad=0 说明坑无法复现，测试无效');
  console.log('      （有符号版本查错 ' + bad + '/256 项 —— 坑已复现）');
});

t('负向断言：修复后（ULT）错误数必须为 0', () => {
  const r = solve(`
SBOX = [(i * 37 + 11) % 256 for i in range(256)]
TBL = list(enumerate(SBOX))
bad = 0
for c in range(256):
    if simplify(lookup_expr(BitVecVal(c, 8), TBL)).as_long() != SBOX[c]:
        bad += 1
badn = BitVec('bad_ult', 32)
s.add(badn == bad)
`);
  assert.strictEqual(r.status, 'sat');
  assert.strictEqual(r.model.bad_ult, 0, 'ULT 版本仍有查错项');
});

t('随机打乱的魔改 S 盒也能正确查表', () => {
  const r = solve(`
import random
random.seed(7)
SBOX = list(range(256)); random.shuffle(SBOX)
TBL = list(enumerate(SBOX))
bad = 0
for c in range(256):
    if simplify(lookup_expr(BitVecVal(c, 8), TBL)).as_long() != SBOX[c]:
        bad += 1
badn = BitVec('bad_shuf', 32)
s.add(badn == bad)
`);
  assert.strictEqual(r.status, 'sat');
  assert.strictEqual(r.model.bad_shuf, 0, '魔改 S 盒查表有错误');
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
