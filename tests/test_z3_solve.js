#!/usr/bin/env node
'use strict';

/**
 * test_z3_solve.js — z3_solve 工具的契约测试
 *
 * 覆盖：
 *  1. buildZ3SolveScript 生成的脚本能被真 python 执行并输出合法 JSON
 *  2. sat 场景：model 里每个变量值都真的满足约束（不是只看 status）
 *  3. unsat 场景：必须是 "unsat" 而不是 "error"（区分「无解」和「工具坏了」）
 *  4. 负向断言：故意把约束改矛盾，必须从 sat 变 unsat（证明测试能抓错）
 *  5. z3 未安装时的报错文案可操作（含 pip install 提示）
 *  6. main.js 的六处联动都注册了 z3_solve
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

/** 生成脚本 → 写临时文件 → 真跑 python → 解析 JSON */
function solve(constraints, opts) {
  const py = buildZ3SolveScript(constraints, opts || {});
  const tmp = path.join(os.tmpdir(), `z3t_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
  fs.writeFileSync(tmp, py, 'utf8');
  try {
    const out = execFileSync('python', [tmp], { encoding: 'utf8', timeout: 60000 });
    return JSON.parse(out.trim());
  } finally {
    try { fs.unlinkSync(tmp); } catch (e) { /* ignore */ }
  }
}

console.log('=== z3_solve 契约测试 ===');

t('sat：单变量解满足约束', () => {
  const r = solve("x = BitVec('x', 8)\ns.add(x ^ 0x12 == 0x34)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  assert.strictEqual(r.model.x ^ 0x12, 0x34);
});

t('sat：多变量逐字节约束 + as_text 拼接', () => {
  const r = solve(
    "f0 = BitVec('f0', 8)\nf1 = BitVec('f1', 8)\nf2 = BitVec('f2', 8)\nf3 = BitVec('f3', 8)\n" +
    "s.add(f0 == 0x66)\ns.add(f1 == 0x6c)\ns.add(f2 == 0x61)\ns.add(f3 == 0x67)"
  );
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  assert.strictEqual(r.as_text, 'flag', 'as_text 应为 flag，实际 ' + r.as_text);
  assert.strictEqual(r.as_bytes_hex, '666c6167');
});

t('sat：未显式声明 s 也能跑（工具自动建 Solver）', () => {
  const r = solve("y = BitVec('y', 16)\ns.add(y == 0x1234)");
  assert.strictEqual(r.status, 'sat', JSON.stringify(r));
  assert.strictEqual(r.model.y, 0x1234);
});

t('unsat：矛盾约束必须报 unsat，不能变成 error', () => {
  const r = solve("a = BitVec('a', 8)\ns.add(a == 1)\ns.add(a == 2)");
  assert.strictEqual(r.status, 'unsat', JSON.stringify(r));
  assert.ok(!r.error, 'unsat 不应带 error 字段');
  assert.ok(r.summary && r.summary.length > 0, 'unsat 应有人类可读说明');
});

// ── 负向断言：证明测试能抓错 ──
t('负向断言：同一约束组改矛盾后 status 必须翻转 sat→unsat', () => {
  const good = solve("z = BitVec('z', 8)\ns.add(z == 0x41)");
  assert.strictEqual(good.status, 'sat', '前置条件：可解版本应为 sat');
  const bad = solve("z = BitVec('z', 8)\ns.add(z == 0x41)\ns.add(z == 0x42)");
  assert.strictEqual(bad.status, 'unsat', '加矛盾后必须变 unsat');
  assert.notStrictEqual(good.status, bad.status, 'status 必须翻转，否则测试无效');
});

t('负向断言：约束代码语法错误必须报 error（不能静默当 sat/unsat）', () => {
  const r = solve('this is not python !!!');
  assert.strictEqual(r.status, 'error', JSON.stringify(r));
  assert.ok(/约束代码执行失败/.test(r.error || ''), '错误信息应指明是约束代码问题');
});

t('负向断言：约束代码引用未定义符号必须报 error', () => {
  const r = solve("q = BitVec('q', 8)\ns.add(q == undefined_symbol_xyz)");
  assert.strictEqual(r.status, 'error', JSON.stringify(r));
});

t('生成的脚本自带 z3 缺失提示（可操作性）', () => {
  const py = buildZ3SolveScript("x = BitVec('x', 8)", {});
  assert.ok(py.includes('pip install z3-solver'), '应提示如何安装 z3');
  assert.ok(py.includes('ImportError'), '应捕获 ImportError 而非崩溃');
});

t('timeout 参数被写进脚本', () => {
  const py = buildZ3SolveScript("x = BitVec('x', 8)", { timeout: 7 });
  assert.ok(py.includes('7000'), 'timeout 7 秒应生成为 7000ms');
});

// ── 六处联动检查 ──
t('main.js：z3_solve 已接入 schema', () => {
  const src = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  assert.ok(/name:\s*"z3_solve"/.test(src), 'schema 缺少 z3_solve');
  assert.ok(/constraints:\s*\{/.test(src), 'schema 缺少 constraints 参数');
});

t('main.js：z3_solve 已接入 dispatch', () => {
  const src = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  assert.ok(/case\s*'z3_solve':/.test(src), 'dispatch 缺少 z3_solve');
  assert.ok(/runZ3Solve\(/.test(src), '缺少 runZ3Solve 调用');
  assert.ok(/async function runZ3Solve/.test(src), '缺少 runZ3Solve 定义');
});

t('main.js：z3_solve 已接入 precheck', () => {
  const src = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  assert.ok(/name\s*===\s*'z3_solve'\s*&&/.test(src), 'precheck 缺少 z3_solve 校验');
});

t('main.js：z3_solve 已接入 toolLabel', () => {
  const src = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  assert.ok(/case\s*'z3_solve':\s*return\s*'符号求解'/.test(src), 'toolLabel 缺少 z3_solve');
});

t('z3-solve.js 真正 require 了 buildZ3SolveScript', () => {
  const src = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  assert.ok(/require\('\.\/z3-solve'\)/.test(src), 'main.js 必须 require z3-solve 模块');
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
