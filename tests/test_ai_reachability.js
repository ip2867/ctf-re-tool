#!/usr/bin/env node
'use strict';

/**
 * AI 提示词 → 工具 的**可达性**：新增能力必须在提示词或技能里被点名，
 * 否则模型不知道它存在，等于没做。
 *
 * 检查三层：
 *   ① tool schema（模型每轮都能看到）—— 工具名与关键参数
 *   ② system prompt（技能索引 / 分流表）—— 提到用哪个工具解决哪类问题
 *   ③ skills（按需 read_skill）—— 具体怎么用、有什么坑
 *
 * 本文件专门盯"本轮新增的能力"是否三层都通。
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

const read = (rel) => {
  const p = path.join(ROOT, rel);
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
};
const mainSrc = read('electron/main.js');
const appSrc = read('src/js/app.js');
const skillFiles = fs.readdirSync(path.join(ROOT, 'skills'), { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => ({ name: d.name, text: read(path.join('skills', d.name, 'SKILL.md')) }))
  .filter((s) => s.text);
const allSkills = skillFiles.map((s) => s.text).join('\n');

console.log('=== AI 可达性：新能力在 schema / 提示词 / 技能 三层是否都通 ===');

// schema 片段（粗略切片：从 name: "xxx" 到下一个 name: ）
function schemaDesc(name) {
  const key = `name: "${name}"`;
  const i = mainSrc.indexOf(key);
  if (i < 0) return '';
  const j = mainSrc.indexOf('name: "', i + key.length);
  return mainSrc.slice(i, j < 0 ? i + 4000 : j);
}

console.log('\nA) z3_solve');
t('schema 有定义且含关键参数', () => {
  const d = schemaDesc('z3_solve');
  assert.ok(d.length > 0, 'schema 缺 z3_solve');
  assert.ok(/constraints/.test(d), 'schema 缺 constraints 参数');
});
t('schema 描述点名 lookup_expr 与别名', () => {
  const d = schemaDesc('z3_solve');
  assert.ok(/lookup_expr/.test(d), 'schema 未提 lookup_expr —— AI 会自己拼 If 链踩 ULT 坑');
  assert.ok(/rotl|zext|lshr/.test(d), 'schema 未提别名');
});
t('schema 说明 unsat 是有效结果', () => {
  assert.ok(/unsat\s*是有效结果|unsat.*不是.*失败/.test(schemaDesc('z3_solve')),
    'schema 未说明 unsat 是有效结果 —— AI 会以为工具坏了');
});
t('schema 要求回代验证', () => {
  assert.ok(/回代验证/.test(schemaDesc('z3_solve')), 'schema 未要求回代验证');
});
t('技能里有 z3_solve 的完整用法', () => {
  assert.ok(allSkills.includes('z3_solve'), '所有技能都没提 z3_solve');
  const tooling = read('skills/ctf-reverse-tooling/SKILL.md');
  assert.ok(/lookup_expr/.test(tooling), 'tooling 技能没提 lookup_expr');
  assert.ok(/回代验证|回代原始校验/.test(tooling), 'tooling 技能没提回代验证');
});

console.log('\nB) 动调能力预检');
t('技能写明"SSH 通 ≠ 能调"与自检脚本', () => {
  const bin = read('skills/ctf-reverse-binary/SKILL.md');
  assert.ok(/kali_probe\.py/.test(bin), 'binary 技能没提自检脚本');
  assert.ok(/raise\(SIGSTOP\)/.test(bin), 'binary 技能没写正确的 ptrace 自检写法');
});
t('技能给出本机实测基线（避免沿用过期结论）', () => {
  const bin = read('skills/ctf-reverse-binary/SKILL.md');
  assert.ok(/qemu-riscv32/.test(bin), 'binary 技能没提 qemu-riscv32 缺失这一边界');
});

console.log('\nC) 算法识别（含新增常量指纹）');
t('技能写明 FindCrypt 插件不可用及替代', () => {
  const ci = read('skills/ctf-crypto-identify/SKILL.md');
  assert.ok(/findcrypt/i.test(ci), 'crypto-identify 没提 FindCrypt 状态');
  assert.ok(/scan_crypto/.test(ci), 'crypto-identify 没提 scan_crypto 替代');
});
t('新增指纹都写进技能速查表', () => {
  const ci = read('skills/ctf-crypto-identify/SKILL.md');
  for (const kw of ['ChaCha', 'SHA1', 'Blowfish', 'PRESENT']) {
    assert.ok(ci.includes(kw), `速查表缺 ${kw}`);
  }
});
t('技能写明大二进制里的常量只是线索（置信度降级）', () => {
  const ci = read('skills/ctf-crypto-identify/SKILL.md');
  assert.ok(/16MB|通用程序量级|low/.test(ci), '未说明体量降级规则');
});

console.log('\nD) 反调试');
t('技能含信号类反调试家族', () => {
  const ad = read('skills/ctf-antidebug/SKILL.md');
  for (const kw of ['SIGILL', 'SIGFPE', 'fork', 'rdtsc']) {
    assert.ok(ad.includes(kw), `antidebug 缺 ${kw}`);
  }
});
t('技能含综合绕过优先级（换环境优先）', () => {
  const ad = read('skills/ctf-antidebug/SKILL.md');
  assert.ok(/Unicorn|Qiling/.test(ad), '未提换执行环境');
  assert.ok(/优先级/.test(ad), '未给优先级');
});

console.log('\nE) 技能路由（模型靠 description 决定是否加载）');
t('每个技能 description 都存在且非空', () => {
  for (const s of skillFiles) {
    const m = s.text.match(/^description:\s*(.+)$/m);
    assert.ok(m && m[1].trim().length > 10, `${s.name} 缺 description`);
  }
});
t('本轮有实质改动的技能，description 覆盖了正文新增内容', () => {
  const checks = [
    ['ctf-crypto-identify', ['PRNG', 'LCG']],
    ['ctf-reverse-tooling', ['z3_solve', 'Unicorn']],
    ['ctf-antidebug', ['SIGILL|信号', '沙箱|VM']],
  ];
  for (const [name, kws] of checks) {
    const s = skillFiles.find((x) => x.name === name);
    assert.ok(s, `技能 ${name} 不存在`);
    const desc = (s.text.match(/^description:\s*(.+)$/m) || [])[1] || '';
    for (const kw of kws) {
      const re = new RegExp(kw);
      assert.ok(re.test(desc), `${name} 的 description 未覆盖 "${kw}" —— 该知识不可达`);
    }
  }
});

console.log('\nF) 提示词侧：工具名是否出现在分流/导航里');
t('z3_solve 在技能或提示词中被点到（不是只存在于 schema）', () => {
  const where = [appSrc, allSkills].filter((s) => s.includes('z3_solve')).length;
  assert.ok(where >= 1, 'z3_solve 只存在于 schema，AI 不知道何时该用');
});
t('负向断言：schema 里的工具数必须等于技能里被点名的子集之外仍有覆盖', () => {
  const names = [...mainSrc.matchAll(/name:\s*"([a-z0-9_]+)"/g)].map((m) => m[1]);
  const uniq = [...new Set(names)];
  assert.ok(uniq.length >= 50, `工具数异常：${uniq.length}`);
  const mentioned = uniq.filter((n) => allSkills.includes(n) || appSrc.includes(n));
  console.log(`     ${mentioned.length}/${uniq.length} 个工具在技能/提示词中被点名`);
  // 不要求全部点名（部分工具靠 schema 描述自解释），但核心求解类必须有
  for (const core of ['z3_solve', 'scan_crypto', 'extract_payload', 'run_python']) {
    assert.ok(mentioned.includes(core), `核心工具 ${core} 只在 schema 里，缺使用指引`);
  }
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
