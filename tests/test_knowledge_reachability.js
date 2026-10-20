// 知识库"真的被用上"的回归：不只检查页面存在，而是模拟 prefetchKnowledge
// 的检索词选择 + wikiSearch 打分，验证题面特征真的能把对应方法论拉进提示词。
//
// 为什么需要这个测试：知识库最常见的失效不是"文件丢了"，而是
// 「写了、但自动预取选词选不到」——页面存在、检索函数正常，可 AI 永远看不到。
// 本测试锁住三条链路：
//   1. 特征词表（POOL / FEATURES）真的能被题面命中
//   2. wikiSearch 打分后目标页进入前 max 名
//   3. 无动态需求的普通题**不会**误命中（避免提示词被无关方法论污染）
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (cond, name, detail) => {
  if (cond) { pass++; console.log('  OK   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (detail ? '  → ' + detail : '')); }
};

const root = path.join(__dirname, '..');
const wikiRoot = path.join(root, 'wiki');
const appSrc = fs.readFileSync(path.join(root, 'src', 'js', 'app.js'), 'utf8');

// ── 复刻生产 wikiSearch ──
function listWiki() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.md')) out.push({ path: p, rel: path.relative(wikiRoot, p).replace(/\\/g, '/') });
    }
  };
  walk(wikiRoot);
  return out;
}
const PAGES = listWiki();
function search(q, max = 4) {
  const terms = String(q).toLowerCase().split(/\s+/).filter(Boolean);
  const res = [];
  for (const p of PAGES) {
    let content = '';
    try { content = fs.readFileSync(p.path, 'utf8'); } catch (e) { continue; }
    const low = content.toLowerCase();
    const meta = ((content.match(/^---\n([\s\S]*?)\n---/) || [])[1] || '').toLowerCase();
    const head = (content.split('\n').find(l => /^#\s/.test(l)) || '').toLowerCase();
    let s = 0;
    for (const t of terms) {
      s += Math.min(low.split(t).length - 1, 10) + (meta.includes(t) ? 8 : 0) + (head.includes(t) ? 4 : 0);
    }
    if (s > 0) res.push({ rel: p.rel, score: s });
  }
  return res.sort((a, b) => b.score - a.score).slice(0, max);
}

// ── 复刻 prefetchKnowledge 的选词逻辑（从真实源码解析，避免测试与实现漂移）──
const poolBlock = (appSrc.match(/const POOL = \[([\s\S]*?)\];/) || [])[1] || '';
const POOL = [...poolBlock.matchAll(/'([^']+)'/g)].map(m => m[1]);
const featBlock = (appSrc.match(/const FEATURES = \[([\s\S]*?)\n    \];/) || [])[1] || '';
const FEATURES = [...featBlock.matchAll(/\[\/(.+?)\/[a-z]*,\s*\n?\s*'([^']+)'\]/gs)].map(m => ({
  re: new RegExp(m[1]), terms: m[2],
}));
function pickTerms(haystack, fileType) {
  const hay = String(haystack).toLowerCase();
  const hits = POOL.filter(t => hay.includes(t));
  const feats = [];
  for (const f of FEATURES) { try { if (f.re.test(hay)) feats.push(f.terms); } catch (e) { } }
  const ft = String(fileType || '').toUpperCase();
  if (/PE|ELF|EXE|BIN/.test(ft)) hits.push('native');
  return [...new Set([...feats, ...hits].map(s => String(s).trim()).filter(Boolean))].slice(0, 6);
}

console.log('\n[1] 动态调试特征能被识别并检索到方法论页');
const POSITIVE = [
  {
    name: 'SMC 自修改代码',
    fileType: 'PE',
    hay: 'VirtualProtect(section, size, PAGE_EXECUTE_READWRITE, &old);\n// 循环逐字节 xor 后写回 .text\nmemcpy(decoded, buf, len); // 自解码',
  },
  {
    name: '反调试',
    fileType: 'PE',
    hay: 'if (IsDebuggerPresent()) exit(1);\nNtQueryInformationProcess(h, 7, &dbg, sizeof(dbg), 0);',
  },
  {
    name: 'GUI CrackMe',
    fileType: 'PE',
    hay: 'int __stdcall WinMain(...) { DialogBoxParam(hInst, MAKEINTRESOURCE(101), 0, DialogFunc, 0); }\ncase WM_COMMAND: check_input();\nGetDlgItemTextA(hDlg, 1001, buf, 64);',
  },
  {
    name: '时间相关校验',
    fileType: 'PE',
    hay: 'DWORD t = GetTickCount();\nSYSTEMTIME st; GetSystemTime(&st);',
  },
  {
    name: 'ELF ptrace 反调试',
    fileType: 'ELF',
    hay: 'if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) return 1;\n// 检查 /proc/self/status TracerPid',
  },
];
for (const c of POSITIVE) {
  const terms = pickTerms(c.hay, c.fileType);
  const res = search(terms.join(' '), 4);
  const idx = res.findIndex(x => /method_static_first_dynamic/.test(x.rel));
  ok(idx === 0, `${c.name} → 方法论页第 1 位`, idx >= 0 ? '实际第 ' + (idx + 1) : '未命中；检索词=' + terms.join(' '));
}

console.log('\n[2] 无动态需求的普通题不误命中（避免污染提示词）');
const NEGATIVE = [
  { name: '纯算法题（RC4 + memcmp）', fileType: 'PE', hay: 'main sub_401000 rc4 memcmp flag correct' },
];
for (const c of NEGATIVE) {
  const terms = pickTerms(c.hay, c.fileType);
  const res = search(terms.join(' '), 4);
  const idx = res.findIndex(x => /method_static_first_dynamic/.test(x.rel));
  ok(idx < 0, `${c.name} → 不拉动态调试方法论`, idx >= 0 ? '误命中第 ' + (idx + 1) : '');
}

console.log('\n[3] 特征词表本身覆盖动态调试信号');
for (const [name, needle] of [
  ['SMC/自修改', '自修改'],
  ['反调试', '反调试'],
  ['GUI/消息循环', '消息循环'],
  ['时间校验', 'gettickcount'],
]) {
  ok(new RegExp(needle, 'i').test(featBlock), `FEATURES 含 ${name} 识别规则`);
}
ok(/动态调试/.test(poolBlock), 'POOL 含「动态调试」检索词');
ok(/断点/.test(poolBlock), 'POOL 含「断点」检索词');

console.log('\n[4] 方法论页与提示词互指');
const methodSrc = fs.readFileSync(path.join(wikiRoot, 'reverse', 'method_static_first_dynamic.md'), 'utf8');
ok(/入场条件/.test(methodSrc), '方法论页含入场条件');
ok(/method_static_first_dynamic\.md/.test(appSrc), '提示词指向方法论页');
// 提示词里的路径必须与实际文件一致（大小写/目录都要对）
const pathInPrompt = (appSrc.match(/wiki_read\("([^"]*method_static_first_dynamic[^"]*)"\)/) || [])[1];
ok(!!pathInPrompt && fs.existsSync(path.join(wikiRoot, pathInPrompt)),
  '提示词中的 wiki_read 路径真实存在', pathInPrompt || '未找到引用');

console.log('\n[5] 技能层可达性（AI 选技能的入口）');
const binarySkill = fs.readFileSync(path.join(root, 'skills', 'ctf-reverse-binary', 'SKILL.md'), 'utf8');
const binaryDesc = (binarySkill.match(/^description:\s*(.+)$/m) || [])[1] || '';
// 技能描述是 AI 决定"要不要加载这个技能"的唯一依据；动态调试必须出现在描述里
ok(/动态调试/.test(binaryDesc), 'ctf-reverse-binary 的描述提到动态调试');
ok(/断点|入场/.test(binaryDesc), '描述里点出断点/入场这类触发词');

const dispatchSkill = fs.readFileSync(path.join(root, 'skills', 'ctf-dispatch', 'SKILL.md'), 'utf8');
ok(/运行时值/.test(dispatchSkill), 'ctf-dispatch 分流表含"需要运行时值"一类');
ok(/method_static_first_dynamic\.md/.test(dispatchSkill), '分流表指向方法论页');
ok(/取证不是探索/.test(dispatchSkill), '解题顺序原则写明动态调试的定位');
// 顺序：静态取数必须排在动态调试之前
const idxStatic = dispatchSkill.indexOf('静态取数并锁定函数');
const idxDyn = dispatchSkill.indexOf('定向动态调试(5分钟)');
ok(idxStatic > 0 && idxDyn > idxStatic, '顺序原则里静态取数排在动态调试之前');

console.log('\n[6] 提示词的知识库导航完整性');
// reverse/ 下的方法篇原先不在提示词清单里（只列非 reverse/ 的手法页），
// AI 只看到"40+ 篇题库"不会想到里面还有方法论 → 必须显式点名。
const methodPagesBlock = (appSrc.match(/const METHOD_PAGES = \[([\s\S]*?)\]\.filter/) || [])[1] || '';
const methodPages = [...methodPagesBlock.matchAll(/'([^']+)'/g)].map(m => m[1]);
ok(methodPages.length >= 5, '提示词点名了方法论专页', '实际 ' + methodPages.length + ' 条');
ok(methodPages.includes('reverse/method_static_first_dynamic.md'), '点名了动态调试方法论');
let missingPage = null;
for (const rel of methodPages) {
  if (!fs.existsSync(path.join(wikiRoot, rel))) { missingPage = rel; break; }
}
ok(!missingPage, '点名的路径全部真实存在', missingPage || '');
ok(/方法论专页/.test(appSrc), '提示词用「方法论专页」与题库区分开');
ok(/method_static_first_dynamic\.md\\?`?（动态调试入场条件）/.test(appSrc),
  '提示词明确引导到动态调试方法论');

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
