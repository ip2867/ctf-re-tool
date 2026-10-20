// 知识库/技能一致性：动态调试方法论必须可被检索到，且索引与正文对得上。
// 防止"文档写了但 AI 搜不到"——这是知识库最常见的静默失效。
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (cond, name, detail) => {
  if (cond) { pass++; console.log('  OK   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (detail ? '  → ' + detail : '')); }
};

const root = path.join(__dirname, '..');
const wikiRoot = path.join(root, 'wiki');

// [1] 方法论页存在，front matter 结构完整
console.log('\n[1] 动态调试方法论页结构');
const methodPath = path.join(wikiRoot, 'reverse', 'method_static_first_dynamic.md');
ok(fs.existsSync(methodPath), '方法页存在');
const methodSrc = fs.readFileSync(methodPath, 'utf8');
const fm = (methodSrc.match(/^---\n([\s\S]*?)\n---/) || [])[1] || '';
for (const field of ['title', 'category', 'tags', 'keywords', 'one_liner', 'attack_chain', 'failed_attempts', 'lesson']) {
  ok(new RegExp('^' + field + ':', 'm').test(fm), `front matter 含 ${field}`);
}

// [2] 关键论断必须写进正文（防止后续改写把核心纪律弄丢）
console.log('\n[2] 核心纪律正文可查');
const mustHave = [
  ['动态调试是取证手段', '是取证手段'],
  ['四条入场条件', '四条全满足'],
  ['断点选址优先级', '断点选址'],
  ['窗口期', '窗口期'],
  ['窗口期三种应对', '入口先停'],
  ['一次命中取数清单', '一次命中的取数清单'],
  ['离线复算', '离线复算'],
  ['SMC 正确顺序', '解密循环结束处下断点'],
  ['PIE 重定位', '重定位后的地址'],
  ['运行态不能单步', '运行态'],
  ['Frida 同样适用', 'Frida'],
];
for (const [name, needle] of mustHave) {
  ok(methodSrc.includes(needle), name, '缺少关键词: ' + needle);
}

// [3] 能通过 wikiSearch 的打分逻辑命中（复刻生产实现的核心）
console.log('\n[3] 生产检索逻辑可命中');
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
const pages = listWiki();
function search(q) {
  const terms = String(q).toLowerCase().split(/\s+/).filter(Boolean);
  const res = [];
  for (const p of pages) {
    let content = '';
    try { content = fs.readFileSync(p.path, 'utf8'); } catch (e) { continue; }
    const low = content.toLowerCase();
    const meta = ((content.match(/^---\n([\s\S]*?)\n---/) || [])[1] || '').toLowerCase();
    let s = 0;
    for (const t of terms) {
      s += Math.min(low.split(t).length - 1, 10) + (meta.includes(t) ? 8 : 0);
    }
    if (s > 0) res.push({ rel: p.rel, score: s });
  }
  return res.sort((a, b) => b.score - a.score);
}
const queries = [
  '动态调试 入场条件',
  '静态先行 断点',
  '断点设了不命中',
  'PIE 重定位 断点',
  '窗口期',
  '什么时候该动态调试',
  'suspend 运行态',
];
for (const q of queries) {
  const top = search(q)[0];
  ok(!!top && /method_static_first_dynamic/.test(top.rel), `"${q}" → 命中方法页`, top ? top.rel : '无结果');
}

// [4] 索引已登记（AI-SEARCH-INDEX 与 reverse/_INDEX 都要有入口）
console.log('\n[4] 索引登记');
const aiIndex = fs.readFileSync(path.join(wikiRoot, 'AI-SEARCH-INDEX.md'), 'utf8');
const revIndex = fs.readFileSync(path.join(wikiRoot, 'reverse', '_INDEX.md'), 'utf8');
ok(/method_static_first_dynamic\.md/.test(aiIndex), 'AI-SEARCH-INDEX 已链接方法页');
// 必须落在"动态调试"这个技术标签小节内（而不是散落在别处）
const dbgSection = (aiIndex.match(/### 动态调试[\s\S]*?(?=\n### |\n## )/) || [''])[0];
ok(/method_static_first_dynamic\.md/.test(dbgSection), 'AI-SEARCH-INDEX 归在「动态调试」小节');
ok(/关键词/.test(dbgSection), '该小节给出检索关键词');
ok(/method_static_first_dynamic/.test(revIndex), 'reverse/_INDEX 已登记条目');
ok(/动态调试/.test(revIndex), 'reverse/_INDEX 条目描述含"动态调试"');

// [5] 技能页必须把入场条件放在动态调试章节开头
console.log('\n[5] ctf-reverse-binary 技能同步');
const skillPath = path.join(root, 'skills', 'ctf-reverse-binary', 'SKILL.md');
const skill = fs.readFileSync(skillPath, 'utf8');
ok(/入场条件/.test(skill), '技能页含"入场条件"');
ok(/动态调试不是探索手段，是取证手段/.test(skill), '技能页写明核心纪律');
ok(/写不出第 3 条/.test(skill), '技能页给出可执行的判定');
ok(/method_static_first_dynamic\.md/.test(skill), '技能页指向方法论页');
ok(/list_funcs/.test(skill) && /decompile/.test(skill), '技能页给出静态取数的具体工具');
ok(/窗口期/.test(skill), '技能页含窗口期');
ok(/SMC/.test(skill) && /解密循环结束处/.test(skill), '技能页含 SMC 正确顺序');

// [6] 提示词必须把入场条件放在 start 之前
console.log('\n[6] 提示词门禁');
const appSrc = fs.readFileSync(path.join(root, 'src', 'js', 'app.js'), 'utf8');
const idxEnter = appSrc.indexOf('入场条件：静态没跑完，不要启动调试器');
const idxStart = appSrc.indexOf('不动态能不能拿到答案');
ok(idxEnter > 0, '提示词含入场条件段');
ok(idxEnter > 0 && idxStart > idxEnter, '入场条件排在"先问"之前');
ok(/写不出第 3 条/.test(appSrc), '提示词给出可执行判定');
ok(/断点选址优先级/.test(appSrc), '提示词含断点选址优先级');
ok(/窗口期/.test(appSrc), '提示词含窗口期');
ok(/一次命中的取数清单/.test(appSrc), '提示词含取数清单');

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
