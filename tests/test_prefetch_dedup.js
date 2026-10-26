// 知识库预取去重（40 题实测：多特征命中产出 4 条"动态调试 静态先行 断点…"词串，
// 整串 Set 去重挡不住 → 同一方法论页重复占满检索结果，提示词被灌到 111KB）
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r/g, '');

console.log('[1] 词级去重落地');
{
  ok(/const seenW = new Set\(\)/.test(appSrc) && /for \(const w of t\.split\(\/\\s\+\/\)\)/.test(appSrc), '按单词拆分去重');
  ok(/const terms = words\.slice\(0, 12\)/.test(appSrc), '去重后取前 12 个词');
  ok(!/\.\.\.new Set\(\[\.\.\.extra, \.\.\.feats, \.\.\.hits\]/.test(appSrc), '旧的整串 Set 去重已替换');
}

console.log('\n[2] 行为验证：重叠词串折叠');
{
  const fn = new Function('extra', 'feats', 'hits', 'ft', `
    const rawTerms = [...extra, ...hits, ...feats].map(s => String(s).trim()).filter(Boolean);
    const seenW = new Set();
    const words = [];
    for (const t of rawTerms) {
      for (const w of t.split(/\\s+/)) {
        const k = w.trim();
        if (k && !seenW.has(k)) { seenW.add(k); words.push(k); }
      }
    }
    const terms = words.slice(0, 12);
    if (!terms.length) terms.push(ft || 'reverse');
    return terms;
  `);
  const feats = [
    '动态调试 静态先行 断点 smc 自修改代码 窗口期',
    '动态调试 静态先行 断点 反调试 窗口期',
    '动态调试 静态先行 断点 gui 窗口期 32位 改内存',
    '动态调试 静态先行 断点 窗口期',
    'des sign',
  ];
  const t = fn([], feats, ['native'], 'PE');
  const dup = t.filter((w, i) => t.indexOf(w) !== i);
  ok(dup.length === 0, '无重复词', JSON.stringify(t));
  ok(t.length <= 12, '上限 12 词', String(t.length));
  ok(t.includes('native') && t.includes('des') && t.includes('smc') && t.includes('窗口期'), '类型词不被长特征词挤出、特征词增量保留');
  const empty = fn([], [], [], '');
  ok(empty.length === 1 && empty[0] === 'reverse', '空特征回退 reverse');
}
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
