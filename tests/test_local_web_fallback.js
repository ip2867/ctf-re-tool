// 验证"Burp 不可用 → 本地 HTML/JS 回退"：脚本抽取 + 线索统计必须给出实质内容。
// 实测（equation 题）：57KB equation.html 里算法全在内嵌 JS，旧逻辑因 Burp 起不来整题结束。
const fs = require('fs');
const p = require('path');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

// 复刻 analyzeLocalWebFile 的抽取逻辑（与实现保持同步）
function extractLocalWeb(raw, file) {
  let scripts = [];
  const isJs = /\.(js|mjs)$/i.test(file);
  if (isJs) scripts = [raw];
  else {
    const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = re.exec(raw)) !== null) {
      const body = m[1];
      if (body && body.trim().length > 40) scripts.push(body);
    }
    if (!scripts.length) scripts = [raw];
  }
  scripts.sort((a, b) => b.length - a.length);
  const picked = scripts.slice(0, 4);
  const clueRes = [
    [/CryptoJS|JSEncrypt|sm2|sm3|sm4|crypto\.subtle/gi, '密码库'],
    [/atob\(|btoa\(|base64/gi, 'Base64'],
    [/fromCharCode|charCodeAt|String\.fromCharCode/gi, '字符码变换'],
    [/\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*[,{]/, '常量数组'],
    [/\^=|<<|>>>/g, '位运算'],
    [/eval\(|Function\(/g, '动态执行（可能混淆）'],
  ];
  const clues = [];
  for (const [re, name] of clueRes) {
    const n = (raw.match(re) || []).length;
    if (n) clues.push(`${name}: ${n}`);
  }
  return { scripts, picked, clues, total: raw.length };
}

// 真样本改为可选：node tests/test_local_web_fallback.js --real <x.html>
// CI 只跑合成用例（不依赖本机 E: 盘）。
const realIdx = process.argv.indexOf('--real');
const sample = realIdx >= 0 ? String(process.argv[realIdx + 1] || '') : '';
if (!sample) {
  console.log('（未提供 --real <path>，仅跑合成用例）');
} else if (!fs.existsSync(sample)) {
  console.log('（样本不存在，仅跑合成用例）');
} else {
  console.log('[真实样本 equation.html]');
  const raw = fs.readFileSync(sample, 'utf8');
  const r = extractLocalWeb(raw, sample);
  ok(r.total > 10000, `读入 ${r.total} 字符`);
  ok(r.scripts.length >= 1, `提取 ${r.scripts.length} 段脚本`);
  ok(r.picked[0].length > 1000, `最长脚本 ${r.picked[0].length} 字符`);
  ok(r.clues.length >= 1, `线索: ${r.clues.join(', ')}`);
  const js = r.picked[0];
  ok(/charCodeAt|fromCharCode|atob|btoa|\^|eval|function/i.test(js), '脚本包含可分析代码');
}

console.log('\n[合成用例]');
{
  const html = `<html><body><script>
  function check(s){ var c=[]; for(var i=0;i<s.length;i++) c.push(s.charCodeAt(i)^0x12); return c; }
  var table=[12,34,56,78,90];
  </script><script>var x=atob("ZmxhZ3t0ZXN0fQ=="); var y=x.split("").map(function(c){return c.charCodeAt(0)});</script></body></html>`;
  const r = extractLocalWeb(html, 'x.html');
  ok(r.scripts.length === 2, `提取 ${r.scripts.length} 段`);
  ok(r.picked[0].length >= r.picked[1].length, '按长度降序');
  ok(r.clues.some(c => /字符码/.test(c)), '识别字符码变换');
  ok(r.clues.some(c => /Base64/.test(c)), '识别 Base64');
  ok(r.clues.some(c => /常量数组/.test(c)), '识别常量数组');
}
{
  const js = 'var k=[1,2,3]; function f(a){return a^0x5a;}';
  const r = extractLocalWeb(js, 'a.js');
  ok(r.scripts.length === 1 && r.scripts[0] === js, '.js 文件整体作为脚本');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
