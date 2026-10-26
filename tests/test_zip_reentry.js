// ZIP 手包重复进入（40 题实测：平台批量重拉同一附件 → 旧实现直接 return，
// 整轮被短路成秒级 no-verified-flag；10 轮连跑 10 次同一道题的次生原因之一）
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r/g, '');

console.log('[1] 重复进入改为复用已解压主文件');
{
  // 抽取整个 analyzeZipHandout 函数体做断言（复用探测在 addLog 之前，不能只看标记后窗口）
  const start = appSrc.indexOf('async function analyzeZipHandout');
  const fnLines = appSrc.slice(start).split('\n');
  const body = [];
  let depth = 0, started = false;
  for (const l of fnLines) {
    body.push(l);
    for (const ch of l) { if (ch === '{') { depth++; started = true; } else if (ch === '}') depth--; }
    if (started && depth === 0) break;
  }
  const fn = body.join('\n');
  ok(/state\._zipHandoutMain = state\._zipHandoutMain \|\| new Map\(\)/.test(fn), '记录 zip → 主文件映射');
  ok(/直接复用已解压主文件继续求解/.test(fn), '重复进入走复用分支（不再直接 return）');
  ok(!/同一压缩包已处理过，跳过（防循环）/.test(fn), '旧的"跳过"文案已移除');
  ok(/readFile\(prevMain\)/.test(fn), '复用前探测主文件仍存在（AV 隔离场景）');
  ok(/analyzeFile\(prevMain, \{ keepPlatformContext: true \}\)/.test(fn), '复用分支重走 analyzeFile');
  ok(/await autoAnalyze\(\)/.test(fn), '复用分支继续自动求解');
}
console.log('\n[2] 主文件丢失时回退为重新解压');
{
  ok(/重新解压/.test(appSrc), '有重新解压路径');
  ok(/state\._zipHandoutSeen\.delete\(normZip\)/.test(appSrc), '从 seen 集合移除后落到正常解压流程');
}
console.log('\n[3] 正常路径记录映射 + 防递归闸保留');
{
  ok(/state\._zipHandoutMain\.set\(normZip, String\(main\)\)/.test(appSrc), '选定主文件时写入映射');
  ok(/自引用压缩包/.test(appSrc) && /has\(normZip\)/.test(appSrc), '自引用/防递归检查仍在');
}
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
