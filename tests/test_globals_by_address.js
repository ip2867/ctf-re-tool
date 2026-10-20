// 按地址读全局表单测：名字交集不可靠（关键表是 dword 数组，符号名未必是 global）。
const fs = require('fs');
const path = require('path');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

function grab(name) {
  const startIdx = appSrc.search(new RegExp('^(?:async\\s+)?function\\s+' + name + '\\s*\\(', 'm'));
  if (startIdx < 0) throw new Error('未找到函数 ' + name);
  const lines = appSrc.slice(startIdx).split(/\r?\n/);
  const out = [];
  let depth = 0, started = false;
  for (const line of lines) {
    out.push(line);
    for (const ch of line) {
      if (ch === '{') { depth++; started = true; }
      else if (ch === '}') depth--;
    }
    if (started && depth === 0) break;
  }
  return out.join('\n');
}

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const mod = { exports: {} };
new Function('module', 'exports',
  grab('parseAddrValue') + '\n' + grab('probeStride') + '\n' + grab('collectGlobalRegions') + '\n'
  + 'module.exports = { collectGlobalRegions, probeStride, parseAddrValue };'
)(mod, mod.exports);
const { collectGlobalRegions } = mod.exports;

console.log('[1] 从反编译文本抽 ≤ 0x41F000 与 0x41F200（resolver 解析符号）');
{
  const text = `  v1 = dword_41F000[0];\n  v2 = *(_DWORD *)0x41F200;\n  sub_401000();\n  v3 = 0x10;`;
  const resolver = (n) => (n === 'dword_41F000' ? '0x41F000' : '');
  const imageMap = {
    format: 'pe', imageBase: 0x400000, sizeOfImage: 0x30000,
    sections: [
      { name: '.text', va: 0x1000, vsize: 0x10000, rawSize: 0x10000, executable: true, writable: false },
      { name: '.data', va: 0x1f000, vsize: 0x8000, rawSize: 0x8000, executable: false, writable: true },
    ],
  };
  const regions = collectGlobalRegions([text], imageMap, { resolver });
  const addrs = regions.map(r => r.addr.toLowerCase());
  ok(addrs.includes('0x41f000'), `含 0x41f000（实际 ${addrs.join(',')}）`);
  ok(addrs.includes('0x41f200'), `含 0x41f200（实际 ${addrs.join(',')}）`);
  ok(regions.length === 2, `两个 region（实际 ${regions.length}）`);
  ok(regions.every(r => 'stride' in r), '每个 region 含 stride');
  ok(regions.some(r => Array.isArray(r.referrers) && r.referrers.includes('dword_41F000')), 'referrers 记录符号名');
  ok(regions.every(r => Number(r.size) <= 65536), '单区间 ≤65536');
}

console.log('\n[2] 可执行节里的地址必须被排除');
{
  const text = `v = *(int*)0x401234;`;
  const imageMap = {
    format: 'pe', imageBase: 0x400000, sizeOfImage: 0x30000,
    sections: [{ name: '.text', va: 0x1000, vsize: 0x10000, executable: true, writable: false }],
  };
  const regions = collectGlobalRegions([text], imageMap, {});
  ok(regions.length === 0, `代码节地址不进入数据表（实际 ${regions.length}）`);
}

console.log('\n[3] main.js 静态断言：case list_globals + normalizeIdaArgs 生成 queries{count:500}');
{
  ok(/case 'list_globals'/.test(mainSrc), "存在 case 'list_globals'");
  const seg = mainSrc.slice(mainSrc.indexOf("case 'list_globals':", mainSrc.indexOf('function normalizeIdaArgs')));
  ok(/queries/.test(seg.slice(0, 800)), 'normalizeIdaArgs 生成 queries');
  ok(/q\.count === undefined\) q\.count = 500/.test(seg.slice(0, 1200)), '缺省 count=500');
  ok(/q\.filter/.test(seg.slice(0, 1200)) && /q\.offset/.test(seg.slice(0, 1200)), 'filter/offset 也收进 queries');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
