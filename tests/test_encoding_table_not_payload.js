// 回归：Base64/Base91 变表是**算法数据**，不能被描述成"可执行载荷/本层是 loader"。
// 实测（cnbragon、kanxue-ctf-gxustudent）：Data 段里的 Base91 变表被当 shellcode，
// summary 断言"本层是 loader、必须提取下一层"，而同一次扫描里 AES 已是 high 置信度
// → AI 放着确定的主逻辑不逆，去 dump 不存在的 payload。
const fs = require('fs');
const p = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader');

// payloadDescription 未被 loader 导出（依赖 DOM 无关，但需要单独抽取）
const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const s = mainSrc.indexOf('function payloadDescription(');
if (s < 0) throw new Error('未定位 payloadDescription');
// 用花括号配对找函数真实结尾。不能按"下一个 function"切：函数后面紧跟的是注释块，
// 那样会把后面的 require('./crypto-tables') 一起塞进 eval（报 require is not defined）。
let depth = 0, e = -1, inStr = null, esc = false;
for (let i = mainSrc.indexOf('{', s); i < mainSrc.length; i++) {
  const c = mainSrc[i];
  if (inStr) {
    if (esc) { esc = false; continue; }
    if (c === '\\') { esc = true; continue; }
    if (c === inStr) inStr = null;
    continue;
  }
  if (c === '"' || c === "'" || c === '`') { inStr = c; continue; }
  if (c === '{') depth++;
  else if (c === '}') { depth--; if (depth === 0) { e = i + 1; break; } }
}
if (e < 0) throw new Error('未找到 payloadDescription 结尾');
const mod = { exports: {} };
// payloadDescription 在容器分支里会调 payloadRecipe —— 一并抽取，否则 B 组抛 ReferenceError。
const s2 = mainSrc.indexOf('function payloadRecipe(');
let d2 = 0, e2 = -1, inS = null, es = false;
for (let i = mainSrc.indexOf('{', s2); i < mainSrc.length; i++) {
  const c = mainSrc[i];
  if (inS) {
    if (es) { es = false; continue; }
    if (c === '\\') { es = true; continue; }
    if (c === inS) inS = null;
    continue;
  }
  if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
  if (c === '{') d2++;
  else if (c === '}') { d2--; if (d2 === 0) { e2 = i + 1; break; } }
}
if (s2 < 0 || e2 < 0) throw new Error('未定位 payloadRecipe');
new Function('module', 'exports', mainSrc.slice(s2, e2) + '\n' + mainSrc.slice(s, e)
  + '\nmodule.exports = { payloadDescription, payloadRecipe };')(mod, mod.exports);
const { payloadDescription } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('A) 编码表描述不得声称"本层是 loader"');
{
  const p1 = {
    type: 'table', label: 'Base91变表', offset: 0x1e9f0, length: 91, confidence: 'medium',
    head: 'ABCDEFGH', encode: { kind: 'b91-table', key: 40, stride: 1, period: 1 },
  };
  const d = payloadDescription(p1, 1);
  ok(!/loader|壳/.test(d.note), '不出现 loader/壳 断言');
  ok(!/提取下一层|下一层载荷/.test(d.note), '不要求提取下一层');
  ok(/自定义表|变表/.test(d.note), '指出是自定义编码表');
  ok(/不要因为它的存在去 dump/.test(d.note), '显式劝阻误提取');
  ok(!/^\s*$/.test(d.evidence) && /偏移/.test(d.evidence), '证据包含偏移');
}

console.log('B) 真实 PE 载荷仍应判定为 loader');
{
  const p2 = {
    type: 'pe', offset: 0x2000, length: 4096, confidence: 'high',
    head: '4d5a9000', encode: { kind: 'xor', key: 0x5a, stride: 1, period: 1 },
  };
  const d = payloadDescription(p2, 1);
  ok(/loader/.test(d.note), 'PE 载荷仍提示 loader');
  ok(/提取/.test(d.note), '仍要求提取');
}

console.log('C) 真实样本：编码表存在时不应把整个扫描结论变成"本层为 loader"');
{
  // 真样本校验改为可选：node tests/test_encoding_table_not_payload.js --real <path>
  // CI 不依赖本机样本目录（干净 checkout 没有 E: 盘）。
  const realIdx = process.argv.indexOf('--real');
  const sample = realIdx >= 0 ? String(process.argv[realIdx + 1] || '') : '';
  if (!sample) { console.log('  (未提供 --real <path>，跳过真样本校验)'); }
  else if (!fs.existsSync(sample)) { console.log('  (样本缺失，跳过)'); }
  else {
    const r = scanCryptoFingerprints(sample);
    ok(!!r.success, '扫描成功');
    const tables = (r.payloads || []).filter(x => x.type === 'table');
    const realPayloads = (r.payloads || []).filter(x => x.type !== 'table');
    ok(tables.length >= 1, `检出编码表 ${tables.length} 张`);
    ok(realPayloads.length === 0, `无可执行载荷（实得 ${realPayloads.length}）`);
    const aes = (r.summary || []).some(x => /AES/.test(x.algo) && x.confidence === 'high');
    ok(aes, 'AES 仍为 high 置信度');
  }
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
