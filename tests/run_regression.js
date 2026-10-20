// 回归题集运行器：node tests/run_regression.js
// 目的（PLAN Phase 1.3/1.4）：把"类级通用"从设计/单测层面的结论，变成**多题实测**结论。
//
// 每道题 = 一个目录，含：
//   · 原始题目文件（**只放原题，不放解密后的中间产物**，否则测的是"已知答案"）
//   · expect.json（预期链路：应命中什么 / 不应误报什么 / 耗时上限）
//
// 判定分两类，含义不同、都重要：
//   · 正例（summaryMustContain / payloads 非空）：能力**有没有生效**
//   · 负例（summaryMustNotContain / payloads 为空）：能力**会不会误伤**
// 回归题集的价值一半在正例，一半在负例——负例就是"不误导 AI"的护栏。
const fs = require('fs'), p = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader.js');
const pcap = require('../electron/pcap.js');

const root = p.join(__dirname, 'regression');
let pass = 0, fail = 0, skipped = 0;
const rows = [];

function norm(s) { return String(s || ''); }
function summaryText(r) { return (r.summary || []).map(s => norm(s.algo) + ' ' + norm(s.evidence)).join('\n'); }

for (const caseId of fs.readdirSync(root).sort()) {
  const dir = p.join(root, caseId);
  if (!fs.statSync(dir).isDirectory()) continue;
  const expPath = p.join(dir, 'expect.json');
  if (!fs.existsSync(expPath)) { console.log(`⚠️  ${caseId}: 缺 expect.json，跳过`); continue; }
  const exp = JSON.parse(fs.readFileSync(expPath, 'utf8'));

  // kind:'pcap' —— 抓包不是"伴随文件"：它本身就是该 case 的被测对象。
  // 这类 case 不依赖 .gitignore 排除的题目二进制（pcap 已入库），因此必须真的跑，不能跳过。
  if (exp.kind === 'pcap' && exp.pcap) {
    const pcapFile = p.join(dir, exp.pcap.file || 'evidence.pcap');
    if (!fs.existsSync(pcapFile)) {
      console.log(`❌ ${caseId}: 缺少 pcap 文件（${exp.pcap.file}）`);
      fail++; rows.push([caseId, 'FAIL', '缺少 pcap']);
      continue;
    }
    const problems = [];
    let r;
    const t0 = Date.now();
    try { r = pcap.analyzePcap(pcapFile); } catch (err) {
      console.log(`❌ ${caseId}: pcap 解析抛错 ${err.message}`);
      fail++; rows.push([caseId, 'ERROR', err.message]);
      continue;
    }
    const ms = Date.now() - t0;
    if (exp.pcap.magic && r.magic !== exp.pcap.magic) problems.push(`magic ${r.magic} ≠ ${exp.pcap.magic}`);
    if (exp.pcap.packets != null && r.packets !== exp.pcap.packets) problems.push(`packets ${r.packets} ≠ ${exp.pcap.packets}`);
    if (exp.pcap.flows != null && r.flows.length !== exp.pcap.flows) problems.push(`flows ${r.flows.length} ≠ ${exp.pcap.flows}`);
    if (exp.pcap.http != null && r.http !== exp.pcap.http) problems.push(`http ${r.http} ≠ ${exp.pcap.http}`);
    for (const port of (exp.pcap.ports || [])) {
      if (!r.flows.some(f => f.ports.includes(port))) problems.push(`缺少端口 ${port}`);
    }
    const okPcap = problems.length === 0;
    if (okPcap) pass++; else fail++;
    rows.push([caseId, okPcap ? 'PASS' : 'FAIL', problems.join('; ') || `${ms}ms`]);
    console.log(`${okPcap ? '✅' : '❌'} ${caseId.padEnd(34)} ${String(ms).padStart(6)}ms  ` +
      `kind=pcap packets=${r.packets} flows=${r.flows.length} http=${r.http}` +
      (okPcap ? '' : `\n     └─ ${problems.join('; ')}`));
    continue;
  }

  const mainPath = p.join(dir, exp.main || fs.readdirSync(dir).find(f => f !== 'expect.json'));
  // 题目二进制不入库（体积/版权）：本地未准备时跳过，不算失败。
  if (!fs.existsSync(mainPath)) {
    console.log(`⏭  ${caseId}: 本地未准备题目文件（${exp.main}），跳过`);
    skipped++;
    continue;
  }

  const t0 = Date.now();
  let r;
  try { r = scanCryptoFingerprints(mainPath); } catch (e) {
    console.log(`❌ ${caseId}: 扫描抛错 ${e.message}`); fail++; rows.push([caseId, 'ERROR', e.message]); continue;
  }
  const ms = Date.now() - t0;
  const e = exp.expect || {};
  const stext = summaryText(r);
  const problems = [];

  // 正例：必须命中
  for (const want of (e.summaryMustContain || [])) {
    if (!stext.includes(want)) problems.push(`未命中预期「${want}」`);
  }
  // 负例：不得误报
  for (const bad of (e.summaryMustNotContain || [])) {
    if (stext.includes(bad)) problems.push(`误报「${bad}」`);
  }
  // payload 精确匹配（type + offset + encode 子集）
  if (Array.isArray(e.payloads)) {
    const got = r.payloads || [];
    if (e.payloads.length === 0 && got.length) {
      problems.push(`不该有 payload，实际 ${got.length} 个：` + got.map(x => x.type + '@0x' + x.offset.toString(16)).join(','));
    }
    for (const want of e.payloads) {
      const hit = got.find(g => {
        if (want.type && g.type !== want.type) return false;
        if (want.offset && '0x' + g.offset.toString(16) !== want.offset) return false;
        if (want.encode) {
          const ge = g.encode || {};
          for (const k of Object.keys(want.encode)) {
            const wv = want.encode[k], gv = ge[k];
            if (Array.isArray(wv) || Array.isArray(gv)) {
              if (JSON.stringify(wv) !== JSON.stringify(gv)) return false;
            } else if (wv !== gv) return false;
          }
        }
        return true;
      });
      if (!hit) problems.push(`未找到预期 payload ${JSON.stringify(want)}`);
    }
  }
  // 性能
  if (e.maxMs && ms > e.maxMs) problems.push(`超时 ${ms}ms > ${e.maxMs}ms`);

  const ok = problems.length === 0;
  if (ok) pass++; else fail++;
  rows.push([caseId, ok ? 'PASS' : 'FAIL', problems.join('; ') || `${ms}ms`]);
  console.log(`${ok ? '✅' : '❌'} ${caseId.padEnd(34)} ${String(ms).padStart(6)}ms  ` +
    `payloads=${(r.payloads || []).length}  summary=[${(r.summary || []).map(s => s.algo).join(', ')}]` +
    (ok ? '' : `\n     └─ ${problems.join('; ')}`));
}

console.log('\n================ 回归题集结果 ================');
for (const [id, st, note] of rows) console.log(`${st === 'PASS' ? '✅' : '❌'} ${id.padEnd(34)} ${note}`);
console.log(`\n${pass}/${pass + fail} 道题通过` + (skipped ? `（${skipped} 道本地未准备，已跳过）` : ''));
process.exit(fail ? 1 : 0);
