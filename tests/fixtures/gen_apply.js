const fs = require('fs');
const path = require('path');
const { buildApplyTraceScript, summarizeTrace } = require(path.join(__dirname, '..', '..', 'electron', 'emu-trace.js'));

const dir = __dirname;
const tr = JSON.parse(fs.readFileSync(path.join(dir, 'trace.json'), 'utf8'));

// 1) 回填脚本能否吃下这份真实轨迹
const r = buildApplyTraceScript({ trace: tr });
if (r.error) { console.error('APPLY ERR', r.error); process.exit(1); }
fs.writeFileSync(path.join(dir, 'run_apply.py'), r.args.code, 'utf8');
console.log('APPLY ok: indTargets=%d edges=%d ranges=%d truncated=%s',
  r.stats.indTargets, r.stats.edges, r.stats.ranges, JSON.stringify(r.stats.truncated));

// 2) 回填脚本里必须出现真实的目标地址
const targets = tr.indirect_sites.flatMap(s => s.targets.map(t => parseInt(t.dst, 16)));
console.log('DISTINCT IND TARGETS =', new Set(targets).size);
console.log('sample targets in python:', /0x402080|4202624/.test(r.args.code), r.args.code.includes('IND_TARGETS'));

// 3) 摘要可读性
console.log('\n--- summarizeTrace ---');
console.log(summarizeTrace(tr));
