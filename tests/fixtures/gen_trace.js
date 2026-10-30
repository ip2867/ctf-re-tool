const fs = require('fs');
const path = require('path');
const { buildEmuTraceScript, summarizeTrace } = require(path.join(__dirname, '..', '..', 'electron', 'emu-trace.js'));

const dir = __dirname;
const bin = path.join(dir, 'dispatch_fixture');
const out = path.join(dir, 'trace.json');
const r = buildEmuTraceScript({
  binary: bin,
  start: 0x401000,      // 从入口（main）起，它会 call 进 check 再返回
  mode: 'function',
  out,
  max_insns: 200000,
});
if (r.error) { console.error('ERR', r.error); process.exit(1); }
const p = path.join(dir, 'run_trace.py');
fs.writeFileSync(p, r.script, 'utf8');
console.log('script written', p, r.script.length);

// 跑完后（若 trace.json 存在）打印摘要
if (process.argv.includes('--summary')) {
  try {
    const tr = JSON.parse(fs.readFileSync(out, 'utf8'));
    console.log('\n' + summarizeTrace(tr));
  } catch (e) { console.error('no trace yet:', e.message); }
}
