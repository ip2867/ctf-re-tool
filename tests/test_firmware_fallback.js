// 验证 analyzeBIN 的本地兜底采集脚本（Kali 不可用时使用）。
// 直接抽取 app.js 里 localFirmwareProbe 的 Python 片段，对真实固件文件跑一遍。
const fs = require('fs');
const p = require('path');
const { execFileSync } = require('child_process');

const appSrc = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
// 必须从 localFirmwareProbe 内部定位：app.js 里还有另一处 `const py = [`（别的分析流程），
// 从文件开头找会抽到错误的脚本（实测拿到 "SIZE ... STR ..." 的输出）。
const fnStart = appSrc.indexOf('async function localFirmwareProbe');
if (fnStart < 0) throw new Error('未定位 localFirmwareProbe');
const s = appSrc.indexOf('const py = [', fnStart);
const e = appSrc.indexOf("].join('\\n');", s);
if (s < 0 || e < 0) throw new Error('未定位 localFirmwareProbe 的 Python 片段');
// 把 JS 数组字面量转成真实脚本：逐行取出单引号字符串
const block = appSrc.slice(s, e);
const pyLines = [...block.matchAll(/^\s*'((?:[^'\\]|\\.)*)',?$/gm)].map(m => m[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\'));
if (pyLines.length < 10) throw new Error('Python 片段解析失败，行数=' + pyLines.length);
const py = pyLines.join('\n');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

const sample = 'E:/ctf/pratice/ai/firmware/51475f91-7b90-41dd-81a3-8b82df4f29d0.bin';
console.log('样本:', sample);
if (!fs.existsSync(sample)) {
  console.log('（样本不存在，跳过实际执行）');
} else {
  const tmp = p.join(require('os').tmpdir(), 'fw_probe_test.py');
  fs.writeFileSync(tmp, py, 'utf8');
  let out;
  try { out = execFileSync('python', [tmp, sample], { encoding: 'utf8', timeout: 120000 }); }
  catch (err) { out = String(err.stdout || '') + String(err.stderr || ''); }
  const line = out.trim().split(/\r?\n/).filter(Boolean).pop() || '{}';
  let j = null;
  // 与实现一致：用 __FWPROBE__…__ENDFW__ 标记解析（strings 可能含换行/任意字节）
  const mm = out.match(/__FWPROBE__([\s\S]*?)__ENDFW__/);
  try { j = JSON.parse(mm ? mm[1] : '{}'); } catch (e2) { }
  if (!mm) console.log('  (输出片段)', out.slice(0, 400));
  ok(!!j, '输出为合法 JSON', out.slice(0, 300));
  if (j) {
    ok(j.bytes > 0, `读到字节数 ${j.bytes}`);
    ok(/^[0-9a-f]{2}( [0-9a-f]{2}){15}$/.test(j.magic || ''), `magic 16 字节: ${j.magic}`);
    ok(typeof j.strings === 'string' && j.strings.length > 0, `字符串 ${(j.strings || '').split('\n').length} 条`);
    ok(typeof j.entropy === 'string', `熵块输出: ${String(j.entropy).split('\n')[0]}`);
    // 关键：不能再是"四个空结果"
    ok(j.strings.length > 100 || j.entropy.length > 10, '至少有一项实质内容（不再是空）');
  }
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
