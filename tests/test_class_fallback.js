// 裸 .class 常量池兜底（40 题实测「Java逆向解密」：JEB 拉不起 + jadx 无输出 → 2 分钟放弃）
//   ① 行为验证：用真实 .class 结构的字节串喂给 parseClassSummary（从 main.js 抽取源码执行）
//   ② 接线验证：preload 暴露 classFileSummary；渲染层在 jadx 失败后调用并交 AI + finalizeSolve
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// ── 抽取 main.js 里的 parseClassSummary（函数级源码抽取，同 test_answer_shape 风格）──
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const start = mainSrc.indexOf('function parseClassSummary(');
if (start < 0) { console.log('FAIL 未找到 parseClassSummary'); process.exit(1); }
const lines = mainSrc.slice(start).split(/\r?\n/);
const fnLines = [];
let depth = 0, started = false;
for (const l of lines) {
  fnLines.push(l);
  for (const ch of l) { if (ch === '{') { depth++; started = true; } else if (ch === '}') depth--; }
  if (started && depth === 0) break;
}
const parseClassSummary = new Function('return (' + fnLines.join('\n') + ')')();

// ── 构造一个最小但结构完整的 .class ──
function u2(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; }
function u4(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; }
function utf8Tag(s) { const body = Buffer.from(s, 'utf8'); return Buffer.concat([Buffer.from([1]), u2(body.length), body]); }
// 常量池（count=9，索引 1..8）：
//  1 Utf8 'Foo'  2 Class→1  3 Utf8 'java/lang/Object'  4 Class→3
//  5 Utf8 'check'  6 Utf8 '()Ljava/lang/String;'  7 NameAndType 5:6  8 Utf8 'Code'
const pool = Buffer.concat([
  utf8Tag('Foo'), Buffer.concat([Buffer.from([7]), u2(1)]),
  utf8Tag('java/lang/Object'), Buffer.concat([Buffer.from([7]), u2(3)]),
  utf8Tag('check'), utf8Tag('()Ljava/lang/String;'),
  Buffer.concat([Buffer.from([12]), u2(5), u2(6)]),
  utf8Tag('Code'),
]);
const code = Buffer.from([0x2a, 0xb7, 0x00, 0x00]);
const codeAttr = Buffer.concat([
  u2(8), u4(2 + 2 + 4 + code.length + 2 + 2),   // name_idx=Code, len
  u2(1), u2(1), u4(code.length), code,           // max_stack/max_locals/code_len/code
  u2(0), u2(0),                                  // 异常表 0 / 方法属性 0
]);
const classFile = Buffer.concat([
  u4(0xCAFEBABE), u2(0), u2(61),                 // magic + 版本
  u2(9), pool,                                    // 常量池
  u2(0x0001), u2(2), u2(4),                       // access / this / super
  u2(0),                                          // 接口数
  u2(0),                                          // 字段数
  u2(1),                                          // 方法数
  u2(0x0009), u2(5), u2(6), u2(1), codeAttr,      // check()Ljava/lang/String; + Code
  u2(0),                                          // 类属性数
]);

console.log('[1] 行为：解析合成 .class');
{
  const r = parseClassSummary(classFile);
  ok(r.ok === true, '合法 .class 解析成功', JSON.stringify(r).slice(0, 120));
  ok(r.thisClass === 'Foo' && r.superClass === 'java.lang.Object', 'this/super 类名（/ → .）', `${r.thisClass}/${r.superClass}`);
  ok(r.version === '61.0', '版本号 major.minor', String(r.version));
  ok((r.methods || []).length === 1, '方法数 = 1');
  const m0 = (r.methods || [])[0] || {};
  ok(m0.name === 'check' && m0.desc === '()Ljava/lang/String;', '方法名+描述符', JSON.stringify(m0).slice(0, 80));
  ok(m0.codeHex === code.toString('hex'), 'Code 字节码 hex（含属性长度跳转正确）', String(m0.codeHex));
  ok((r.strings || []).includes('check') && (r.strings || []).includes('Code'), '字符串常量抽取');
}
console.log('\n[2] 行为：非 .class / 坏输入');
{
  ok(parseClassSummary(Buffer.from('hello world!')).ok === false, '非魔数 → ok:false');
  ok(parseClassSummary(Buffer.alloc(4)).ok === false, '过短 → ok:false');
  // 头部被截断（常量池后无内容）：仍应返回已解析部分而不是抛异常
  const truncated = classFile.slice(0, 4 + 4 + 2 + pool.length + 2);
  let survived = true, rt;
  try { rt = parseClassSummary(truncated); } catch (e) { survived = false; }
  ok(survived && rt && rt.ok === true && (rt.methods || []).length === 0, '截断文件 best-effort（不抛异常）');
}
console.log('\n[3] 接线');
{
  const pre = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');
  ok(/classFileSummary: \(filePath\) => ipcRenderer\.invoke\('class-file-summary'/.test(pre), 'preload 暴露 classFileSummary');
  ok(/ipcMain\.handle\('class-file-summary'/.test(mainSrc), '主进程注册 IPC');
  const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
  ok(/classFileSummary\(state\.currentFile\)/.test(appSrc), '渲染层在 jadx 失败分支调用');
  ok(/finalizeSolve\(res\.text, \{ source: 'ai-class-summary' \}\)/.test(appSrc), '结果走统一验证入口 finalizeSolve');
  ok(/\.class\$\/i\.test\(String\(state\.currentFile/.test(appSrc), '只在裸 .class 上启用');
}
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
