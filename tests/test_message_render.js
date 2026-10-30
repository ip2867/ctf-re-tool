// 消息渲染回归：伪 Markdown 不能破坏内容，也不能引入 XSS
//
// 实测问题（AI 输出里几乎每段都有 *）：
//   · `2*3*4` → `2<em>3</em>4`（乘号变斜体）
//   · `int *p` → 指针解引用被当斜体
//   · ```python ... ``` 围栏代码块被拆成零散 <code>，缩进与换行全丢
//   · 溢出风险：`/\*(.*?)\*/g` 对 6 万字符的流式文本逐帧全量重跑
//
// 同时必须守住：先转义再替换（否则 AI/工具输出里的 <script> 会被执行）。
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function fnBody(name) {
  const i = appSrc.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('未找到 function ' + name);
  let j = appSrc.indexOf('{', i), depth = 0, inS = null, esc = false, inRe = false, inReCls = false;
  const prevSig = (k) => { let x = k - 1; while (x >= 0 && /\s/.test(appSrc[x])) x--; return x >= 0 ? appSrc[x] : ''; };
  for (let k = j; k < appSrc.length; k++) {
    const c = appSrc[k];
    if (inS) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === inS) inS = null; continue; }
    if (inRe) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === '[') { inReCls = true; continue; }
      if (c === ']') { inReCls = false; continue; }
      if (c === '/' && !inReCls) inRe = false;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '/') { const p = prevSig(k); if (p === '' || /[([{,;:=!&|?+\-*%<>~^]/.test(p)) { inRe = true; continue; } continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return appSrc.slice(i, k + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

// escapeHtml 用 DOM API，纯 Node 下模拟一个最小实现（与浏览器 textContent/innerHTML 等价）
const shim = `
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
`;
const api = {};
new Function('out', shim + fnBody('formatMessage') + '\nout.formatMessage = formatMessage;')(api);
const F = api.formatMessage;

console.log('[1] 乘号/指针不被当成斜体（AI 输出里几乎每段都有 *）');
{
  ok(F('2*3*4 = 24').includes('2*3*4'), '`2*3*4` 原样保留', F('2*3*4 = 24'));
  ok(!/<em>/.test(F('2*3*4 = 24')), '乘号不产生 <em>');
  ok(F('int *p = &a;').includes('int *p'), 'C 指针解引用原样保留', F('int *p = &a;'));
  ok(F('def f(*args, **kw)').includes('*args'), 'Python *args 原样保留', F('def f(*args, **kw)'));
  ok(F('a * b * c').includes('a * b * c'), '带空格的乘法原样保留', F('a * b * c'));
}

console.log('\n[2] 合法标记仍然生效');
{
  ok(/<strong>粗体<\/strong>/.test(F('**粗体**')), '**粗体** → <strong>', F('**粗体**'));
  ok(/<em>斜体<\/em>/.test(F('这是 *斜体* 文本')), '*斜体* → <em>', F('这是 *斜体* 文本'));
  ok(/<code>x<\/code>/.test(F('用 `x` 表示')), '`x` → <code>', F('用 `x` 表示'));
}

console.log('\n[3] 围栏代码块整体保留（不拆成零散 <code>，缩进与换行不丢）');
{
  const md = '看这段：\n```python\nfor i in range(3):\n    print(i)\n```\n结束';
  const html = F(md);
  ok(/<pre class="code-block"><code>/.test(html), '生成 <pre><code> 块', html.slice(0, 160));
  ok(html.includes('    print(i)'), '缩进保留（4 空格）', JSON.stringify(html.slice(0, 200)));
  ok(html.includes('for i in range(3):'), '代码内容完整');
  ok(!/<\/code><code>/.test(html), '没有被拆成多个 <code>（旧实现会）', html.slice(0, 200));
  // 代码块内的 * 不能被当斜体
  const md2 = '```c\nint *p = 0;\n```';
  ok(F(md2).includes('int *p = 0;'), '代码块内的 * 不被当标记');
}

console.log('\n[4] 安全：先转义再替换，不引入 XSS');
{
  const evil = '<script>alert(1)</script>';
  const out = F(evil);
  ok(!/<script>/.test(out), '脚本标签被转义', out);
  ok(/&lt;script&gt;/.test(out), '转义为实体');

  const evil2 = '**<img src=x onerror=alert(1)>**';
  const out2 = F(evil2);
  ok(!/<img/.test(out2), '粗体里的 img 标签被转义', out2);

  // 代码块内容也必须转义（这里最容易漏）
  const evil3 = '```\n<script>alert(2)</script>\n```';
  const out3 = F(evil3);
  ok(!/<script>/.test(out3), '代码块内的脚本标签也被转义', out3.slice(0, 200));
}

console.log('\n[5] 结构性断言：不再有"裸单星全局替换"');
{
  const body = fnBody('formatMessage');
  ok(!/\.replace\(\/\\\*\(\.\*\?\)\\\*\/g/.test(body), '已移除 `\\*(.*?)\\*` 全局贪婪替换');
  ok(/code-block/.test(body), '实现了围栏代码块处理');
  ok(/escapeHtml/.test(body), '仍然先转义');
  // 转义必须发生在标记替换之前
  const iEsc = body.indexOf('escapeHtml');
  const iStrong = body.indexOf('<strong>');
  ok(iEsc >= 0 && iStrong > iEsc, 'escapeHtml 在 <strong> 替换之前（顺序错即 XSS）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
