// flag 提取的"前缀截断/漏掉"回归
//
// 实测（DancingKeys.sys，ByteCTF 2019 驱动逆向）：
//   真实答案 bytectf{d0f20eff6fc4f6060776c8ca63319a1e}
//   本地复现脚本打印的是 ctf{d0f20eff6fc4f6060776c8ca63319a1e}   ← 前缀 "byte" 被吃掉
//   而验证闭环用「答案出现在复现输出里」的子串判定，截断版也能通过 → 错的 flag 被标成已验证。
//
// 两个不同的 root cause，都在"用已知前缀列表匹配 flag"这个思路上：
//   ① Python 侧 FLAG_RE（app.js 内嵌脚本）：`(?:nctf|flag|ctf|...)\{` 无左侧边界
//      → bytectf{} 从 ctf 处开始匹配，结果被截断。
//   ② JS 侧 extractFlags：`\b(?:flag|ctf|...)\{` 有左侧边界
//      → bytectf{} 里 ctf 左边是 e，\b 不成立 → 整条匹配不到，flag 直接丢。
//
// 正确做法是用「标识符 + 花括号」的通用形态，左侧禁止紧邻标识符字符。
// 这样既不截断也不遗漏，而且不依赖"记得往列表里加前缀"。
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// ---- 从 app.js 精确切出 extractFlags 及其依赖的常量/函数 ----
function sliceBetween(startMarker, endMarker) {
  const a = appSrc.indexOf(startMarker);
  if (a < 0) throw new Error('未找到起点 ' + startMarker);
  const b = appSrc.indexOf(endMarker, a);
  if (b < 0) throw new Error('未找到终点 ' + endMarker);
  return appSrc.slice(a, b);
}

// extractFlags 依赖：DECOY_FLAG_RE / isDecoyFlag / DEGENERATE_DIGESTS / isDegenerateDigest
// （looksLikeFlag 也依赖它们；这里只验证 extractFlags 的提取行为）
const depsSrc = sliceBetween('const DECOY_FLAG_RE', 'function looksLikeFlag(');
const extractSrc = sliceBetween('function extractFlags(', '// ---- IDA 结果归一化助手 ----');
const api = {};
new Function('out', depsSrc + '\n' + extractSrc + '\nout.extractFlags = extractFlags;')(api);

console.log('[1] 前缀尾部是已知前缀时，不得截断');
{
  // bytectf 尾部是 ctf；xmctf 尾部也是 ctf
  // ⚠️ 花括号内至少 3 字符：更短的会被占位符过滤器正确拦下（那是另一条规则，不是本测试的靶子）
  const r1 = api.extractFlags('bytectf{d0f20eff6fc4f6060776c8ca63319a1e}');
  ok(r1.length === 1 && r1[0] === 'bytectf{d0f20eff6fc4f6060776c8ca63319a1e}',
    'bytectf{...} 完整提取（不截成 ctf{...}）', JSON.stringify(r1));

  const r2 = api.extractFlags('xmctf{abcdef}');
  ok(r2.length === 1 && r2[0] === 'xmctf{abcdef}', 'xmctf{...} 完整提取', JSON.stringify(r2));

  const r3 = api.extractFlags('the answer is bytectf{deadbeef} ok');
  ok(r3.length === 1 && r3[0] === 'bytectf{deadbeef}', '句子中间的 bytectf{...} 也完整', JSON.stringify(r3));
}

console.log('\n[2] 常见前缀照旧工作');
{
  const cases = [
    ['flag{abc123}', 'flag{abc123}'],
    ['ctf{abc123}', 'ctf{abc123}'],
    ['nctf{abcdef}', 'nctf{abcdef}'],
    ['picoCTF{abcdef}', 'picoCTF{abcdef}'],
    ['dasctf{abcdef}', 'dasctf{abcdef}'],
  ];
  for (const [inp, want] of cases) {
    const r = api.extractFlags(inp);
    ok(r.length === 1 && r[0] === want, `提取 ${want}`, JSON.stringify(r));
  }
}

console.log('\n[3] 不误报：非 flag 形态不提取');
{
  const bad = ['no flag here', 'a{bc}', 'hello world', '函数 sub_140001000 返回 0'];
  for (const b of bad) {
    const r = api.extractFlags(b);
    ok(r.length === 0, `不提取 ${JSON.stringify(b)}`, JSON.stringify(r));
  }
  // 占位符仍要过滤
  ok(api.extractFlags('flag{...}').length === 0, '占位符 flag{...} 不提取');
  ok(api.extractFlags('flag{fake_this}').length === 0, '诱饵 flag{fake_this} 不提取');
}

console.log('\n[4] 端到端：app.js 内嵌的 Python FLAG_RE 也不能截断');
{
  // 找到含 FLAG_RE 定义的模板字符串，按 JS 语义求值，再用 python 实跑
  let found = null;
  for (let i = 0; i < appSrc.length; i++) {
    if (appSrc[i] !== '`') continue;
    let j = i + 1;
    while (j < appSrc.length) {
      if (appSrc[j] === '\\') { j += 2; continue; }
      if (appSrc[j] === '`') break;
      j++;
    }
    const body = appSrc.slice(i + 1, j);
    if (body.includes('FLAG_RE = re.compile(')) { found = body; break; }
    i = j;
  }
  ok(!!found, '找到含 FLAG_RE 的 Python 模板');
  if (found) {
    // 模板里含 ${payload} 之类插值：求值时给个占位值即可，我们只关心 FLAG_RE 那段文本
    const stubbed = found.replace(/\$\{[^}]*\}/g, 'STUB');
    const rendered = new Function('return `' + stubbed + '`;')();
    const ri = rendered.indexOf('FLAG_RE = re.compile(');
    const seg = rendered.slice(ri, rendered.indexOf('def printable', ri));
    ok(/\(\?<!\[A-Za-z0-9_\]\)/.test(seg), 'Python FLAG_RE 带左侧标识符边界断言', seg.slice(0, 200));

    const py = 'import re\n' + seg + `
tests = [
    (b"bytectf{d0f20eff6fc4f6060776c8ca63319a1e}", b"bytectf{d0f20eff6fc4f6060776c8ca63319a1e}"),
    (b"xmctf{yy}", b"xmctf{yy}"),
    (b"the answer is bytectf{deadbeef} ok", b"bytectf{deadbeef}"),
    (b"flag{abc123}", b"flag{abc123}"),
    (b"nctf{xx}", b"nctf{xx}"),
]
bad = 0
for src, want in tests:
    m = FLAG_RE.search(src)
    got = m.group(0) if m else None
    if got != want:
        bad += 1
        print("MISMATCH", src, "want", want, "got", got)
for src in (b"no flag here", b"a{bc}"):
    if FLAG_RE.search(src):
        bad += 1
        print("FALSE POSITIVE", src)
print("BAD=%d" % bad)
`;
    const pyPath = path.join(require('os').tmpdir(), 'ctf_flagre_' + Date.now() + '.py');
    fs.writeFileSync(pyPath, py, 'utf8');
    let out = '';
    try {
      out = execSync('python -I "' + pyPath + '"', { encoding: 'utf8', windowsHide: true, timeout: 30000 });
    } catch (e) {
      out = 'ERR ' + (e.stdout || '') + (e.stderr || '');
    }
    try { fs.unlinkSync(pyPath); } catch (e) { /* 清理失败无影响 */ }
    ok(/BAD=0/.test(out), 'Python FLAG_RE 实跑：5 个正例全对、2 个负例不误报', out.slice(0, 300));
  }
}

console.log('\n[5] 结构性断言：不允许再出现"已知前缀列表 + 无左边界"的写法');
{
  // FLAG_RE 现在写成多行 re.compile(...)；截取到下一个空行之前即可
  const a = appSrc.indexOf('FLAG_RE = re.compile(');
  ok(a > 0, '找到 FLAG_RE 定义');
  const b = appSrc.indexOf('def printable', a);
  const flagReBlock = a > 0 && b > a ? appSrc.slice(a, b) : '';
  ok(!/^FLAG_RE = re\.compile\(rb"\(\?:nctf\|/.test(flagReBlock.trim()),
    'FLAG_RE 不再是"裸前缀列表"开头（那样必截断）', flagReBlock.slice(0, 140));
  ok(/\(\?<!\[A-Za-z0-9_\]\)/.test(flagReBlock), 'FLAG_RE 带左侧标识符边界', flagReBlock.slice(0, 140));

  const exFn = extractSrc;
  ok(/\(\?<!\[A-Za-z0-9_\]\)/.test(exFn), 'extractFlags 用左侧标识符边界（不是 \\b + 前缀列表）');
  ok(!/\\b\(\?:flag\|ctf\|nssctf/.test(exFn), 'extractFlags 不再用"\\b + 已知前缀列表"（bytectf 会漏）');
}

console.log('\n[6] 内嵌 Python 模板里不得出现 JS 风格注释（会让整个脚本语法错误）');
{
  // 实测教训：往 FLAG_RE 上方加说明时写成了 `// ...`，这段文本在模板字符串里
  // 会原样成为 Python 源码 → `SyntaxError: invalid character '⚠'`，
  // 于是**所有**解密复现全线失败（连正确的 AES 用例都报"未命中"）。
  // 这类错误只在真正跑 Python 时暴露，看 JS 是不会报的。
  // 注释写在 FLAG_RE 之前，取"注释块起点 → def printable"整段。
  // ⚠️ 文件是 CRLF，用 '\n\n' 查找会落空，必须同时兼容 \r\n\r\n。
  const fa = appSrc.indexOf('FLAG_RE = re.compile(');
  const nb = appSrc.indexOf('def printable', fa);
  const from = Math.max(0, fa - 3000);
  const before = appSrc.slice(from, fa);
  const iCRLF = before.lastIndexOf('\r\n\r\n');
  const iLF = before.lastIndexOf('\n\n');
  const iBlank = Math.max(iCRLF, iLF);
  const cStart = iBlank >= 0 ? from + iBlank : from;
  const block = (nb > fa) ? appSrc.slice(cStart, nb) : '';
  ok(block.length > 0, '取到 FLAG_RE 前后的模板片段', 'len=' + block.length);
  ok(!/^\s*\/\//m.test(block), 'Python 模板内不用 // 注释', (block.match(/^\s*\/\/.*$/m) || [''])[0].slice(0, 100));
  ok(/^\s*#/m.test(block), '用的是 Python 的 # 注释');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
