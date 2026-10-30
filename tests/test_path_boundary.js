// AI 工具路径边界回归
//
// 实测问题：渲染层走的 IPC `read-file` / `write-file` 有 isSensitivePath +
// isPathAllowedForWrite 两道校验，但 AI 工具调用的 `read_file` / `write_file`
// 走的是两个裸函数，**完全没有校验**。
// 后果：模型（可能被题目附件里的文本诱导）可以直接读 config.json 拿到
// apiKey / ctf2Token / kali 口令，也可以往启动目录/系统目录写文件。
//
// 这不是"AI 本来就能跑 bash"所以无所谓的论证——bash 是显式的高权限工具，
// 而 read_file/write_file 看起来像"读题目文件"的安全工具，权限却和 bash 一样，
// 属于"声明与实际权限不符"，必须补齐。
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function fnBody(name) {
  let i = mainSrc.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('未找到 function ' + name);
  if (mainSrc.slice(Math.max(0, i - 6), i) === 'async ') i -= 6;
  let p = mainSrc.indexOf('(', i), pDepth = 0, j = -1;
  for (let k = p; k < mainSrc.length; k++) {
    if (mainSrc[k] === '(') pDepth++;
    else if (mainSrc[k] === ')') { pDepth--; if (pDepth === 0) { j = mainSrc.indexOf('{', k); break; } }
  }
  let depth = 0, inS = null, esc = false;
  for (let k = j; k < mainSrc.length; k++) {
    const c = mainSrc[k];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (inS === '`' && c === '$' && mainSrc[k + 1] === '{') {
        let d = 0;
        for (let m = k + 1; m < mainSrc.length; m++) {
          if (mainSrc[m] === '{') d++;
          else if (mainSrc[m] === '}') { d--; if (d === 0) { k = m; break; } }
        }
        continue;
      }
      if (c === inS) inS = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return mainSrc.slice(i, k + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

console.log('[1] 结构性：readFile / writeFile 必须带校验');
{
  const rf = fnBody('readFile');
  const wf = fnBody('writeFile');
  ok(/isSensitivePath/.test(rf), 'readFile 挡敏感文件（config.json 含 apiKey/口令）', rf.slice(0, 100));
  ok(/isSensitivePath/.test(wf), 'writeFile 挡敏感文件');
  ok(/isPathAllowedForWrite/.test(wf), 'writeFile 有写入范围校验');
  ok(!/mkdirSync/.test(rf), 'readFile 不会创建目录');
}

console.log('\n[2] 行为：用打桩的 fs/path/config 实测各分支');
{
  const CONFIG_PATH = path.join(ROOT, 'fake-userdata', 'config.json');
  const WORKDIR = path.join(ROOT, 'fake-case');

  // 打桩环境：把函数体里引用的外部依赖都注进去
  const code = fnBody('readFile') + '\n' + fnBody('writeFile');
  const stubFs = {
    _written: null,
    readFileSync(p) {
      if (String(p).includes('secret')) throw new Error('EACCES');
      return 'CONTENT:' + p;
    },
    writeFileSync(p, content) { this._written = { p, content }; },
    mkdirSync() { },
    existsSync() { return false; },
  };
  function build(cfgPath, workdir) {
    const state = { config: {} };
    const allowedWriteRoots = () => [workdir].filter(Boolean).map(r => path.resolve(r));
    const isPathAllowedForWrite = (p) => {
      const t = path.resolve(String(p || ''));
      const norm = (s) => (process.platform === 'win32' ? s.toLowerCase() : s);
      return allowedWriteRoots().some(r => { const R = norm(r); return norm(t) === R || norm(t).startsWith(R + path.sep); });
    };
    const isSensitivePath = (p) => cfgPath
      ? (process.platform === 'win32'
        ? path.resolve(String(p || '')).toLowerCase() === path.resolve(cfgPath).toLowerCase()
        : path.resolve(String(p || '')) === path.resolve(cfgPath))
      : false;
    const fn = new Function('fs', 'path', 'CONFIG_PATH', 'currentWorkDir', 'config',
      'isSensitivePath', 'isPathAllowedForWrite', 'allowedWriteRoots',
      code + '\n__h.readFile = readFile; __h.writeFile = writeFile;');
    const h = {};
    fn(stubFs, path, cfgPath, workdir, state.config, isSensitivePath, isPathAllowedForWrite, allowedWriteRoots);
    return h;
  }

  const h = (() => {
    const holder = {};
    const state = { config: {} };
    const allowedWriteRoots = () => [WORKDIR].map(r => path.resolve(r));
    const isPathAllowedForWrite = (p) => {
      const t = path.resolve(String(p || ''));
      const norm = (s) => (process.platform === 'win32' ? s.toLowerCase() : s);
      return allowedWriteRoots().some(r => { const R = norm(r); return norm(t) === R || norm(t).startsWith(R + path.sep); });
    };
    const isSensitivePath = (p) => path.resolve(String(p || '')).toLowerCase() === path.resolve(CONFIG_PATH).toLowerCase();
    const fn = new Function('fs', 'path', 'CONFIG_PATH', 'currentWorkDir', 'config',
      'isSensitivePath', 'isPathAllowedForWrite', 'allowedWriteRoots', '__h',
      code + '\n__h.readFile = readFile; __h.writeFile = writeFile;');
    fn(stubFs, path, CONFIG_PATH, WORKDIR, state.config, isSensitivePath, isPathAllowedForWrite, allowedWriteRoots, holder);
    return holder;
  })();

  ok(typeof h.readFile === 'function' && typeof h.writeFile === 'function', '两个函数可执行');

  // 读配置 → 拒绝
  const r1 = h.readFile(CONFIG_PATH);
  ok(/拒绝读取/.test(r1), '读 config.json 被拒绝', r1.slice(0, 120));

  // 读普通题目文件 → 放行（题目文件可以在任意盘符，读取不设范围限制）
  const r2 = h.readFile('E:\\ctf\\some\\chall.exe');
  ok(/CONTENT:/.test(r2), '普通文件仍可读（读取不限制范围）', r2.slice(0, 80));

  // 写配置 → 拒绝
  const w1 = h.writeFile(CONFIG_PATH, 'x');
  ok(/拒绝写入/.test(w1), '写 config.json 被拒绝', w1.slice(0, 120));

  // 写到系统目录 → 拒绝
  const w2 = h.writeFile('C:\\Windows\\System32\\evil.dll', 'x');
  ok(/超出允许范围/.test(w2), '写系统目录被拒绝', w2.slice(0, 140));

  // 写到题目目录 → 放行
  const w3 = h.writeFile(path.join(WORKDIR, 'solve.py'), 'print(1)');
  ok(/已写入/.test(w3), '写题目目录被允许', w3.slice(0, 140));
  ok(stubFs._written && stubFs._written.p.endsWith('solve.py'), '确实写入了目标文件');

  // 路径穿越：从允许的根用 ../ 逃出去 → 拒绝
  const w4 = h.writeFile(path.join(WORKDIR, '..', '..', 'evil.txt'), 'x');
  ok(/超出允许范围/.test(w4), '../ 穿越到根外被拒绝', w4.slice(0, 140));
}

console.log('\n[3] 结构性：工具 dispatch 走的确实是这两个带校验的函数');
{
  ok(/case 'read_file':\s*\n\s*return readFile\(input\.path\)/.test(mainSrc), 'read_file → readFile()');
  ok(/case 'write_file':\s*\n\s*return writeFile\(input\.path, input\.content\)/.test(mainSrc), 'write_file → writeFile()');
  // 只应存在这两处调用（避免有人绕过它们直接 fs.readFileSync(input.path)）
  const bareReads = (mainSrc.match(/fs\.readFileSync\(input\.[a-z_]+/g) || []).length;
  ok(bareReads === 0, '没有其他地方直接用 fs.readFileSync(input.xxx) 绕过校验', '发现 ' + bareReads + ' 处');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
