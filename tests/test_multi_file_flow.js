// 多文件 → 自动分析 链路完整性检查
// 回答用户的问题：「打开多个文件后点自动分析，AI 是只读题目文件，还是多个文件一起利用？」
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// ── 工具函数：从源码里定位函数体并抽取 ──
// 必须跳过**字符串 / 模板字符串 / 注释**里的花括号，否则：
//   · `async function analyzeFile(filePath, opts = {})` 的 `{}` 会提前结束配平
//   · 模板字符串里的 `${...}`、正则里的 `{n,m}` 也会干扰
function extractFn(src, name) {
  const patterns = ['async function ' + name, 'function ' + name + '(', 'function ' + name + ' '];
  let i2 = -1;
  for (const p of patterns) { i2 = src.indexOf(p); if (i2 >= 0) break; }
  if (i2 < 0) return '';
  // ⚠ 不能直接取函数名后第一个 { —— 那可能是**参数默认值**里的对象字面量
  //    （如 `analyzeFile(filePath, opts = {})`），会立刻被配平掉，只抽到函数签名。
  // 正确做法：找到参数列表的右括号 ')'，其后的第一个 '{' 才是函数体起点。
  const parenOpen = src.indexOf('(', i2);
  let parenDepth = 0, parenEnd = -1;
  for (let k = parenOpen; k < src.length; k++) {
    const ch = src[k];
    if (ch === '(') parenDepth++;
    else if (ch === ')') { parenDepth--; if (parenDepth === 0) { parenEnd = k; break; } }
  }
  if (parenEnd < 0) return '';
  const braceStart = src.indexOf('{', parenEnd);
  if (braceStart < 0) return '';

  let depth = 0, started = false;
  let inStr = null, esc = false, inTmpl = false, inLine = false, inBlock = false;
  for (let k = braceStart; k < src.length; k++) {
    const ch = src[k], nx = src[k + 1];
    if (inLine) { if (ch === '\n') inLine = false; continue; }
    if (inBlock) { if (ch === '*' && nx === '/') { inBlock = false; k++; } continue; }
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (inTmpl) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === '`') { inTmpl = false; continue; }
      continue;
    }
    if (ch === '/' && nx === '/') { inLine = true; k++; continue; }
    if (ch === '/' && nx === '*') { inBlock = true; k++; continue; }
    if (ch === '"' || ch === "'") { inStr = ch; continue; }
    if (ch === '`') { inTmpl = true; continue; }
    if (ch === '{') { depth++; started = true; }
    else if (ch === '}') { depth--; if (started && depth === 0) return src.slice(i2, k + 1); }
  }
  return '';
}

console.log('[1] 多选时：材料是否被写入 _platformFiles');
{
  const fn = extractFn(appSrc, 'handleSelectFile');
  ok(fn.length > 0, 'handleSelectFile 存在');
  ok(/_platformFiles = others\.slice\(\)/.test(fn), '非主文件登记进 _platformFiles');
  ok(/fileDigest\(paths\)/.test(fn), '先对全部材料做摘要');
  ok(/先判断哪些是题面/.test(fn), '要求 AI 自己判断哪个是题面');
}

console.log('\n[2] analyzeFile 会不会清空 _platformFiles（多选后点自动分析的关键）');
{
  const fn = extractFn(appSrc, 'analyzeFile');
  ok(/state\._platformFiles = null/.test(fn), 'analyzeFile 内部会清空（换题清理）');
  // 关键：多选流程是先 analyzeFile 再赋值，所以不会被清掉
  const sel = extractFn(appSrc, 'handleSelectFile');
  const iAnalyze = sel.indexOf('await analyzeFile(main)');
  const iAssign = sel.indexOf('_platformFiles = others');
  ok(iAnalyze > 0 && iAssign > iAnalyze,
    '先 analyzeFile 再赋值 —— 顺序正确，不会被清空',
    `analyze@${iAnalyze} assign@${iAssign}`);
}

console.log('\n[3] 自动分析链路上，伴生材料是否真的进了提示词');
{
  // 阶段1：autoSolveBinaryFlag → toolUseDeepSolveBinary
  const deep = extractFn(appSrc, 'toolUseDeepSolveBinary');
  ok(deep.length > 0, 'toolUseDeepSolveBinary 存在');
  ok(/state\._platformFiles/.test(deep), '阶段1 读 _platformFiles');
  ok(/sideFilesBlock/.test(deep), '生成 sideFilesBlock 注入提示词');
  // 必须用 fileDigest 而不是扩展名白名单
  ok(/fileDigest/.test(deep), '阶段1 用 fileDigest 取内容（不是扩展名白名单）');
  ok(!/const TEXT_EXT = \/\\\.\(txt\|out\|md/.test(deep),
    '不再用旧的文本扩展名白名单（docx 会被漏掉）');
  ok(/docx', 'xlsx', 'pptx', 'pdf'\]\.includes\(it\.kind\)/.test(deep),
    '显式处理 docx/xlsx/pptx/pdf');

  // 阶段2：detailedBinaryAnalysis
  const det = extractFn(appSrc, 'detailedBinaryAnalysis');
  ok(/state\._platformFiles/.test(det), '阶段2 也读 _platformFiles');
  ok(/file_digest/.test(det), '阶段2 提示 AI 用 file_digest 读材料');
  ok(/先怀疑"材料没看全"/.test(det), '阶段2 引导：失败先怀疑材料没看全');
}

console.log('\n[4] 源码题 / XML 题的伴生材料也走同一套');
{
  const src = extractFn(appSrc, 'analyzeSourceText');
  ok(/fileDigest/.test(src), 'analyzeSourceText 用 fileDigest');
  const xml = extractFn(appSrc, 'analyzeXMLText');
  ok(/fileDigest/.test(xml), 'analyzeXMLText 用 fileDigest');
}

console.log('\n[5] read_file 对 Office 的支持（AI 手动读也能拿到正文）');
{
  ok(/extractOfficeText/.test(mainSrc), 'read_file 接入 office-text');
  ok(/officeKind/.test(mainSrc), '返回 officeKind 便于 AI 判断');
}

console.log('\n[6] 消息里给路径时，也带上同级材料');
{
  const j = mainSrc.indexOf('ipcMain.handle(\'resolve-message-path\'');
  const seg = mainSrc.slice(j, j + 4000);
  ok(/siblings:/.test(seg), '返回 siblings（同目录其它文件）');
  ok(/files: existingFiles/.test(seg), '多个存在的文件全部返回');
  const fn = extractFn(appSrc, 'tryOpenPathFromMessage');
  ok(/preloadMaterials\(sibs\)/.test(fn), '消息路径也会预读材料');
}

console.log('\n[7] preload / IPC 三层是否对齐');
{
  const preSrc = fs.readFileSync(path.join(ROOT, 'electron', 'preload.js'), 'utf8');
  const pairs = [
    ['select-file', 'selectFile'],
    ['file-digest', 'fileDigest'],
    ['resolve-message-path', 'resolveMessagePath'],
  ];
  for (const [ipc, api] of pairs) {
    const hasIpc = mainSrc.includes("ipcMain.handle('" + ipc + "'");
    const hasPre = preSrc.includes(api + ':');
    ok(hasIpc && hasPre, `${ipc} ↔ ${api} 三层对齐`,
      `ipc=${hasIpc} preload=${hasPre}`);
  }
}

console.log('\n[8] 工具层：AI 能自己读多个文件');
{
  for (const t of ['file_digest', 'list_dir', 'recover_string']) {
    ok(new RegExp('name: "' + t + '"').test(mainSrc), `${t} 已定义`);
    ok(new RegExp("case '" + t + "'").test(mainSrc), `${t} 有 dispatch`);
  }
  ok(/file_digest.*一次读多个文件/s.test(mainSrc) || /一次读多个文件/.test(mainSrc),
    'file_digest 描述说明"一次读多个"');
}

console.log('\n[9] 语法与引用完整性');
{
  const { execFileSync } = require('child_process');
  const files = ['src/js/app.js', 'electron/main.js', 'electron/preload.js',
    'electron/file-digest.js', 'electron/office-text.js', 'electron/path-intent.js',
    'electron/string-recover.js', 'electron/frida-lint.js'];
  let allOk = true;
  const bad = [];
  for (const f of files) {
    try { execFileSync('node', ['--check', path.join(ROOT, f)], { stdio: 'pipe' }); }
    catch (e) { allOk = false; bad.push(f); }
  }
  ok(allOk, `${files.length} 个核心文件语法通过`, bad.join(', '));

  // 引用的模块都必须存在
  const requires = [...mainSrc.matchAll(/require\('\.\/([a-z-]+)'\)/g)].map(m => m[1]);
  const uniq = [...new Set(requires)];
  const missing = uniq.filter(n => !fs.existsSync(path.join(ROOT, 'electron', n + '.js')));
  ok(missing.length === 0, 'main.js 里所有本地 require 都能解析', missing.join(', '));
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
