// rank 3 单测：IDA 身份决策 + PID 差集 + 渲染层/主进程实现一致性
//
// 主进程有一份（electron/binary-map.js），渲染层另有一份最小实现（app.js，不能 require）。
// 两份必须同语义，否则"日志说通过、实际却复用了错库"这类问题会复发。
const fs = require('fs');
const path = require('path');
const M = require(path.join(__dirname, '..', 'electron', 'binary-map.js'));

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

// 从 app.js 抽出渲染层实现（与 test_land_nudge 等同一套 extract 手法）
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
function grab(name) {
  const re = new RegExp('function ' + name + '\\s*\\(', 'g');
  const m = re.exec(appSrc);
  if (!m) throw new Error('未找到函数 ' + name);
  let i = appSrc.indexOf('{', m.index);
  let depth = 0, inS = null, esc = false;
  for (let j = i; j < appSrc.length; j++) {
    const c = appSrc[j];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return appSrc.slice(m.index, j + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

const renderer = {};
{
  const code = [
    grab('normalizePathForCompare'),
    grab('basenameOf'),
    grab('decideIdaAction'),
    grab('planPidClose'),
    grab('parseAddrLoose'),
    grab('isAddrInImageLoose'),
    grab('filterFunctionsInImage'),
  ].join('\n');
  new Function('exports', code + '\nexports.decideIdaAction=decideIdaAction;exports.planPidClose=planPidClose;exports.filterFunctionsInImage=filterFunctionsInImage;exports.basenameOf=basenameOf;exports.normalizePathForCompare=normalizePathForCompare;')(renderer);
}
ok(typeof renderer.decideIdaAction === 'function', '已从 app.js 抽出渲染层实现');

console.log('[1] decideIdaAction 四态（主进程与渲染层必须一致）');
{
  const cases = [
    { name: '未监听 → launch', input: { listening: false }, expect: 'launch' },
    { name: '身份未知 → reload', input: { listening: true, identity: { success: false }, targetPath: 'C:\\a\\x.exe' }, expect: 'reload' },
    { name: '目标不一致 → reload', input: { listening: true, identity: { success: true, input_path: 'C:\\b\\y.exe' }, targetPath: 'C:\\a\\x.exe' }, expect: 'reload' },
    { name: '路径一致 → reuse', input: { listening: true, identity: { success: true, input_path: 'C:/A/X.EXE' }, targetPath: 'c:\\a\\x.exe' }, expect: 'reuse' },
    { name: '缺目标路径 → reload', input: { listening: true, identity: { success: true, input_path: 'C:\\a\\x.exe' }, targetPath: '' }, expect: 'reload' },
  ];
  for (const c of cases) {
    const a = M.decideIdaAction(c.input);
    const b = renderer.decideIdaAction(c.input);
    ok(a.action === c.expect, c.name + '（主进程）', a.action);
    ok(b.action === c.expect, c.name + '（渲染层）', b.action);
    ok(a.action === b.action && a.reason === b.reason, c.name + ' 两层结论一致', JSON.stringify([a, b]));
  }
}

console.log('\n[2] 日志文案可区分（运维/日志取证依赖这三句）');
{
  const u = M.decideIdaAction({ listening: true, identity: { success: false } });
  ok(/身份未知/.test(u.log), '身份未知', u.log);
  const mm = M.decideIdaAction({
    listening: true, identity: { success: true, input_path: 'C:\\q\\Quizow.exe' }, targetPath: 'C:\\q\\cnbragon.exe',
  });
  ok(/目标不一致/.test(mm.log), '目标不一致', mm.log);
  ok(/quizow\.exe/i.test(mm.log) && /cnbragon\.exe/i.test(mm.log), '含双方文件名', mm.log);
  const rr = M.decideIdaAction({
    listening: true, identity: { success: true, input_path: 'C:\\q\\cnbragon.exe' }, targetPath: 'C:\\q\\cnbragon.exe',
  });
  ok(/身份校验通过/.test(rr.log), '身份校验通过', rr.log);
}

console.log('\n[3] planPidClose 两层一致');
{
  const cases = [
    [[100, 200], [100, 200, 300, 400]],
    [[], [7]],
    [[5], [5]],
    [null, null],
  ];
  for (const [before, after] of cases) {
    const a = M.planPidClose(before, after);
    const b = renderer.planPidClose(before, after);
    ok(JSON.stringify(a) === JSON.stringify(b), `输入 ${JSON.stringify([before, after])} 一致`, JSON.stringify([a, b]));
  }
  const k = M.planPidClose([100, 200], [100, 200, 300]);
  ok(JSON.stringify(k) === '[300]', '只返回新增 PID', JSON.stringify(k));
}

console.log('\n[4] 落界过滤：两层实现结果一致（含 QuiZow 真实形态）');
{
  // 构造与 QuiZow 同形的 PE32：ImageBase 0x400000 / SizeOfImage 0x7000 / .text RVA 0x1000 vsize 0x15c4
  const b = Buffer.alloc(0x400, 0);
  b[0] = 0x4d; b[1] = 0x5a;
  b.writeUInt32LE(0x80, 0x3c);
  b.writeUInt32LE(0x00004550, 0x80);
  b.writeUInt16LE(1, 0x86);
  b.writeUInt16LE(0xf0, 0x94);
  const opt = 0x98;
  b.writeUInt16LE(0x10b, opt);
  b.writeUInt32LE(0x400000, opt + 28);
  b.writeUInt32LE(0x7000, opt + 56);
  const sec = opt + 0xf0;
  b.write('.text\0\0\0', sec, 'latin1');
  b.writeUInt32LE(0x15c4, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x15c4, sec + 16);
  const map = M.parseImageMap(b);
  ok(!!map, 'PE32 解析成功');

  const funcs = [
    { address: '0x401000', name: 'inside1' },
    { address: '0x4015b0', name: 'inside2' },
    { address: '0x42F038', name: 'quizow_out' },
    { address: '0x402594', name: 'quizow_out2' },
    { addr: '0x140001000', name: 'other_pe' },
    { name: 'noaddr' },
  ];
  const a = M.filterFunctionsInImage(funcs, map);
  const r = renderer.filterFunctionsInImage(funcs, map);
  ok(a.kept.length === r.kept.length && a.dropped.length === r.dropped.length,
    `两层数量一致 kept=${a.kept.length} dropped=${a.dropped.length}`,
    JSON.stringify([a.kept.map(f => f.name), r.kept.map(f => f.name)]));
  ok(JSON.stringify(a.kept.map(f => f.name)) === JSON.stringify(r.kept.map(f => f.name)),
    '保留集合完全相同');
  ok(a.dropped.some(f => f.name === 'quizow_out'), '0x42F038 被剔除');
  ok(a.dropped.some(f => f.name === 'noaddr'), '无地址条目被剔除');

  // ELF 形态
  const elfPath = path.join(__dirname, 'regression', 'not-baby-parallelism-elf64', 'pppp');
  if (fs.existsSync(elfPath)) {
    const em = M.parseImageMap(fs.readFileSync(elfPath));
    const ef = [{ address: '0x401000', name: 'x' }, { address: '0x2000', name: 'y' }];
    const ea = M.filterFunctionsInImage(ef, em);
    const er = renderer.filterFunctionsInImage(ef, em);
    ok(JSON.stringify(ea.kept.map(f => f.name)) === JSON.stringify(er.kept.map(f => f.name)),
      'ELF 落界两层一致', JSON.stringify([ea.kept.map(f => f.name), er.kept.map(f => f.name)]));
  }
}

console.log('\n[5] 主进程 IPC 存在性（静态断言）');
{
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/ipcMain\.handle\('ida-identity'/.test(mainSrc), "main.js 注册 ida-identity");
  ok(/ipcMain\.handle\('file-image-map'/.test(mainSrc), 'main.js 注册 file-image-map');
  ok(/server_health/.test(mainSrc), 'ida-identity 调用 server_health');

  const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');
  ok(/idaIdentity:\s*\(\)\s*=>\s*ipcRenderer\.invoke\('ida-identity'\)/.test(preloadSrc), 'preload 暴露 idaIdentity');
  ok(/fileImageMap:\s*\(filePath\)\s*=>\s*ipcRenderer\.invoke\('file-image-map'/.test(preloadSrc), 'preload 暴露 fileImageMap');

  ok(/decideIdaAction\(/.test(appSrc), 'app.js 调用 decideIdaAction');
  ok(/filterFunctionsInImage\(/.test(appSrc), 'app.js 调用 filterFunctionsInImage');
  ok(/身份校验通过/.test(appSrc), 'app.js 保留「身份校验通过」文案');
  ok(!/检测到 IDA MCP 已在运行（13337），跳过再次启动 IDA/.test(appSrc),
    '旧的"仅凭端口就复用"文案已移除');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
