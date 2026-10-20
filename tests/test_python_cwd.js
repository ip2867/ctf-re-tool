// run_python 工作目录 / 产物登记单测。
//
// 旧实现 spawn('python',[tempFile]) 不设 cwd → 脚本里的相对路径写到进程当前目录
// （实测把 rk.bin/tabs.json/sbox.json 写到了仓库根）。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pickPythonCwd, snapshotDir, scanNewArtifacts } = require('../electron/py-artifacts.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] pickPythonCwd 优先级 explicit > caseDir/scripts > workDir > temp');
{
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'ctfpy-'));
  const caseDir = path.join(base, 'case');
  fs.mkdirSync(path.join(caseDir, 'scripts'), { recursive: true });
  const work = path.join(base, 'work');
  fs.mkdirSync(work, { recursive: true });
  const explicit = path.join(base, 'explicit');
  fs.mkdirSync(explicit, { recursive: true });

  ok(pickPythonCwd({ explicitCwd: explicit, caseDir, workDir: work }) === explicit, 'explicit 优先');
  ok(pickPythonCwd({ caseDir, workDir: work }) === path.join(caseDir, 'scripts'), 'caseDir/scripts 次之');
  ok(pickPythonCwd({ workDir: work }) === work, 'workDir 再次');
  const tmp = pickPythonCwd({});
  ok(tmp === os.tmpdir(), `无输入时回退 temp（${tmp}）`);
  // 不存在的 explicit 不生效
  ok(pickPythonCwd({ explicitCwd: path.join(base, 'nope'), caseDir, workDir: work }) === path.join(caseDir, 'scripts'),
    '不存在的 explicit 被忽略');
}

console.log('\n[2] scanNewArtifacts 只返回新增/修改文件');
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctfart-'));
  fs.writeFileSync(path.join(dir, 'old.bin'), 'old');
  const before = snapshotDir(dir);
  const since = Date.now();
  fs.writeFileSync(path.join(dir, 'out.bin'), 'AB');
  fs.writeFileSync(path.join(dir, 'old.bin'), 'old-modified-content');
  const arts = scanNewArtifacts(dir, since, before);
  const names = arts.map(a => a.name).sort();
  ok(names.includes('out.bin'), `含新文件 out.bin（${names.join(',')}）`);
  ok(names.includes('old.bin'), '含被修改的 old.bin');
  ok(!names.includes('nonexistent'), '不含不存在的文件');
  const out = arts.find(a => a.name === 'out.bin');
  ok(out && out.size === 2, `out.bin 大小 2（实际 ${out && out.size}）`);
  // 空快照 + 无 since → 全部视为新增
  const all = scanNewArtifacts(dir, 0, new Map());
  ok(all.length >= 2, `空快照视为全部新增（${all.length}）`);
}

console.log('\n[3] 源码静态断言');
{
  ok(/setCaseDir: \(dir\) => ipcRenderer\.invoke\('set-case-dir', dir\)/.test(preloadSrc), 'preload 暴露 setCaseDir');
  ok(/caseArtifacts: \(\) => ipcRenderer\.invoke\('case-artifacts'\)/.test(preloadSrc), 'preload 暴露 caseArtifacts');
  const runPy = mainSrc.slice(mainSrc.indexOf('name: "run_python"'), mainSrc.indexOf('name: "run_python"') + 700);
  ok(/cwd:/.test(runPy) || /cwd\b/.test(runPy), 'run_python schema 含 cwd');
  ok(/case 'run_python':\s*\r?\n\s*return await runPythonScript\(input\.script, input\.cwd\);/.test(mainSrc),
    'dispatch 调用 runPythonScript(input.script, input.cwd)');
  ok(/ipcMain\.handle\('set-case-dir'/.test(mainSrc), '主进程有 set-case-dir');
  ok(/ipcMain\.handle\('case-artifacts'/.test(mainSrc), '主进程有 case-artifacts');
  ok(/artifact: \$\{a\.path\} \(\$\{a\.size\} bytes\)/.test(mainSrc), '返回文本追加 artifact: <path> (<n> bytes)');
  ok(/evidence', 'artifacts\.jsonl'/.test(mainSrc), '登记到 evidence/artifacts.jsonl');
  ok(/await window\.electronAPI\.setCaseDir\(cs\.caseDir\)/.test(
    fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8')), '渲染层 caseInit 后调用 setCaseDir');
  ok(/kind: 'run_python_artifact'/.test(fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8')),
    'finalizeSolve 转成 run_python_artifact evidence');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
