// Windows 批处理启动器回归
//
// 实测根因（D3CTF AncientGameV2 那一轮）：
//   日志写 "burp 已启动"，但 cmd 窗口里是
//     'E:\ctf\tools\BurpSuite' 不是内部或外部命令
//   然后白等 150s 超时、回退本地分析。
//
// 根因是 `spawn('cmd', ['/c','start','', batPath])`：
//   start 会**再解析一遍**命令行，含空格的路径被按空格拆开，
//   于是「命令 E:\ctf\tools\BurpSuite」+「参数 V2025.11.2\MCP_Burp.bat」。
//
// 实测对照（目录名与文件名都含空格，E:\ctf\tools\BurpSuite V2025.11.2\_p2.bat）：
//   /c <bat>                → ✅ 无参数可用
//   /c <bat> <arg>          → ❌ 报'...BurpSuite' 不是内部或外部命令
//   /c "<bat>" <arg>        → ❌ 文件名、目录名或卷标语法不正确
//   /c "<bat> <arg>"        → ❌ 引号被当成文件名一部分
//   /s /c ""<bat>" "<arg>"" + verbatim → ✅ 参数也正确传入
//
// 本测试锁三件事：
//   ① 实现用的是唯一可行的 /s /c + verbatim 形式；
//   ② 用真实"带空格路径 + 带空格参数"跑一遍，确认真能执行且参数完整；
//   ③ 启动失败必须如实报 failure，不能谎报"已启动"。
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

console.log('[1] 结构性：实现必须是 /s /c + windowsVerbatimArguments');
{
  ok(mainSrc.includes("['/s', '/c'"), '使用 cmd /s /c 形式');
  ok(/windowsVerbatimArguments:\s*true/.test(mainSrc), '设置 windowsVerbatimArguments: true');
  ok(!mainSrc.includes("'/c', 'start'"), '不再使用 cmd /c start 启动 bat（会被二次解析）');
  // 精确检查：只禁止"启动 bat 时用 start"。
  // spawnArgv 的 GUI 分支仍会用 start（exe 需要可见窗口），那是正确用法，不在本测试范围。
  const badLines = mainSrc.split('\n').filter(l =>
    !/^\s*\/\//.test(l) && /'\/c'/.test(l) && /'start'/.test(l) && /Path|path/.test(l)
  );
  ok(badLines.length === 0, '没有"用 start 启动 bat"的残留调用', badLines.join(' | '));
  // 两处调用都走同一个 helper
  const calls = (mainSrc.match(/spawnBatchLauncher\(/g) || []).length;
  ok(calls >= 3, '至少一处定义 + 两处调用（launch-tool 与 Burp）', '发现 ' + calls + ' 处');
}

console.log('\n[2] 行为：带空格的路径 + 带空格的参数，必须真的执行');
{
  // 造一个"路径含空格"的目录与 bat
  const dir = path.join(os.tmpdir(), 'ctf bat test dir');
  fs.mkdirSync(dir, { recursive: true });
  const bat = path.join(dir, 'probe script.bat');
  const marker = path.join(dir, 'result.txt');
  try { fs.unlinkSync(marker); } catch (e) { }
  fs.writeFileSync(bat,
    '@echo off\r\n' +
    'echo RAN > "' + marker + '"\r\n' +
    'echo ARG1=[%~1] >> "' + marker + '"\r\n' +
    'echo ARG2=[%~2] >> "' + marker + '"\r\n' +
    'exit /b 0\r\n', 'utf8');

  // 复刻实现（与 main.js 中的 spawnBatchLauncher 一致）
  const spawnBatchLauncher = (batPath, extraArgs = []) => {
    const quote = (s) => '"' + String(s).replace(/"/g, '""') + '"';
    const inner = [quote(batPath)].concat(extraArgs.map(quote)).join(' ');
    return spawn(process.env.ComSpec || 'cmd.exe', ['/s', '/c', '"' + inner + '"'], {
      shell: false, detached: true, stdio: 'ignore', windowsHide: true,
      windowsVerbatimArguments: true,
    });
  };

  const done = new Promise((resolve) => {
    spawnBatchLauncher(bat, ['arg one', 'arg two']);
    setTimeout(resolve, 4000);
  });

  done.then(() => {
    const ran = fs.existsSync(marker);
    ok(ran, '带空格的路径 + 参数，bat 真的被执行了');
    if (ran) {
      const txt = fs.readFileSync(marker, 'utf8');
      ok(/ARG1=\[arg one\]/.test(txt), '第一个参数完整传入（含空格）', txt.replace(/\r?\n/g, ' | '));
      ok(/ARG2=\[arg two\]/.test(txt), '第二个参数完整传入', txt.replace(/\r?\n/g, ' | '));
    }
    try { fs.unlinkSync(bat); } catch (e) { }
    try { fs.unlinkSync(marker); } catch (e) { }

    console.log('\n[3] 启动失败必须如实报错，不能谎报"已启动"');
    {
      // launchBurpForMcp 必须在超时后返回 success:false
      const i = mainSrc.indexOf('async function launchBurpForMcp');
      const seg = mainSrc.slice(i, i + 3500);
      ok(/success:\s*false/.test(seg), 'Burp 启动失败路径返回 success:false');
      ok(/未监听|未就绪/.test(seg), '失败时说明端口未监听（给出可诊断信息）');
      // launch-tool 的 bat 分支不能无条件 success（必须在 spawn 前校验路径存在）
      const lt = mainSrc.indexOf("ipcMain.handle('launch-tool'");
      const ltSeg = mainSrc.slice(lt, lt + 2500);
      ok(/fs\.existsSync\(toolPath\)/.test(ltSeg), 'launch-tool 启动前校验工具路径存在');
    }

    console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
    process.exit(fail ? 1 : 0);
  });
}
