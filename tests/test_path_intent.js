// 从消息里识别路径（path-intent）回归
//
// 实测（NaughtyBoy / 驱动逆向）：用户在聊天里写
//     E:\ctf\pratice\ai\[ByteCTF2019]驱动逆向\attachment_x\驱动逆向 这个有两个文件是一道ctf逆向题目，你打开后求解flag
// 工具只认对话框选中的文件 → 命中"求解flag"快捷命令 → autoAnalyze() → 「请先选择文件」
// → 用户看到的就是"他不理我"。
const path = require('path');
const { extractPaths, looksLikeOpenRequest, pickPathFromMessage } =
  require(path.join(__dirname, '..', 'electron', 'path-intent.js'));

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// 用户实际发的那句话（原样）
const REAL_MSG = 'E:\\ctf\\pratice\\ai\\[ByteCTF2019]驱动逆向\\attachment_x\\驱动逆向 这个有两个文件是一道ctf逆向题目，你打开后求解flag';

console.log('[1] 真实场景：用户原话');
{
  const paths = extractPaths(REAL_MSG);
  ok(paths.length === 1, '提取到 1 个路径', JSON.stringify(paths));
  ok(paths[0].startsWith('E:\\ctf\\pratice\\ai\\'), '路径以 E:\\ctf 开头', paths[0]);
  ok(!/[，,。]$/.test(paths[0]), '末尾中文标点已剥离', JSON.stringify(paths[0]));
  ok(/驱动逆向$/.test(paths[0]), '中文路径段完整保留', paths[0]);

  const pick = pickPathFromMessage(REAL_MSG);
  ok(pick !== null, '能挑出路径');
  ok(pick.path === paths[0], '挑出的就是该路径');
  ok(pick.kind === 'unknown' || pick.kind === 'dir', '识别为目录/未知（无扩展名）', pick.kind);
  ok(looksLikeOpenRequest(REAL_MSG), '识别出"打开/求解"意图');
}

console.log('\n[2] 带扩展名的文件优先于目录');
{
  const msg = '把 E:\\ctf\\a\\b 和 E:\\ctf\\a\\b\\chall.exe 都看一下';
  const all = extractPaths(msg);
  ok(all.length === 2, '提取到 2 个路径', JSON.stringify(all));
  const pick = pickPathFromMessage(msg);
  ok(pick.path === 'E:\\ctf\\a\\b\\chall.exe', '优先选带扩展名的文件', pick.path);
  ok(pick.kind === 'file', 'kind=file');
}

console.log('\n[3] 多个文件取最后一个（用户通常最后才说真正要跑的那个）');
{
  const msg = '看下 C:\\x\\a.apk 和 C:\\x\\b.apk';
  const pick = pickPathFromMessage(msg);
  ok(pick.path === 'C:\\x\\b.apk', '取最后一个文件', pick.path);
}

console.log('\n[4] POSIX / UNC / 正斜杠');
{
  const p1 = extractPaths('目标在 /home/kali/chall/pwn 这里');
  ok(p1.length === 1 && p1[0] === '/home/kali/chall/pwn', 'POSIX 绝对路径', JSON.stringify(p1));

  const p2 = extractPaths('打开 \\\\server\\share\\a.exe');
  ok(p2.length === 1, 'UNC 路径识别', JSON.stringify(p2));

  const p3 = extractPaths('用 E:/ctf/a/b.exe 跑');
  ok(p3.length === 1 && p3[0] === 'E:/ctf/a/b.exe', '正斜杠 Windows 路径', JSON.stringify(p3));
}

console.log('\n[5] 不应误报');
{
  ok(extractPaths('这个题怎么做').length === 0, '纯中文无路径');
  ok(extractPaths('').length === 0, '空串');
  ok(extractPaths('http://a.b/c').length === 0 || !extractPaths('http://a.b/c').some(p => p.startsWith('http')),
    'URL 不该被当成路径', JSON.stringify(extractPaths('http://a.b/c')));
  ok(extractPaths('C:relative').length === 0, 'C:relative 不是绝对路径');
}

console.log('\n[6] 意图判定');
{
  ok(looksLikeOpenRequest('打开这个文件'), '"打开"算意图');
  ok(looksLikeOpenRequest('帮我分析一下'), '"分析"算意图');
  ok(looksLikeOpenRequest('求解flag'), '"求解"算意图');
  ok(!looksLikeOpenRequest('今天天气不错'), '无关语句不算');
}

console.log('\n[7] 接线：主进程/渲染层要能用上');
{
  const fs = require('fs');
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
  const preSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');

  ok(/require\('\.\/path-intent'\)/.test(mainSrc), 'main.js 引用 path-intent');
  ok(/resolve-message-path/.test(mainSrc), '主进程有 resolve-message-path handler');
  ok(/resolveMessagePath/.test(preSrc), 'preload 暴露 resolveMessagePath');
  ok(/tryOpenPathFromMessage/.test(appSrc), '渲染层有 tryOpenPathFromMessage');
  ok(/await tryOpenPathFromMessage\(message\)/.test(appSrc), '在 processUserMessage 里被调用');
  // 必须在快捷命令之前（否则又会被"请先选择文件"拦住）
  const iOpen = appSrc.indexOf('await tryOpenPathFromMessage(message)');
  const iFlag = appSrc.indexOf("lowerMessage.includes('求解flag')");
  ok(iOpen > 0 && iFlag > 0 && iOpen < iFlag, '路径解析排在「求解flag」快捷命令之前',
    `open=${iOpen} flag=${iFlag}`);
  // 目录展开挑主文件
  ok(/function pickMainFile/.test(mainSrc), '有 pickMainFile（目录展开挑主文件）');
}

console.log('\n[8] pickMainFile 的挑选规则');
{
  // 从 main.js 抽出真实实现跑（避免只做字符串匹配）
  const fs = require('fs');
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  const i = mainSrc.indexOf('function pickMainFile');
  ok(i > 0, 'pickMainFile 已定义');
  // 用花括号配平切出完整函数体（内部还有 sort（a,b)=>... 等嵌套）
  let depth = 0, started = false, end = -1;
  for (let k = i; k < mainSrc.length; k++) {
    const ch = mainSrc[k];
    if (ch === '{') { depth++; started = true; }
    else if (ch === '}') { depth--; if (started && depth === 0) { end = k + 1; break; } }
  }
  ok(end > i, '函数体配平成功');
  const impl = mainSrc.slice(i, end);
  const pickMainFile = new Function(impl + '\nreturn pickMainFile;')();

  const files = [
    { name: 'readme.md', size: 2000 },
    { name: 'chall.exe', size: 50000 },
    { name: '说明.txt', size: 500 },
    { name: 'screenshot.png', size: 300000 },
  ];
  const best = pickMainFile(files);
  ok(best && best.name === 'chall.exe', '挑出可执行文件而不是 readme/图片', best && best.name);

  const apkFirst = pickMainFile([
    { name: 'note.md', size: 100 },
    { name: 'target.apk', size: 900000 },
  ]);
  ok(apkFirst && apkFirst.name === 'target.apk', 'apk 优先于 md', apkFirst && apkFirst.name);

  ok(pickMainFile([]) === null, '空列表返回 null');
  ok(pickMainFile([{ name: 'x.bin', size: 10 }]) !== null, '单文件也能挑');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
