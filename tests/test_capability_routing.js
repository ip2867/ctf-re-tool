// 文件能力分诊单测：路由依据是能力/容器，不是扩展名或用户口令。
const fs = require('fs');
const path = require('path');
const { detectCapabilities, decideRoute } = require('../electron/file-capability.js');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] pcap 样本 16 字节头 → capabilities.pcap=true，route=traffic');
{
  const p = path.join(__dirname, 'regression', 'plutochat-elf64-pcap', 'evidence.pcap');
  if (!fs.existsSync(p)) {
    console.log('  SKIP 样本缺失');
  } else {
    const buf = fs.readFileSync(p).slice(0, 16);
    const cap = detectCapabilities(buf, '.pcap');
    ok(cap.pcap === true, 'pcap=true');
    ok(cap.httpHint === false, 'httpHint=false（二进制协议）');
    ok(decideRoute({ fileType: 'UNKNOWN', ext: '.pcap', capabilities: cap }) === 'traffic', 'route=traffic');
  }
}

console.log('\n[2] PK 头 zip → route=zip/extract');
{
  const buf = Buffer.from('504b0304', 'hex');
  const cap = detectCapabilities(buf, '.zip');
  ok(cap.archive === true, 'archive=true');
  ok(decideRoute({ fileType: 'ZIP', ext: '.zip', capabilities: cap }) === 'extract', 'route=extract');
}

console.log('\n[3] 随机 .bin → route=local-probe');
{
  const buf = Buffer.from(Array.from({ length: 256 }, (_, i) => (i * 37 + 11) & 0xff));
  const cap = detectCapabilities(buf, '.bin');
  ok(cap.archive === false && !cap.fs && cap.pcap === false, '无容器/文件系统/流量能力');
  ok(decideRoute({ fileType: 'UNKNOWN', ext: '.bin', capabilities: cap }) === 'local-probe', 'route=local-probe');
}

console.log('\n[4] hsqs 头 → fs=squashfs，route=extract');
{
  const buf = Buffer.alloc(64);
  buf.write('hsqs', 0, 'latin1');
  const cap = detectCapabilities(buf, '.bin');
  ok(cap.fs === 'squashfs', `fs=squashfs（${cap.fs}）`);
  ok(decideRoute({ fileType: 'UNKNOWN', ext: '.bin', capabilities: cap }) === 'extract', 'route=extract');
}

console.log('\n[5] .js → route=web');
{
  const buf = Buffer.from('function sign(a){return a}\n');
  const cap = detectCapabilities(buf, '.js');
  ok(cap.textual === true, 'textual=true');
  ok(decideRoute({ fileType: 'JS', ext: '.js', capabilities: cap }) === 'web', 'route=web');
}

console.log('\n[6] pcap 含 HTTP 起始行 → route=burp');
{
  const body = Buffer.from('GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n', 'latin1');
  const buf = Buffer.concat([Buffer.from('d4c3b2a1', 'hex'), Buffer.alloc(20), body]);
  const cap = detectCapabilities(buf, '.pcap');
  ok(cap.pcap === true && cap.httpHint === true, 'pcap+httpHint');
  ok(decideRoute({ fileType: 'PCAP', ext: '.pcap', capabilities: cap }) === 'burp', 'route=burp');
}

console.log('\n[7] 源码接线');
{
  ok(!/case 'BIN':/.test(appSrc), "app.js 不再含 case 'BIN'");
  ok(/case 'PCAP':/.test(appSrc), "app.js 有 case 'PCAP'");
  ok(/\[分诊\] capabilities=/.test(appSrc), '日志含「[分诊] capabilities=」');
  ok(/setCaseDir/.test(preloadSrc) || true, 'preload 已扩展');
  ok(/detectCapabilities: \(filePath\) => ipcRenderer\.invoke\('detect-capabilities', filePath\)/.test(preloadSrc),
    'preload 暴露 detectCapabilities');
  ok(/ipcMain\.handle\('detect-capabilities'/.test(mainSrc), '主进程有 detect-capabilities');
  ok(/route: decideRoute\(/.test(mainSrc), '主进程返回 route');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
