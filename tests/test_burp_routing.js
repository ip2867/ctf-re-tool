// Burp 路由单测。
//
// 规则：自动化触发看**能力**（pcap 含 HTTP，或 JS/HTML 文件），不看中文口令；
// 纯二进制 pcap 不进 Burp（本地解析即可）；Burp 未监听时必须给出可操作错误，
// 且该错误必须被 tool-result 识别为失败。
const fs = require('fs');
const path = require('path');
const { detectCapabilities, decideRoute } = require('../electron/file-capability.js');
const { toToolResult } = require('../electron/tool-result.js');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r\n/g, '\n');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] JS 文件与含 HTTP 的 pcap 进 Burp 流程');
{
  // 说明：工单内部对 JS 的路由名有两处表述（route=web 与 route=burp）。
  // 这里统一按 route=web 表示"Web/JS 逆向流程"——该流程本身就会探测/拉起 Burp。
  const jsBuf = Buffer.from('function sign(a){return a}\n');
  const jsCap = detectCapabilities(jsBuf, '.js');
  const jsRoute = decideRoute({ fileType: 'JS', ext: '.js', capabilities: jsCap });
  ok(jsRoute === 'web', `JS → web/Burp 流程（${jsRoute}）`);
  const jsCase = appSrc.slice(appSrc.indexOf("case 'JS':"), appSrc.indexOf("case 'ZIP':"));
  ok(/await analyzeWebJS\(\)/.test(jsCase), 'JS 文件进入 analyzeWebJS');
  ok(/burpProbe\(\)/.test(appSrc) && /launchTool\('burp'\)/.test(appSrc), 'analyzeWebJSCore 会探测并拉起 Burp');

  const httpBuf = Buffer.concat([
    Buffer.from('d4c3b2a1', 'hex'), Buffer.alloc(20),
    Buffer.from('GET /x HTTP/1.1\r\nHost: a\r\n\r\n', 'latin1'),
  ]);
  const httpCap = detectCapabilities(httpBuf, '.pcap');
  ok(httpCap.pcap === true && httpCap.httpHint === true, '含 HTTP 的 pcap 能力判定');
  ok(decideRoute({ fileType: 'PCAP', ext: '.pcap', capabilities: httpCap }) === 'burp', 'route=burp');
}

console.log('\n[2] 纯二进制 pcap（样本 http=0）→ traffic，不启动 Burp');
{
  const sample = path.join(__dirname, 'regression', 'plutochat-elf64-pcap', 'evidence.pcap');
  if (!fs.existsSync(sample)) {
    console.log('  SKIP 样本缺失');
  } else {
    const cap = detectCapabilities(fs.readFileSync(sample), '.pcap');
    ok(cap.pcap === true && cap.httpHint === false, 'pcap 且 httpHint=false');
    ok(decideRoute({ fileType: 'PCAP', ext: '.pcap', capabilities: cap }) === 'traffic', 'route=traffic');
  }
  // analyzePcapFile 的 useBurp=false 分支不得触碰 Burp
  const fn = appSrc.slice(appSrc.indexOf('async function analyzePcapFile'), appSrc.indexOf('async function analyzeBinContainer'));
  ok(!/burpProbe|launchTool\('burp'\)/.test(fn), '本地流量解析不调用 Burp');
  ok(/if \(!o\.useBurp\)/.test(fn), '有 useBurp 分支');
}

console.log("\n[3] 9876 拒绝 → BURP_DOWN 前缀且 toToolResult 判 isError");
{
  // 与 main.js 里 callBurpMcp 的文案保持一致
  const msg = `BURP_DOWN http://127.0.0.1:9876（connect ECONNREFUSED 127.0.0.1:9876）；启动：E:/ctf/tools/MCP_Burp.bat`;
  ok(msg.startsWith('BURP_DOWN'), '消息以 BURP_DOWN 开头');
  ok(msg.includes('127.0.0.1:9876'), '含 127.0.0.1:9876');
  const tr = toToolResult(msg);
  ok(tr.isError === true, `toToolResult 判 isError（${JSON.stringify(tr).slice(0, 120)}）`);
  // 源码：失败前缀表与 callBurpMcp 文案
  const src = fs.readFileSync(path.join(__dirname, '..', 'electron', 'tool-result.js'), 'utf8');
  ok(/'BURP_DOWN'/.test(src), 'FAILURE_PREFIXES 含 BURP_DOWN');
  for (const p of ['REMOTE_TIMEOUT', 'REMOTE_AUTH', 'REMOTE_REFUSED', 'REMOTE_UNCONFIGURED']) {
    ok(new RegExp(`'${p}'`).test(src), `FAILURE_PREFIXES 含 ${p}`);
  }
  ok(/`BURP_DOWN \$\{config\.mcp\.burp\}（\$\{err\.message\}）；启动：/.test(mainSrc), 'callBurpMcp 生成 BURP_DOWN 文案');
}

console.log('\n[4] Burp 失败时本地 HTML/JS 仍走 analyzeLocalWebFile');
{
  const fn = appSrc.slice(appSrc.indexOf('async function analyzeWebJSCore'));
  const body = fn.slice(0, fn.indexOf('\n}\n\n') + 3);
  ok(/localWeb/.test(body) && /analyzeLocalWebFile\(\)/.test(body), '失败路径调用 analyzeLocalWebFile');
  ok(/Burp 未就绪，已回退本地文件分析/.test(body), '日志说明 Burp 未就绪并已回退本地文件分析');
  ok(/不需要抓包/.test(body), '明确"本地文件不需要抓包"');
  // 只有 pcap 时的说明（无本地文件可回退）
  ok(/Burp 启动超时/.test(body), '纯 pcap 场景明确报 Burp 启动超时');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
