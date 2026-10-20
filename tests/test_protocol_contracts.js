// 2026-10-20 修复回归：Burp 必填参数补齐、MCP isError 透传、ssh 退出码、
// gzip 魔数长度、WASM 路由、Burp 错误串被当历史。
//
// 这些缺陷都不是"某道题"的问题，而是协议层/形态层的通用错误，
// 因此用例只断言机制，不引用题名或样本路径。
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8').replace(/\r\n/g, '\n');
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r\n/g, '\n');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

// 从 main.js 里抽出纯函数（与 Electron 无关），在沙箱里执行。
// 只暴露被测函数，不执行任何顶层业务代码。
function extractFn(name, src) {
  const start = src.indexOf('function ' + name + '(');
  if (start < 0) throw new Error('未找到函数: ' + name);
  let i = src.indexOf('{', start);
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) break; }
  }
  return src.slice(start, i + 1);
}

const sandbox = { module: { exports: {} }, console };
vm.createContext(sandbox);
const consts = mainSrc.slice(mainSrc.indexOf('const BURP_ARG_SYNONYMS'), mainSrc.indexOf('function adaptBurpArgs'));
vm.runInContext(consts, sandbox);
for (const fn of ['adaptBurpArgs', 'mcpResultIsError', 'mcpErrorText']) {
  vm.runInContext(extractFn(fn, mainSrc), sandbox);
}
const { adaptBurpArgs, mcpResultIsError, mcpErrorText } = sandbox;

console.log('[1] adaptBurpArgs 补齐 required 字段（Burp get_proxy_http_history 的 offset）');
{
  // 真实 schema：count/offset 都 required
  const toolDef = {
    name: 'get_proxy_http_history',
    inputSchema: {
      type: 'object',
      properties: { count: { type: 'integer' }, offset: { type: 'integer' } },
      required: ['count', 'offset'],
    },
  };
  const out = adaptBurpArgs(toolDef, { max: 30 });
  ok(out.count === 30, 'max → count', JSON.stringify(out));
  ok(out.offset === 0, '缺失的必填 offset 补 0（旧实现漏了这个字段，整条 history 报错）', JSON.stringify(out));

  // 显式给了 offset 不能被覆盖
  const out2 = adaptBurpArgs(toolDef, { max: 5, offset: 42 });
  ok(out2.offset === 42, '显式 offset 保留', JSON.stringify(out2));

  // 无 required 的 schema 不应凭空加字段
  const noReq = { inputSchema: { type: 'object', properties: { count: { type: 'integer' } } } };
  const out3 = adaptBurpArgs(noReq, { max: 3 });
  ok(out3.offset === undefined, '无 required 时不加多余字段', JSON.stringify(out3));

  // 其它类型的中性初值
  const mixed = {
    inputSchema: {
      type: 'object',
      properties: { flag: { type: 'boolean' }, names: { type: 'array' }, q: { type: 'string' } },
      required: ['flag', 'names', 'q'],
    },
  };
  const out4 = adaptBurpArgs(mixed, {});
  ok(out4.flag === false && Array.isArray(out4.names) && out4.q === '', 'boolean/array/string 各自补中性值', JSON.stringify(out4));
}

console.log('\n[2] MCP result.isError 必须被识别为失败（此前被当成功文本交给 AI）');
{
  const extErr = {
    result: {
      content: [{ type: 'text', text: "Tool 'dbg_start' requires extension 'dbg'. Enable with ?ext=dbg" }],
      isError: true,
    },
  };
  ok(mcpResultIsError(extErr) === true, 'requires extension → isError');
  ok(/requires extension/.test(mcpErrorText(extErr)), '错误文本被取出');

  const fieldErr = {
    result: { content: [{ type: 'text', text: "Field 'offset' is required ..." }], isError: true },
  };
  ok(mcpResultIsError(fieldErr) === true, '字段缺失 → isError');

  const okResp = { result: { content: [{ type: 'text', text: '[]' }], isError: false } };
  ok(mcpResultIsError(okResp) === false, '正常返回不算错误');

  const rpcErr = { error: { message: 'boom' } };
  ok(mcpResultIsError(rpcErr) === true, 'JSON-RPC error 仍算错误');

  // 源码接线：三个 MCP 客户端都必须使用它
  ok(/if \(mcpResultIsError\(resp\)\)[\s\S]{0,80}throw new Error\(mcpErrorText\(resp\)\)/.test(mainSrc),
    'IDA 客户端接入了 isError 判定');
  const burpCall = mainSrc.slice(mainSrc.indexOf('async function burpMcpCallTool'), mainSrc.indexOf('// ========== CTF²'));
  ok(/mcpResultIsError\(resp\)/.test(burpCall), 'Burp 客户端接入了 isError 判定');
}

console.log('\n[3] sshExec 透传远端退出码');
{
  const fn = extractFn('sshExec', mainSrc);
  ok(/stream\.on\('close', \(code, signal\)/.test(fn), 'close 回调接收 exit code');
  ok(/success: exitCode === 0/.test(fn), '非 0 退出码 → success:false');
  ok(/exitCode,/.test(fn), '返回体带 exitCode');
  // remoteExecTool 消费真实退出码
  const remote = mainSrc.slice(mainSrc.indexOf('async function remoteExecTool'), mainSrc.indexOf('// 调用IDA MCP'));
  ok(/r\.exitCode !== undefined \? r\.exitCode/.test(remote), 'remote_exec 使用 sshExec 的真实退出码');
}

console.log('\n[4] gzip 魔数是 2 字节：不能用 4 字节 head 全等比较');
{
  const { detectCapabilities, decideRoute } = require('../electron/file-capability.js');
  const gz = Buffer.concat([Buffer.from('1f8b0800', 'hex'), Buffer.alloc(64)]);
  const cap = detectCapabilities(gz, '.bin');
  ok(cap.archive === true, 'gzip 魔数 → archive=true（旧实现长度不等恒 false）', JSON.stringify(cap));
  ok(decideRoute({ fileType: 'UNKNOWN', ext: '.bin', capabilities: cap }) === 'extract', '有 gzip 能力 → extract 而不是 local-probe');
  // 其它魔数不能被改坏
  const zip = Buffer.concat([Buffer.from('504b0304', 'hex'), Buffer.alloc(64)]);
  ok(detectCapabilities(zip, '.bin').archive === true, 'ZIP 魔数仍识别');
}

console.log('\n[5] WASM 有独立路由，不落到"不支持的文件类型"');
{
  const swStart = appSrc.indexOf('async function autoAnalyze');
  const sw = appSrc.slice(appSrc.indexOf("switch (state.fileType)", swStart), appSrc.indexOf('// 结构化文本（XML/JSON/plist）', swStart));
  ok(/case 'WASM'/.test(sw), 'switch 里有 WASM 分支');
  ok(/case 'PCAP'/.test(sw), 'switch 里有 PCAP 分支');
  // WASM 分支不得调用 Kali 专用流程之外的东西（即不能报"不支持"）
  const wasmCase = sw.slice(sw.indexOf("case 'WASM'"), sw.indexOf("case 'UNKNOWN'"));
  ok(wasmCase.length > 0 && !/不支持的文件类型/.test(wasmCase), 'WASM 不落到 default 的"不支持"提示');
}

console.log('\n[6] Burp 错误串不得被当成"已有代理流量"');
{
  // 抽出 burpHistoryLooksEmpty 与常量，在沙箱里跑
  const s2 = { module: { exports: {} }, console };
  vm.createContext(s2);
  const constLine = appSrc.slice(appSrc.indexOf('const BURP_ERROR_RE'), appSrc.indexOf('function burpHistoryLooksEmpty'));
  vm.runInContext(constLine, s2);
  vm.runInContext(extractFn('burpHistoryLooksEmpty', appSrc), s2);
  vm.runInContext(extractFn('burpResultIsError', appSrc), s2);
  const looksEmpty = s2.burpHistoryLooksEmpty;

  ok(looksEmpty("Error: Field 'offset' is required for type with serial name 'net.portswigger.mcp.tools.GetProxyHttpHistory'") === true,
    "offset 报错 → 判空（旧实现判非空 → 跳过拉起浏览器 + 把报错喂给 AI）");
  // 任何 MCP 错误串都不是历史（包括扩展未启用的提示）：判空才是安全方向，
  // 否则会把报错当成"已有流量"并喂给 AI。
  ok(looksEmpty("Tool 'dbg_start' requires extension 'dbg'") === true, '扩展未启用错误串 → 判空');
  ok(looksEmpty('BURP_DOWN http://127.0.0.1:9876（connect ECONNREFUSED）') === true, 'BURP_DOWN → 判空');
  ok(looksEmpty('{"isError":true,"message":"x"}') === true, '结构化 isError → 判空');
  ok(looksEmpty('[]') === true, '空数组 → 判空');
  ok(looksEmpty('[{"request":"GET / HTTP/1.1"}]') === false, '真实历史 → 非空');
  ok(looksEmpty('({"entries":[{"id":1}]})') === false, 'entries 非空 → 非空');
  ok(s2.burpResultIsError("Error: Field 'offset' is required") === true, 'burpResultIsError 识别错误串');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
