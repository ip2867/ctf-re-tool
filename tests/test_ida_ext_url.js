// IDA MCP 扩展组 URL 单测。
//
// 插件把 dbg_* 全部标 @ext("dbg")；zeromcp 的 tools/list 跳过未启用的扩展组，
// tools/call 返回 requires extension。仓库配置的 URL 没有 query → 调试工具对 AI 完全不可见。
const fs = require('fs');
const path = require('path');
const { idaMcpEffectiveUrl, needsSessionReset } = require('../electron/ida-mcp-url.js');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const BASE = 'http://127.0.0.1:13337/mcp';

console.log('[1] 无 query → 追加 ?ext=dbg');
{
  const u = idaMcpEffectiveUrl(BASE, ['dbg']);
  ok(u === 'http://127.0.0.1:13337/mcp?ext=dbg', `实际 ${u}`);
}

console.log('\n[2] 已有 ?a=1 → 用 & 追加，且不重复');
{
  const u = idaMcpEffectiveUrl(BASE + '?a=1', ['dbg']);
  ok(u === 'http://127.0.0.1:13337/mcp?a=1&ext=dbg', `实际 ${u}`);
  const u2 = idaMcpEffectiveUrl(BASE + '?ext=dbg', ['dbg']);
  ok(u2 === 'http://127.0.0.1:13337/mcp?ext=dbg', `已含 ext 时不重复（${u2}）`);
}

console.log('\n[3] 多扩展组 → ext=dbg,foo');
{
  const u = idaMcpEffectiveUrl(BASE, ['dbg', 'foo']);
  ok(u === 'http://127.0.0.1:13337/mcp?ext=dbg%2Cfoo' || u === 'http://127.0.0.1:13337/mcp?ext=dbg,foo',
    `实际 ${u}`);
  const params = new URL(u).searchParams.get('ext');
  ok(params === 'dbg,foo', `ext 值为 dbg,foo（实际 ${params}）`);
}

console.log('\n[4] 已有 ext 与新增组合并去重');
{
  const u = idaMcpEffectiveUrl(BASE + '?ext=dbg', ['dbg', 'foo']);
  const params = new URL(u).searchParams.get('ext');
  ok(params === 'dbg,foo', `合并去重（实际 ${params}）`);
}

console.log('\n[5] 末尾无斜杠');
{
  const u = idaMcpEffectiveUrl('http://127.0.0.1:13337/mcp/', ['dbg']);
  ok(new URL(u).pathname === '/mcp', `path 无尾斜杠（${u}）`);
}

console.log('\n[6] needsSessionReset');
{
  ok(needsSessionReset('http://a/mcp', 'http://a/mcp?ext=dbg') === true, '不同 effective URL → true');
  ok(needsSessionReset('http://a/mcp?ext=dbg', 'http://a/mcp?ext=dbg') === false, '相同 → false');
  ok(needsSessionReset(null, 'http://a/mcp') === true, 'null vs 有值 → true');
}

console.log('\n[7] 源码静态断言：idaMcpGetBaseUrl 使用该模块');
{
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/require\('\.\/ida-mcp-url'\)/.test(mainSrc), 'require ida-mcp-url');
  const fn = mainSrc.slice(mainSrc.indexOf('async function idaMcpGetBaseUrl'), mainSrc.indexOf('async function idaMcpGetBaseUrl') + 700);
  ok(/idaMcpEffectiveUrl\(/.test(fn), 'idaMcpGetBaseUrl 调用 idaMcpEffectiveUrl');
  ok(/idaExtensions/.test(fn), '读取 config.mcp.idaExtensions');
  ok(/\[IDA MCP\] 扩展组:/.test(fn), '启动日志含「[IDA MCP] 扩展组:」');
  ok(/needsSessionReset\(idaMcpState\.baseUrl, baseUrl\)/.test(mainSrc), '会话缓存按 effective URL 比较');
  // 不修改插件源码（本仓库内没有任何 api_debug.py）
  ok(!fs.existsSync(path.join(__dirname, '..', 'api_debug.py')), '未新增/修改插件源码');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
