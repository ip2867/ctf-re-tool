// IDA 调试能力判定单测。
//
// 旧实现用关键词 ['breakpoint','debug','process','start','ea','ip',...] 过滤，
// 'ea'/'ip'/'start' 几乎命中所有工具 → "检测到 44 个调试相关工具"。
const fs = require('fs');
const path = require('path');
const {
  classifyIdaDebugTools, debuggerNotStartedLog, DBG_TOOL_WHITELIST,
} = require('../electron/ida-debug-capability.js');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] 静态工具列表 → enabled=false');
{
  const r = classifyIdaDebugTools(['py_eval', 'get_bytes', 'server_health'], false);
  ok(r.enabled === false, 'enabled=false');
  ok(r.tools.length === 0, 'tools 为空');
  ok(r.log.includes('dbg 扩展未启用'), `日志含「dbg 扩展未启用」（${r.log}）`);
}

console.log('\n[2] 含 dbg_* → 只列白名单里的调试工具');
{
  const r = classifyIdaDebugTools(['dbg_start', 'dbg_read', 'ida_decompile']);
  ok(r.enabled === true, 'enabled=true');
  ok(JSON.stringify(r.tools) === JSON.stringify(['dbg_start', 'dbg_read']), `tools=['dbg_start','dbg_read']（${JSON.stringify(r.tools)}）`);
  ok(r.log === '[IDA调试能力] 可用: dbg_start, dbg_read', `日志文本（${r.log}）`);
  ok(debuggerNotStartedLog() === '[IDA调试能力] 扩展已启用但调试器未启动（仅工具可见）', '未启动提示文案');
}

console.log("\n[3] 子串匹配必须已删除（ea / ip / start / process）");
{
  const r = classifyIdaDebugTools(['py_exec_file', 'get_bytes', 'server_health', 'ida_decompile', 'start_process'], false);
  ok(r.enabled === false, `不再误判静态工具（实际 enabled=${r.enabled}, tools=${r.tools.join(',')}）`);
  ok(!DBG_TOOL_WHITELIST.includes('ea') && !DBG_TOOL_WHITELIST.includes('ip'), '白名单无 ea/ip');
}

console.log('\n[4] app.js 两处调用点都消费同一结果');
{
  ok(!/function detectIdaDebugCapability\(tools\)\s*\{\s*\r?\n\s*try\s*\{[\s\S]{0,900}kw\.some/.test(appSrc), '旧的关键词过滤实现已删除');
  ok(/function logIdaDebugCapability\(cap\)/.test(appSrc), '统一的能力日志函数存在');
  const occ = [...appSrc.matchAll(/detectIdaDebugCapability\(toolsResult\)/g)].length;
  const calls = occ - (/function detectIdaDebugCapability\(toolsResult\)/.test(appSrc) ? 1 : 0);
  ok(calls === 2, `两个调用点都传 toolsResult（实际 ${calls}）`);
  ok(!/detectIdaDebugCapability\(toolsResult\.tools\)/.test(appSrc), '不再只传 tools 数组（会绕过主进程判定）');
  ok(/debugCapability/.test(appSrc), '消费主进程返回的 debugCapability');
  // 旧的 'ea'/'ip' 关键词数组条目不得残留
  ok(!/'ea',\s*'ip'/.test(appSrc), "源码不再含 'ea' 关键词数组条目");
}

console.log('\n[5] main.js 的 ida-mcp-analyze 返回 debugCapability');
{
  ok(/const debugCapability = classifyIdaDebugTools\(/.test(mainSrc), 'main.js 调用 classifyIdaDebugTools');
  ok(/debugCapability,\s*\r?\n\s*message: 'IDA MCP 连接成功'/.test(mainSrc), '返回体含 debugCapability');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
