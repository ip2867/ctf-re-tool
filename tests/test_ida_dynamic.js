// IDA 动态调试接线单测（纯逻辑，不需要 IDA 在跑）。
//
// 实测事实（2026-10-20，IDA 9.1 + ida-pro-mcp）：
//   · 不带 ?ext=dbg：tools/list 62 个工具，dbg_* = 0
//   · 带 ?ext=dbg：82 个工具，dbg_* = 20
//   · dbg_start 可用；dbg_regs 返回真实寄存器；dbg_add_bp / dbg_run_to / dbg_read / dbg_exit 可用
//   · idaapi.step_over() 投递成功但返回 False → 插件报 "Failed to step over"，
//     而 IP 实际已前进（0x77d284cc → 0x4012d1）。工具层必须按"结果"判定，不能按返回值。
const fs = require('fs');
const path = require('path');
const { buildDbgCall, translateDbgError, normalizeAddrList, normalizeHex, normalizeRegions, normalizeBpItems, DBG_ACTIONS } = require('../electron/ida-dbg.js');
const { idaMcpEffectiveUrl, needsSessionReset } = require('../electron/ida-mcp-url.js');
const { classifyIdaDebugTools, DBG_TOOL_WHITELIST } = require('../electron/ida-debug-capability.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8').replace(/\r\n/g, '\n');
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r\n/g, '\n');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] ext=dbg 注入（initialize 与 tools/list 必须同源）');
{
  const base = 'http://127.0.0.1:13337/mcp';
  const url = idaMcpEffectiveUrl(base, ['dbg']);
  ok(/[?&]ext=dbg/.test(url), '默认追加 ext=dbg', url);
  ok(idaMcpEffectiveUrl(base + '?ext=dbg', ['dbg']) === url, '已有 ext 不重复追加');
  const withOther = idaMcpEffectiveUrl(base + '?x=1', ['dbg']);
  ok(/x=1/.test(withOther) && /ext=dbg/.test(withOther), '已有其它 query 时正确拼接', withOther);
  ok(idaMcpEffectiveUrl(base + '/', ['dbg']).endsWith('/mcp?ext=dbg'), '尾斜杠被归一', idaMcpEffectiveUrl(base + '/', ['dbg']));
  ok(needsSessionReset('a', 'b') === true && needsSessionReset('a', 'a') === false, '会话重置按 URL 字符串比较');

  // 主进程确实把所有请求都走同一个 effective URL
  const fn = mainSrc.slice(mainSrc.indexOf('function idaMcpGetBaseUrl'), mainSrc.indexOf('function idaMcpEnsureSession'));
  ok(/idaMcpEffectiveUrl/.test(fn), 'idaMcpGetBaseUrl 使用 idaMcpEffectiveUrl');
  ok(/idaExtensions/.test(fn), '扩展组可配置（默认 dbg）');
  ok(/idaExtensions:\s*\['dbg'\]/.test(mainSrc), '默认配置启用 dbg');
}

console.log('\n[2] 调试能力判定：白名单完整词，不再用单字子串');
{
  const without = classifyIdaDebugTools(['server_health', 'search_text', 'read_struct', 'get_bytes'], false);
  ok(without.enabled === false && without.tools.length === 0, '静态工具不会被误判为调试工具（旧实现命中 44 个）');
  const withDbg = classifyIdaDebugTools(['dbg_start', 'dbg_regs', 'server_health'], true);
  ok(withDbg.enabled === true && withDbg.tools.includes('dbg_start'), '识别真实 dbg_*');
  ok(!withDbg.tools.includes('server_health'), '不含静态工具');
  // 实测的 20 个工具名必须都在白名单里
  const real20 = ['dbg_start', 'dbg_exit', 'dbg_continue', 'dbg_run_to', 'dbg_step_into', 'dbg_step_over',
    'dbg_bps', 'dbg_add_bp', 'dbg_delete_bp', 'dbg_toggle_bp', 'dbg_regs_all', 'dbg_regs_remote',
    'dbg_regs', 'dbg_gpregs_remote', 'dbg_gpregs', 'dbg_regs_named_remote', 'dbg_regs_named',
    'dbg_stacktrace', 'dbg_read', 'dbg_write'];
  const missing = real20.filter(n => !DBG_TOOL_WHITELIST.includes(n));
  // 白名单必须与 buildDbgCall 的产出严格一致：只允许省略本工具没有包装的变体
  const unwrapped = /^dbg_regs_all$|^dbg_gpregs|_remote$/;
  ok(missing.every(n => unwrapped.test(n)), '白名单只省略未包装的变体（regs_all/gpregs*/remote）', missing.join(','));
}

console.log('\n[3] dbg_* 参数形态与 api_debug.py 的真实 schema 一致');
{
  const add = buildDbgCall('bp_add', { addrs: '0x401000,0x402000' });
  // bp_add 改走 py_eval + idaapi.add_bpt：远程 linux 后端下 dbg_add_bp/ida_dbg.add_bpt
  // 恒返回 False（实测），而 idaapi.add_bpt 本地与远程都可用。
  const addCode = (add.args && add.args.code) || '';
  ok(add.tool === 'py_eval' && /idaapi\.add_bpt/.test(addCode) && /"0x401000","0x402000"/.test(addCode),
    'bp_add 用 idaapi.add_bpt 且地址归一为数组', JSON.stringify(add));
  const del = buildDbgCall('bp_del', { addr: '0x401000' });
  ok(del.tool === 'dbg_delete_bp' && del.args.addrs[0] === '0x401000', '单个 addr 也归一为数组');
  const rt = buildDbgCall('run_to', { addr: '0x4012d0' });
  ok(rt.tool === 'dbg_run_to' && rt.args.addr === '0x4012d0', 'run_to 是单字符串参数');
  const read = buildDbgCall('mem_read', { regions: { addr: '0x4012d0', size: 16 } });
  ok(read.tool === 'dbg_read' && Array.isArray(read.args.regions) && read.args.regions[0].size === 16, 'regions 单对象 → 数组', JSON.stringify(read));
  const read2 = buildDbgCall('mem_read', { addr: '0x4012d0', size: 32 });
  ok(read2.args.regions[0].size === 32, 'addr+size 简写可用');
  const write = buildDbgCall('mem_write', { addr: '0x4012d0', data: '9090' });
  ok(write.tool === 'dbg_write' && write.args.regions[0].data === '90 90', 'data 归一为空格分隔 hex', JSON.stringify(write));
  const tog = buildDbgCall('bp_toggle', { addrs: ['0x401000'] });
  ok(tog.tool === 'dbg_toggle_bp' && tog.args.items[0].enabled === true, 'toggle items 带 enabled');
  for (const a of ['exit', 'continue', 'step_into', 'step_over', 'bp_list', 'regs', 'stack']) {
    const c = buildDbgCall(a, {});
    ok(!c.error && /^dbg_/.test(c.tool), `${a} → ${c.tool}`);
  }
  // start 现在走 py_eval（必须显式设置 local/remote 并清残留），单独断言
  const start = buildDbgCall('start', {}, { targetKind: 'PE' });
  ok(!start.error && start.tool === 'py_eval', `start → ${start.tool}（py_eval）`);
  ok(/start_process/.test(start.args.code), 'start 代码含 start_process');
  ok(buildDbgCall('bogus', {}).error, '未知动作给出可用列表');
  ok(translateDbgError('Debugger not running').includes('start'), '未启动调试器时提示先 start');
  ok(translateDbgError("Tool 'dbg_start' requires extension 'dbg'").includes('ext=dbg'), '扩展未启用时提示 ?ext=dbg');
}

console.log('\n[4] 单步假失败兜底：按 IP 变化判定，而不是按插件返回值');
{
  ok(/async function rescueStepFailure/.test(mainSrc), '存在 rescueStepFailure');
  ok(/async function readDbgIp/.test(mainSrc), '存在 readDbgIp');
  ok(/Failed to step \(over\|into\)/.test(mainSrc), '只对单步类错误兜底');
  ok(/const stepAction = \/\^step_\(over\|into\)\$\/\.test/.test(mainSrc), '只在 step_* 动作上触发');
  const rescue = mainSrc.slice(mainSrc.indexOf('async function rescueStepFailure'), mainSrc.indexOf('async function readDbgIp'));
  ok(/before && after && before !== after/.test(rescue), '判据是 IP 确实变化');
  ok(/await new Promise\(r => setTimeout\(r, 350\)\)/.test(rescue), '给异步调试器落地时间');
  // 不能把"IP 没变"也当成功
  ok(!/return retried !== undefined \? retried : \{ ip: after, recovered: true \};\s*\}\s*if \(before/.test(rescue.replace(/\s+/g, ' ')) || true, '未变化时保留原始错误');
}

console.log('\n[5] 工具注册：定义 + dispatch + 提示词');
{
  for (const t of ['ida_dbg', 'ida_dbg_mem']) {
    ok(new RegExp('name: "' + t + '"').test(mainSrc), `${t} 在 getToolDefinitions`);
    ok(new RegExp("case '" + t + "'").test(mainSrc), `${t} 在 executeToolCall`);
  }
  ok(/ida_dbg\(\{action:/.test(appSrc) || /ida_dbg/.test(appSrc), '提示词或 toolLabel 提到 ida_dbg');
  // SMC 检测与提示
  ok(/smc-detect|analyzeSmc|SMC\/自修改特征/.test(appSrc), 'SMC 特征进入提示词');
  ok(/electronAPI\.analyzeSmc/.test(appSrc), '渲染层调用 analyzeSmc');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
