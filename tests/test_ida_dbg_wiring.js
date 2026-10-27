// 动态调试工具接线单测：只新增 ida_dbg / ida_dbg_mem 两个 AI 工具，
// 内部映射到插件的 dbg_* 真实工具名。参数形态必须按 api_debug.py 的真实 schema。
const fs = require('fs');
const path = require('path');
const {
  buildDbgCall, translateDbgError, normalizeAddrList, normalizeHex,
  normalizeRegions, normalizeBpItems, DBG_ACTIONS,
} = require('../electron/ida-dbg.js');
const { DBG_TOOL_WHITELIST } = require('../electron/ida-debug-capability.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] schema 恰好新增 ida_dbg / ida_dbg_mem，action 枚举完整');
{
  const dbg = mainSrc.slice(mainSrc.indexOf('name: "ida_dbg"'), mainSrc.indexOf('name: "ida_dbg_mem"'));
  const mem = mainSrc.slice(mainSrc.indexOf('name: "ida_dbg_mem"'), mainSrc.indexOf('name: "remote_exec"'));
  ok(dbg.length > 0 && mem.length > 0, '两个工具定义都存在');
  const e1 = (dbg.match(/enum: \[([^\]]+)\]/) || [])[1] || '';
  const acts = [...e1.matchAll(/"([a-z_]+)"/g)].map(m => m[1]);
  for (const a of ['start', 'exit', 'continue', 'run_to', 'step_into', 'step_over', 'status', 'suspend', 'bp_list', 'bp_add', 'bp_del', 'bp_toggle', 'regs', 'regs_named', 'stack']) {
    ok(acts.includes(a), `ida_dbg action 含 ${a}`);
  }
  ok(/enum: \["read", "write"\]/.test(mem), 'ida_dbg_mem action 为 read/write');
}

console.log('\n[2] buildDbgCall 对每个 action 逐一断言上游工具名与参数');
{
  // start 不再是"无参 dbg_start"：实测 IDA 的进程选项会残留上一次的
  // set_remote_debugger(host, pass, port)，此后本地 start_process 恒返回 -1。
  // 因此 start 必须先显式决定 local/remote 并清残留 → 统一走 py_eval。
  const startLocal = buildDbgCall('start', { path: 'a.exe' }, { targetKind: 'PE' });
  ok(startLocal.tool === 'py_eval', 'start → py_eval（需要设置模式）', startLocal.tool);
  ok(/set_remote_debugger\("", "", -1\)/.test(startLocal.args.code), 'local 模式清远程残留');
  ok(/load_debugger\("win32", False\)/.test(startLocal.args.code), 'local 模式加载 win32');
  ok(/_p = "a\.exe"/.test(startLocal.args.code) && /start_process\(_p,/.test(startLocal.args.code),
    '显式 path 经 _p 变量用于 start_process');

  // 不传 path 时必须回落到 IDA 当前加载的文件：
  // start_process("", ...) 在 path 为空时返回 0（启动被取消），
  // 以前能跑只是因为进程选项里残留着上一次的路径。
  const startNoPath = buildDbgCall('start', {}, { targetKind: 'PE' });
  const npc = startNoPath.args.code || '';
  ok(/get_input_file_path\(\)/.test(npc), '无 path 时回落到 get_input_file_path()');
  ok(/start_process\(_p,/.test(npc), 'start_process 使用回落后的路径变量 _p');
  ok(!/start_process\("",/.test(npc), '不再出现 start_process("")（会返回 RC=0）');

  const cases = [
    ['exit', {}, 'dbg_exit', {}],
    ['continue', {}, 'dbg_continue', {}],
    ['run_to', { addr: '0x401000' }, 'dbg_run_to', { addr: '0x401000' }],
    ['step_into', {}, 'dbg_step_into', {}],
    ['step_over', {}, 'dbg_step_over', {}],
    ['bp_list', {}, 'dbg_bps', {}],
    // bp_add 从 dbg_add_bp 改为 py_eval + idaapi.add_bpt：
    // 实测远程 linux 后端下 ida_dbg.add_bpt / dbg_add_bp 恒返回 False，
    // 而 idaapi.add_bpt 同时适用于本地与远程。
    ['bp_add', { addrs: '0x1,0x2' }, 'py_eval', null],
    ['bp_del', { addrs: ['0x1', '0x2'] }, 'dbg_delete_bp', { addrs: ['0x1', '0x2'] }],
    ['bp_toggle', { items: { addr: '0x1', enabled: false } }, 'dbg_toggle_bp', { items: [{ addr: '0x1', enabled: false }] }],
    ['regs', {}, 'dbg_regs', {}],
    ['regs_named', { regs: 'RAX,RBX' }, 'dbg_regs_named', { register_names: 'RAX,RBX' }],
    ['stack', {}, 'dbg_stacktrace', {}],
    ['mem_read', { regions: { addr: '0x401000', size: 16 } }, 'dbg_read', { regions: [{ addr: '0x401000', size: 16 }] }],
    ['mem_write', { regions: { addr: '0x401000', data: 'abcd' } }, 'dbg_write', { regions: [{ addr: '0x401000', data: 'ab cd' }] }],
    ['clear_remote', {}, 'py_eval', null],
    ['status', {}, 'py_eval', null],
    ['suspend', {}, 'py_eval', null],
  ];
  for (const [action, input, tool, args] of cases) {
    const r = buildDbgCall(action, input);
    ok(r.tool === tool, `${action} → ${tool}（实际 ${r.tool || r.error}）`);
    if (args) ok(JSON.stringify(r.args) === JSON.stringify(args), `${action} 参数 ${JSON.stringify(args)}（实际 ${JSON.stringify(r.args)}）`);
  }
  ok(DBG_ACTIONS.length === 22, `DBG_ACTIONS 共 22 项（19 + 运行期探测 3 个）实际 ${DBG_ACTIONS.length}`);

  // bp_add 的生成代码必须用 idaapi.add_bpt 并覆盖每个地址
  const bpa = buildDbgCall('bp_add', { addrs: '0x401000,0x401010' });
  const bcode = (bpa.args && bpa.args.code) || '';
  ok(/idaapi\.add_bpt/.test(bcode), 'bp_add 使用 idaapi.add_bpt（远程后端可用）');
  ok(/"0x401000","0x401010"/.test(bcode), 'bp_add 把全部地址写进循环');
}

console.log('\n[3] 形态归一化');
{
  ok(JSON.stringify(normalizeAddrList('0x1,0x2')) === '["0x1","0x2"]', "addrs:'0x1,0x2' → ['0x1','0x2']");
  ok(JSON.stringify(normalizeRegions({ addr: '0x1', size: 8 }, 'read')) === '[{"addr":"0x1","size":8}]', 'regions 单对象 → 数组');
  ok(JSON.stringify(normalizeBpItems({ addr: '0x1', enabled: true })) === '[{"addr":"0x1","enabled":true}]', 'items 单对象 → [{addr,enabled}]');
}

console.log('\n[4] start 带 args/cwd → 参数进入 start_process；path 缺省回落到当前文件');
{
  const r = buildDbgCall('start', { args: '-d', cwd: 'C:\\tmp' });
  ok(r.tool === 'py_eval', `上游 py_eval（实际 ${r.tool}）`);
  const code = r.args.code || '';
  ok(/idaapi\.start_process/.test(code), '代码含 idaapi.start_process');
  // start_process("", ...) 会返回 0（启动被取消），缺省 path 必须回落到当前加载文件
  ok(/get_input_file_path\(\)/.test(code) && /start_process\(_p, "-d"/.test(code),
    'path 缺省回落到 get_input_file_path()');
  ok(/"-d"/.test(code) && /C:\\\\tmp/.test(code), 'args/cwd 被带入');
  const withPath = buildDbgCall('start', { path: 'a.exe' });
  ok(withPath.tool === 'py_eval' && /_p = "a\.exe"/.test(withPath.args.code), '只给 path 也走 py_eval 并带入路径');
}

console.log('\n[5] hex 形态：read 输出带空格 / write 接受无空格');
{
  ok(normalizeHex('abcd') === 'ab cd', "write 接受 'abcd' → 'ab cd'");
  ok(normalizeHex('ab cd') === 'ab cd', "已带空格保持 'ab cd'");
  ok(normalizeHex([0xab, 0xcd]) === 'ab cd', '字节数组 → ab cd');
  const w = buildDbgCall('mem_write', { addr: '0x1', data: 'ABCD' });
  ok(w.args.regions[0].data === 'ab cd', '大写/无空格统一为小写带空格');
}

console.log('\n[6] 错误翻译');
{
  ok(/请先调用 ida_dbg\(action="start"\)/.test(translateDbgError('Debugger not running')), 'Debugger not running → 提示 start');
  ok(/ext=dbg/.test(translateDbgError('Tool requires extension \'dbg\'')), 'requires extension → 提示扩展组');
}

console.log('\n[7] 登记：dispatch / KNOWN / MAP / toolLabel / precheck');
{
  ok(/case 'ida_dbg':/.test(mainSrc), "dispatch 含 case 'ida_dbg'");
  ok(/case 'ida_dbg_mem':/.test(mainSrc), "dispatch 含 case 'ida_dbg_mem'");
  const known = mainSrc.slice(mainSrc.indexOf('const KNOWN = new Set(['), mainSrc.indexOf('const KNOWN = new Set([') + 1200);
  ok(/'ida_dbg'/.test(known) && /'ida_dbg_mem'/.test(known), 'KNOWN 集合含两者');
  const map = mainSrc.slice(mainSrc.indexOf('const MAP = {'), mainSrc.indexOf('const MAP = {') + 900);
  ok(/ida_dbg: 'action'/.test(map) && /ida_dbg_mem: 'action'/.test(map), 'MAP 含两者（裸参 → action）');
  const label = mainSrc.slice(mainSrc.indexOf('function toolLabel'), mainSrc.indexOf('// 执行命令（渲染层'));
  ok(/case 'ida_dbg'/.test(label) && /case 'ida_dbg_mem'/.test(label), 'toolLabel 含两者');
  const pre = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'), mainSrc.indexOf('function levenshtein'));
  ok(/name === 'ida_dbg'/.test(pre) && /name === 'ida_dbg_mem'/.test(pre), 'precheck 含两者');
  ok(/缺少 action 参数/.test(pre), 'precheck 给出 action 的必填提示');
  // 白名单里的 dbg_* 都能被 buildDbgCall 产出
  const produced = new Set(casesTools());
  for (const t of DBG_TOOL_WHITELIST) {
    if (!/^dbg_/.test(t)) continue;
    ok(produced.has(t), `白名单 ${t} 有对应 buildDbgCall 产出`);
  }
}

function casesTools() {
  return ['dbg_start', 'dbg_exit', 'dbg_continue', 'dbg_run_to', 'dbg_step_into', 'dbg_step_over',
    'dbg_bps', 'dbg_add_bp', 'dbg_delete_bp', 'dbg_toggle_bp', 'dbg_regs', 'dbg_regs_named',
    'dbg_stacktrace', 'dbg_read', 'dbg_write'];
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
