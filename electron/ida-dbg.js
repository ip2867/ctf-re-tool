'use strict';
// ida-pro-mcp 的 dbg_* 工具 → 两个合并 AI 工具（ida_dbg / ida_dbg_mem）的映射。
//
// 插件有 20 个 dbg_* 工具，逐个建 schema 会让 AI 的工具表膨胀。这里把控制类
// （start/exit/continue/run_to/step/bp/regs/stack）合并成 ida_dbg，把内存读写
// 合并成 ida_dbg_mem，内部映射回真实工具名。
//
// 参数形态必须按 api_debug.py 的真实 schema：
//   · 无参：dbg_start / dbg_exit / dbg_continue / dbg_step_into / dbg_step_over / dbg_bps / dbg_regs / dbg_stacktrace
//   · dbg_run_to(addr) 单个字符串
//   · dbg_add_bp / dbg_delete_bp 的 addrs 是 list[str] | str
//   · dbg_read 的 regions 是 list[{addr,size}]，dbg_write 是 list[{addr,data}]
//
// 纯函数、零 Electron 依赖，便于在无 IDA 的环境下测试。

// addrs: '0x1,0x2' | ['0x1','0x2'] | '0x1' → ['0x1','0x2']
function normalizeAddrList(v) {
  if (v == null) return [];
  const arr = Array.isArray(v) ? v : [v];
  const out = [];
  for (const item of arr) {
    const s = String(item == null ? '' : item).trim();
    if (!s) continue;
    // 单个字符串里可能再带逗号/分号/空白分隔
    for (const part of s.split(/[,;\s]+/)) {
      const p = part.trim();
      if (p) out.push(p);
    }
  }
  return [...new Set(out)];
}

// hex：接受 'ab cd'、'abcd'、Buffer/Uint8Array、数字数组 → 'ab cd'
function normalizeHex(v) {
  if (v == null) return '';
  let bytes = [];
  if (Buffer.isBuffer(v)) bytes = Array.from(v);
  else if (Array.isArray(v)) {
    bytes = v.map((x) => {
      if (typeof x === 'number') return x & 0xff;
      return parseInt(String(x), 16);
    });
  } else {
    const s = String(v).replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
    if (!s) return '';
    for (let i = 0; i + 1 < s.length; i += 2) bytes.push(parseInt(s.slice(i, i + 2), 16));
  }
  return bytes.filter((b) => Number.isFinite(b)).map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

// regions 单对象 → 数组；元素保留 {addr,size} / {addr,data}
function normalizeRegions(v, kind) {
  if (v == null) return [];
  const arr = Array.isArray(v) ? v : [v];
  return arr.map((r) => {
    if (r == null || typeof r !== 'object') return null;
    const addr = String(r.addr != null ? r.addr : (r.address != null ? r.address : '')).trim();
    if (!addr) return null;
    if (kind === 'write') {
      return { addr, data: normalizeHex(r.data != null ? r.data : r.bytes) };
    }
    const size = Number(r.size != null ? r.size : r.length);
    return { addr, size: Number.isFinite(size) && size > 0 ? size : 16 };
  }).filter(Boolean);
}

// bp_toggle: 单对象 {addr,enabled} → [{addr,enabled}]；也接受 ['0x1','0x2']
function normalizeBpItems(v) {
  if (v == null) return [];
  const arr = Array.isArray(v) ? v : [v];
  const out = [];
  for (const item of arr) {
    if (item == null) continue;
    if (typeof item === 'object') {
      const addr = String(item.addr != null ? item.addr : (item.address != null ? item.address : '')).trim();
      if (!addr) continue;
      out.push({ addr, enabled: item.enabled === undefined ? true : !!item.enabled });
    } else {
      // 单个字符串里可能再带逗号（"0x1,0x2"）
      for (const part of String(item).split(/[,;\s]+/)) {
        const addr = part.trim();
        if (addr) out.push({ addr, enabled: true });
      }
    }
  }
  return out;
}

const DBG_ACTIONS = [
  'start', 'exit', 'continue', 'run_to', 'step_into', 'step_over',
  'bp_list', 'bp_add', 'bp_del', 'bp_toggle', 'regs', 'regs_named', 'stack',
  'mem_read', 'mem_write',
];

// 返回 {tool, args}；tool 是上游真实工具名（或 py_eval）。无法识别时返回 {error}。
function buildDbgCall(action, input) {
  const i = input || {};
  const a = String(action || '').toLowerCase();

  switch (a) {
    case 'start': {
      const hasArgs = i.args !== undefined || i.cwd !== undefined;
      if (hasArgs) {
        // dbg_start 自己不收参数（固定 start_process("","","")），要带参数只能走 py_eval。
        // path 缺省为空串 = 调试 IDA 当前已加载的数据库（主进程只有 currentWorkDir，没有 currentFile）。
        const p = i.path !== undefined ? i.path : (i.file !== undefined ? i.file : '');
        const args = i.args == null ? '' : String(i.args);
        const cwd = i.cwd == null ? '' : String(i.cwd);
        const py = `import idaapi\nidaapi.start_process(${JSON.stringify(String(p))}, ${JSON.stringify(args)}, ${JSON.stringify(cwd)})\nprint("started")`;
        return { tool: 'py_eval', args: { code: py } };
      }
      return { tool: 'dbg_start', args: {} };
    }
    case 'exit': return { tool: 'dbg_exit', args: {} };
    case 'continue': return { tool: 'dbg_continue', args: {} };
    case 'run_to': {
      const addr = String(i.addr != null ? i.addr : (i.address != null ? i.address : '')).trim();
      if (!addr) return { error: 'ida_dbg(action="run_to") 需要 addr 参数（目标地址）' };
      return { tool: 'dbg_run_to', args: { addr } };
    }
    case 'step_into': return { tool: 'dbg_step_into', args: {} };
    case 'step_over': return { tool: 'dbg_step_over', args: {} };
    case 'bp_list': return { tool: 'dbg_bps', args: {} };
    case 'bp_add': {
      const addrs = normalizeAddrList(i.addrs != null ? i.addrs : (i.addr != null ? i.addr : i.address));
      if (!addrs.length) return { error: 'ida_dbg(action="bp_add") 需要 addrs 参数（地址或地址数组）' };
      return { tool: 'dbg_add_bp', args: { addrs } };
    }
    case 'bp_del': {
      const addrs = normalizeAddrList(i.addrs != null ? i.addrs : (i.addr != null ? i.addr : i.address));
      if (!addrs.length) return { error: 'ida_dbg(action="bp_del") 需要 addrs 参数（地址或地址数组）' };
      return { tool: 'dbg_delete_bp', args: { addrs } };
    }
    case 'bp_toggle': {
      const items = normalizeBpItems(i.items != null ? i.items : (i.addrs != null ? i.addrs : i.addr));
      if (!items.length) return { error: 'ida_dbg(action="bp_toggle") 需要 items 参数（{addr,enabled} 或地址数组）' };
      return { tool: 'dbg_toggle_bp', args: { items } };
    }
    case 'regs': return { tool: 'dbg_regs', args: {} };
    case 'regs_named': {
      // 上游要逗号分隔的单个字符串，不是数组
      const names = normalizeAddrList(i.regs != null ? i.regs : (i.register_names != null ? i.register_names : i.names));
      if (!names.length) return { error: 'ida_dbg(action="regs_named") 需要 regs 参数（如 "RAX,RBX"）' };
      return { tool: 'dbg_regs_named', args: { register_names: names.join(',') } };
    }
    case 'stack': return { tool: 'dbg_stacktrace', args: {} };
    case 'mem_read': {
      const regions = normalizeRegions(i.regions != null ? i.regions : { addr: i.addr != null ? i.addr : i.address, size: i.size }, 'read');
      if (!regions.length) return { error: 'ida_dbg_mem(action="read") 需要 regions（[{addr,size}]）或 addr+size' };
      return { tool: 'dbg_read', args: { regions } };
    }
    case 'mem_write': {
      const regions = normalizeRegions(i.regions != null ? i.regions : { addr: i.addr != null ? i.addr : i.address, data: i.data }, 'write');
      if (!regions.length) return { error: 'ida_dbg_mem(action="write") 需要 regions（[{addr,data}]）或 addr+data' };
      return { tool: 'dbg_write', args: { regions } };
    }
    default:
      return { error: `未知的调试动作: ${action}（可用: ${DBG_ACTIONS.join(', ')}）` };
  }
}

// 上游错误翻译成"下一步该怎么做"。
function translateDbgError(msg) {
  const s = String(msg || '');
  if (/Debugger not running/i.test(s)) return '请先调用 ida_dbg(action="start") 启动调试器';
  if (/requires extension/i.test(s)) {
    return 'IDA MCP 未启用 dbg 扩展组（URL 需带 ?ext=dbg）——请检查主进程的 mcp.idaExtensions 配置';
  }
  return s;
}

module.exports = {
  buildDbgCall, translateDbgError,
  normalizeAddrList, normalizeHex, normalizeRegions, normalizeBpItems,
  DBG_ACTIONS,
};
