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
  'mode', 'clear_remote',
];

// start 的调试模式判定。
//
// 实测（2026-10-20）：IDA 的进程选项是**全局持久**的——某次 set_remote_debugger 之后，
// ida_dbg.get_process_options() 会一直带着 (host, password, port)，
// 此后哪怕 load_debugger("win32") 成功，start_process 也返回 -1。
// 这就是"本地 Windows 调试明明可用，却一直 Failed to start debugger"的真因。
//
// 因此 start 必须先决定模式，并且**本地模式要显式清掉远程参数**。
function decideDebugMode(input, ctx) {
  const i = input || {};
  const c = ctx || {};
  const explicit = String(i.mode || c.mode || '').toLowerCase();
  if (explicit === 'local' || explicit === 'remote') return explicit;
  // 未显式指定时按目标类型推断：
  //   PE（MZ）→ local（Local Windows debugger）
  //   ELF 且配了 Kali → remote gdb（gdbserver 在 Kali 上跑目标）
  //   其余 → local（默认行为，失败时上层会给出 remote 提示）
  const kind = String(c.targetKind || c.fileType || '').toUpperCase();
  if (kind === 'ELF') return c.remoteAvailable ? 'remote' : 'local';
  return 'local';
}

// 生成 start 前需要的 py_eval 代码：设置模式 + 清残留 + 起进程。
// 返回 {tool, args}，与 buildDbgCall 的其它分支同形态。
function buildStartPrelude(mode, input, ctx) {
  const i = input || {};
  const c = ctx || {};
  const lines = ['import ida_dbg', 'import idaapi'];

  if (mode === 'remote') {
    const host = String(i.remote_host || c.remoteHost || '').trim();
    const port = Number(i.remote_port || c.remotePort) || 23946;
    const pass = String(i.remote_pass != null ? i.remote_pass : (c.remotePass || ''));
    if (!host) {
      return { error: 'remote 模式需要 remote_host（Kali 的 IP，linux_server 所在主机）' };
    }
    // ⚠️ Linux 远程调试用的是 IDA 自带的 dbgsrv/linux_server，不是 gdbserver。
    // 调试器名必须是 "linux"；用 "gdb" 会走另一套（GDB 协议）客户端，
    // 与 linux_server 的私有协议不兼容（实测：能连上但调试器不接管）。
    // 参考：看雪《IDA动态调试环境搭建教程》——Android 用 android_server，Linux 对应 linux_server。
    lines.push(`ida_dbg.load_debugger("linux", True)`);
    lines.push(`ida_dbg.set_remote_debugger(${JSON.stringify(host)}, ${JSON.stringify(pass)}, ${port})`);
  } else {
    // 本地：先清远程参数（空 host/port=-1 表示不使用远程），再加载 win32
    lines.push(`try: ida_dbg.set_remote_debugger("", "", -1)`);
    lines.push(`except Exception: pass`);
    lines.push(`ida_dbg.load_debugger("win32", False)`);
  }

  const p = i.path !== undefined ? i.path : (i.file !== undefined ? i.file : '');
  const args = i.args == null ? '' : String(i.args);
  const cwd = i.cwd == null ? '' : String(i.cwd);
  lines.push(`_rc = idaapi.start_process(${JSON.stringify(String(p))}, ${JSON.stringify(args)}, ${JSON.stringify(cwd)})`);
  lines.push(`print("START_RC", _rc)`);
  // -1 时把关键状态一起打出来，省掉下一轮排查
  lines.push(`if _rc == -1:`);
  lines.push(`    try: print("DBG_ON", ida_dbg.is_debugger_on())`);
  lines.push(`    except Exception: pass`);
  lines.push(`    try:`);
  lines.push(`        _o = ida_dbg.get_process_options()`);
  lines.push(`        _s = _o[3] if isinstance(_o, tuple) else getattr(_o, "host", "")`);
  lines.push(`        print("STALE_REMOTE", repr(_s))`);
  lines.push(`    except Exception as _e: print("OPTS_ERR", _e)`);

  return { tool: 'py_eval', args: { code: lines.join('\n') } };
}

// 返回 {tool, args}；tool 是上游真实工具名（或 py_eval）。无法识别时返回 {error}。
function buildDbgCall(action, input, ctx) {
  const i = input || {};
  const a = String(action || '').toLowerCase();

  switch (a) {
    case 'mode':
    case 'clear_remote': {
      // 只清远程调试残留（不启动进程）。用于"本地调试莫名失败"时先复位。
      const py = [
        'import ida_dbg',
        'try:',
        '    ida_dbg.set_remote_debugger("", "", -1)',
        '    print("REMOTE_CLEARED")',
        'except Exception as e:',
        '    print("CLEAR_ERR", e)',
        'try: ida_dbg.load_debugger("win32", False); print("LOCAL_LOADED")',
        'except Exception as e: print("LOAD_ERR", e)',
      ].join('\n');
      return { tool: 'py_eval', args: { code: py } };
    }
    case 'start': {
      const mode = decideDebugMode(i, ctx);
      const prelude = buildStartPrelude(mode, i, ctx);
      if (prelude.error) return { error: prelude.error };
      return prelude;
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
  if (/Failed to start debugger/i.test(s)) {
    return s + '。常见原因：①残留的远程调试配置（先 ida_dbg(action="clear_remote")）；' +
      '②目标是 ELF 却走了本地模式（改用 mode="remote" 并给 remote_host）；' +
      '③进程选项里的路径为空（start 时传 path）';
  }
  return s;
}

module.exports = {
  buildDbgCall, translateDbgError, decideDebugMode, buildStartPrelude,
  normalizeAddrList, normalizeHex, normalizeRegions, normalizeBpItems,
  DBG_ACTIONS,
};
