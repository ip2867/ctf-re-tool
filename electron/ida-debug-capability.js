'use strict';
// IDA 调试能力判定（纯函数）。
//
// 旧实现用关键词数组 ['breakpoint','debug','process','start','ea','ip',...] 过滤 tools/list，
// 结果 'ea'/'ip'/'start' 几乎命中所有工具（server_health/get_bytes/py_exec_file 全都算"调试工具"），
// 日志打出"检测到 44 个调试相关工具，可用自动化动态调试"——与事实完全相反。
//
// 现在只认白名单完整词（插件里真实存在的 dbg_* 工具名），并区分三态：
//   · 扩展组未启用（tools/list 里没有任何 dbg_*）
//   · 扩展已启用（能看到 dbg_*）
//   · 扩展已启用但调试器未启动（由调用方在 start 时判定，这里只给可见性结论）

// 只列"本工具确实包装并暴露给 AI"的工具：白名单必须与 buildDbgCall 的产出严格一致，
// 否则能力探测会宣称一个 AI 根本调不到的调试能力（这正是旧实现 44 个假阳性的同类错误）。
// dbg_regs_all / dbg_gpregs* / *_remote 变体不列入——本工具不包装它们。
const DBG_TOOL_WHITELIST = [
  'dbg_start', 'dbg_exit', 'dbg_continue', 'dbg_run_to',
  'dbg_step_into', 'dbg_step_over',
  'dbg_bps', 'dbg_add_bp', 'dbg_delete_bp', 'dbg_toggle_bp',
  'dbg_regs', 'dbg_regs_named', 'dbg_stacktrace',
  'dbg_read', 'dbg_write',
];

function classifyIdaDebugTools(toolNames, extensionEnabled) {
  const names = (Array.isArray(toolNames) ? toolNames : [])
    .map(n => String(n == null ? '' : n))
    .filter(Boolean);
  const tools = names.filter(n => DBG_TOOL_WHITELIST.includes(n));

  if (!tools.length) {
    return {
      enabled: false,
      tools: [],
      log: '[IDA调试能力] dbg 扩展未启用（tools/list 无 dbg_*）',
    };
  }
  return {
    enabled: true,
    tools,
    log: `[IDA调试能力] 可用: ${tools.join(', ')}`,
  };
}

// 调试器尚未 start 时的提示（工具可见 ≠ 调试器在跑）。
function debuggerNotStartedLog() {
  return '[IDA调试能力] 扩展已启用但调试器未启动（仅工具可见）';
}

module.exports = { classifyIdaDebugTools, debuggerNotStartedLog, DBG_TOOL_WHITELIST };
