'use strict';
// 运行期探测原语（runtime probing primitives）
//
// ── 为什么需要这一层（Matr1x 实测教训）──────────────────────────────
// 上一轮解 Matr1x 时，静态读 handler 被混淆挡住，最后卡在
// "sub_39E3 那 12 个转动 handler 对 54 格的置换语义"。
// 但 handler **做了什么** 完全可以在运行期直接量：转动就是置换 54 个格子，
// 跑一次、前后各 dump 一次、逐项 diff，置换表就出来了。
//
// 现有 ida_dbg 只能"读单点内存 / 读寄存器"，缺的是：
//   ① 一次操作里完成「执行 → 前后快照 → 差分」这个闭环
//   ② 在不重新设计题目的前提下，强制让被混淆打断的控制流继续
//   ③ 统计"函数到底碰了哪些全局数据"，从而识别单行/单块校验
//
// 本模块只生成 IDAPython 代码（走 py_eval），不直接碰 IDA 状态，
// 因此可单测：给定入参 → 断言生成的代码包含预期结构。

// ───────────────────────── 通用工具 ─────────────────────────

function parseIntLoose(v) {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  const s = String(v == null ? '' : v).trim();
  if (!s) return null;
  const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : (/^-?\d+$/.test(s) ? parseInt(s, 10) : NaN);
  return Number.isFinite(n) ? n : null;
}

/**
 * 归一化快照区域：既要接受 [{addr,size}]，也要接受裸地址（默认按 dword 计）。
 * size 上限 8MB —— 单次 py_eval 里把几 MB 数据 hex 出来会撑爆 MCP 响应。
 */
function normalizeSnapshotRegions(v, defaultSize) {
  const out = [];
  const push = (addr, size) => {
    const a = parseIntLoose(addr);
    let n = parseIntLoose(size);
    if (a === null || a < 0) return;
    if (n === null || n <= 0) n = defaultSize || 256;
    out.push({ addr: a, size: Math.min(n, 8 * 1024 * 1024) });
  };
  if (Array.isArray(v)) {
    for (const it of v) {
      if (it && typeof it === 'object') push(it.addr != null ? it.addr : it.address, it.size);
      else push(it, defaultSize);
    }
  } else if (v && typeof v === 'object') {
    push(v.addr != null ? v.addr : v.address, v.size);
  } else if (v != null) {
    push(v, defaultSize);
  }
  return out;
}

// ───────────────────── ① 运行期状态差分 ─────────────────────

/**
 * 生成"前后快照 + 差分"的代码。
 *
 * 用法（AI 视角）：
 *   ida_dbg({action:"snapshot_diff", regions:[{addr:"0x13200",size:216}], mode:"until_return"})
 *
 * mode:
 *   "manual"        —— 只拍 before 快照并返回快照 id，等 AI 手动 continue 后再调 once
 *   "single_step"   —— 拍完 before 立刻单步 1 条，再拍 after（看一条指令的效果）
 *   "until_return"  —— 以当前函数返回地址为临时断点，continue 到返回后拍 after
 *                      （最适合"整个 handler 做了什么变换"）
 *   "until_addr"    —— continue 到指定 addr（需 target）
 *
 * 关键设计：快照存在 IDA 的 Python 全局里（_CTF_SNAPS），
 * 不经过 MCP 往返，避免 216 字节 × 前后两份被 hex 两次再在 JS 侧 diff。
 * 差分直接在 IDAPython 里算完，只回传变化项。
 */
function buildSnapshotDiff(input) {
  const i = input || {};
  const regions = normalizeSnapshotRegions(i.regions != null ? i.regions : (i.addr != null ? i.addr : i.address), i.size);
  if (!regions.length) {
    return { error: 'snapshot_diff 需要 regions（[{addr,size}] 或 addr+size）' };
  }
  const mode = String(i.mode || 'until_return').toLowerCase();
  const allowed = ['manual', 'once', 'single_step', 'until_return', 'until_addr'];
  if (!allowed.includes(mode)) {
    return { error: `snapshot_diff 的 mode 只能是 ${allowed.join('/')}` };
  }
  const target = parseIntLoose(i.target != null ? i.target : i.addr_to);
  if (mode === 'until_addr' && target === null) {
    return { error: 'mode="until_addr" 需要 target 参数（目标地址）' };
  }

  const L = [];
  L.push('import ida_dbg, idaapi, idc');
  L.push('_R = ' + JSON.stringify(regions.map(r => ({ a: r.addr, s: r.size }))));
  L.push('try: _SNAP');
  L.push('except NameError: _SNAP = {}');
  L.push('def _ctf_take(_tag):');
  L.push('    _d = {}');
  L.push('    for _r in _R:');
  L.push('        try:');
  L.push('            _b = idaapi.dbg_read_memory(_r["a"], _r["s"])');
  L.push('            _d[_r["a"]] = _b.hex() if _b else None');
  L.push('        except Exception as _e:');
  L.push('            _d[_r["a"]] = None');
  L.push('    _SNAP[_tag] = _d');
  L.push('    return _d');
  L.push('def _ctf_diff(_a, _b):');
  L.push('    _out = []');
  L.push('    for _r in _R:');
  L.push('        _x = _a.get(_r["a"]); _y = _b.get(_r["a"])');
  L.push('        if _x is None or _y is None:');
  L.push('            _out.append({"addr": hex(_r["a"]), "error": "read-failed"}); continue');
  L.push('        _n = min(len(_x), len(_y)) // 2');
  L.push('        _chg = []');
  L.push('        for _k in range(_n):');
  L.push('            _u = _x[_k*2:_k*2+2]; _v = _y[_k*2:_k*2+2]');
  L.push('            if _u != _v:');
  L.push('                _chg.append({"off": _k, "before": _u, "after": _v})');
  L.push('        _out.append({"addr": hex(_r["a"]), "bytes": _n, "changed": len(_chg), "diff": _chg[:512]})');
  L.push('    return _out');

  if (mode === 'manual') {
    L.push('_ctf_take("before")');
    L.push('print("SNAPSHOT before taken for", len(_R), "region(s)")');
    L.push('print("NEXT call ida_dbg(action=\\"snapshot_diff\\", mode=\\"once\\") to diff")');
  } else if (mode === 'once') {
    L.push('_ctf_take("after")');
    L.push('if "before" not in _SNAP:');
    L.push('    print("NO_BEFORE 请先以 mode=\\"manual\\" 拍 before 快照")');
    L.push('else:');
    L.push('    for _d in _ctf_diff(_SNAP["before"], _SNAP["after"]):');
    L.push('        print("REGION", _d.get("addr"), "bytes", _d.get("bytes"), "changed", _d.get("changed"))');
    L.push('        for _c in (_d.get("diff") or [])[:256]:');
    L.push('            print("  CHANGE off=%d %s -> %s" % (_c["off"], _c["before"], _c["after"]))');
  } else if (mode === 'single_step') {
    L.push('_ctf_take("before")');
    L.push('_ip0 = ida_dbg.get_ip_val()');
    L.push('print("BEFORE_IP", hex(_ip0) if _ip0 is not None else "None")');
    L.push('try: ida_dbg.step_into()');
    L.push('except Exception as _e: print("STEP_ERR", _e)');
    L.push('_ctf_take("after")');
    L.push('_ip1 = ida_dbg.get_ip_val()');
    L.push('print("AFTER_IP", hex(_ip1) if _ip1 is not None else "None")');
    L.push('for _d in _ctf_diff(_SNAP["before"], _SNAP["after"]):');
    L.push('    print("REGION", _d.get("addr"), "changed", _d.get("changed"))');
    L.push('    for _c in (_d.get("diff") or [])[:256]:');
    L.push('        print("  CHANGE off=%d %s -> %s" % (_c["off"], _c["before"], _c["after"]))');
  } else if (mode === 'until_addr') {
    L.push('_ctf_take("before")');
    L.push('_t = ' + target);
    L.push('_bp_new = True');
    L.push('try:');
    L.push('    if idaapi.get_bpt_qty() and any(b.ea == _t for b in idaapi.dbg_bps()):');
    L.push('        _bp_new = False');
    L.push('except Exception: pass');
    L.push('try:');
    L.push('    if _bp_new: idaapi.add_bpt(_t, 0, idaapi.BPT_SOFT)');
    L.push('    ida_dbg.continue_process()');
    L.push('except Exception as _e: print("CONT_ERR", _e)');
    L.push('print("TARGET", hex(_t))');
    L.push('print("NEXT 等进程停在目标后，再调 snapshot_diff(mode=\\"once\\")")');
  } else {
    // until_return：以当前函数的返回地址为临时断点
    L.push('_ctf_take("before")');
    L.push('_ip = ida_dbg.get_ip_val()');
    L.push('_f = idaapi.get_func(_ip) if _ip is not None else None');
    L.push('if _f is None:');
    L.push('    print("NO_FUNC", hex(_ip) if _ip is not None else "None")');
    L.push('    print("FALLBACK 用 mode=\\"single_step\\" 或手动 continue 后 mode=\\"once\\"")');
    L.push('else:');
    L.push('    _t = _f.end_ea');
    L.push('    print("RET_ADDR", hex(_t))');
    L.push('    try:');
    L.push('        idaapi.add_bpt(_t, 0, idaapi.BPT_SOFT)');
    L.push('    except Exception as _e: print("BP_ERR", _e)');
    L.push('    try:');
    L.push('        ida_dbg.continue_process()');
    L.push('        print("CONTINUED")');
    L.push('    except Exception as _e: print("CONT_ERR", _e)');
    L.push('    print("NEXT 停在返回地址后，调 snapshot_diff(mode=\\"once\\")")');
  }

  return { tool: 'py_eval', args: { code: L.join('\n') } };
}

// ───────────────────── ② 强制控制流继续 ─────────────────────

/**
 * 在断点处改寄存器值并继续执行。
 *
 * 为什么必须有：Matr1x 的 sub_4638 本该循环 6 次校验 6 行，但第一轮就被
 * `test eax,eax; je exit` 提前退出，导致只抓到 1 行的 2 个常量、漏掉 5 行。
 * 手工在 gdb 里可以 `commands ... set $eax=1 ... end`，但通过 MCP 做不到。
 *
 * input:
 *   set: [{reg:"eax", value:1}, ...]   要写入的寄存器
 *   then: "continue" | "step_into" | "step_over" | "none"
 *   repeat: N      执行上述操作的次数（默认 1）——用于"让循环跑满"
 *   bp_addr: 可选，在指定地址下断点（配合 repeat 反复命中）
 */
function buildForceContinue(input) {
  const i = input || {};
  const sets = [];
  const raw = Array.isArray(i.set) ? i.set : (i.set && typeof i.set === 'object' ? [i.set] : []);
  for (const s of raw) {
    if (!s) continue;
    const reg = String(s.reg != null ? s.reg : (s.name || '')).trim();
    const val = parseIntLoose(s.value != null ? s.value : s.v);
    if (!reg || val === null) continue;
    sets.push({ reg, val });
  }
  if (!sets.length) {
    return { error: 'force_continue 需要 set（[{reg:"eax", value:1}]），至少一个有效寄存器' };
  }
  const then = String(i.then || 'continue').toLowerCase();
  const allowed = ['continue', 'step_into', 'step_over', 'none'];
  if (!allowed.includes(then)) return { error: `force_continue 的 then 只能是 ${allowed.join('/')}` };
  const repeat = Math.min(Math.max(parseIntLoose(i.repeat) || 1, 1), 200);
  const bp = parseIntLoose(i.bp_addr != null ? i.bp_addr : i.addr);

  const L = [];
  L.push('import ida_dbg, idaapi, idc');
  L.push('_SETS = ' + JSON.stringify(sets));
  L.push('_REPEAT = ' + repeat);
  if (bp !== null) L.push('_BP = ' + bp);
  else L.push('_BP = None');
  L.push('if _BP is not None:');
  L.push('    try:');
  L.push('        if not any(b.ea == _BP for b in idaapi.dbg_bps()):');
  L.push('            idaapi.add_bpt(_BP, 0, idaapi.BPT_SOFT)');
  L.push('            print("BP_ADDED", hex(_BP))');
  L.push('    except Exception as _e: print("BP_ERR", _e)');
  L.push('for _n in range(_REPEAT):');
  L.push('    _ip = ida_dbg.get_ip_val()');
  L.push('    print("ITER", _n, "IP", hex(_ip) if _ip is not None else "None")');
  // ⚠ 写寄存器要用 idc.set_reg_value（IDAPython 的 idc 层），
  //   ida_dbg 模块里没有 set_reg_value，upstream MCP 也没有写寄存器的工具。
  L.push('    for _s in _SETS:');
  L.push('        try:');
  L.push('            _ok = idc.set_reg_value(_s["val"], _s["reg"])');
  L.push('            print("  SET", _s["reg"], "=", _s["val"], "rc=", _ok)');
  L.push('        except Exception as _e:');
  L.push('            print("  SET_ERR", _s["reg"], _e)');;
  if (then === 'continue') {
    L.push('    try:');
    L.push('        ida_dbg.continue_process()');
    L.push('        print("  CONTINUED")');
    L.push('    except Exception as _e: print("  CONT_ERR", _e)');
  } else if (then === 'step_into') {
    L.push('    try:');
    L.push('        ida_dbg.step_into()');
    L.push('    except Exception as _e: print("  STEP_ERR", _e)');
  } else if (then === 'step_over') {
    L.push('    try:');
    L.push('        ida_dbg.step_over()');
    L.push('    except Exception as _e: print("  STEP_ERR", _e)');
  }
  L.push('print("FORCE_DONE repeats=", _REPEAT, "then=", ' + JSON.stringify(then) + ')');

  return { tool: 'py_eval', args: { code: L.join('\n') } };
}

// ───────────────────── ③ 全局元素读取统计 ─────────────────────

/**
 * 统计函数体直接引用了多少个不同的全局地址/元素。
 *
 * 为什么有用：Matr1x 的 sub_4638 打了 631 步混淆，静态完全看不出它只校验**一行**；
 * 而它实际只引用 9 个 off_13200 元素。一旦量出"9 个元素 ≈ 一行的宽度"，
 * 就能推断"调用方在循环里喂 6 次"，从而知道还有 5 组常量没抓到。
 *
 * 实现走 IDA 的 xref/数据引用，而不是读伪代码文本（伪代码在混淆下不可信）。
 *
 * input: func（函数名或地址）；可选 limit（默认 512）
 */
function buildGlobalReads(input) {
  const i = input || {};
  const func = String(i.func != null ? i.func : (i.function_name || i.address || '')).trim();
  if (!func) return { error: 'global_reads 需要 func（函数名或地址）' };
  const limit = Math.min(Math.max(parseIntLoose(i.limit) || 512, 1), 4096);

  const L = [];
  L.push('import idaapi, idautils, ida_funcs, idc, ida_bytes, ida_segment');
  L.push('import re');
  L.push('_q = ' + JSON.stringify(func));
  L.push('_limit = ' + limit);

  L.push('def _ctf_resolve(_q):');
  L.push('    try:');
  L.push('        _ea = int(_q, 16) if re.match(r"^0x[0-9a-fA-F]+$", _q) else (int(_q) if _q.isdigit() else None)');
  L.push('    except Exception:');
  L.push('        _ea = None');
  L.push('    if _ea is not None:');
  L.push('        _f = ida_funcs.get_func(_ea)');
  L.push('        if _f: return _f');
  L.push('    _ea = idc.get_name_ea_simple(_q)');
  L.push('    if _ea != idaapi.BADADDR:');
  L.push('        _f = ida_funcs.get_func(_ea)');
  L.push('        if _f: return _f');
  L.push('    return None');

  L.push('_f = _ctf_resolve(_q)');
  L.push('if _f is None:');
  L.push('    print("FUNC_NOT_FOUND", _q)');
  L.push('else:');
  L.push('    print("FUNC", idc.get_func_name(_f.start_ea), hex(_f.start_ea), hex(_f.end_ea))');
  L.push('    _globals = {}');
  L.push('    _calls = []');
  L.push('    _insn = 0');
  L.push('    _ea = _f.start_ea');
  L.push('    while _ea < _f.end_ea and _insn < 200000:');
  L.push('        _insn += 1');
  L.push('        for _x in idautils.XrefsFrom(_ea, 0):');
  L.push('            if _x.iscode:');
  L.push('                continue');
  L.push('            _t = _x.to');
  L.push('            _seg = ida_segment.getseg(_t) if _t != idaapi.BADADDR else None');
  L.push('            if _seg is None: continue');
  L.push('            _kind = ida_segment.segment_t().type if False else None');
  L.push('            _sname = ida_segment.get_segm_name(_seg) or ""');
  L.push('            if _sname in (".text", "text", ".plt", "extern"): continue');
  L.push('            _globals.setdefault(_t, 0)');
  L.push('            _globals[_t] += 1');
  L.push('        _nxt = idc.next_head(_ea, _f.end_ea)');
  L.push('        if _nxt == _ea or _nxt == idaapi.BADADDR: break');
  L.push('        _ea = _nxt');
  L.push('    print("INSN_COUNT", _insn)');
  L.push('    print("GLOBAL_REFS", len(_globals))');
  L.push('    _addrs = sorted(_globals.keys())');
  L.push('    if _addrs:');
  L.push('        print("ADDR_SPAN", hex(_addrs[0]), hex(_addrs[-1]), "size=", _addrs[-1] - _addrs[0] + 4)');
  L.push('        _strides = {}');
  L.push('        for _k in range(1, len(_addrs)):');
  L.push('            _d = _addrs[_k] - _addrs[_k-1]');
  L.push('            _strides[_d] = _strides.get(_d, 0) + 1');
  L.push('        _top = sorted(_strides.items(), key=lambda kv: -kv[1])[:6]');
  L.push('        print("STRIDES", " ".join("%d x%d" % (k, v) for k, v in _top))');
  L.push('        _common = _top[0][0] if _top else 0');
  L.push('        if _common in (4, 8):');
  L.push('            _n = (len(_addrs) - 1) * _common // _common + 1');
  L.push('            print("ELEMENT_WIDTH", _common, "APPROX_ELEMENTS", len(_addrs))');
  L.push('            print("HINT 引用是 %d 字节步长的数组元素；若元素数 < 一行宽度，说明该函数只处理一行/一块，调用方在循环里喂多次" % _common)');
  L.push('    for _a in _addrs[:_limit]:');
  L.push('        _nm = idc.get_name(_a) or ""');
  L.push('        _v = ida_bytes.get_dword(_a) if ida_bytes.is_loaded(_a) else 0');
  L.push('        print("REF", hex(_a), "x%d" % _globals[_a], _nm, "0x%08x" % (_v & 0xffffffff))');

  return { tool: 'py_eval', args: { code: L.join('\n') } };
}

module.exports = {
  buildSnapshotDiff,
  buildForceContinue,
  buildGlobalReads,
  normalizeSnapshotRegions,
  parseIntLoose,
};
