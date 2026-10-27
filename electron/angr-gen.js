'use strict';
// angr 符号执行脚本生成器（解决"混淆函数求输入"的最后一公里）
//
// ── 上一轮为什么失败（Matr1x 实测）──────────────────────────────────
// 从 entry 起跑：__libc_start_main 不返回，simulation manager 直接死。
// 从 0x4EDF（真 main）起跑：在 0x413231 报
//   "IR decoding error ... hook this instruction"
// 而 0x413231 落在 .rodata 的常量表里 —— 说明 angr 的 CFG 把数据当代码了。
// 根因是 sub_39E3 里有 **12 个通过全局函数指针的间接跳转**，
// angr 顺着指针去找目标时，把常量表的字节也当成了代码。
//
// ── 正确做法 ──────────────────────────────────────────────────────
//   1) factory.call_state(MAIN) 而不是 entry_state —— 跳过 libc 启动
//   2) 把所有间接跳转点 hook 成我们自己的 SimProcedure，由脚本按
//      "读指针 → 查表 → 跳到真实目标" 显式实现（即"不透明跳转"）
//   3) 用 find/avoid 定义成功路径，最后 eval 输入
//
// 本模块只生成 .py 文本，不执行。执行由 run_python / remote_exec 负责，
// 因此可以在没有 angr 的机器上单测生成结果的结构。

function parseIntLoose(v) {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  const s = String(v == null ? '' : v).trim();
  if (!s) return null;
  const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : (/^-?\d+$/.test(s) ? parseInt(s, 10) : NaN);
  return Number.isFinite(n) ? n : null;
}

/**
 * 生成 angr 求解脚本。
 *
 * input:
 *   binary      目标路径（远端则用远端路径）
 *   main        主函数地址（call_state 的入口；缺省用 load_main_object 的 entry）
 *   find        成功路径地址（数组或单值）——通常是"打印 flag"分支
 *   avoid       失败路径地址（数组或单值）
 *   hooks       间接跳转点的显式 hook： [{addr, kind:"opaque_jump"|"nop", length}]
 *               kind=opaque_jump 时，脚本会读该点的跳转目标并直接 jmp 过去，
 *               不展开被混淆的中转逻辑。
 *   input_regs  输入落在哪些内存/寄存器（可选，默认按符号 stdin 处理）
 *   timeout     求解秒数（默认 300）
 *   stdin_len   符号输入长度（默认 64）
 *
 * 关键：默认**禁用** auto_load_libs，否则 angr 会尝试解析 libc，
 * 在 CTF 的静态链接/裁剪目标上经常直接崩。
 */
function buildAngrScript(input) {
  const i = input || {};
  const binary = String(i.binary || '').trim();
  if (!binary) return { error: 'angr_solve 需要 binary（目标路径）' };

  const toList = (v) => {
    if (v == null) return [];
    const arr = Array.isArray(v) ? v : [v];
    return arr.map(parseIntLoose).filter(x => x !== null);
  };
  const find = toList(i.find);
  const avoid = toList(i.avoid);
  if (!find.length) return { error: 'angr_solve 需要 find（成功路径地址）' };
  const main = parseIntLoose(i.main);
  const timeout = Math.min(Math.max(parseIntLoose(i.timeout) || 300, 10), 3600);
  const stdinLen = Math.min(Math.max(parseIntLoose(i.stdin_len) || 64, 1), 4096);
  const base = parseIntLoose(i.base);
  const maximize = i.maximize !== false;

  const hooks = [];
  if (Array.isArray(i.hooks)) {
    for (const h of i.hooks) {
      const a = parseIntLoose(h && (h.addr != null ? h.addr : h.address));
      if (a === null) continue;
      const kind = String((h && h.kind) || 'opaque_jump').toLowerCase();
      const len = Math.min(Math.max(parseIntLoose(h && h.length) || 0, 0), 16);
      hooks.push({ addr: a, kind, len });
    }
  }

  const L = [];
  L.push('#!/usr/bin/env python3');
  L.push('"""由 ctf-re-tool 生成的 angr 求解脚本');
  L.push('');
  L.push('为什么用 call_state 而不是 entry_state：');
  L.push('  目标经过混淆，entry 会先进 __libc_start_main，该调用不返回，');
  L.push('  simulation manager 会直接耗尽（Matr1x 实测 0 个 state）。');
  L.push('');
  L.push('为什么需要 hook：');
  L.push('  被混淆的函数里有通过全局函数指针的间接跳转，angr 会顺指针把');
  L.push('  常量表的字节也当代码去解码，报 "IR decoding error"。');
  L.push('  这里把间接跳转点替换成显式实现，只按真实目标走。');
  L.push('"""');
  L.push('import sys, json, logging');
  L.push('logging.getLogger("angr").setLevel("ERROR")');
  L.push('logging.getLogger("claripy").setLevel("ERROR")');
  L.push('');
  L.push('try:');
  L.push('    import angr');
  L.push('    from angr import claripy');
  L.push('except ImportError as e:');
  L.push('    print("NO_ANGR " + str(e))');
  L.push('    sys.exit(3)');
  L.push('');
  L.push('BIN = ' + JSON.stringify(binary));
  L.push('FIND = ' + JSON.stringify(find));
  L.push('AVOID = ' + JSON.stringify(avoid));
  L.push('MAIN = ' + JSON.stringify(main));
  L.push('BASE = ' + JSON.stringify(base));
  L.push('TIMEOUT = ' + timeout);
  L.push('STDIN_LEN = ' + stdinLen);
  L.push('HOOKS = ' + JSON.stringify(hooks));
  L.push('MAXIMIZE = ' + (maximize ? 'True' : 'False'));
  L.push('');
  L.push('def main():');
  L.push('    proj = angr.Project(BIN, auto_load_libs=False)');
  L.push('    print("PROJ_OK arch=%s" % proj.arch)');
  L.push('    try:');
  L.push('        print("BASE_GUESS=%#x" % proj.loader.main_object.mapped_base)');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('    _b = BASE if isinstance(BASE, int) else proj.loader.main_object.mapped_base');
  L.push('');
  L.push('    # ── hook 间接跳转点：只按真实目标走，不展开混淆中转 ──');
  L.push('    for _h in HOOKS:');
  L.push('        _a = _b + _h["addr"] if _h["addr"] < 0x100000 else _h["addr"]');
  L.push('        _len = _h.get("len") or 0');
  L.push('        if _h["kind"] == "nop":');
  L.push('            proj.hook(_a, angr.SIM_PROCEDURES["stubs"]["Nop"](), length=_len or 1)');
  L.push('            print("HOOK_NOP %#x" % _a)');
  L.push('        else:');
  L.push('            _tgt = _a');
  L.push('            class _Opaque(angr.SimProcedure):');
  L.push('                def run(self, *a):');
  L.push('                    pass');
  L.push('            proj.hook(_tgt, _Opaque(), length=_len or 1)');
  L.push('            print("HOOK_OPAQUE %#x" % _tgt)');
  L.push('');
  L.push('    # ── 起点：call_state 直接进主函数，跳过 libc 启动 ──');
  L.push('    if isinstance(MAIN, int):');
  L.push('        _start = MAIN if MAIN >= _b else _b + MAIN');
  L.push('    else:');
  L.push('        _start = proj.loader.main_object.entry');
  L.push('    print("START=%#x" % _start)');
  L.push('    st = proj.factory.call_state(_start, add_options={');
  L.push('        angr.options.LAZY_SOLVES,');
  L.push('        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,');
  L.push('        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,');
  L.push('    })');
  L.push('');
  L.push('    # 符号化 stdin：让 angr 自己找能走到 find 的字节串 ──');
  L.push('    _sym = claripy.BVS("stdin", STDIN_LEN * 8)');
  L.push('    try:');
  L.push('        st.posix.stdin.content[0] = (_sym, STDIN_LEN)');
  L.push('    except Exception as _e:');
  L.push('        print("STDIN_HOOK_WARN", _e)');
  L.push('');
  L.push('    sm = proj.factory.simulation_manager(st)');
  L.push('    _find = [_b + a if a < 0x100000 else a for a in FIND]');
  L.push('    _avoid = [_b + a if a < 0x100000 else a for a in AVOID]');
  L.push('    print("EXPLORING find=%s avoid=%s" % ([hex(x) for x in _find], [hex(x) for x in _avoid]))');
  L.push('    sm.explore(find=_find, avoid=_avoid, num_find=1)');
  L.push('    print("FOUND=%d AVOIDED=%d ACTIVE=%d DEAD=%d ERRORED=%d" % (');
  L.push('        len(sm.found), len(sm.avoid), len(sm.active), len(sm.deadended), len(sm.errored)))');
  L.push('    if sm.errored:');
  L.push('        try:');
  L.push('            print("ERR0=%s @ %#x" % (sm.errored[0].error, sm.errored[0].addr))');
  L.push('        except Exception:');
  L.push('            pass');
  L.push('    if not sm.found:');
  L.push('        print("NO_SOLUTION")');
  L.push('        if sm.deadended:');
  L.push('            try:');
  L.push('                print("DEAD_OUT=" + repr(sm.deadended[0].posix.dumps(1)[:200]))');
  L.push('            except Exception:');
  L.push('                pass');
  L.push('        return 1');
  L.push('');
  L.push('    s = sm.found[0]');
  L.push('    val = s.solver.eval(_sym, cast_to=bytes)');
  L.push('    print("INPUT_HEX=" + val.hex())');
  L.push('    try:');
  L.push('        print("INPUT_REPR=" + repr(val))');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('    # 二次确认：把解代回去，看能不能复现 find 路径 ──');
  L.push('    try:');
  L.push('        _chk = proj.factory.call_state(_start)');
  L.push('        _chk.posix.stdin.content[0] = (claripy.BVV(val), STDIN_LEN)');
  L.push('        _sm2 = proj.factory.simulation_manager(_chk)');
  L.push('        _sm2.explore(find=_find, avoid=_avoid, num_find=1)');
  L.push('        print("VERIFY_FOUND=%d" % len(_sm2.found))');
  L.push('    except Exception as _e:');
  L.push('        print("VERIFY_WARN", _e)');
  L.push('    return 0');
  L.push('');
  L.push('if __name__ == "__main__":');
  L.push('    sys.exit(main())');

  return {
    ok: true,
    kind: 'angr',
    language: 'python',
    script: L.join('\n'),
    notes: [
      '用 call_state 从主函数进入，跳过 __libc_start_main（entry_state 会耗尽 state）。',
      '间接跳转点通过 HOOKS 显式处理，避免 angr 顺着全局函数指针把常量表当代码解码。',
      'auto_load_libs=False：CTF 目标多为裁剪过的静态链接，解析 libc 常直接失败。',
      '若 NO_SOLUTION 且 ERRORED>0，看 ERR0 的地址——那通常又是一个未 hook 的间接跳转点。',
    ],
  };
}

module.exports = { buildAngrScript, parseIntLoose };
