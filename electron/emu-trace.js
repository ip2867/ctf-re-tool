'use strict';
// 执行轨迹原语（emulation trace）——把"运行期地面真值"变成 IDA 能看懂的 CFG
//
// ── 这类题到底卡在哪（Obfuscating Macros II 实测）─────────────────────
// 程序被切成 92 段，段与段之间的跳转目标在**运行期**用栈算出来，静态看不出来：
//     mov [rbp+var_D0], 2      ; 把段号 2 压进栈
//     call push_...
//     jmp  switch              ; 间接跳转，目标 = lookup(2)
// IDA 因此只能看到一堆互不相连的碎片 + 一个 `jmp rax`，反编译当然读不懂。
//
// 人类解法（题目作者自述）是："record a execution trace and set those jump targets"。
// 也就是：真跑一遍，把每次间接跳转实际去了哪里记下来，再把这些目标回填成代码/xref。
// 段一合并，整个函数就变成一段能读的循环。
//
// ── 本模块做什么 ───────────────────────────────────────────────────
// 1) 生成一段自包含的 Python：用 Unicorn 真正执行目标，记录
//      · 每个**间接跳转点** src → 实际目标 dst（以及当时的操作数寄存器值）
//      · 全部非顺序控制流边（CFG 地面真值）
//      · 执行过的地址集合（IDA 漏标为代码的区域）
// 2) 把结果写成 JSON，并打印一份小摘要。
// 3) 配套的 ida_apply_trace 把 JSON 回填进 IDA：create_insn + add_cref + add_func。
//
// ── 为什么不用 angr ────────────────────────────────────────────────
// angr 是符号执行，为"求输入"设计；这类题只要能跑起来就行，Unicorn 快几百倍，
// 而且不会有"顺着函数指针把常量表当代码解码"的问题（它只走真实执行路径）。
// 两条路线互补：先 emu_trace 把 CFG 修好、算法读出来；读不出来再上 angr_solve。
//
// 本模块只生成文本，不执行，因此可单测。

function parseIntLoose(v) {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  const s = String(v == null ? '' : v).trim();
  if (!s) return null;
  const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : (/^-?\d+$/.test(s) ? parseInt(s, 10) : NaN);
  return Number.isFinite(n) ? n : null;
}

function toIntList(v) {
  if (v == null) return [];
  const arr = Array.isArray(v) ? v : [v];
  return arr.map(parseIntLoose).filter(x => x !== null);
}

/**
 * 生成 Unicorn 执行轨迹脚本。
 *
 * input:
 *   binary      目标 ELF 路径（必填）
 *   start       起始地址；mode=function 时是要调用的函数地址，mode=entry 时覆盖入口
 *   mode        "function"（默认，直接调用 start，参数走寄存器，ret 即停）
 *               "entry"（从 ELF 入口跑，遇到 syscall/stop_at/max_insns 停）
 *   args        mode=function 的参数（按 rdi, rsi, rdx, rcx, r8, r9 依次写入）
 *   stop_at     额外停机地址（数组）
 *   max_insns   指令上限（默认 2,000,000）
 *   stdin       喂给 stdin 的字节（hex 串或普通字符串）
 *   out         轨迹 JSON 输出路径（缺省 <cwd>/emu_trace.json）
 *   ret_sentinel 返回值哨兵地址（默认自动挑一个未映射高地址）
 *   heap_size   堆大小字节（默认 16MB）
 *
 * 契约：脚本输出 `TRACE_JSON=<path>`，最后一行打印摘要；JSON 结构见下。
 */
function buildEmuTraceScript(input) {
  const i = input || {};
  const binary = String(i.binary || i.path || '').trim();
  if (!binary) return { error: 'emu_trace 需要 binary（目标 ELF 路径）' };

  const mode = String(i.mode || 'function').toLowerCase();
  if (!['function', 'entry'].includes(mode)) {
    return { error: `emu_trace 的 mode 只能是 function / entry（收到 ${mode}）` };
  }
  const start = parseIntLoose(i.start != null ? i.start : i.address);
  if (mode === 'function' && start === null) {
    return { error: 'mode=function 需要 start（要调用的函数地址，如 0x401006）' };
  }
  const args = toIntList(i.args);
  const stopAt = toIntList(i.stop_at != null ? i.stop_at : i.break_at);
  const maxInsns = Math.min(Math.max(parseIntLoose(i.max_insns) || 2000000, 1000), 50000000);
  const heapSize = Math.min(Math.max(parseIntLoose(i.heap_size) || 16 * 1024 * 1024, 65536), 512 * 1024 * 1024);
  const outPath = String(i.out || '').trim() || 'emu_trace.json';
  const retSentinel = parseIntLoose(i.ret_sentinel) || 0x79000000;

  // stdin 解析规则（故意保守）：
  //   "0x4142..." 或 "hex:4142..."  → 明确当 hex
  //   全 hex 字符 + 偶数长 + 至少含一个数字 → 当 hex（"41424344"）
  //   其余（含纯字母的 "ABCD"/"beef"）→ 按 UTF-8 文本
  // 纯字母的合法 hex 更可能是密码，误判成 hex 会静默改变输入。
  let stdinHex = '';
  if (i.stdin != null && String(i.stdin).length) {
    const s = String(i.stdin);
    const compact = s.replace(/[\s,]/g, '');
    if (/^0x/i.test(compact)) {
      stdinHex = compact.slice(2).toLowerCase();
    } else if (/^hex:/i.test(compact)) {
      stdinHex = compact.slice(4).toLowerCase();
    } else if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && /\d/.test(compact) && !/[^\x00-\x7f]/.test(s)) {
      stdinHex = compact.toLowerCase();
    } else {
      stdinHex = Buffer.from(s, 'utf8').toString('hex');
    }
  }

  const L = [];
  L.push('#!/usr/bin/env python3');
  L.push('"""ctf-re-tool emu_trace —— 记录执行轨迹，取出运行期的间接跳转目标');
  L.push('');
  L.push('这类题（分段 dispatch / VM）的跳转目标在运行期才算出，静态 CFG 是碎的。');
  L.push('真跑一遍，把 每次间接跳转 src -> dst 与当时的操作数值 记下来，');
  L.push('再用 ida_apply_trace 回填成 create_insn + add_cref + add_func。');
  L.push('"""');
  L.push('import sys, os, json, struct');
  L.push('');
  L.push('try:');
  L.push('    from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN, UC_PROT_ALL');
  L.push('    from unicorn.x86_const import *');
  L.push('    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET');
  L.push('    from capstone.x86 import X86_OP_REG, X86_OP_MEM');
  L.push('    from elftools.elf.elffile import ELFFile');
  L.push('except Exception as _e:');
  L.push('    print("NO_DEPS " + repr(_e))');
  L.push('    print("需要: pip install unicorn capstone pyelftools")');
  L.push('    sys.exit(3)');
  L.push('');
  L.push('BIN = ' + JSON.stringify(binary));
  L.push('MODE = ' + JSON.stringify(mode));
  L.push('START = ' + (start === null ? 'None' : String(start)));
  L.push('ARGS = ' + JSON.stringify(args));
  L.push('STOP_AT = ' + JSON.stringify(stopAt));
  L.push('MAX_INSNS = ' + maxInsns);
  L.push('STDIN_BYTES = bytes.fromhex(' + JSON.stringify(stdinHex) + ')');
  L.push('OUT = ' + JSON.stringify(outPath));
  L.push('RET_SENTINEL = ' + retSentinel);
  L.push('HEAP_SIZE = ' + heapSize);
  L.push('');
  L.push('STACK_BASE = 0x20000000');
  L.push('STACK_SIZE = 4 * 1024 * 1024');
  L.push('HEAP_BASE = 0x30000000');
  L.push('TRAMP_BASE = 0x31000000');
  L.push('TLS_BASE = 0x32000000');
  L.push('');
  L.push('S = {');
  L.push('    "insn": 0, "stop": None, "error": None,');
  L.push('    "ind": {},        # src -> {(value, dst): count}');
  L.push('    "edges": {},      # (src, dst) -> count   非顺序控制流');
  L.push('    "exec": set(),');
  L.push('    "stubs": {},');
  L.push('    "stdout": bytearray(),');
  L.push('    "pending": None,  # {"src":.., "value":..|None, "op":str}');
  L.push('    "heap_ptr": None,');
  L.push('    "stdin_pos": 0,');
  L.push('    "stdin_buf": None,');
  L.push('}');
  L.push('');
  L.push('');
  L.push('# ── ELF 加载 ─────────────────────────────────────────────');
  L.push('def load_elf(path):');
  L.push('    with open(path, "rb") as f:');
  L.push('        ef = ELFFile(f)');
  L.push('        bits = ef.elfclass');
  L.push('        entry = ef.header.e_entry');
  L.push('        segs = []');
  L.push('        has_interp = False');
  L.push('        for seg in ef.iter_segments():');
  L.push('            if seg["p_type"] == "PT_INTERP":');
  L.push('                has_interp = True');
  L.push('            if seg["p_type"] != "PT_LOAD":');
  L.push('                continue');
  L.push('            segs.append((seg["p_vaddr"], seg.data(), seg["p_memsz"]))');
  L.push('        # 动态符号 + 重定位：把 PLT / GOT 槽映射到符号名（通用 mini-libc 前提）');
  L.push('        symtab = []');
  L.push('        dyn = ef.get_section_by_name(".dynsym")');
  L.push('        if dyn is not None:');
  L.push('            symtab = [s.name for s in dyn.iter_symbols()]');
  L.push('        relocs = []');
  L.push('        for sn in (".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"):');
  L.push('            sec = ef.get_section_by_name(sn)');
  L.push('            if sec is None:');
  L.push('                continue');
  L.push('            for r in sec.iter_relocations():');
  L.push('                idx = r["r_info_sym"]');
  L.push('                nm = symtab[idx] if 0 <= idx < len(symtab) else ""');
  L.push('                relocs.append((r["r_offset"], nm, r["r_info_type"]))');
  L.push('        plt = ef.get_section_by_name(".plt") or ef.get_section_by_name(".plt.sec")');
  L.push('        plt_info = None');
  L.push('        if plt is not None:');
  L.push('            plt_info = (plt["sh_addr"], plt["sh_entsize"] or 16, plt["sh_size"])');
  L.push('    return bits, entry, segs, has_interp, relocs, plt_info');
  L.push('');
  L.push('');
  L.push('def map_region(uc, covered, va, data, memsz):');
  L.push('    lo = va & ~0xfff');
  L.push('    hi = (va + max(memsz, len(data)) + 0xfff) & ~0xfff');
  L.push('    for (a, b) in covered:');
  L.push('        if lo >= a and hi <= b:');
  L.push('            if data:');
  L.push('                uc.mem_write(va, data)');
  L.push('            return');
  L.push('    if hi <= lo:');
  L.push('        return');
  L.push('    try:');
  L.push('        uc.mem_map(lo, hi - lo, UC_PROT_ALL)');
  L.push('        covered.append((lo, hi))');
  L.push('    except UcError:');
  L.push('        pass');
  L.push('    if data:');
  L.push('        uc.mem_write(va, data)');
  L.push('');
  L.push('');
  L.push('bits, entry, segs, has_interp, relocs, plt_info = load_elf(BIN)');
  L.push('BITS = bits');
  L.push('PTRSZ = 8 if BITS == 64 else 4');
  L.push('MASK = (1 << (BITS)) - 1');
  L.push('SPREG = "rsp" if BITS == 64 else "esp"');
  L.push('IPREG = "rip" if BITS == 64 else "eip"');
  L.push('PK = "<Q" if BITS == 64 else "<I"');
  L.push('');
  L.push('uc = Uc(UC_ARCH_X86, UC_MODE_64 if BITS == 64 else UC_MODE_32)');
  L.push('MD = Cs(CS_ARCH_X86, CS_MODE_64 if BITS == 64 else CS_MODE_32)');
  L.push('MD.detail = True');
  L.push('');
  L.push('_covered = []');
  L.push('for (va, data, msz) in segs:');
  L.push('    map_region(uc, _covered, va, data, msz)');
  L.push('');
  L.push('map_region(uc, _covered, STACK_BASE, b"", STACK_SIZE)');
  L.push('map_region(uc, _covered, HEAP_BASE, b"", HEAP_SIZE)');
  L.push('map_region(uc, _covered, TLS_BASE, b"", 0x2000)');
  L.push('S["heap_ptr"] = HEAP_BASE + 0x1000');
  L.push('');
  L.push('# TLS canary：fs:[0x28] 读不到会直接 UC_ERR_READ_UNMAPPED');
  L.push('try:');
  L.push('    uc.reg_write(UC_X86_REG_FS_BASE, TLS_BASE)');
  L.push('except Exception:');
  L.push('    pass');
  L.push('uc.mem_write(TLS_BASE + 0x28, struct.pack(PK, 0x1122334455667788 & MASK))');
  L.push('');
  L.push('');
  L.push('# ── 寄存器名 ↔ Unicorn 常量 ───────────────────────────────');
  L.push('_RN = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15",');
  L.push('       "eax","ebx","ecx","edx","esi","edi","ebp","esp","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",');
  L.push('       "rip","eip"]');
  L.push('REGMAP = {}');
  L.push('for _n in _RN:');
  L.push('    _v = globals().get("UC_X86_REG_" + _n.upper())');
  L.push('    if _v is not None:');
  L.push('        REGMAP[_n] = _v');
  L.push('');
  L.push('');
  L.push('def _rname(rid):');
  L.push('    try:');
  L.push('        return MD.reg_name(rid)');
  L.push('    except Exception:');
  L.push('        return None');
  L.push('');
  L.push('');
  L.push('def rreg(uc, rid):');
  L.push('    n = rid if isinstance(rid, str) else _rname(rid)');
  L.push('    if not n:');
  L.push('        return 0');
  L.push('    c = REGMAP.get(n)');
  L.push('    if c is None:');
  L.push('        return 0');
  L.push('    try:');
  L.push('        return uc.reg_read(c) & MASK');
  L.push('    except Exception:');
  L.push('        return 0');
  L.push('');
  L.push('');
  L.push('def wreg(uc, name, val):');
  L.push('    c = REGMAP.get(name)');
  L.push('    if c is None:');
  L.push('        return');
  L.push('    try:');
  L.push('        uc.reg_write(c, val & MASK)');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('');
  L.push('');
  L.push('def mem_ea(uc, mem):');
  L.push('    ea = mem.disp');
  L.push('    if mem.base:');
  L.push('        ea += rreg(uc, mem.base)');
  L.push('    if mem.index:');
  L.push('        ea += rreg(uc, mem.index) * (mem.scale or 1)');
  L.push('    return ea & MASK');
  L.push('');
  L.push('');
  L.push('def rd_ptr(uc, ea):');
  L.push('    try:');
  L.push('        return struct.unpack(PK, uc.mem_read(ea, PTRSZ))[0]');
  L.push('    except Exception:');
  L.push('        return None');
  L.push('');
  L.push('');
  L.push('# ── 通用 mini-libc（PLT / GOT 打桩）───────────────────────');
  L.push('def _base_name(n):');
  L.push('    for c in ("@", "("):');
  L.push('        if c in n:');
  L.push('            n = n.split(c)[0]');
  L.push('    return n');
  L.push('');
  L.push('');
  L.push('def _bump(sz):');
  L.push('    sz = (int(sz) + 15) & ~15');
  L.push('    p = S["heap_ptr"]');
  L.push('    if p + sz > HEAP_BASE + HEAP_SIZE:');
  L.push('        S["heap_ptr"] = p');
  L.push('        return HEAP_BASE + 0x1000');
  L.push('    S["heap_ptr"] = p + sz');
  L.push('    return p');
  L.push('');
  L.push('');
  L.push('def _ret(uc):');
  L.push('    sp = rreg(uc, SPREG)');
  L.push('    ra = rd_ptr(uc, sp)');
  L.push('    if ra is None:');
  L.push('        ra = RET_SENTINEL');
  L.push('    wreg(uc, SPREG, sp + PTRSZ)');
  L.push('    wreg(uc, IPREG, ra)');
  L.push('    return ra');
  L.push('');
  L.push('');
  L.push('def _write_out(b):');
  L.push('    if isinstance(b, str):');
  L.push('        b = b.encode("utf-8", "replace")');
  L.push('    S["stdout"] += b');
  L.push('');
  L.push('');
  L.push('def do_stub(uc, name):');
  L.push('    S["stubs"][name] = S["stubs"].get(name, 0) + 1');
  L.push('    n = _base_name(name)');
  L.push('    a0 = rreg(uc, "rdi")');
  L.push('    a1 = rreg(uc, "rsi")');
  L.push('    a2 = rreg(uc, "rdx")');
  L.push('    if n in ("_Znwm", "_Znam", "malloc", "realloc"):');
  L.push('        wreg(uc, "rax", _bump(a0))');
  L.push('        _ret(uc); return');
  L.push('    if n == "calloc":');
  L.push('        p = _bump(a0 * a1)');
  L.push('        try: uc.mem_write(p, b"\\x00" * min(a0 * a1, 1 << 20))');
  L.push('        except Exception: pass');
  L.push('        wreg(uc, "rax", p); _ret(uc); return');
  L.push('    if n in ("_ZdlPv", "_ZdaPv", "free", "cfree"):');
  L.push('        _ret(uc); return');
  L.push('    if n in ("memset", "bzero"):');
  L.push('        ln = a1 if n == "bzero" else a2');
  L.push('        val = 0 if n == "bzero" else a1');
  L.push('        try: uc.mem_write(a0, bytes([val & 0xff]) * min(ln, 1 << 20))');
  L.push('        except Exception: pass');
  L.push('        wreg(uc, "rax", a0); _ret(uc); return');
  L.push('    if n in ("memcpy", "memmove"):');
  L.push('        try:');
  L.push('            uc.mem_write(a0, bytes(uc.mem_read(a1, min(a2, 1 << 20))))');
  L.push('        except Exception:');
  L.push('            pass');
  L.push('        wreg(uc, "rax", a0); _ret(uc); return');
  L.push('    if n in ("strlen", "strnlen"):');
  L.push('        k = 0');
  L.push('        try:');
  L.push('            while k < 100000:');
  L.push('                if uc.mem_read(a0 + k, 1)[0] == 0:');
  L.push('                    break');
  L.push('                k += 1');
  L.push('        except Exception:');
  L.push('            pass');
  L.push('        wreg(uc, "rax", k); _ret(uc); return');
  L.push('    if n == "fwrite":');
  L.push('        try: _write_out(bytes(uc.mem_read(a0, min(a1 * a2, 1 << 20))))');
  L.push('        except Exception: pass');
  L.push('        wreg(uc, "rax", a1); _ret(uc); return');
  L.push('    if n in ("puts", "fputs", "printf", "__printf_chk", "__isoc99_scanf"):');
  L.push('        buf = a1 if n in ("printf", "__printf_chk") else a0');
  L.push('        try:');
  L.push('            ln = 0');
  L.push('            while ln < 65536 and uc.mem_read(buf + ln, 1)[0] != 0:');
  L.push('                ln += 1');
  L.push('            _write_out(bytes(uc.mem_read(buf, ln)))');
  L.push('        except Exception:');
  L.push('            pass');
  L.push('        wreg(uc, "rax", 0); _ret(uc); return');
  L.push('    if n in ("std::cout", "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc", "_ZSt4cout"):');
  L.push('        try:');
  L.push('            ln = 0');
  L.push('            while ln < 65536 and uc.mem_read(a1 + ln, 1)[0] != 0:');
  L.push('                ln += 1');
  L.push('            _write_out(bytes(uc.mem_read(a1, ln)))');
  L.push('        except Exception:');
  L.push('            pass');
  L.push('        wreg(uc, "rax", 0); _ret(uc); return');
  L.push('    if n == "__libc_start_main":');
  L.push('        # 直接跳进 main，跳过 libc 初始化（动态链接下唯一可行的入口）');
  L.push('        try:');
  L.push('            uc.mem_write(rreg(uc, SPREG), struct.pack(PK, RET_SENTINEL))');
  L.push('        except Exception:');
  L.push('            pass');
  L.push('        wreg(uc, IPREG, a0); return');
  L.push('    if n in ("__stack_chk_fail", "__assert_fail", "abort"):');
  L.push('        S["error"] = "abort:" + n');
  L.push('        S["stop"] = "abort"');
  L.push('        uc.emu_stop(); return');
  L.push('    # 其余一律返回 0（cout/ios 之类会走这条路）');
  L.push('    wreg(uc, "rax", 0)');
  L.push('    _ret(uc)');
  L.push('');
  L.push('');
  L.push('# 建立符号地址表：PLT 桩 + GOT 槽重定向到跳板，两种调用约定都能兜住');
  L.push('STUBS = {}');
  L.push('_nsym = 0');
  L.push('_names = []');
  L.push('for (off, nm, rtype) in relocs:');
  L.push('    if not nm:');
  L.push('        continue');
  L.push('    tramp = TRAMP_BASE + _nsym * 0x10');
  L.push('    _nsym += 1');
  L.push('    STUBS[tramp] = nm');
  L.push('    _names.append(nm)');
  L.push('    try:');
  L.push('        uc.mem_write(off, struct.pack(PK, tramp))   # -fno-plt / BIND_NOW 直接走 GOT');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('if _nsym:');
  L.push('    map_region(uc, _covered, TRAMP_BASE, b"", max(0x1000, _nsym * 0x10))');
  L.push('if plt_info is not None and _nsym:');
  L.push('    # .plt 顺序与 .rela.plt 顺序一致（第 0 项是 PLT0 解析器桩，所以要 +1）');
  L.push('    _pa, _pe, _ps = plt_info');
  L.push('    for _k in range(_nsym):');
  L.push('        _a = _pa + (_k + 1) * (_pe or 16)');
  L.push('        if _a < _pa + _ps:');
  L.push('            STUBS.setdefault(_a, _names[_k])');
  L.push('');
  L.push('');
  L.push('def hook_code(uc, address, size, user):');
  L.push('    S["insn"] += 1');
  L.push('    if S["insn"] > MAX_INSNS:');
  L.push('        S["stop"] = "max_insns"; uc.emu_stop(); return');
  L.push('    if address == RET_SENTINEL:');
  L.push('        S["stop"] = "return"; uc.emu_stop(); return');
  L.push('    if address in STOP_SET:');
  L.push('        S["stop"] = "stop_at:%#x" % address; uc.emu_stop(); return');
  L.push('    if address in STUBS:');
  L.push('        S["pending"] = None');
  L.push('        do_stub(uc, STUBS[address]); return');
  L.push('');
  L.push('    p = S["pending"]');
  L.push('    if p is not None:');
  L.push('        src = p["src"]');
  L.push('        key = (src, address)');
  L.push('        S["edges"][key] = S["edges"].get(key, 0) + 1');
  L.push('        if p.get("op") is not None:');
  L.push('            d = S["ind"].setdefault(src, {})');
  L.push('            kk = (p.get("value"), address)');
  L.push('            d[kk] = d.get(kk, 0) + 1');
  L.push('    S["pending"] = None');
  L.push('');
  L.push('    try:');
  L.push('        code = bytes(uc.mem_read(address, 16))');
  L.push('        ins = next(MD.disasm(code, address, 1))');
  L.push('    except Exception:');
  L.push('        return');
  L.push('    S["exec"].add(address)');
  L.push('');
  L.push('    grp = set(ins.groups)');
  L.push('    is_branch = (CS_GRP_JUMP in grp) or (CS_GRP_CALL in grp) or (CS_GRP_RET in grp)');
  L.push('    if not is_branch:');
  L.push('        return');
  L.push('    ind = False');
  L.push('    txt = None');
  L.push('    val = None');
  L.push('    if len(ins.operands) == 1:');
  L.push('        op = ins.operands[0]');
  L.push('        if op.type == X86_OP_REG:');
  L.push('            ind = True');
  L.push('            txt = ins.reg_name(op.reg)');
  L.push('            val = rreg(uc, op.reg)');
  L.push('        elif op.type == X86_OP_MEM:');
  L.push('            ind = True');
  L.push('            ea = mem_ea(uc, op.mem)');
  L.push('            txt = "[" + (ins.reg_name(op.mem.base) or "") + "+%#x]" % op.mem.disp');
  L.push('            val = rd_ptr(uc, ea)');
  L.push('    S["pending"] = {"src": address, "value": val, "op": txt if ind else None}');
  L.push('');
  L.push('');
  L.push('def hook_syscall(uc, user):');
  L.push('    nr = rreg(uc, "rax")');
  L.push('    a0 = rreg(uc, "rdi"); a1 = rreg(uc, "rsi"); a2 = rreg(uc, "rdx")');
  L.push('    ret = 0');
  L.push('    if nr == 0:   # read');
  L.push('        n = min(a2, max(0, len(STDIN_BYTES) - S["stdin_pos"]))');
  L.push('        try: uc.mem_write(a1, STDIN_BYTES[S["stdin_pos"]:S["stdin_pos"] + n])');
  L.push('        except Exception: pass');
  L.push('        S["stdin_pos"] += n');
  L.push('        ret = n');
  L.push('    elif nr == 1:  # write');
  L.push('        try: _write_out(bytes(uc.mem_read(a1, min(a2, 1 << 20))))');
  L.push('        except Exception: pass');
  L.push('        ret = a2');
  L.push('    elif nr in (60, 231):');
  L.push('        S["stop"] = "exit:%d" % a0');
  L.push('        S["error"] = "exit" if a0 else None');
  L.push('        uc.emu_stop(); return');
  L.push('    elif nr == 12:');
  L.push('        ret = _bump(0x10000)');
  L.push('    elif nr == 9:');
  L.push('        ret = _bump(max(a1, 0x1000))');
  L.push('    wreg(uc, "rax", ret)');
  L.push('    wreg(uc, IPREG, rreg(uc, IPREG) + 2)');
  L.push('');
  L.push('');
  L.push('STOP_SET = set(STOP_AT)');
  L.push('uc.hook_add(UC_HOOK_CODE, hook_code)');
  L.push('if MODE == "entry":');
  L.push('    try:');
  L.push('        uc.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('');
  L.push('');
  L.push('# ── 起跑 ────────────────────────────────────────────────');
  L.push('def push_arg(uc, v):');
  L.push('    sp = rreg(uc, SPREG) - PTRSZ');
  L.push('    uc.mem_write(sp, struct.pack(PK, v & MASK))');
  L.push('    wreg(uc, SPREG, sp)');
  L.push('');
  L.push('');
  L.push('def setup_function(uc, fn, argv):');
  L.push('    sp = STACK_BASE + STACK_SIZE - 0x200');
  L.push('    sp = (sp & ~0xf) - 8          # 函数入口处 rsp %% 16 == 8（call 后的约定）');
  L.push('    wreg(uc, SPREG, sp)');
  L.push('    uc.mem_write(sp, struct.pack(PK, RET_SENTINEL))');
  L.push('    if BITS == 64:');
  L.push('        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]');
  L.push('        for k, v in enumerate(argv[:6]):');
  L.push('            wreg(uc, regs[k], v)');
  L.push('    else:');
  L.push('        # cdecl：参数从右往左压栈，返回地址在栈顶');
  L.push('        for v in reversed(argv):');
  L.push('            push_arg(uc, v)');
  L.push('    wreg(uc, IPREG, fn)');
  L.push('');
  L.push('');
  L.push('def setup_entry(uc, e):');
  L.push('    sp = STACK_BASE + STACK_SIZE - 0x400');
  L.push('    sp = sp & ~0xf');
  L.push('    argp = sp - 0x200');
  L.push('    uc.mem_write(argp, b"chall\\x00")');
  L.push('    uc.mem_write(sp, struct.pack(PK, 1))');
  L.push('    uc.mem_write(sp + PTRSZ, struct.pack(PK, argp))');
  L.push('    uc.mem_write(sp + 2 * PTRSZ, struct.pack(PK, 0))');
  L.push('    wreg(uc, SPREG, sp)');
  L.push('    wreg(uc, IPREG, e)');
  L.push('');
  L.push('');
  L.push('_start_ip = START if START is not None else entry');
  L.push('try:');
  L.push('    if MODE == "function":');
  L.push('        setup_function(uc, START, ARGS)');
  L.push('        _start_ip = START');
  L.push('    else:');
  L.push('        setup_entry(uc, _start_ip)');
  L.push('    if STDIN_BYTES:');
  L.push('        S["stdin_buf"] = _bump(len(STDIN_BYTES) + 16)');
  L.push('    uc.emu_start(_start_ip, RET_SENTINEL, count=MAX_INSNS)');
  L.push('except UcError as _e:');
  L.push('    S["error"] = "UcError:%s pc=%s" % (_e, hex(rreg(uc, IPREG)))');
  L.push('    S["stop"] = "error"');
  L.push('except Exception as _e:');
  L.push('    S["error"] = "%s: %s" % (type(_e).__name__, _e)');
  L.push('    S["stop"] = "error"');
  L.push('if not S["stop"]:');
  L.push('    S["stop"] = "finished"');
  L.push('');
  L.push('');
  L.push('# ── 汇总输出 ────────────────────────────────────────────');
  L.push('def to_ranges(addrs):');
  L.push('    out = []');
  L.push('    cur = None');
  L.push('    for a in sorted(addrs):');
  L.push('        if cur is None:');
  L.push('            cur = [a, a]');
  L.push('        elif a <= cur[1] + 16:');
  L.push('            cur[1] = a');
  L.push('        else:');
  L.push('            out.append(cur); cur = [a, a]');
  L.push('    if cur is not None:');
  L.push('        out.append(cur)');
  L.push('    return out');
  L.push('');
  L.push('');
  L.push('sites = []');
  L.push('for src in sorted(S["ind"].keys()):');
  L.push('    tg = S["ind"][src]');
  L.push('    targets = [{"value": (None if v is None else hex(v)), "dst": hex(d), "count": c}');
  L.push('               for (v, d), c in sorted(tg.items(), key=lambda kv: -kv[1])]');
  L.push('    sites.append({"src": hex(src), "targets": targets, "distinct": len(targets)})');
  L.push('sites.sort(key=lambda x: -x["distinct"])');
  L.push('');
  L.push('res = {');
  L.push('    "binary": BIN, "mode": MODE, "bits": BITS, "entry": hex(entry),');
  L.push('    "start": hex(_start_ip), "stop": S["stop"], "error": S["error"],');
  L.push('    "insn_count": S["insn"],');
  L.push('    "indirect_sites": sites,');
  L.push('    "edges": [[hex(a), hex(b)] for (a, b) in sorted(S["edges"].keys())],');
  L.push('    "exec_ranges": [[hex(a), hex(b)] for (a, b) in to_ranges(S["exec"])],');
  L.push('    "regs": {"rax": hex(rreg(uc, "rax")), "rdx": hex(rreg(uc, "rdx"))},');
  L.push('    "stubs": S["stubs"],');
  L.push('    "has_interp": has_interp,');
  L.push('    "stdout": bytes(S["stdout"])[:65536].decode("utf-8", "replace"),');
  L.push('}');
  L.push('with open(OUT, "w", encoding="utf-8") as f:');
  L.push('    json.dump(res, f, ensure_ascii=False)');
  L.push('');
  L.push('print("TRACE_JSON=" + OUT)');
  L.push('print("STOP=" + str(S["stop"]))');
  L.push('if S["error"]:');
  L.push('    print("ERROR=" + str(S["error"]))');
  L.push('print("INSNS=%d EXEC_RANGES=%d EDGES=%d IND_SITES=%d" % (');
  L.push('    S["insn"], len(res["exec_ranges"]), len(res["edges"]), len(sites)))');
  L.push('print("RAX=%s RDX=%s" % (res["regs"]["rax"], res["regs"]["rdx"]))');
  L.push('for s in sites[:24]:');
  L.push('    tgt = " ".join("%s%s(x%d)" % (("v=%s " % t["value"]) if t["value"] else "", t["dst"], t["count"])');
  L.push('                   for t in s["targets"][:16])');
  L.push('    print("IND %s -> %d targets: %s" % (s["src"], s["distinct"], tgt))');
  L.push('if res["stdout"]:');
  L.push('    print("STDOUT=" + repr(res["stdout"][:400]))');
  L.push('if has_interp:');
  L.push('    print("NOTE=该 ELF 有 PT_INTERP（动态链接）：mode=entry 不可靠，优先 mode=function 直接调目标函数")');
  L.push('if S["stubs"]:');
  L.push('    print("STUBS=" + ", ".join("%s x%d" % (k, v) for k, v in sorted(S["stubs"].items(), key=lambda kv: -kv[1])[:12]))');

  return {
    ok: true,
    kind: 'emu-trace',
    language: 'python',
    script: L.join('\n'),
    outPath,
    notes: [
      'Unicorn 只走真实执行路径，不会像 angr 那样把常量表误当代码解码。',
      'indirect_sites 的 value 就是"运行期构造出来的跳转表"内容——段号 → 段地址一目了然。',
      'mode=function 直接调用目标函数（参数走 rdi/rsi/...），最适合"已知变换函数、只想跑通它"。',
      '动态链接目标（有 PT_INTERP）不要用 mode=entry，入口是 ld.so，仿真不出来。',
      'PLT 与 GOT 槽都重定向到同一组 mini-libc 桩：malloc/new/memcpy/memset 等通用实现，其余返回 0。',
    ],
  };
}

/**
 * 生成把轨迹回填进 IDA 的 IDAPython。
 *
 * input:
 *   trace       emu_trace 产出的 JSON（对象；也接受 JSON 字符串或文件路径）
 *   make_funcs  是否在跳转目标处建函数（默认 true）
 *   code_ranges 是否把执行过的区间也 MakeCode（默认 false——可能与其他边界冲突）
 *   auto_wait   回填后是否等待 IDA 重新分析（默认 false，快；true 更稳但慢）
 *
 * 回填后 IDA 的 CFG 才连成一片：反编译器能顺着 add_cref 找到各段，
 * 各段也能被单独 ida_decompile。
 */
function buildApplyTraceScript(input) {
  const i = input || {};
  let tr = i.trace;
  if (tr == null) return { error: 'ida_apply_trace 需要 trace（emu_trace 的结果对象 / JSON 文本 / JSON 文件路径）' };

  let trace = null;
  if (typeof tr === 'string') {
    const s = tr.trim();
    if (!s) return { error: 'trace 为空' };
    if (s.startsWith('{')) {
      try { trace = JSON.parse(s); } catch (e) { return { error: `trace 不是合法 JSON: ${e.message}` }; }
    } else {
      return { error: 'trace 传文件路径时需要主进程先读取；这里请传对象或 JSON 文本' };
    }
  } else if (typeof tr === 'object') {
    trace = tr;
  } else {
    return { error: 'trace 类型不支持' };
  }

  const edges = [];
  const seen = new Set();
  for (const e of (Array.isArray(trace.edges) ? trace.edges : [])) {
    if (!Array.isArray(e) || e.length < 2) continue;
    const a = parseIntLoose(e[0]);
    const b = parseIntLoose(e[1]);
    if (a === null || b === null) continue;
    const k = a + ':' + b;
    if (seen.has(k)) continue;
    seen.add(k);
    edges.push([a, b]);
  }
  // 间接跳转点单独收集：这些才是最需要 crefs 的地方
  const indTargets = new Set();
  for (const s of (Array.isArray(trace.indirect_sites) ? trace.indirect_sites : [])) {
    for (const t of (Array.isArray(s.targets) ? s.targets : [])) {
      const d = parseIntLoose(t.dst);
      if (d !== null) indTargets.add(d);
    }
  }
  const ranges = [];
  for (const r of (Array.isArray(trace.exec_ranges) ? trace.exec_ranges : [])) {
    if (!Array.isArray(r) || r.length < 2) continue;
    const a = parseIntLoose(r[0]);
    const b = parseIntLoose(r[1]);
    if (a === null || b === null || b < a) continue;
    ranges.push([a, b]);
  }
  if (!edges.length && !indTargets.size) {
    return { error: 'trace 里没有 edges / indirect_sites，无法回填（先跑 emu_trace 并确认 STOP=return）' };
  }

  // 体积控制：py_eval 的代码会走 MCP，太大容易超时/超限
  const MAX_EDGES = 40000;
  const MAX_RANGES = 4000;
  let edgesTrim = edges;
  let rangesTrim = ranges;
  const truncated = [];
  if (edges.length > MAX_EDGES) { edgesTrim = edges.slice(0, MAX_EDGES); truncated.push(`edges ${edges.length}->${MAX_EDGES}`); }
  if (ranges.length > MAX_RANGES) { rangesTrim = ranges.slice(0, MAX_RANGES); truncated.push(`ranges ${ranges.length}->${MAX_RANGES}`); }

  const makeFuncs = i.make_funcs !== false;
  const codeRanges = i.code_ranges === true;
  const autoWait = i.auto_wait === true;

  const L = [];
  L.push('import ida_bytes, ida_ua, ida_funcs, ida_xref, ida_segment, ida_auto, ida_kernwin, idc, idaapi');
  L.push('_S = {"made": 0, "fail": 0, "xrefs": 0, "funcs": 0, "func_skip": 0}');
  L.push('EDGES = ' + JSON.stringify(edgesTrim));
  L.push('IND_TARGETS = ' + JSON.stringify([...indTargets].sort((a, b) => a - b)));
  L.push('RANGES = ' + JSON.stringify(rangesTrim));
  L.push('MAKE_FUNCS = ' + (makeFuncs ? 'True' : 'False'));
  L.push('CODE_RANGES = ' + (codeRanges ? 'True' : 'False'));
  L.push('');
  L.push('def _exec_seg(ea):');
  L.push('    s = ida_segment.getseg(ea)');
  L.push('    if s is None:');
  L.push('        return False');
  L.push('    return bool(s.perm & ida_segment.SEGPERM_EXEC)');
  L.push('');
  L.push('def _make_code(ea):');
  L.push('    if not _exec_seg(ea):');
  L.push('        return False');
  L.push('    if ida_bytes.is_code(ida_bytes.get_flags(ea)):');
  L.push('        return True');
  L.push('    h = idc.get_item_head(ea)');
  L.push('    if h != idc.BADADDR and h != ea:');
  L.push('        ida_bytes.del_items(h, ida_bytes.DELIT_SIMPLE, (ea - h) + 16)');
  L.push('    ok = ida_ua.create_insn(ea)');
  L.push('    if ok:');
  L.push('        _S["made"] += 1');
  L.push('        return True');
  L.push('    _S["fail"] += 1');
  L.push('    return False');
  L.push('');
  L.push('def _add_fn(ea):');
  L.push('    if not MAKE_FUNCS:');
  L.push('        return');
  L.push('    if ida_funcs.get_func(ea) is not None:');
  L.push('        _S["func_skip"] += 1');
  L.push('        return');
  L.push('    try:');
  L.push('        if ida_funcs.add_func(ea):');
  L.push('            _S["funcs"] += 1');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('');
  L.push('def _cref(a, b):');
  L.push('    try:');
  L.push('        if ida_xref.add_cref(a, b, ida_xref.XREF_FAR):');
  L.push('            _S["xrefs"] += 1');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('');
  L.push('# 1) 间接跳转目标：这些是"运行期才存在"的段，必须先 MakeCode');
  L.push('for _d in IND_TARGETS:');
  L.push('    _make_code(_d)');
  L.push('    _add_fn(_d)');
  L.push('');
  L.push('# 2) 控制流边 -> 代码 xref（反编译器据此把各段连起来）');
  L.push('for _e in EDGES:');
  L.push('    _a, _b = _e[0], _e[1]');
  L.push('    _make_code(_b)');
  L.push('    _cref(_a, _b)');
  L.push('');
  L.push('# 3) 可选：把执行过的区间也标成代码（能救回 IDA 漏掉的整段）');
  L.push('if CODE_RANGES:');
  L.push('    for _r in RANGES:');
  L.push('        _ea = _r[0]');
  L.push('        while _ea <= _r[1]:');
  L.push('            _ok = _make_code(_ea)');
  L.push('            _sz = idc.get_item_size(_ea) or 1');
  L.push('            _ea += _sz if _ok else 1');
  L.push('');
  L.push('if ' + (autoWait ? 'True' : 'False') + ':');
  L.push('    try:');
  L.push('        ida_auto.auto_wait()');
  L.push('    except Exception:');
  L.push('        pass');
  L.push('try:');
  L.push('    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)');
  L.push('    ida_kernwin.request_refresh(ida_kernwin.IWID_NAMES)');
  L.push('except Exception:');
  L.push('    pass');
  L.push('');
  L.push('print("APPLY insn_made=%d fail=%d xrefs=%d funcs=%d func_skipped=%d" % (');
  L.push('    _S["made"], _S["fail"], _S["xrefs"], _S["funcs"], _S["func_skip"]))');
  L.push('print("IND_TARGETS=%d EDGES=%d RANGES=%d" % (len(IND_TARGETS), len(EDGES), len(RANGES)))');
  L.push('print("NEXT 现在 ida_decompile 目标函数，各段应已连成一片；仍缺段就用 code_ranges=true 再来一次")');

  return {
    ok: true,
    kind: 'apply-trace',
    tool: 'py_eval',
    args: { code: L.join('\n') },
    stats: {
      edges: edgesTrim.length,
      indTargets: indTargets.size,
      ranges: rangesTrim.length,
      truncated,
    },
    notes: [
      '先 create_insn 再 add_cref：目标处不是指令时 xref 挂不上。',
      'indirect_sites 的目标优先处理——它们是静态完全看不到的段入口。',
      'make_funcs 让每段变成可单独 ida_decompile 的函数，便于逐段还原语义。',
    ],
  };
}

/** 把 emu_trace 的 summary 压成一段给人看的文字（主进程用）。 */
function summarizeTrace(trace) {
  if (!trace || typeof trace !== 'object') return '（无轨迹数据）';
  const out = [];
  out.push(`停止原因: ${trace.stop || '?'}${trace.error ? `（${trace.error}）` : ''}`);
  out.push(`执行指令: ${trace.insn_count != null ? trace.insn_count : '?'}`);
  out.push(`返回寄存器: RAX=${(trace.regs && trace.regs.rax) || '?'} RDX=${(trace.regs && trace.regs.rdx) || '?'}`);
  const sites = Array.isArray(trace.indirect_sites) ? trace.indirect_sites : [];
  out.push(`间接跳转点: ${sites.length} 个`);
  for (const s of sites.slice(0, 12)) {
    const ts = (s.targets || []).slice(0, 12)
      .map(t => `${t.value ? t.value + '→' : ''}${t.dst}×${t.count}`)
      .join('  ');
    out.push(`  ${s.src} → ${s.distinct} 个目标: ${ts}`);
  }
  if (sites.length > 12) out.push(`  …另有 ${sites.length - 12} 个跳转点（见 JSON）`);
  const stubs = trace.stubs && typeof trace.stubs === 'object' ? Object.keys(trace.stubs) : [];
  if (stubs.length) out.push(`打桩的导入函数: ${stubs.slice(0, 12).join(', ')}${stubs.length > 12 ? ' …' : ''}`);
  if (trace.stdout) out.push(`stdout: ${JSON.stringify(String(trace.stdout).slice(0, 300))}`);
  if (trace.has_interp) out.push('注意: 该 ELF 动态链接，mode=entry 不可靠；用 mode=function 直接调目标函数。');
  return out.join('\n');
}

module.exports = { buildEmuTraceScript, buildApplyTraceScript, summarizeTrace, parseIntLoose };
