'use strict';
// CTF 花指令特征库（11 类）+ 修复
//
// ── 依据 ──────────────────────────────────────────────────────────────
// · 用户文章 https://ip2867.github.io/post/ctf-flower-code/ （11 类特征速查）
// · 看雪《[花指令]由易到难全面解析CTF中的花指令》
// · 实测数据（Matr1x: 非边界跳转 239→8，覆盖率 25.1%→28.2%，函数 54→93，反编译 66.7%）
//
// ── 重要纪律（文章开头明确强调，必须写进输出）────────────────────────────
//   IDA 里看到 `loc_XXXX: ; CODE XREF: ...↓j` **只表示该地址被跳转引用**，
//   **不等于**它是花指令。必须再查三件事：
//     ① 跳转目标是否**非对齐**（loc_XXXX+1 / +2）
//     ② XREF 是否指向**指令中间**
//     ③ 上下文是否**错位**（红色 db、孤立操作码、反汇编断裂）
//   本模块的每条候选都会带上"依据哪一条判据"，避免 AI 只看 XREF 就下结论。
//
// ── 修复原则 ──────────────────────────────────────────────────────────
//   策略 A nop_jump    ：只把出问题的**跳转指令本身**换成等长 NOP（字节偏移不变，最安全）
//   策略 B to_jmp      ：把条件跳转改成无条件 jmp 越过垃圾（文章第 2 类）
//   策略 C report_only ：需人工/动态确认（call/ret 跳板、伪造函数、栈指针混淆等）
//
//   为什么不整段 nop：把前序 xor/test 一起清掉会让后续指令重新错位
//   （实测 Matr1x: patch 53 处后不可解码 4→7、覆盖率不升反降）。

const MAX_REPORT = 800;

// ── 11 类特征（编号与文章一致，便于对照）──
const FEATURES = {
  F01_false_jump: '假跳转目标/非对齐跳转：jmp loc_XXXX+1 这种目标落在指令中间',
  F02_true_false_jcc: '永真/永假条件跳转：xor/test 后接 jcc，条件由前序唯一决定',
  F03_call_ret_addr: 'call/ret 地址操纵：被调函数内 add dword ptr [esp],N; retn',
  F04_call_next_pop: 'call $+5 型：call 下一条指令 + pop（压栈取址；若是取 EIP 用途则非花指令）',
  F05_jmp_chain: '简单 jmp/多层跳转链：连续 jmp，或 jmp 目标是下一条指令中间',
  F06_orphan_opcode: '操作码污染/字节错位：孤立的 0xE8/0xEB/0x0F 等被当成数据或吃掉后文',
  F07_fake_func: '伪造函数/伪调用：call 目标不是真正函数开头（XREF ↓p 指向指令中间）',
  F08_bad_xref: '异常交叉引用：XREF 指向非指令开头（需回看来源跳转的目标对齐性）',
  F09_junk_seq: '垃圾指令序列：nop/xchg eax,eax/push eax;pop eax/inc-dec 等无副作用的冗余',
  F10_stack_confusion: '栈指针混淆：add esp,N; jmp … sub esp,N 跨越花指令，esp 不平衡',
  F11_jmp_to_data: '跳转到数据：跳转目标落在 db 数据区（按 C 可转代码）',
  EXCL_pic_call_pop: '（排除项）call $+5; pop reg 且结果用于取址 = 正常 PIC，不是花指令',
};

function isJcc(d) { return d && (d.kind === 'jcc8' || d.kind === 'jcc32'); }
function isJmp(d) { return d && (d.kind === 'jmp8' || d.kind === 'jmp32'); }
function isRet(d) { return d && (d.kind === 'ret' || d.kind === 'retimm'); }

/**
 * 判定「标志位被设为确定值」——**只认真正自反/恒定的写法**。
 *
 * ⚠ 这里是最容易把正常程序改坏的地方，判据必须严格：
 *   ✔ xor r,r / sub r,r / sbb r,r  → ZF=1、CF=0，恒定
 *   ✔ clc/stc/cli/sti/cmc         → 直接改标志位
 *   ✘ test r,r / and r,r / cmp r,r → 结果**取决于 r 的值**，r 未知则不恒定
 *   ✘ cmp r,imm / add r,imm 等    → 同理取决于 r
 *   ✘ test [mem],reg             → 取决于内存
 * 实测教训：把 `test eax,eax; jz +2`（编译器最常见的空指针检查）当成"条件恒定"后，
 * 工具会把 jz 改成无条件 jmp，静默跳过后续真实代码。
 */
function isFlagSetter(d) {
  if (!d) return false;
  // 直接改标志位的单字节指令
  if (d.kind === 'simple' && [0xf5, 0xf8, 0xf9, 0xfa, 0xfb, 0xf4].includes(d.op)) return true;
  // 只认 xor/sub/sbb 且两端是同一寄存器（xor r,r / sub r,r 必为 0）。
  // and(0x21/0x23) 结果仍是 r 本身，不恒定，故排除。
  if (d.modrm && [0x31, 0x29, 0x33, 0x2b].includes(d.op)) {
    return d.modrm.mod === 3 && d.modrm.reg === d.modrm.rm;
  }
  return false;
}

/** 已知的标志位快照：{ ZF, CF, SF, OF } —— 只对能确定的写法返回 */
function knownFlags(d) {
  if (!d) return null;
  // clc/stc/cli/sti/cmc：只影响 CF（cmc 取反，需上下文，保守不认）
  if (d.kind === 'simple') {
    if (d.op === 0xf8) return { ZF: null, CF: 0, SF: null, OF: null };  // clc
    if (d.op === 0xf9) return { ZF: null, CF: 1, SF: null, OF: null };  // stc
    return null;
  }
  // xor r,r / sub r,r / sbb r,r → 结果 0，ZF=1, CF=0, SF=0, OF=0
  if (d.modrm && [0x31, 0x29, 0x33, 0x2b].includes(d.op) &&
      d.modrm.mod === 3 && d.modrm.reg === d.modrm.rm) {
    return { ZF: 1, CF: 0, SF: 0, OF: 0 };
  }
  return null;
}

/**
 * 判断这条 jcc 在已知标志位下是「必跳」还是「必不跳」。
 * 返回 'taken' | 'notTaken' | null（无法判定）。
 *
 * 为什么必须做这一步：只判断"前序是指令设置标志"是不够的——
 * 若不看方向就把"永不跳"改成"永远跳"，程序行为直接反转（实测
 * `xor eax,eax; jnz +2; mov al,1` 被改成无条件跳，跳过了 mov al,1）。
 * 反向跳更糟：`xor eax,eax; jz -2` 会被改成 0xEB 0xFE = 无条件死循环。
 */
function jccDirection(d, flags) {
  if (!d || !flags) return null;
  const op = d.op & 0xff;              // 去掉可能的前缀编码
  const ZF = flags.ZF, CF = flags.CF, SF = flags.SF, OF = flags.OF;
  switch (op) {
    case 0x74: return ZF === null ? null : (ZF === 1 ? 'taken' : 'notTaken');   // jz/je
    case 0x75: return ZF === null ? null : (ZF === 1 ? 'notTaken' : 'taken');   // jnz/jne
    case 0x72: return CF === null ? null : (CF === 1 ? 'taken' : 'notTaken');   // jb/jc
    case 0x73: return CF === null ? null : (CF === 1 ? 'notTaken' : 'taken');   // jae/jnc
    case 0x76: return (CF === null || ZF === null) ? null : ((CF === 1 || ZF === 1) ? 'taken' : 'notTaken'); // jbe
    case 0x77: return (CF === null || ZF === null) ? null : ((CF === 1 || ZF === 1) ? 'notTaken' : 'taken'); // ja
    case 0x7c: return (SF === null || OF === null) ? null : (SF !== OF ? 'taken' : 'notTaken'); // jl
    case 0x7d: return (SF === null || OF === null) ? null : (SF !== OF ? 'notTaken' : 'taken'); // jge
    case 0x78: return (SF === null || OF === null) ? null : (SF === OF ? 'taken' : 'notTaken'); // js
    case 0x79: return (SF === null || OF === null) ? null : (SF === OF ? 'notTaken' : 'taken'); // jns
    default: return null;
  }
}

function regOfPushPop(d) {
  if (!d || d.kind !== 'pushpop') return null;
  if (d.op >= 0x50 && d.op <= 0x57) return { dir: 'push', reg: d.op - 0x50 };
  if (d.op >= 0x58 && d.op <= 0x5f) return { dir: 'pop', reg: d.op - 0x58 };
  return null;
}

/** 是否是操作 esp 的指令（add/sub/mov esp, ...） */
function touchesEsp(d) {
  if (!d || !d.modrm) return false;
  // mod=3 且 rm=4 表示 esp
  if (d.modrm.mod === 3 && d.modrm.rm === 4) return true;
  // [esp] 形式：mod!=3, rm=4, SIB base=4
  return false;
}

function opName(d) {
  if (!d) return '?';
  const m = {
    jcc8: 'jcc', jcc32: 'jcc32', jmp8: 'jmp', jmp32: 'jmp', call32: 'call',
    pushpop: d.op >= 0x58 ? 'pop' : 'push', ret: 'ret', retimm: 'retn',
    modrm: 'op', aluimm: 'alu', aluimm8: 'alu', test32: 'test', test8: 'test',
    movimm: 'mov', simple: 'op', nop: 'nop', pushimm: 'push', pushimm8: 'push',
    grp3: 'grp3', shiftimm: 'shift', leave: 'leave', int3: 'int3',
  };
  return (m[d.kind] || d.kind) + '(0x' + (d.op & 0xff).toString(16) + ')';
}

/**
 * 扫描 11 类花指令特征。
 * @param {Buffer} buf
 * @param {object} opts { start, end, decodeInsn, features: string[]（可选，限定类别） }
 */
function scanJunkFeatures(buf, opts = {}) {
  const { decodeInsn } = opts;
  if (typeof decodeInsn !== 'function') return { ok: false, error: '需要 decodeInsn' };
  const start = Number.isFinite(opts.start) ? opts.start : 0;
  let end = Number.isFinite(opts.end) ? opts.end : buf.length;

  // ⚠ 必须夹到文件范围内。调用方（main.js 的 junk-probe / junk_repair / junk_scan）
  // 用 ELF 的 p_memsz 推导代码区，而 memsz 常大于文件实际长度（BSS 尾巴）；
  // 不夹的话线性解码会一路扫到文件外、指令表无限增长，主进程直接 OOM 崩掉。
  const clamped = [];
  if (!(start >= 0)) return { ok: false, error: `代码区起点非法: ${start}` };
  if (start >= buf.length) return { ok: false, error: `代码区起点超出文件长度: ${start} >= ${buf.length}` };
  if (end > buf.length) { clamped.push(`end ${end} > 文件长度 ${buf.length}，已夹到文件末尾`); end = buf.length; }
  if (end - start < 4) return { ok: false, error: `代码区过小: [${start}, ${end})` };

  // 允许的 features 过滤：既接受完整 key（F01_false_jump），也接受 schema 里宣传的短名
  // （false_jump / short_skip / junk_after_jcc / dead_push_pop / opaque_pair）。
  // 早期只认完整 key，导致按 schema 传短名时 want 里全是匹配不到的名字 →
  // on() 恒 false → **静默关闭全部检测**（实测传 features:['false_jump'] 候选数 1→0）。
  const ALIASES = {
    false_jump: 'F01_false_jump',
    true_false_jcc: 'F02_true_false_jcc',
    short_skip: 'F02_true_false_jcc',
    junk_after_jcc: 'F02_true_false_jcc',
    opaque_pair: 'F02_true_false_jcc',
    call_ret_addr: 'F03_call_ret_addr',
    pic_call_pop: 'F04_call_next_pop',
    jmp_chain: 'F05_jmp_chain',
    orphan_opcode: 'F06_orphan_opcode',
    dead_push_pop: 'F07_fake_func',
    fake_func: 'F07_fake_func',
    bad_xref: 'F08_bad_xref',
    junk_seq: 'F09_junk_seq',
    stack_confusion: 'F10_stack_confusion',
    jmp_to_data: 'F11_jmp_to_data',
  };
  let want = null;
  let unknownFeatures = [];
  if (Array.isArray(opts.features) && opts.features.length) {
    want = new Set();
    for (const raw of opts.features.map(String)) {
      const key = ALIASES[raw] || raw;
      if (Object.prototype.hasOwnProperty.call(FEATURES, key)) want.add(key);
      else unknownFeatures.push(raw);
    }
    // 全都认不出来 → 回退到"全开"，而不是把所有检测关掉
    if (!want.size) {
      want = null;
      unknownFeatures = unknownFeatures.map(x => x);
    }
  }
  const on = (f) => !want || want.has(f);

  // 线性解码
  const insns = [];
  let p = start;
  while (p < end) {
    const d = decodeInsn(buf, p);
    if (!d || d.len <= 0 || p + d.len > end) { insns.push({ off: p, len: 1, undecodable: true }); p += 1; }
    else { insns.push(d); p += d.len; }
  }
  const boundary = new Set(insns.filter(i => !i.undecodable).map(i => i.off));
  const idx = new Map(insns.map((i, k) => [i.off, k]));
  const insnAt = (off) => idx.get(off) !== undefined ? insns[idx.get(off)] : null;

  const features = {};
  for (const k of Object.keys(FEATURES)) features[k] = 0;
  const candidates = [];
  const push = (c) => { features[c.feature] = (features[c.feature] || 0) + 1; candidates.push(c); };

  for (let i = 0; i < insns.length; i++) {
    const d = insns[i];
    if (d.undecodable) continue;
    const fall = d.off + d.len;

    // ═════ F01/F02/F08 条件跳转族 ═════
    if (isJcc(d)) {
      const taken = fall + d.rel;
      const relAbs = Math.abs(d.rel);
      const inRange = taken >= start && taken < end;
      const targetBad = inRange && !boundary.has(taken);
      const fallD = insnAt(fall);
      const fallOk = !!fallD && !fallD.undecodable;

      // 前序确定标志位（回看 3 条）
      let flagSetter = null;
      for (let k = i - 1; k >= Math.max(0, i - 3); k--) {
        const pv = insns[k];
        if (!pv || pv.undecodable) break;
        if (isFlagSetter(pv)) { flagSetter = pv; break; }
        if (isJmp(pv) || isRet(pv)) break;
      }
      const condConstant = !!flagSetter;
      // 标志位快照（只有 flagSetter 是自反写法时才有值）。用于判定 jcc 方向：
      // 不判方向就改字节会把"永不跳"改成"永远跳"，直接反转程序行为。
      const flags = flagSetter ? knownFlags(flagSetter) : null;

      // F01 假跳转目标（目标非对齐）—— 最硬判据
      // ⚠ 只有当条件恒不成立（notTaken）时，nop 掉 jcc 才等价于原执行流。
      //   若条件恒成立，nop 会让执行落进本该被跳过的字节；方向未知更不能动。
      if (on('F01_false_jump') && targetBad && condConstant && fallOk) {
        const dir = jccDirection(d, flags);
        if (dir === 'notTaken') {
          push({
            feature: 'F01_false_jump',
            off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
            strategy: 'nop_jump', safe: true,
            evidence: `跳转目标 0x${taken.toString(16)} 不落在指令边界上（= loc_${taken.toString(16)}+N 型）`,
            reason: `条件跳转 ${d.kind}(rel=${d.rel}) 目标非对齐，且条件恒不成立；` +
              `nop 后顺序落到 0x${fall.toString(16)}（解码正常）`,
            nopRange: { from: d.off, to: d.off + d.len },
          });
          continue;
        }
        // 方向为 taken 或未知 → 只报告，不改字节
        push({
          feature: 'F01_false_jump',
          off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
          strategy: 'report_only', safe: false,
          evidence: `跳转目标 0x${taken.toString(16)} 不落在指令边界上；前序 ${opName(flagSetter)}@0x${flagSetter.off.toString(16)}`,
          reason: dir === 'taken'
            ? '条件恒成立 → nop 会让执行落入本该跳过的字节，只报告不修改'
            : '标志位方向无法静态判定 → 只报告，需动态确认',
        });
        continue;
      }

      // F08 异常交叉引用（与 F01 同源，但强调"XREF 指向指令中间"）
      if (on('F08_bad_xref') && targetBad && !condConstant) {
        push({
          feature: 'F08_bad_xref',
          off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
          strategy: 'report_only', safe: false,
          evidence: `XREF 指向的 0x${taken.toString(16)} 不是指令开头（但前序无确定标志位，条件不恒定）`,
          reason: `跳转目标非对齐，可能来自另一条路径的正常跳转；需人工确认条件来源`,
          nopRange: null,
        });
        continue;
      }

      // F02 永真/永假 + 短跳过
      // ⚠ 必须知道方向：只有「条件恒不成立（notTaken）」时，把 jcc 改成无条件 jmp 才是错的；
      //   正确做法是把它 nop 掉（fallthrough 走原 fall 路径）。
      //   「条件恒成立（taken）」时不能 nop —— 那会落进本该跳过的字节。
      if (on('F02_true_false_jcc') && condConstant && relAbs > 0 && relAbs <= 4 && fallOk) {
        const dir = jccDirection(d, flags);
        if (dir === 'notTaken') {
          // 永不跳 → 整条 jcc 换成等长 NOP，顺序执行 == 原本的 fall 路径，语义完全不变
          push({
            feature: 'F02_true_false_jcc',
            off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
            strategy: 'nop_jump', safe: true,
            evidence: `前序 ${opName(flagSetter)}@0x${flagSetter.off.toString(16)} 使条件恒不成立（${opName(d)} 永不跳）`,
            reason: `条件恒假 → 该跳转永不执行，换成等长 NOP 不改变执行流；` +
              `跳过区 [0x${fall.toString(16)},0x${taken.toString(16)}) 的 ${relAbs} 字节是垃圾`,
            nopRange: { from: d.off, to: d.off + d.len },
          });
          continue;
        }
        if (dir === 'taken') {
          // 永远跳 → 跳转本身可以保留（它总会生效），只把跳过区当垃圾报告，不动字节
          push({
            feature: 'F02_true_false_jcc',
            off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
            strategy: 'report_only', safe: false,
            evidence: `前序 ${opName(flagSetter)}@0x${flagSetter.off.toString(16)} 使条件恒成立（${opName(d)} 必跳）`,
            reason: `条件恒真 → 跳转总会生效，改字节会破坏原语义；此处仅报告，` +
              `跳过区 [0x${fall.toString(16)},0x${taken.toString(16)}) 可视为死代码`,
          });
          continue;
        }
        // 方向无法判定（标志位信息不足）→ 只报告，绝不改字节
      }

      // 互补跳转对（文章未单列，但属 F02 变体）
      // ⚠ 只有「两条 jcc 跳到同一目标」才是真正的恒跳（jz T; jnz T ⇒ 必到 T）；
      //   若目标不同，两条各走一边，nop 掉第一条会改变 ZF=0 时的去向。
      if (on('F02_true_false_jcc')) {
        for (let gap = 0; gap <= 2; gap++) {
          const j = idx.get(fall + gap);
          if (j === undefined) continue;
          const b = insns[j];
          if (!b || b.undecodable || !isJcc(b)) continue;
          if ((d.op & 0xfe) !== (b.op & 0xfe)) continue;
          if ((d.op & 1) === (b.op & 1)) continue;
          const tB = b.off + b.len + b.rel;
          // 只有「两侧目标完全相同」才是无条件跳；目标不同一律不动
          if (tB !== taken) continue;
          if (!fallOk) break;
          push({
            feature: 'F02_true_false_jcc',
            off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
            strategy: 'report_only', safe: false,
            evidence: `互补跳转对 ${opName(d)}@0x${d.off.toString(16)} + ${opName(b)}@0x${b.off.toString(16)}，两侧同目标 0x${taken.toString(16)}`,
            reason: '两条互斥条件跳到同一处 ⇒ 无条件跳；这是构造形态，nop 其中一条会改变 ZF 另一侧的落点，故只报告',
          });
          break;
        }
        continue;
      }
      continue;
    }

    // ═════ F05 简单 jmp / 多层跳转链 ═════
    if (on('F05_jmp_chain') && isJmp(d)) {
      const taken = fall + d.rel;
      // 跳 1~4 字节（跳过垃圾）
      // ⚠ 不能 nop：nop 掉 jmp 后执行会**落进它原本跳过的字节**，把垃圾变成执行路径。
      //   实测 `jmp +2; <e8 5b>; ret` 被 nop 后，e8 被当成 call 执行并吞掉后续字节。
      //   只有"被跳过的字节确实是死代码"才能动，静态无从证明 → 只报告。
      if (d.rel > 0 && d.rel <= 4 && taken >= start && taken < end) {
        push({
          feature: 'F05_jmp_chain',
          off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
          strategy: 'report_only', safe: false,
          evidence: `无条件跳转跳过 ${d.rel} 字节（[0x${fall.toString(16)},0x${taken.toString(16)}) 区间疑似垃圾）`,
          reason: 'nop 跳转会让执行落入被跳过的字节（垃圾变代码），静态无法证明该区间是死代码 → 只报告',
        });
        continue;
      }
      // 连续 jmp 链（jmp -> jmp -> ...）
      const nextD = insnAt(taken);
      if (nextD && isJmp(nextD) && d.rel !== 0) {
        push({
          feature: 'F05_jmp_chain',
          off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken, fall,
          strategy: 'report_only', safe: false,
          evidence: `跳转目标是另一条 jmp（多层跳转链）`,
          reason: `多层跳转增加分析复杂度但**语义合法**；不要单独 nop，需追踪到最终目标`,
          nopRange: null,
        });
      }
      continue;
    }

    // ═════ F04 排除项 / F07 伪调用 ═════
    if (d.kind === 'call32') {
      const nextD = insnAt(fall);
      // F04 call $+5; pop reg
      if (on('F04_call_next_pop') && d.rel === 0 && nextD) {
        const q = regOfPushPop(nextD);
        if (q && q.dir === 'pop') {
          // 判断该 pop 的结果是否被使用（用于取址 = PIC，不是花指令）
          let used = false;
          for (let k = i + 2; k < Math.min(insns.length, i + 8); k++) {
            const x = insns[k];
            if (!x || x.undecodable) break;
            // 若该寄存器随后参与 add/sub/mov 到内存，视为取址用途
            if (x.modrm && (x.modrm.reg === q.reg || x.modrm.rm === q.reg)) { used = true; break; }
          }
          if (used) {
            features.EXCL_pic_call_pop++;
          } else {
            push({
              feature: 'F04_call_next_pop',
              off: d.off, len: d.len + nextD.len, kind: 'call_pop', rel: 0, taken: fall, fall,
              strategy: 'report_only', safe: false,
              evidence: `call $+5; pop 寄存器，且该寄存器未被后续指令使用`,
              reason: `合法但无意义的"压栈取址"（结果未用）→ 疑似花指令；` +
                `**不要盲改**：若该寄存器后续被间接使用（如 jmp reg），改了就崩`,
              nopRange: null,
            });
          }
          continue;
        }
      }
      // F07 伪造函数 / 伪调用：call 目标不是指令边界
      if (on('F07_fake_func') && d.rel !== 0) {
        const t = fall + d.rel;
        if (t >= start && t < end && !boundary.has(t)) {
          push({
            feature: 'F07_fake_func',
            off: d.off, len: d.len, kind: 'call32', rel: d.rel, taken: t, fall,
            strategy: 'report_only', safe: false,
            evidence: `call 目标 0x${t.toString(16)} 不是指令开头（XREF ↓p 指向指令中间）`,
            reason: `IDA 可能把这里误识别成函数（sub_XXXX）；**需人工确认**：` +
              `若是真调用则该处必然是指令起点，说明前方有字节错位`,
            nopRange: null,
          });
        }
      }
      continue;
    }
  }

  // ═════ F03 call/ret 地址操纵 ═════
  if (on('F03_call_ret_addr')) {
    for (let i = 0; i < insns.length; i++) {
      const d = insns[i];
      if (d.undecodable || d.kind !== 'call32' || d.rel === 0) continue;
      let espAdj = null, ret = null;
      for (let k = i + 1; k < Math.min(insns.length, i + 7); k++) {
        const x = insns[k];
        if (x.undecodable) break;
        // add/sub dword ptr [esp], imm  → op 0x81/0x83, reg ∈ {0,5}
        if ((x.op === 0x81 || x.op === 0x83) && x.modrm && (x.modrm.reg === 0 || x.modrm.reg === 5)) espAdj = x;
        if (isRet(x) && espAdj) { ret = x; break; }
        if (isJmp(x)) break;
      }
      if (ret) {
        features.F03_call_ret_addr++;
        candidates.push({
          feature: 'F03_call_ret_addr',
          off: d.off, len: ret.off + ret.len - d.off, kind: 'trampoline',
          taken: null, fall: null, strategy: 'report_only', safe: false,
          evidence: `call@0x${d.off.toString(16)} → ${opName(espAdj)}@0x${espAdj.off.toString(16)} → ret@0x${ret.off.toString(16)}`,
          reason: `被调函数内直接改 [esp] 返回地址后 retn，越过垃圾字节。` +
            `**不要盲 nop**（会破坏返回地址）；动态单步跟一次最稳`,
          nopRange: null,
        });
      }
    }
  }

  // ═════ F06 操作码污染 / 孤立操作码 ═════
  if (on('F06_orphan_opcode')) {
    // 判据：某处 1~2 字节的"指令"其 opcode 是 0xE8/0xE9/0xEB/0x0F（诱导型），
    // 且它与前后指令不构成合理序列（前后都是 ret/jmp 或本身就是 undecodable 邻接）
    const ORPHAN_OPS = new Set([0xe8, 0xe9, 0xeb, 0x0f, 0x68, 0x6a, 0xc7, 0x74, 0x75]);
    for (let i = 0; i < insns.length; i++) {
      const d = insns[i];
      if (d.undecodable) continue;
      if (d.len > 6) continue;
      const op = d.op & 0xff;
      if (!ORPHAN_OPS.has(op)) continue;
      // 前一条是 ret / 后一条是 ret，且本指令不被任何跳转引用 → 高度可疑
      const prev = insns[i - 1], next = insns[i + 1];
      const prevTerm = prev && !prev.undecodable && (isRet(prev) || isJmp(prev));
      const nextTerm = next && !next.undecodable && isRet(next);
      if (prevTerm && nextTerm) {
        push({
          feature: 'F06_orphan_opcode',
          off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken: null, fall: d.off + d.len,
          strategy: 'report_only', safe: false,
          evidence: `孤立指令 ${opName(d)}@0x${d.off.toString(16)}（前有 ret/jmp、后有 ret，且不在跳转目标内）`,
          reason: `疑似被误解析的操作码污染（文章第 6 类）。` +
            `**先在 IDA 里按 D 转数据、再按 C 从正确位置重建代码**，不要直接 nop`,
          nopRange: null,
        });
      }
    }
  }

  // ═════ F09 垃圾指令序列 ═════
  if (on('F09_junk_seq')) {
    // 无副作用组合：push reg; pop same reg / xchg eax,eax / nop 连续 / inc reg; dec reg
    for (let i = 0; i < insns.length - 1; i++) {
      const a = insns[i], b = insns[i + 1];
      if (a.undecodable || b.undecodable) continue;
      const pa = regOfPushPop(a), pb = regOfPushPop(b);
      if (pa && pb && pa.dir === 'push' && pb.dir === 'pop' && pa.reg === pb.reg) {
        push({
          feature: 'F09_junk_seq',
          off: a.off, len: a.len + b.len, kind: 'push_pop_same',
          taken: null, fall: b.off + b.len,
          strategy: 'nop_jump', safe: true,
          evidence: `push ${['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'][pa.reg]}; pop 同一寄存器（净效果为零）`,
          reason: `典型的垃圾指令对（保存后立即恢复，中间无任何操作）`,
          nopRange: { from: a.off, to: b.off + b.len },
        });
        continue;
      }
      // xchg eax,eax（0x90 是 nop，0x87 0xC0 是 xchg eax,eax）
      if (a.op === 0x87 && a.modrm && a.modrm.mod === 3 && a.modrm.reg === a.modrm.rm) {
        push({
          feature: 'F09_junk_seq',
          off: a.off, len: a.len, kind: 'xchg_self',
          taken: null, fall: a.off + a.len,
          strategy: 'nop_jump', safe: true,
          evidence: `xchg reg,reg（自身交换，等于 nop）`,
          reason: `NOP 变形的垃圾指令`,
          nopRange: { from: a.off, to: a.off + a.len },
        });
      }
    }
  }

  // ═════ F10 栈指针混淆 ═════
  if (on('F10_stack_confusion')) {
    // 模式：add esp,N; jmp ...; 目标处 sub esp,N（成对但跨越跳转）
    for (let i = 0; i < insns.length; i++) {
      const d = insns[i];
      if (d.undecodable || !(d.op === 0x81 || d.op === 0x83) || !d.modrm) continue;
      if (!(d.modrm.reg === 0 || d.modrm.reg === 5)) continue;   // add/sub esp, imm
      if (d.modrm.mod !== 3 || d.modrm.rm !== 4) continue;
      let jmpIdx = -1;
      for (let k = i + 1; k < Math.min(insns.length, i + 4); k++) {
        if (isJmp(insns[k])) { jmpIdx = k; break; }
        if (insns[k].undecodable) break;
      }
      if (jmpIdx < 0) continue;
      features.F10_stack_confusion++;
      candidates.push({
        feature: 'F10_stack_confusion',
        off: d.off, len: insns[jmpIdx].off + insns[jmpIdx].len - d.off, kind: 'stack_confuse',
        taken: null, fall: null, strategy: 'report_only', safe: false,
        evidence: `${opName(d)}@0x${d.off.toString(16)} 后紧跟 jmp@0x${insns[jmpIdx].off.toString(16)}`,
        reason: `疑似栈指针混淆（文章第 10 类）：先调 esp 再跳转，目标处再反向调整以跨越花指令。` +
          `**需盯着 esp 变化人工确认**，盲 nop 可能导致栈失衡`,
        nopRange: null,
      });
    }
  }

  // ═════ F11 跳转到数据 ═════
  if (on('F11_jmp_to_data')) {
    // 判据：跳转目标落在边界上，但该"指令"解码后立刻是无效/后续错位
    for (let i = 0; i < insns.length; i++) {
      const d = insns[i];
      if (d.undecodable || !(isJcc(d) || isJmp(d))) continue;
      const t = d.off + d.len + d.rel;
      if (t < start || t >= end) continue;
      const td = insnAt(t);
      if (!td || td.undecodable) continue;
      // 目标处解出的"指令"是 1 字节的怪东西（如 0xE8 单独出现）→ 疑似数据
      if (td.len === 1 && [0xe8, 0xe9, 0xeb, 0x0f].includes(td.op & 0xff)) {
        push({
          feature: 'F11_jmp_to_data',
          off: d.off, len: d.len, kind: d.kind, rel: d.rel, taken: t, fall: d.off + d.len,
          strategy: 'report_only', safe: false,
          evidence: `跳转目标 0x${t.toString(16)} 处解出孤立操作码 ${opName(td)}`,
          reason: `疑似跳进数据区。**在 IDA 里按 C 尝试转代码**，转不了就是数据`,
          nopRange: null,
        });
      }
    }
  }

  // ═════ 排除项统计：PIC 取址 ═════
  for (let i = 0; i < insns.length - 1; i++) {
    const d = insns[i], n = insns[i + 1];
    if (d.kind === 'call32' && d.rel === 0) {
      const q = regOfPushPop(n);
      if (q && q.dir === 'pop') features.EXCL_pic_call_pop++;
    }
  }

  const badTargets = insns.filter(d => {
    if (d.undecodable || d.rel === null || d.rel === undefined) return false;
    if (!(isJcc(d) || isJmp(d) || d.kind === 'call32')) return false;
    const t = d.off + d.len + d.rel;
    return t >= start && t < end && !boundary.has(t);
  }).length;

  const patchable = candidates.filter(c => c.nopRange && c.safe);
  return {
    ok: true,
    codeRange: { start, end, size: end - start },
    insnCount: insns.length,
    candidates: candidates.slice(0, MAX_REPORT),
    warnings: clamped.concat(
      unknownFeatures.length ? [`未识别的 features 名已忽略: ${unknownFeatures.join(',')}`] : []
    ),
    stats: {
      insnCount: insns.length,
      undecodable: insns.filter(i => i.undecodable).length,
      badTargets,
      total: candidates.length,
      patchable: patchable.length,
      reportOnly: candidates.length - patchable.length,
      features,
      unknownFeatures,
      clamped,
    },
    notes: [
      '**判定纪律**（文章开头强调）：IDA 里看到 `loc_XXXX: ; CODE XREF: ...↓j` 只表示该地址被跳转引用，' +
        '**不等于**是花指令。必须再查：① 目标是否非对齐（+1/+2）② XREF 是否指向指令中间 ③ 上下文是否错位（红色 db）。' +
        '本工具每条候选都标注了用的是哪条判据。',
      '特征库（11 类）：' + Object.entries(FEATURES).map(([k, v]) => `\n  · ${k} = ${v}`).join(''),
      '修复策略：nop_jump（等长 NOP，偏移不变）/ to_jmp（改无条件 jmp）/ report_only（需人工或动态确认）',
      '为什么不整段 nop：把前序 xor/test 一起清掉会让后续指令重新错位（实测不可解码 4→7）。',
    ].filter(Boolean),
  };
}

/** 应用修补 */
function applyRepair(buf, candidates) {
  const out = Buffer.from(buf);
  const applied = [], skipped = [];
  const ranges = [];
  for (const c of candidates || []) {
    if (!c) continue;
    if (!c.safe) { skipped.push({ off: c.off, feature: c.feature, why: '需人工/动态确认' }); continue; }
    if (c.strategy === 'to_jmp' && c.jmpPatch) {
      const { off, bytes } = c.jmpPatch;
      // 必须同时校验上下界：Buffer 的负索引只是普通属性，out[-1]=x 会被静默丢弃，
      // 而 out[0] 仍然被改写 → 报"已应用"却写错了位置（实测 off=-1 时发生）。
      if (!(Number.isFinite(off) && off >= 0)) { skipped.push({ off, why: `偏移非法 ${off}` }); continue; }
      if (!Array.isArray(bytes) || !bytes.length) { skipped.push({ off, why: '无补丁字节' }); continue; }
      if (off + bytes.length > out.length) { skipped.push({ off, why: '越界' }); continue; }
      if (ranges.some(r => off < r.to && off + bytes.length > r.from)) { skipped.push({ off, why: '重叠' }); continue; }
      ranges.push({ from: off, to: off + bytes.length });
      for (let i = 0; i < bytes.length; i++) out[off + i] = bytes[i];
      applied.push({ off, len: bytes.length, feature: c.feature, strategy: 'to_jmp' });
      continue;
    }
    if (!c.nopRange) { skipped.push({ off: c.off, feature: c.feature, why: '无 nopRange' }); continue; }
    const { from, to } = c.nopRange;
    if (!(from >= 0 && to <= out.length && to > from)) { skipped.push({ off: from, why: '越界' }); continue; }
    if (to - from !== c.len) { skipped.push({ off: from, why: `长度不符 ${to - from}!=${c.len}` }); continue; }
    if (ranges.some(r => from < r.to && to > r.from)) { skipped.push({ off: from, why: '重叠' }); continue; }
    ranges.push({ from, to });
    for (let i = from; i < to; i++) out[i] = 0x90;
    applied.push({ off: from, len: to - from, feature: c.feature, strategy: 'nop_jump' });
  }
  return { buffer: out, applied, skipped };
}

module.exports = { scanJunkFeatures, applyRepair, FEATURES };
