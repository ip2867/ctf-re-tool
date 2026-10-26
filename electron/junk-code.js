'use strict';
// 花指令（junk code）通用识别与修补引擎
//
// ── 设计立场 ──────────────────────────────────────────────────────────
// 本模块**不针对任何具体题目的字节序列**，只实现"花指令之所以成立"的一般原理。
// 依据（公开方法论文档）：
//   · 看雪《[原创][花指令]由易到难全面解析CTF中的花指令》(Dua0g)：
//     花指令 = "构造永恒跳转 + 插入垃圾数据"；修复 = patch 成 nop 后重新反汇编；
//     判据 = 互补条件跳转 + 确定标志位 + push/pop 栈平衡边界。
//   · x86 反汇编原理：线性扫描顺序解码，指令长度可变 →
//     **任意一处边界判断错误会导致后续全部解码错位**。这是花指令唯一的杀伤机制。
//   · 常见垃圾字节：E8/E9/EB/0F/68/6A/C7/74 等"看起来像指令前缀"的单字节，
//     因为解码器会把后续字节当成它的操作数吃掉。
//
// ── 通用识别框架（四层，从强到弱，互不依赖具体模式）────────────────────
//   L1 跳转可达性：对每条 jcc/jmp，判断它的"另一侧"是否可证明不可达
//        (a) 前序存在确定标志位指令（xor/sub/and r,r / test r,r / cmp r,imm / clc）
//        (b) 不可达侧长度 ≤ 2 字节就到达 join 点（_emit 单字节垃圾的典型形态）
//   L2 边界歧义：不可达侧的字节解码后是否"越界"（落进别的指令中间 / 超出代码区）
//        —— 越界说明该位置本来不是指令起点，是插入垃圾造成的伪解码
//        （这是最硬的技术判据，不依赖任何助记符知识）
//   L3 段边界：push reg … pop reg 配对（栈平衡），或函数 prologue/epilogue 作为范围上界
//   L4 校验：nop 前后"跳转目标集合"应保持可达（不把真实代码 nop 掉）
//
// 输出永远是"候选 + 证据 + 置信度 + 建议 nop 范围"，patch 只处理自证安全的范围。

const MAX_REPORT = 500;
const NOP = 0x90;

// ───────────────────────── x86 指令长度解码 ─────────────────────────
const PREFIXES = new Set([
  0x66, 0x67, 0xf0, 0xf2, 0xf3,
  0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65,
]);
// 0x40-0x4F 只在 **64 位模式**下是 REX 前缀；在 32 位代码里它们是 inc/dec reg。
// 早期无条件当 REX 吞掉，会让每条 inc/dec 少 1 字节 → 后续全部错位
//（而"1 字节错位毁掉整段反汇编"正是本模块要解决的病）。
// CTF 逆向目标里 32 位 x86 占绝大多数，故默认按 32 位解释；
// 需要 64 位语义时由调用方传 mode:'x64'。
function isRex(b, x64) { return x64 && b >= 0x40 && b <= 0x4f; }

function decodeInsn(buf, off, opts) {
  const x64 = !!(opts && opts.x64);
  if (!Number.isInteger(off) || off < 0 || off >= buf.length) return null;
  let p = off, opsz16 = false, prefixCount = 0, addrsz16 = false;
  while (p < buf.length) {
    const b = buf[p];
    if (PREFIXES.has(b)) {
      if (b === 0x66) opsz16 = true;
      if (b === 0x67) addrsz16 = true;   // 地址位宽 16，影响 ModRM 位移宽度
      p++; prefixCount++;
    }
    else if (isRex(b, x64)) { p++; prefixCount++; }
    else break;
    if (prefixCount > 6) return null;
  }
  if (p >= buf.length) return null;
  const op = buf[p], opOff = p;
  p++;
  const need = (n) => (p + n <= buf.length ? n : null);
  const readModRM = () => {
    if (p >= buf.length) return null;
    const m = buf[p++];
    const mod = m >> 6, rm = m & 7;
    let extra = 0;
    // 32 位寻址下 mod!=3 才有 SIB/位移；16 位寻址(0x67)格式完全不同，
    // 这里保守按 16 位规则算位移宽度，避免读多/读少。
    if (mod !== 3) {
      if (addrsz16) {
        if (mod === 1) extra += 1;
        else if (mod === 2) extra += 2;
        else if (mod === 0 && rm === 6) extra += 2;
      } else {
        if (rm === 4) {
          if (p >= buf.length) return null;
          const sib = buf[p++];
          if (mod === 0 && (sib & 7) === 5) extra += 4;
        }
        if (mod === 1) extra += 1;
        else if (mod === 2) extra += 4;
        else if (mod === 0 && rm === 5) extra += 4;
      }
    }
    if (p + extra > buf.length) return null;
    const modrmOff = p - 1;
    p += extra;
    return { mod, rm, reg: (m >> 3) & 7, m, modrmOff };
  };

  let rel = null, relOff = 0, kind = null, modrm = null;

  if (op >= 0x70 && op <= 0x7f) {
    if (!need(1)) return null;
    rel = buf.readInt8(p); relOff = p; p += 1; kind = 'jcc8';
  } else if (op === 0xeb) {
    if (!need(1)) return null;
    rel = buf.readInt8(p); relOff = p; p += 1; kind = 'jmp8';
  } else if (op === 0xe9) {
    // 66 E9 是 jmp rel16（4 字节总长），漏掉 opsz16 会多读 2 字节 → 边界错位
    if (opsz16) {
      if (!need(2)) return null;
      rel = buf.readInt16LE(p); relOff = p; p += 2; kind = 'jmp32';
    } else {
      if (!need(4)) return null;
      rel = buf.readInt32LE(p); relOff = p; p += 4; kind = 'jmp32';
    }
  } else if (op === 0xe8) {
    if (opsz16) {
      if (!need(2)) return null;
      rel = buf.readInt16LE(p); relOff = p; p += 2; kind = 'call32';
    } else {
      if (!need(4)) return null;
      rel = buf.readInt32LE(p); relOff = p; p += 4; kind = 'call32';
    }
  } else if (op === 0x0f) {
    if (!need(1)) return null;
    const op2 = buf[p]; p++;
    if (op2 >= 0x80 && op2 <= 0x8f) {
      if (!need(4)) return null;
      rel = buf.readInt32LE(p); relOff = p; p += 4; kind = 'jcc32';
    } else if (op2 === 0x77 || op2 === 0xa2 || op2 === 0x05 || op2 === 0x07 ||
               op2 === 0x0b || op2 === 0x31 || op2 === 0x34 || op2 === 0x35 ||
               op2 === 0xa0 || op2 === 0xa8 || op2 === 0x0e || op2 === 0x06) {
      // 这些 0F xx 指令**没有 ModRM 字节**（emms/cpuid/rdtsc/sysenter 等）。
      // 早期一律走 readModRM 会把下一条指令的首字节当 ModRM 吃掉 → 整体错位。
      kind = 'misc0f';
    } else if (op2 >= 0xc8 && op2 <= 0xcf) {
      // bswap reg：无 ModRM
      kind = 'misc0f';
    } else if (op2 === 0x1f) {
      modrm = readModRM(); if (!modrm) return null; kind = 'nop0f';
    } else {
      modrm = readModRM(); if (!modrm) return null; kind = 'other0f';
    }
    // 注意：这里必须回传 rel/relOff。早先返回 { rel: null } 把上面算好的 rel32 丢掉，
    // 后果是 jcc32 的 target 恒为 null → 边界图把 null 当跳转目标入队 → 崩溃；
    // 线性扫描侧还会因 |null| = 0 误判"短跳过"，把 xor + 整条 jnz 一起 nop 掉。
    return { off, len: p - off, op: 0x0f00 | op2, opOff, kind, rel, relOff, modrm };
  } else if (op >= 0x40 && op <= 0x4f) {
    // 32 位模式下 0x40-0x4F 是 inc/dec reg（单字节，无操作数）；
    // 64 位模式下它们已被上面当 REX 前缀消费掉，走不到这里。
    kind = 'incdec';
  } else if (op >= 0x50 && op <= 0x5f) {
    kind = 'pushpop';
  } else if (op === 0x90) { kind = 'nop'; }
  else if (op === 0x98 || op === 0x99 || op === 0x9c || op === 0x9d || op === 0xf4 ||
           op === 0xf5 || op === 0xf8 || op === 0xf9 || op === 0xfa || op === 0xfb ||
           op === 0xfc || op === 0xfd || op === 0xc9 || op === 0xcc || op === 0xce) {
    kind = op === 0xc9 ? 'leave' : (op === 0xcc ? 'int3' : 'simple');
  } else if (op === 0xc3) { kind = 'ret'; }
  else if (op === 0xc2) { if (!need(2)) return null; p += 2; kind = 'retimm'; }
  else if (op >= 0xb0 && op <= 0xb7) { if (!need(1)) return null; p += 1; kind = 'movimm8'; }
  else if (op >= 0xb8 && op <= 0xbf) {
    const n = opsz16 ? 2 : 4;
    if (!need(n)) return null; p += n; kind = 'movimm';
  } else if (op === 0x68) {
    const n = opsz16 ? 2 : 4;
    if (!need(n)) return null; p += n; kind = 'pushimm';
  } else if (op === 0x6a) { if (!need(1)) return null; p += 1; kind = 'pushimm8'; }
  else if (op === 0xcd) { if (!need(1)) return null; p += 1; kind = 'int'; }
  else if (op === 0xe0 || op === 0xe1 || op === 0xe2 || op === 0xe3) {
    if (!need(1)) return null;
    rel = buf.readInt8(p); relOff = p; p += 1; kind = 'loops';
  } else if (op === 0xa8) { if (!need(1)) return null; p += 1; kind = 'test8'; }
  else if (op === 0xa9) { const n = opsz16 ? 2 : 4; if (!need(n)) return null; p += n; kind = 'test32'; }
  else if (op === 0x25 || op === 0x2d || op === 0x35 || op === 0x3d) {
    // and/sub/xor/cmp eax, imm32（无 ModRM 的短格式）。漏掉会让解码返回 null，
    // 把一条 5 字节指令降级成 1 字节 undecodable，后续全部错位。
    const n = opsz16 ? 2 : 4;
    if (!need(n)) return null; p += n; kind = 'aluimm';
  }
  else if (op === 0x04 || op === 0x0c || op === 0x14 || op === 0x1c ||
           op === 0x24 || op === 0x2c || op === 0x34 || op === 0x3c) {
    // al, imm8 形式（add/or/adc/sbb/and/sub/xor/cmp）
    if (!need(1)) return null; p += 1; kind = 'aluimm8';
  }
  else if (op >= 0x91 && op <= 0x97) { kind = 'xchg_self'; }   // xchg eax, reg
  else if (op === 0x60 || op === 0x61) { kind = 'simple'; }     // pusha/popa
  else if (op === 0xc8) { if (!need(3)) return null; p += 3; kind = 'enter'; }
  else if (op === 0xca || op === 0xcb || op === 0xcf) {         // retf / iret
    if (op === 0xca && !need(2)) return null;
    if (op === 0xca) p += 2;
    kind = 'ret';
  }
  else if (op === 0xd4 || op === 0xd5) { if (!need(1)) return null; p += 1; kind = 'simple'; } // aam/aad
  else if (op >= 0xe4 && op <= 0xe7) { if (!need(1)) return null; p += 1; kind = 'simple'; }   // in/out imm8
  else if (op >= 0xec && op <= 0xef) { kind = 'simple'; }                                       // in/out dx
  else if (op >= 0xa4 && op <= 0xa7) { kind = 'simple'; }    // movs/cmps
  else if (op >= 0xaa && op <= 0xaf) { kind = 'simple'; }    // stos/lods/scas
  else if (op >= 0xa0 && op <= 0xa3) { if (!need(4)) return null; p += 4; kind = 'movmoffs'; }
  else if (op === 0x69 || op === 0x6b) {
    modrm = readModRM(); if (!modrm) return null;
    const n = op === 0x69 ? (opsz16 ? 2 : 4) : 1;
    if (!need(n)) return null; p += n; kind = 'imul';
  } else if ([0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,0x10,0x11,0x12,0x13,0x18,0x19,0x1a,0x1b,
              0x20,0x21,0x22,0x23,0x28,0x29,0x2a,0x2b,0x30,0x31,0x32,0x33,0x38,0x39,0x3a,0x3b,
              0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8d,0x8f,0xd0,0xd1,0xd2,0xd3,0xfe,0xff,
              0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,0x62,0x63,0x8c,0x8e].includes(op)) {
    modrm = readModRM(); if (!modrm) return null; kind = 'modrm';
  } else if (op === 0x80 || op === 0x82 || op === 0x83) {
    modrm = readModRM(); if (!modrm) return null;
    if (!need(1)) return null; p += 1; kind = 'aluimm8';
  } else if (op === 0x81) {
    modrm = readModRM(); if (!modrm) return null;
    const n = opsz16 ? 2 : 4;
    if (!need(n)) return null; p += n; kind = 'aluimm';
  } else if (op === 0xc0 || op === 0xc1) {
    modrm = readModRM(); if (!modrm) return null;
    if (!need(1)) return null; p += 1; kind = 'shiftimm';
  } else if (op === 0xc6) {
    modrm = readModRM(); if (!modrm) return null;
    if (!need(1)) return null; p += 1; kind = 'movimm_modrm';
  } else if (op === 0xc7) {
    modrm = readModRM(); if (!modrm) return null;
    const n = opsz16 ? 2 : 4;
    if (!need(n)) return null; p += n; kind = 'movimm_modrm';
  } else if (op === 0xf6 || op === 0xf7) {
    modrm = readModRM(); if (!modrm) return null;
    if (modrm.reg === 0 || modrm.reg === 1) {
      const n = op === 0xf6 ? 1 : (opsz16 ? 2 : 4);
      if (!need(n)) return null; p += n;
    }
    kind = 'grp3';
  } else {
    return null;
  }
  return { off, len: p - off, op, opOff, kind, rel, relOff, modrm };
}

// ───────────────────────── 语义判定工具 ─────────────────────────
function isJcc(d) { return d && (d.kind === 'jcc8' || d.kind === 'jcc32'); }
function isJmp(d) { return d && (d.kind === 'jmp8' || d.kind === 'jmp32'); }
function isRet(d) { return d && (d.kind === 'ret' || d.kind === 'retimm'); }

/** 自清零：xor/sub/and/cmp reg,reg（mod=3 且 reg==rm）→ 结果为 0，ZF=1 */
function isSelfZero(d) {
  if (!d || !d.modrm) return false;
  if (![0x31, 0x29, 0x33, 0x2b, 0x21, 0x85, 0x39, 0x3b].includes(d.op)) return false;
  return d.modrm.mod === 3 && d.modrm.reg === d.modrm.rm;
}

/** 产生确定标志位：自清零 / test r,r / cmp r,reg / clc,stc,cli,sti / cmp|test r,imm */
function isFlagSetter(d) {
  if (!d) return false;
  if (isSelfZero(d)) return true;
  if (d.kind === 'simple' && [0xf8, 0xf9, 0xfa, 0xfb, 0xf5, 0xf4].includes(d.op)) return true;
  if (d.kind === 'test32' || d.kind === 'test8') return true;
  if (d.kind === 'aluimm' || d.kind === 'aluimm8') return true;   // cmp/add/... r,imm（含 cmp）
  if (d.kind === 'modrm' && (d.op === 0x85 || d.op === 0x39 || d.op === 0x3b)) return true;
  return false;
}

function regOfPushPop(d) {
  if (!d || d.kind !== 'pushpop') return null;
  if (d.op >= 0x50 && d.op <= 0x57) return { dir: 'push', reg: d.op - 0x50 };
  if (d.op >= 0x58 && d.op <= 0x5f) return { dir: 'pop', reg: d.op - 0x58 };
  return null;
}

function opName(d) {
  if (!d) return '?';
  if (d.undecodable) return 'db';
  const map = {
    jcc8: 'jcc', jcc32: 'jcc32', jmp8: 'jmp', jmp32: 'jmp', call32: 'call',
    pushpop: d.op >= 0x58 ? 'pop' : 'push', nop: 'nop', nop0f: 'nop0f', ret: 'ret',
    retimm: 'retn', leave: 'leave', int3: 'int3', simple: 'op', modrm: 'op',
    aluimm: 'alu', aluimm8: 'alu', movimm: 'mov', movimm8: 'mov', movimm_modrm: 'mov',
    pushimm: 'push', pushimm8: 'push', test32: 'test', test8: 'test',
    loops: 'loop', grp3: 'grp3', imul: 'imul', shiftimm: 'shift', misc0f: '0f-misc', other0f: '0f',
  };
  return map[d.kind] || d.kind;
}

// ───────────────────────── 主扫描 ─────────────────────────
/**
 * 尝试从 ELF/PE 头部与启动代码推断函数入口（文件偏移）。
 * 这是递归下降能展开的前提——只给 entry 往往只有 _start 那 20 条指令。
 *
 * ELF: entry 处通常是 `_start`，真正逻辑在 `__libc_start_main(main, ...)` 的第一个参数。
 *      典型 x86-32 形态：`push main` 或 `mov [esp], main` 出现在 call __libc_start_main 之前。
 *      做法：从 entry 线性解码最多 60 条，找 `mov reg, imm32` / `push imm32` 且值落在代码区内，
 *      且该值处能解出合法的函数序言（push ebp; mov ebp,esp）→ 视为候选 main。
 * PE:  用 AddressOfEntryPoint；OEP 一般直接是真实入口，无需额外推断。
 *
 * @returns {{entries:number[], reason:string}}
 */
function inferFunctionEntries(buf, opts = {}) {
  const start = Number.isFinite(opts.start) ? opts.start : 0;
  const end = Number.isFinite(opts.end) ? opts.end : buf.length;
  const entries = [];
  const reasons = [];

  const isElf = buf.length > 64 && buf.readUInt32BE(0) === 0x7f454c46;
  const isPE = buf.length > 0x40 && buf[0] === 0x4d && buf[1] === 0x5a;

  const looksLikePrologue = (off) => {
    const d1 = decodeInsn(buf, off);
    if (!d1 || d1.undecodable) return false;
    // push ebp (0x55) / push rbp (0x55) 或 sub esp,imm 开头
    if (d1.op === 0x55) {
      const d2 = decodeInsn(buf, off + d1.len);
      if (d2 && d2.op === 0x89 && d2.modrm && d2.modrm.mod === 3) return true;   // mov ebp, esp
      return true;
    }
    if (d1.op === 0x53 || d1.op === 0x56 || d1.op === 0x57) return true;         // push ebx/esi/edi
    if (d1.op === 0x83 && d1.modrm && d1.modrm.reg === 5) return true;           // sub esp, imm
    return false;
  };

  // ELF：从 entry 起找 `__libc_start_main` 的首参
  let entryVa = null, textOff = null, textVa = null;
  if (isElf) {
    const is32 = buf[4] === 1;
    entryVa = is32 ? buf.readUInt32LE(24) : Number(buf.readBigUInt64LE(24));
    const phoff = is32 ? buf.readUInt32LE(28) : Number(buf.readBigUInt64LE(32));
    const phentsize = is32 ? buf.readUInt16LE(42) : buf.readUInt16LE(54);
    const phnum = is32 ? buf.readUInt16LE(44) : buf.readUInt16LE(56);
    // 找 PT_LOAD 中含 entry 的段，算出 vaddr→offset 差
    for (let k = 0; k < phnum; k++) {
      const o = phoff + k * phentsize;
      const type = is32 ? buf.readUInt32LE(o) : buf.readUInt32LE(o);
      if (type !== 1) continue;
      const off = is32 ? buf.readUInt32LE(o + 4) : Number(buf.readBigUInt64LE(o + 8));
      const vaddr = is32 ? buf.readUInt32LE(o + 8) : Number(buf.readBigUInt64LE(o + 16));
      const filesz = is32 ? buf.readUInt32LE(o + 16) : Number(buf.readBigUInt64LE(o + 32));
      if (entryVa >= vaddr && entryVa < vaddr + filesz) {
        textOff = entryVa - vaddr + off;
        textVa = vaddr;
        break;
      }
    }
    if (textOff !== null && textOff >= 0 && textOff < buf.length) {
      entries.push(textOff);
      reasons.push(`ELF entry 0x${entryVa.toString(16)} → 文件偏移 0x${textOff.toString(16)}`);
      // ── 找 __libc_start_main 的第一个参数（main）──
      // x86 cdecl：`__libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)`
      // 参数从右向左 push，所以**最早 push 的就是 main**。
      // 实测形态（PIE, -O2）：lea eax,[ebx+off]; push eax ... call __libc_start_main@plt
      const delta = textOff - entryVa;    // 文件偏移 = 虚拟地址 + delta（本段 vaddr=0 时为 0）
      let p = textOff, n = 0;
      const pushes = [];                  // 记录 push 序列（值或"待定"）
      while (p < buf.length && n++ < 80) {
        const d = decodeInsn(buf, p);
        if (!d) break;
        if (d.kind === 'pushimm') {
          pushes.push(buf.readInt32LE(d.off + 1));
        } else if (d.kind === 'pushpop' && d.op >= 0x50 && d.op <= 0x57) {
          const reg = d.op - 0x50;        // push eax(0)/ecx(1)/edx(2)/ebx(3)
          // 往前回溯找该寄存器的 lea / mov imm 赋值
          let val = null;
          for (let k = Math.max(0, p - 40); k < p; ) {
            const pd = decodeInsn(buf, k);
            if (!pd) { k++; continue; }
            // mov reg, imm32（0xB8+reg）
            if (pd.kind === 'movimm' && pd.op === 0xb8 + reg) val = buf.readInt32LE(pd.off + 1) >>> 0;
            // lea reg, [ebx+disp32] / lea reg, [ebp+disp32]：opcode 8D
            if (pd.op === 0x8d && pd.modrm && pd.modrm.mod === 2 && pd.modrm.reg === reg) {
              const dispOff = pd.modrm.modrmOff + 1;
              if (dispOff + 4 <= buf.length) {
                const disp = buf.readInt32LE(dispOff);
                // ebx 在 PIC 里是 GOT 基址；无法静态求值 → 记为 null（不猜）
                val = (pd.modrm.rm === 3) ? null : null;
              }
            }
            k += pd.len;
          }
          pushes.push(val);
        } else if (d.kind === 'call32') {
          // 遇到 call：若是 __libc_start_main（通过 PLT 间接调用的也在附近），取最早 push
          const first = pushes.find(v => typeof v === 'number' && v > 0);
          if (first !== undefined) {
            const fileOff = first + delta;
            if (fileOff >= start && fileOff < end && fileOff !== textOff) {
              // 校验：该处能解出合法指令（不强求 push ebp，因为 -O2 可能没有帧指针）
              const chk = decodeInsn(buf, fileOff);
              if (chk && !chk.undecodable) {
                entries.push(fileOff);
                reasons.push(`__libc_start_main 首参 0x${first.toString(16)} → 文件偏移 0x${fileOff.toString(16)}（可解码校验通过）`);
                break;
              }
            }
          }
          pushes.length = 0;            // call 之后的 push 属于下一个调用
        } else if (d.kind === 'jmp8' || d.kind === 'jmp32' || d.kind === 'ret') {
          break;
        }
        p += d.len;
      }
    }
  } else if (isPE) {
    try {
      const peOff = buf.readUInt32LE(0x3c);
      const optOff = peOff + 24;
      const magic = buf.readUInt16LE(optOff);
      const aoe = magic === 0x20b ? buf.readUInt32LE(optOff + 16) : buf.readUInt32LE(optOff + 16);
      const numSections = buf.readUInt16LE(peOff + 6);
      const sizeOpt = buf.readUInt16LE(peOff + 20);
      const secOff = optOff + sizeOpt;
      const imageBase = magic === 0x20b ? Number(buf.readBigUInt64LE(optOff + 24)) : buf.readUInt32LE(optOff + 28);
      const va = imageBase + aoe;
      for (let k = 0; k < numSections; k++) {
        const s = secOff + k * 40;
        const secVa = buf.readUInt32LE(s + 12);
        const rawSize = buf.readUInt32LE(s + 16);
        const rawPtr = buf.readUInt32LE(s + 20);
        if (va >= imageBase + secVa && va < imageBase + secVa + rawSize) {
          const off = rawPtr + (va - imageBase - secVa);
          entries.push(off);
          reasons.push(`PE AddressOfEntryPoint 0x${va.toString(16)} → 文件偏移 0x${off.toString(16)}`);
          break;
        }
      }
    } catch (e) { /* 头部异常忽略 */ }
  }

  return { entries: [...new Set(entries)], reason: reasons.join('; ') || '未识别到入口，回退到代码区起点' };
}

/**
 * 定位"第一个解码偏移点"——花指令造成解码错位时的真正修复切入点。
 *
 * 为什么需要（实测 Matr1x）：
 *   线性解码后统计出 44% 的跳转目标不在边界上（239/542）。这些**不是 239 处花指令**，
 *   而是"从某处开始整体偏了"的症状。找到第一个偏移点，把它之前的垃圾清掉，
 *   后面就会自然对齐——这比逐个 nop 掉"非边界目标"有效得多。
 *
 * 做法：
 *   1. 线性解码全部，得到 boundary 集合
 *   2. 沿控制流（从入口起）走，记录每次"跳转目标 ∉ boundary"或"目标处解码结果与
 *      线性解码在边界处的结果不同"的位置
 *   3. 取最早的那个位置，报告它前后的字节形态（是不是 xor/test 后接短 jcc、
 *      是不是 push/pop 包裹），作为修补建议
 *
 * @returns {{ok, firstDivergence, candidates, note}}
 */
function findFirstDivergence(buf, opts = {}) {
  const start = Number.isFinite(opts.start) ? opts.start : 0;
  const end = Number.isFinite(opts.end) ? opts.end : buf.length;
  if (end - start < 8) return { ok: false, error: '代码区过小' };

  // 线性解码
  const lin = [];
  let q = start;
  while (q < end) {
    const d = decodeInsn(buf, q);
    if (!d || d.len <= 0) { lin.push({ off: q, len: 1, undecodable: true }); q++; }
    else { lin.push(d); q += d.len; }
  }
  const linBoundary = new Set(lin.filter(i => !i.undecodable).map(i => i.off));

  // 从所有已知"跳转目标"里找最早的非边界目标
  const bad = [];
  for (const d of lin) {
    if (d.undecodable || d.rel === null || d.rel === undefined) continue;
    if (!(d.kind === 'jcc8' || d.kind === 'jcc32' || d.kind === 'jmp8' || d.kind === 'jmp32' || d.kind === 'call32')) continue;
    const t = d.off + d.len + d.rel;
    if (t < start || t >= end) continue;
    if (linBoundary.has(t)) continue;
    bad.push({ from: d.off, target: t, kind: d.kind, rel: d.rel });
  }
  bad.sort((a, b) => a.from - b.from);

  // 对最早几个"非边界目标"做局部诊断：它前面几条指令是什么？目标处解出什么？
  const diag = bad.slice(0, 8).map(b => {
    // 目标处强制解码
    const atTarget = decodeInsn(buf, b.target);
    // 目标前 16 字节的形态
    const ctxInsns = [];
    for (let k = Math.max(start, b.target - 24); k < b.target;) {
      const d = decodeInsn(buf, k);
      if (!d) { k++; continue; }
      ctxInsns.push({ off: k, kind: d.kind, op: d.op, len: d.len, text: opName(d) });
      k += d.len;
    }
    return {
      jumpFrom: b.from,
      jumpKind: b.kind,
      rel: b.rel,
      target: b.target,
      decodesAtTarget: atTarget ? { kind: atTarget.kind, op: atTarget.op, len: atTarget.len, text: opName(atTarget) } : null,
      contextBeforeTarget: ctxInsns.slice(-6),
    };
  });

  const first = diag[0] || null;
  return {
    ok: true,
    linearInsnCount: lin.length,
    badTargetCount: bad.length,
    firstDivergence: first,
    diagnostics: diag,
    note: bad.length
      ? `线性解码有 ${bad.length} 处跳转目标不在指令边界上。**这些不是 ${bad.length} 处花指令**，` +
        `而是"从最早那一处起整体偏移"的症状。修复切入点是最早的偏移（0x${first.jumpKind}@0x${first.jumpFrom.toString(16)} → 0x${first.target.toString(16)}）：` +
        `确认该目标处是否本应为指令起点；若是，则它之前的字节里有插入了垃圾。`
      : '未发现跳转目标落在非指令边界上的情况（线性解码自洽）。',
  };
}

/**
 * 从入口出发递归下降扫描花指令（通解）。
 * 线性扫描一旦偏 1 字节后续全错，所以必须走控制流。
 */
function scanJunkRecursive(buf, opts = {}) {
  const start = Number.isFinite(opts.start) ? opts.start : 0;
  const end = Number.isFinite(opts.end) ? opts.end : buf.length;
  if (start < 0 || end > buf.length || end - start < 4) {
    return { ok: false, error: `代码区范围非法: [${start}, ${end})，文件长 ${buf.length}` };
  }
  const maxBlocks = Number(opts.maxBlocks) || 20000;

  // 入口集合（文件偏移）：优先用调用方给的；否则从文件头推断
  let entries = Array.isArray(opts.entries) ? opts.entries.filter(Number.isFinite) : [];
  let entryReason = '';
  if (!entries.length) {
    const inf = inferFunctionEntries(buf, { start, end });
    entries = inf.entries;
    entryReason = inf.reason;
  }
  if (!entries.length) { entries = [start]; entryReason = '无入口信息，回退代码区起点'; }
  entries = [...new Set(entries)].filter(o => o >= start && o < end);

  // 递归下降：worklist 展开
  const decoded = new Map();      // off -> insn
  const queue = entries.slice();
  const visitedBlock = new Set();
  let blocks = 0;
  // 记录"强制重对齐"的位置（即从非边界地址开始解码）——这些就是花指令导致的歧义点
  const realigned = [];

  while (queue.length && blocks < maxBlocks) {
    const blockStart = queue.shift();
    if (blockStart < start || blockStart >= end) continue;
    if (visitedBlock.has(blockStart)) continue;
    visitedBlock.add(blockStart);
    blocks++;

    let p = blockStart;
    let guard = 0;
    while (p >= start && p < end && guard++ < 5000) {
      if (decoded.has(p)) break;                    // 已解码过（汇合）
      const d = decodeInsn(buf, p);
      if (!d || d.len <= 0 || p + d.len > end) {
        // 解码失败：记录为 1 字节不可解码，继续（不阻塞后续）
        decoded.set(p, { off: p, len: 1, undecodable: true, kind: 'unk' });
        p += 1;
        continue;
      }
      if (p !== blockStart && !isBlockBoundaryStart(p, decoded)) {
        // 从非边界位置开始解码 → 说明上一处跳转目标落在指令中间（花指令症状）
        realigned.push(p);
      }
      decoded.set(p, d);
      p += d.len;

      // 控制流后继
      if (d.kind === 'jcc8' || d.kind === 'jcc32') {
        const t = d.off + d.len + d.rel;
        if (t >= start && t < end) queue.push(t);
        // fallthrough 继续
      } else if (d.kind === 'jmp8' || d.kind === 'jmp32') {
        const t = d.off + d.len + d.rel;
        if (t >= start && t < end) queue.push(t);
        break;                                       // 无条件跳转：块结束
      } else if (d.kind === 'ret' || d.kind === 'retimm') {
        break;
      } else if (d.kind === 'call32' && d.rel !== 0) {
        const t = d.off + d.len + d.rel;
        if (t >= start && t < end) queue.push(t);    // call 目标也是入口
      }
    }
  }

  function isBlockBoundaryStart(off, map) {
    // 若上一字节到 off 之间没有已解码指令，则视为块起点（正常）
    for (const [o, d] of map) {
      if (o < off && o + d.len === off) return false;
    }
    return true;
  }

  // 转化为按地址排序的数组
  const insns = [...decoded.values()].sort((a, b) => a.off - b.off);
  const boundary = new Set(insns.filter(i => !i.undecodable).map(i => i.off));

  // ── 识别：不可达孤岛（在代码区内、但从未被控制流触及的区间）──
  // 这些区间最可能是花指令插入的垃圾（也可能含真实但未被静态引用的函数——需人工确认）
  const unreached = [];
  let cursor = start;
  for (const insn of insns) {
    if (insn.off > cursor) unreached.push({ from: cursor, to: insn.off });
    cursor = Math.max(cursor, insn.off + insn.len);
  }
  if (cursor < end) unreached.push({ from: cursor, to: end });

  // ── 识别：单个不可达区间内的花指令子结构（自清零+短跳 / 互补对）──
  const candidates = [];
  const stats = {
    blocks,
    insnCount: insns.length,
    undecodable: insns.filter(i => i.undecodable).length,
    realignedCount: realigned.length,
    unreachedRegions: unreached.length,
    unreachedBytes: unreached.reduce((s, r) => s + (r.to - r.from), 0),
    selfZeroFalseJump: 0,
    complementaryPair: 0,
    picCallPop: 0,
    total: 0,
  };

  // 在已解码指令流中找"确定标志位 + 短跳转"（不论是否可达，先报告）
  for (let i = 0; i < insns.length; i++) {
    const d = insns[i];
    if (d.undecodable || !isJcc(d)) continue;
    let flagSetter = null;
    for (let k = i - 1; k >= Math.max(0, i - 4); k--) {
      const pv = insns[k];
      if (!pv || pv.undecodable) break;
      if (pv.off + pv.len !== d.off && k === i - 1) { /* 不连续也算 */ }
      if (isFlagSetter(pv)) { flagSetter = pv; break; }
      if (isJmp(pv) || isRet(pv)) break;
    }
    const absRel = Math.abs(d.rel);
    const taken = d.off + d.len + d.rel;
    const targetAmbiguous = taken >= start && taken < end && !boundary.has(taken);
    if (flagSetter && (absRel <= 2 || targetAmbiguous)) {
      stats.selfZeroFalseJump++;
      const from = absRel <= 2 ? d.off + d.len : taken;
      const to = absRel <= 2 ? taken : Math.min(end, taken + 16);
      candidates.push({
        off: d.off,
        type: absRel <= 2 ? 'flagset_short_skip' : 'flagset_ambiguous_target',
        confidence: absRel <= 2 ? 'high' : 'medium',
        evidence: `${opName(flagSetter)}@0x${flagSetter.off.toString(16)} 确定标志位 → ${opName(d)}@0x${d.off.toString(16)}(rel=${d.rel}) 条件恒定；` +
          (absRel <= 2 ? `跳过的 ${absRel} 字节是垃圾` : `目标 0x${taken.toString(16)} 不在指令边界（解码错位证据）`),
        action: 'nop',
        nopRange: absRel <= 2 ? { from, to } : null,
      });
    }
  }

  stats.total = candidates.length;

  // 排除项统计：call $+5; pop reg（PIC 取址，不是花指令）
  for (let i = 0; i < insns.length - 1; i++) {
    const d = insns[i], n = insns[i + 1];
    if (d.kind === 'call32' && d.rel === 0) {
      const pp = regOfPushPop(n);
      if (pp && pp.dir === 'pop') stats.picCallPop++;
    }
  }

  return {
    ok: true,
    mode: 'recursive',
    codeRange: { start, end, size: end - start },
    entries,
    insnCount: insns.length,
    candidates: candidates.slice(0, MAX_REPORT),
    unreachedRegions: unreached.filter(r => r.to - r.from >= 2).slice(0, 60),
    stats,
    notes: [
      `递归下降从 ${entries.length} 个入口展开 ${blocks} 个基本块，解码 ${insns.length} 条指令。`,
      `不可达区间 ${unreached.length} 段（共 ${stats.unreachedBytes} 字节）：这些位置从未被控制流触及，` +
        `最可能是花指令垃圾，但也可能是未被静态引用的真实函数——**需人工/动态确认后再 nop**。`,
      realigned.length ? `发现 ${realigned.length} 处"从非边界地址强制解码"（花指令造成的边界歧义）。` : '',
    ].filter(Boolean),
  };
}

/**
 * 线性扫描式花指令扫描（兜底/对照用）。
 * ⚠ 已知缺陷：线性扫描一旦在某处偏 1 字节，后续所有指令起点都是错的，
 *   此时"跳转目标是否落在边界"的统计全是噪声（实测 Matr1x：报 281 候选、
 *   patch 后不可解码反而 4→7）。**优先用 scanJunkRecursive**；
 *   本函数仅在没有入口信息时做粗筛。
 */
function scanJunk(buf, opts = {}) {
  const start = Number.isFinite(opts.start) ? opts.start : 0;
  const end = Number.isFinite(opts.end) ? opts.end : buf.length;
  if (start < 0 || end > buf.length || end - start < 16) {
    return { ok: false, error: `代码区范围非法: [${start}, ${end})，文件长 ${buf.length}` };
  }

  // ── 线性解码 ──
  const insns = [];
  let p = start;
  while (p < end) {
    const d = decodeInsn(buf, p);
    if (!d || d.len <= 0 || p + d.len > end) {
      insns.push({ off: p, len: 1, undecodable: true, kind: 'unk' });
      p += 1;
    } else {
      insns.push(d);
      p += d.len;
    }
  }
  const boundary = new Set(insns.map(i => i.off));       // 合法指令起点
  const idxOf = new Map(insns.map((i, k) => [i.off, k]));

  // ── L2 基础：找出所有"跳转目标不落在指令边界上"的位置（边界歧义证据）──
  // 这类目标说明：从线性解码的角度，该地址不知道是什么；花指令正是靠制造这种歧义生效。
  const badTargets = new Map();   // target -> [跳转指令的 off...]
  for (const d of insns) {
    if (d.undecodable || d.rel === null || d.rel === undefined) continue;
    if (!(isJcc(d) || isJmp(d))) continue;
    const t = d.off + d.len + d.rel;
    if (t < start || t >= end) continue;
    if (boundary.has(t)) continue;
    if (!badTargets.has(t)) badTargets.set(t, []);
    badTargets.get(t).push(d.off);
  }

  const candidates = [];
  const stats = {
    insnCount: insns.length,
    undecodable: insns.filter(i => i.undecodable).length,
    unreachableBranch: 0,       // L1：可证明不可达的分支
    boundaryAmbiguity: 0,       // L2：跳转目标落在非指令边界
    selfZeroFalseJump: 0,       // L1(a)：自清零 + 永假跳转（单条花指令）
    complementaryPair: 0,       // L1(a')：互补跳转对
    pushPopWrapped: 0,          // L3：push/pop 包裹
    callRetTrampoline: 0,       // L1：call+ret 跳板
    picCallPop: 0,              // 排除项：PIC 取址
    total: 0,
  };
  const push = (c) => candidates.push(c);

  for (let i = 0; i < insns.length; i++) {
    const d = insns[i];
    if (d.undecodable || !isJcc(d)) continue;

    const fallThrough = d.off + d.len;
    const taken = fallThrough + d.rel;
    const relAbs = Math.abs(d.rel);

    // ── L1(a) 自清零 / 确定标志位 + 永假跳转 ──
    // 前置指令使条件恒定 → 其中一侧永不执行；若该侧极短（≤2 字节）或跳向非边界地址，
    // 就是"用单字节垃圾制造解码歧义"的经典形态。
    let flagSetter = null;
    for (let k = i - 1; k >= Math.max(0, i - 4); k--) {
      if (isFlagSetter(insns[k])) { flagSetter = insns[k]; break; }
      if (isJmp(insns[k]) || isRet(insns[k]) || insns[k].undecodable) break;
    }
    const shortSkip = relAbs <= 2;
    const targetIsAmbiguous = !boundary.has(taken) && taken >= start && taken < end;
    if (flagSetter && (shortSkip || targetIsAmbiguous)) {
      stats.selfZeroFalseJump++;
      if (targetIsAmbiguous) stats.boundaryAmbiguity++;
      // nop 范围必须覆盖"制造污染的完整语义单元"：
      //   确定标志位指令 + jcc 本身 + 被跳过的垃圾字节
      // 起点取 flagSetter（如 xor ecx,ecx），这样后续从正确边界重新对齐。
      // （实测教训：只 nop 被跳过的 1 字节不起作用——污染源是前面的 xor;jnz 组合。）
      const from = flagSetter.off;
      const to = shortSkip ? taken : Math.min(end, taken + 16);
      push({
        off: d.off,
        type: shortSkip ? 'flagset_short_skip' : 'flagset_ambiguous_target',
        confidence: shortSkip ? 'high' : 'medium',
        evidence: `确定标志位 ${opName(flagSetter)}@0x${flagSetter.off.toString(16)} → ${opName(d)}@0x${d.off.toString(16)}(rel=${d.rel}) 条件恒定；` +
          (shortSkip
            ? `跳过的 ${relAbs} 字节是垃圾；nop 整段 [0x${from.toString(16)},0x${to.toString(16)}) 让后续从正确边界重新对齐`
            : `转目标 0x${taken.toString(16)} 不落在任何指令边界上（边界歧义 = 解码错位证据）`),
        action: 'nop',
        nopRange: to > from ? { from, to } : null,
      });
      continue;
    }

    // ── L1(a') 互补跳转对：相邻 jcc，条件互斥，一侧跳进垃圾、一侧跳过垃圾 ──
    for (let gap = 0; gap <= 2 && i + 1 < insns.length; gap++) {
      const j = idxOf.get(d.off + d.len + gap);
      if (j === undefined) continue;
      const b = insns[j];
      if (b.undecodable || !isJcc(b)) continue;
      if ((d.op & 0xfe) !== (b.op & 0xfe)) continue;      // 同族
      if ((d.op & 1) === (b.op & 1)) continue;            // 条件互斥
      const tB = b.off + b.len + b.rel;
      const okPair = (taken === tB) || (taken >= b.off && taken < tB && tB > b.off + b.len);
      if (!okPair) continue;

      stats.complementaryPair++;
      let guard = null;
      for (let k = i - 1; k >= Math.max(0, i - 6); k--) {
        const pp = regOfPushPop(insns[k]);
        if (pp && pp.dir === 'push') { guard = insns[k]; break; }
        if (isJmp(insns[k]) || isRet(insns[k])) break;
      }
      if (guard) stats.pushPopWrapped++;
      const from = flagSetter ? flagSetter.off + flagSetter.len : d.off;
      const to = Math.max(taken, tB);
      push({
        off: d.off,
        type: 'complementary_pair',
        confidence: flagSetter ? 'high' : 'medium',
        evidence: `互补跳转 ${opName(d)}@0x${d.off.toString(16)}(rel=${d.rel}) + ${opName(b)}@0x${b.off.toString(16)}(rel=${b.rel})：` +
          `条件互斥必跳其一，一侧落进垃圾区、另一侧跳过它` +
          (flagSetter ? `；前序标志位 ${opName(flagSetter)}@0x${flagSetter.off.toString(16)}` : '') +
          (guard ? `；push/pop 边界 ${opName(guard)}@0x${guard.off.toString(16)}` : ''),
        action: 'nop',
        nopRange: { from, to },
      });
      break;
    }
  }

  // ── L1(b) call + 改栈上返回地址 + ret 跳板 ──
  for (let i = 0; i < insns.length; i++) {
    const d = insns[i];
    if (d.undecodable || d.kind !== 'call32' || d.rel === 0) continue;
    let espAdjust = null, retInsn = null;
    for (let k = i + 1; k < Math.min(insns.length, i + 7); k++) {
      const x = insns[k];
      if (x.undecodable) break;
      // add/sub dword ptr [esp], imm：op 0x81/0x83 且 reg ∈ {0,5}
      if ((x.op === 0x81 || x.op === 0x83) && x.modrm && (x.modrm.reg === 0 || x.modrm.reg === 5)) espAdjust = x;
      if (isRet(x) && espAdjust) { retInsn = x; break; }
      if (isJmp(x)) break;
    }
    if (retInsn) {
      stats.callRetTrampoline++;
      push({
        off: d.off,
        type: 'call_ret_trampoline',
        confidence: 'high',
        evidence: `call@0x${d.off.toString(16)} → ${opName(espAdjust)}@0x${espAdjust.off.toString(16)}（改栈上返回地址）→ ret@0x${retInsn.off.toString(16)}：` +
          `**动态跳板**，静态看不到真实后继；nop 需谨慎（建议配合动态 tracing 确认）`,
        action: 'inspect',
        nopRange: null,
      });
    }
  }

  // ── 排除项：call next; pop reg（PIC 取址，不是花指令）──
  for (let i = 0; i < insns.length - 1; i++) {
    const d = insns[i], n = insns[i + 1];
    if (d.kind === 'call32' && d.rel === 0) {
      const pp = regOfPushPop(n);
      if (pp && pp.dir === 'pop') stats.picCallPop++;
    }
  }

  stats.total = candidates.length;
  const notes = [];
  if (stats.insnCount && stats.undecodable / stats.insnCount > 0.3) {
    notes.push(`不可解码字节占 ${(stats.undecodable / stats.insnCount * 100).toFixed(1)}%：代码区范围可能有误，` +
      `或数据/代码混排。先确认节表边界（PE 用节 rawPtr/rawSize，ELF 用 sh_offset/sh_size）。`);
  }
  if (stats.boundaryAmbiguity > 0) {
    notes.push(`发现 ${stats.boundaryAmbiguity} 处"跳转目标落在非指令边界"——这是**解码错位的直接证据**，` +
      `说明从某个更早的位置起线性扫描已偏；修补后应重新从函数入口反汇编，而不只是 nop 掉候选点。`);
  }
  if (stats.picCallPop > 0) {
    notes.push(`${stats.picCallPop} 处 "call $+5; pop reg" 是 PIC 取址惯用法，**不是花指令**，已排除。`);
  }
  notes.push('判据说明（通用，不针对具体题目）：L1 跳转可达性（确定标志位/短跳过/目标非边界）' +
    '+ L2 边界歧义（跳转目标不落在指令边界）+ L3 段边界（push/pop 栈平衡）。' +
    '**不要**仅凭"xor reg,reg 后面有 jcc"就判花指令——必须有条件恒定或边界歧义证据。');

  return {
    ok: true,
    codeRange: { start, end, size: end - start },
    insnCount: insns.length,
    candidates: candidates.slice(0, MAX_REPORT),
    stats,
    notes,
    ambiguousTargets: [...badTargets.entries()].slice(0, 40).map(([t, from]) => ({ target: t, fromOffsets: from })),
  };
}

// ───────────────────────── 修补 ─────────────────────────
/**
 * 把候选的 nopRange 填 0x90，返回新 Buffer。原文件不动。
 * 只处理带 nopRange 且置信度达标的候选。
 */
function patchJunk(buf, candidates, opts = {}) {
  const out = Buffer.from(buf);
  const applied = [], skipped = [];
  const rank = { high: 3, medium: 2, low: 1 };
  const minRank = rank[opts.minConfidence || 'high'] || 3;
  const ranges = [];

  for (const c of candidates || []) {
    if (!c) continue;
    if (!c.nopRange) { skipped.push({ off: c.off, type: c.type, why: '无安全 nop 范围（需人工/动态确认）' }); continue; }
    if (rank[c.confidence] < minRank) { skipped.push({ off: c.off, type: c.type, why: `置信度 ${c.confidence} 低于阈值` }); continue; }
    const { from, to } = c.nopRange;
    if (!(from >= 0 && to <= out.length && to > from)) { skipped.push({ off: c.off, type: c.type, why: '范围越界' }); continue; }
    if (to - from > 64) { skipped.push({ off: c.off, type: c.type, why: `范围过大（${to - from} 字节），拒绝自动修补` }); continue; }
    // 重叠保护：与已应用范围冲突则跳过
    if (ranges.some(r => from < r.to && to > r.from)) { skipped.push({ off: c.off, type: c.type, why: '与已修补范围重叠' }); continue; }
    ranges.push({ from, to });
    for (let i = from; i < to; i++) out[i] = NOP;
    applied.push({ off: from, to, len: to - from, type: c.type });
  }
  return { buffer: out, applied, skipped };
}

module.exports = { scanJunk, scanJunkRecursive, findFirstDivergence, patchJunk, decodeInsn };
