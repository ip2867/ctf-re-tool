'use strict';
// 可逆循环逆推器（reverse-solve for invertible loops）
//
// ── 为什么需要（Obfuscating Macros II 实测）──────────────────────────
// 这类题的校验主体是一个 N 轮循环，循环体只由几种**双射**算子组成：
//     Y ^= (~X if X 偶 else X)      ; 条件异或
//     X = ~X                        ; 取反
//     128 位循环左移 1 位            ; 交叉回填
//     t=Y; Y=Y+X; X=t               ; 交换后相加
// 每一步都可逆 ⇒ 从目标值出发**逆序**跑一遍就还原输入，几毫秒。
//
// 但手写逆函数极易出错：本次实测中，`swap_add` 的逆向顺序、
// `rot` 的位从哪来，都是我靠"正逆互逆自检"才确认的。
// 而如果只写逆函数不写自检，错了也看不出来（回代会失败，却不知道错在哪一步）。
//
// ── 本模块做什么 ───────────────────────────────────────────────────
// 把循环体声明成**算子列表**，生成一段自包含脚本，内含：
//   ① fwd()  正向执行
//   ② inv()  自动逆序 + 每条替换成逆算子
//   ③ 自检：随机正逆互逆（40+40 组）——不依赖目标值，先证明实现是对的
//   ④ 反解目标值
//   ⑤ 回代验证：fwd(解) 必须精确命中目标
//   ⑥ 打包成字节（可选小端）+ hex / ascii 输出
//
// 关键设计：**算子表在 JS 侧展开**，生成的 Python 里是已经排好序的显式语句。
// 这样 Python 侧没有解释器开销，也不会有"DSL 解析出错"这种隐蔽 bug。
//
// 只生成文本，不执行 → 可单测。

const WIDTHS = { 8: 8, 16: 16, 32: 32, 64: 64 };

// 可逆算子表。inverse 是该算子自己的逆。
//   params: 该算子接受哪些字段
//   emit(side, ...) → 生成 Python 语句（side = 'fwd' | 'inv'）
const OPS = {
  // dst ^= src          （XOR 自逆）
  xor: {
    need: ['dst', 'src'],
    emit: (o) => `${o.dst} ^= ${o.src}`,
    invOf: 'xor',
  },
  // dst ^= 常数
  xor_const: {
    need: ['dst', 'value'],
    emit: (o) => `${o.dst} ^= ${lit(o.value)}`,
    invOf: 'xor_const',
  },
  // dst ^= (~src if src 为偶 else src) —— 条件异或，自逆（要求 src 未被改动）
  xor_cond_not: {
    need: ['dst', 'src'],
    emit: (o) => `${o.dst} ^= ((~${o.src}) & MASK) if ((${o.src} & 1) == 0) else ${o.src}`,
    invOf: 'xor_cond_not',
  },
  // dst ^= (~dst if ...) 自反形态少见，不提供——避免和上面混淆
  // reg = ~reg           （自逆）
  not: {
    need: ['reg'],
    emit: (o) => `${o.reg} = (~${o.reg}) & MASK`,
    invOf: 'not',
  },
  // 单寄存器循环左移 1（可逆：右移 1，最低位回填最高位）
  rotl_single: {
    need: ['reg'],
    emit: (o) => `${o.reg} = ((${o.reg} << 1) & MASK) | (1 if (${o.reg} & MSB) else 0)`,
    invOf: 'rotr_single',
  },
  rotr_single: {
    need: ['reg'],
    emit: (o) => `${o.reg} = ((${o.reg} >> 1) | (MSB if (${o.reg} & 1) else 0))`,
    invOf: 'rotl_single',
  },
  // 两寄存器交叉循环左移 1（把 (a,b) 当 width*2 位的整体）
  rotl_cross: {
    need: ['hi', 'lo'],
    emit: (o) => [
      `_a_hi = ${o.hi} & MSB`,
      `_a_lo = ${o.lo} & MSB`,
      `${o.hi} = ((${o.hi} << 1) & MASK) | (1 if _a_lo else 0)`,
      `${o.lo} = ((${o.lo} << 1) & MASK) | (1 if _a_hi else 0)`,
    ].join('; '),
    invOf: 'rotr_cross',
  },
  rotr_cross: {
    need: ['hi', 'lo'],
    emit: (o) => [
      `_b_hi = ${o.hi} & 1`,
      `_b_lo = ${o.lo} & 1`,
      `${o.hi} = (${o.hi} >> 1) | (MSB if _b_lo else 0)`,
      `${o.lo} = (${o.lo} >> 1) | (MSB if _b_hi else 0)`,
    ].join('; '),
    invOf: 'rotl_cross',
  },
  // dst += src
  add: {
    need: ['dst', 'src'],
    emit: (o) => `${o.dst} = (${o.dst} + ${o.src}) & MASK`,
    invOf: 'sub',
  },
  // dst -= src
  sub: {
    need: ['dst', 'src'],
    emit: (o) => `${o.dst} = (${o.dst} - ${o.src}) & MASK`,
    invOf: 'add',
  },
  // 交换 a, b（自逆）
  swap: {
    need: ['a', 'b'],
    emit: (o) => `${o.a}, ${o.b} = ${o.b}, ${o.a}`,
    invOf: 'swap',
  },
  // t=a; a=b; b=b+t   （逆向：a = b-a; b = a）—— 实测最容易写错的一条
  swap_add: {
    need: ['a', 'b'],
    emit: (o) => `${o.a}, ${o.b} = ${o.b}, (${o.b} + ${o.a}) & MASK`,
    invOf: 'unswap_add',
  },
  unswap_add: {
    need: ['a', 'b'],
    emit: (o) => `${o.a}, ${o.b} = (${o.b} - ${o.a}) & MASK, ${o.a}`,
    invOf: 'swap_add',
  },
  // dst *= 常量（仅奇数可逆，逆元由脚本内 pow 求）
  mul_const: {
    need: ['dst', 'value'],
    emit: (o) => `${o.dst} = (${o.dst} * ${lit(o.value)}) & MASK`,
    invOf: 'mul_inv',
  },
  mul_inv: {
    need: ['dst', 'value'],
    emit: (o) => `${o.dst} = (${o.dst} * pow(${lit(o.value)}, -1, MOD)) & MASK`,
    invOf: 'mul_const',
  },
};

function lit(v) {
  if (typeof v === 'number') {
    if (!Number.isFinite(v) || v < 0) return String(v);
    return v >= 0 ? '0x' + Math.trunc(v).toString(16) : String(v);
  }
  return String(v);
}

/**
 * 生成逆推脚本。
 *
 * input:
 *   ops      循环体算子列表（按正向执行顺序），如
 *            [{op:"xor_cond_not", dst:"Y", src:"X"}, {op:"not", reg:"X"}, ...]
 *   rounds   循环轮数（默认 1）
 *   target   目标值，按 regs 顺序（如 ["0xA1E8895EB916B732", "0x50A2DCC51ED6C4A2"]）
 *   regs     寄存器名（默认 ["X","Y"]）
 *   init     已知初值（可选，给出则跳过反解，只做回代）
 *   width    位宽（默认 64）
 *   pack     是否把结果打包成字节（默认 true）
 *   endian   'little' | 'big'（默认 little）
 */
function buildRevSolveScript(input) {
  const i = input || {};
  const ops = Array.isArray(i.ops) ? i.ops : [];
  if (!ops.length) {
    return {
      error: 'rev_solve 需要 ops（循环体算子列表）。支持：' +
        Object.keys(OPS).filter(k => OPS[k].invOf).join(' / '),
    };
  }
  const regs = (Array.isArray(i.regs) && i.regs.length ? i.regs : ['X', 'Y']).map(String);
  if (regs.length < 1 || regs.length > 4) return { error: 'regs 支持 1~4 个寄存器' };
  const width = WIDTHS[Number(i.width) || 64];
  if (!width) return { error: `width 只能是 ${Object.keys(WIDTHS).join('/')}` };
  const rounds = Math.min(Math.max(Number(i.rounds) || 1, 1), 1 << 24);
  const endian = String(i.endian || 'little').toLowerCase() === 'big' ? 'big' : 'little';
  const doPack = i.pack !== false;

  // ── 校验并展开算子 ──
  const fwdLines = [];
  for (let k = 0; k < ops.length; k++) {
    const o = ops[k] || {};
    const name = String(o.op || '').trim();
    const def = OPS[name];
    if (!def) {
      return { error: `第 ${k + 1} 个算子的 op 不认识：${name}（支持 ${Object.keys(OPS).filter(n => OPS[n].invOf).join('/')}）` };
    }
    for (const f of def.need) {
      if (o[f] === undefined || o[f] === null) {
        return { error: `第 ${k + 1} 个算子（${name}）缺少字段 ${f}` };
      }
    }
    // 寄存器名必须是已声明的
    for (const f of def.need) {
      const v = String(o[f]);
      if (['dst', 'src', 'reg', 'a', 'b', 'hi', 'lo'].includes(f) && !regs.includes(v)) {
        return { error: `第 ${k + 1} 个算子（${name}）的 ${f}="${v}" 不在 regs（${regs.join(',')}）里` };
      }
    }
    fwdLines.push(def.emit(o));
  }

  // ── 逆向：逆序 + 每条换成逆算子 ──
  const invLines = [];
  for (let k = ops.length - 1; k >= 0; k--) {
    const o = ops[k];
    const def = OPS[o.op];
    const invName = def.invOf;
    if (!invName || !OPS[invName]) {
      return { error: `算子 ${o.op} 没有登记的逆运算（内部错误）` };
    }
    invLines.push(OPS[invName].emit(o));
  }

  // ── target 归一化 ──
  const normInt = (v) => {
    if (typeof v === 'number' && Number.isFinite(v)) return '0x' + Math.trunc(v).toString(16);
    const s = String(v == null ? '' : v).trim();
    if (!/^-?(0x[0-9a-fA-F]+|\d+)$/.test(s)) return null;
    return s.startsWith('0x') || s.startsWith('0X') || s.startsWith('-') ? s : '0x' + BigInt(s).toString(16);
  };
  // 位宽检查：目标值超出 WIDTH 位说明参数错了（width=32 却传 64 位值）
  const fitsWidth = (litStr) => {
    try {
      const n = BigInt(litStr);
      return n >= 0n && n <= ((1n << BigInt(width)) - 1n);
    } catch (e) { return false; }
  };
  let target = null;
  if (i.target != null) {
    const arr = Array.isArray(i.target) ? i.target : [i.target];
    if (arr.length !== regs.length) {
      return { error: `target 需要 ${regs.length} 个值（对应 regs=${regs.join(',')}），收到 ${arr.length} 个` };
    }
    target = arr.map(normInt);
    if (target.some(x => x === null)) return { error: 'target 里有无法解析的数值' };
    const over = target.findIndex(x => !fitsWidth(x));
    if (over >= 0) {
      return {
        error: `target[${over}]=${arr[over]} 超出 width=${width} 的表示范围（最大 ${'0x' + ((1n << BigInt(width)) - 1n).toString(16)}）。` +
          `若确实是 64 位值，请把 width 设为 64。`,
      };
    }
  }
  let init = null;
  if (i.init != null) {
    const arr = Array.isArray(i.init) ? i.init : [i.init];
    if (arr.length !== regs.length) return { error: `init 需要 ${regs.length} 个值` };
    init = arr.map(normInt);
    if (init.some(x => x === null)) return { error: 'init 里有无法解析的数值' };
    const overI = init.findIndex(x => !fitsWidth(x));
    if (overI >= 0) {
      return { error: `init[${overI}]=${arr[overI]} 超出 width=${width} 的表示范围；若确实是 64 位值请设 width=64。` };
    }
  }
  if (!target && !init) return { error: 'rev_solve 需要 target（目标值）或 init（已知初值，只做回代）' };

  const L = [];
  L.push('#!/usr/bin/env python3');
  L.push('"""ctf-re-tool rev_solve —— 可逆循环逆推');
  L.push('');
  L.push('循环体每一步都是双射 ⇒ 从目标值逆序回退即可还原输入。');
  L.push('脚本先做「正逆互逆」自检（不依赖目标值），再反解、再回代验证。');
  L.push('如果自检就失败，说明算子表写错了 —— 这时不要看反解结果。');
  L.push('"""');
  L.push('import sys, struct');
  L.push('');
  L.push('WIDTH = ' + width);
  L.push('MASK = (1 << WIDTH) - 1');
  L.push('MSB = 1 << (WIDTH - 1)');
  L.push('MOD = 1 << WIDTH');
  L.push('ROUNDS = ' + rounds);
  L.push('');
  L.push('def fwd(' + regs.join(', ') + '):');
  L.push('    for _ in range(ROUNDS):');
  for (const ln of fwdLines) L.push('        ' + ln);
  L.push('    return (' + regs.join(', ') + ')');
  L.push('');
  L.push('def inv(' + regs.join(', ') + '):');
  L.push('    for _ in range(ROUNDS):');
  for (const ln of invLines) L.push('        ' + ln);
  L.push('    return (' + regs.join(', ') + ')');
  L.push('');
  L.push('');
  L.push('def selfcheck(n=40, rounds=64):');
  L.push('    """正逆互逆自检。不通过就说明算子表错了，别浪费时间看反解。"""');
  L.push('    import random');
  L.push('    random.seed(0xC0FFEE)');
  L.push('    for side, f1, f2 in (("fwd→inv", fwd, inv), ("inv→fwd", inv, fwd)):');
  L.push('        for _ in range(n):');
  L.push('            a = tuple(random.getrandbits(WIDTH) for _ in range(' + regs.length + '))');
  L.push('            r = f2(*f1(*a)) if True else None');
  L.push('            if tuple(r) != tuple(a):');
  L.push('                print("SELFCHECK_FAIL", side, "in=", [hex(x) for x in a], "got=", [hex(x) for x in r])');
  L.push('                return False');
  L.push('    return True');
  L.push('');
  L.push('');
  L.push('if not selfcheck():');
  L.push('    print("自检失败：算子表或逆运算写错了。先修 fwd/inv，不要相信后面的结果。")');
  L.push('    sys.exit(2)');
  L.push('print("SELFCHECK_OK 正逆互逆通过")');
  L.push('');
  L.push('TARGET = ' + (target ? '(' + target.join(', ') + ',)' : 'None'));
  if (init) L.push('INIT = (' + init.join(', ') + ',)');
  else L.push('INIT = None');
  L.push('');
  L.push('if INIT is not None:');
  L.push('    sol = INIT');
  L.push('    print("INIT 模式：跳过反解，只做回代")');
  L.push('else:');
  L.push('    sol = inv(*TARGET)');
  L.push('    print("SOL     =", ", ".join("%#0*x" % (WIDTH // 4 + 2, v) for v in sol))');
  L.push('');
  L.push('# 回代：正向必须精确命中目标');
  L.push('back = fwd(*sol)');
  L.push('print("BACK    =", ", ".join("%#0*x" % (WIDTH // 4 + 2, v) for v in back))');
  L.push('if TARGET is not None:');
  L.push('    ok = tuple(back) == tuple(TARGET)');
  L.push('    print("VERIFY  =", "PASS" if ok else "FAIL")');
  L.push('    if not ok:');
  L.push('        print("目标 =", [hex(x) for x in TARGET])');
  L.push('        sys.exit(3)');
  L.push('');
  if (doPack) {
    L.push('# 打包成字节（按 regs 顺序、' + endian + ' endian）');
    L.push('_fmt = (">" if ' + JSON.stringify(endian) + ' == "big" else "<") + {8:"B",16:"H",32:"I",64:"Q"}[WIDTH] * ' + regs.length);
    L.push('try:');
    L.push('    data = struct.pack(_fmt, *sol)');
    L.push('    print("INPUT_HEX =", data.hex())');
    L.push('    print("INPUT_RAW =", data)');
    L.push('    try:');
    L.push('        print("INPUT_TXT =", data.decode("utf-8"))');
    L.push('    except Exception:');
    L.push('        print("INPUT_TXT = (非 UTF-8)")');
    L.push('    print("PRINTABLE =", all(32 <= b < 127 for b in data))');
    L.push('except Exception as _e:');
    L.push('    print("PACK_FAIL", _e)');
  }

  return {
    ok: true,
    kind: 'rev-solve',
    language: 'python',
    script: L.join('\n'),
    meta: { regs, width, rounds, opCount: ops.length },
    notes: [
      '循环体每一步必须是双射（^ / ~ / 循环移位 / 加减 / 交换）。出现 & 掩码、查表就不能这样逆。',
      '脚本先跑自检再看结果：自检失败说明算子表写错，反解数字全是错的。',
      '回代 VERIFY=PASS 才是真解；只有"算出个数"不算。',
    ],
  };
}

module.exports = { buildRevSolveScript, OPS, parseIntLoose: (v) => Number(v) };
