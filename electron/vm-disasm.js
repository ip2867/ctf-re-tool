// 自定义 VM / 字节码解释器：把"不可读的大数组"变成"可读的指令流"
//
// 设计哲学（与 file_digest / recover_string 一致）：
//   工具只做**确定性提取**，不做语义猜测。判断权交给 AI。
//   认不出的 opcode 一律输出 `# TODO`，绝不编一个看起来合理的语义。
//
// 为什么需要：
//   实测（D3CTF 2019 AncientGameV2）：HTML 里一个 190702 项的平坦数组，
//   解释器只有 `while(1){ a=mem[pc]; ...; mem[c]=~(mem[a]&mem[b]); }`，
//   AI 只能反复手写模拟器试，45 轮无契约。缺的不是"更聪明的猜测"，
//   而是"先把这 19 万个数字变成基本块 + 控制流"的基础设施。

// ── 数组字面量提取 ────────────────────────────────────────────

/**
 * 从文本里提取 `name = [ ... ]` 或 `name: [ ... ]` 或 `var name=[...]` 的数值数组。
 *
 * @param {string} text  源文本（JS/Python/HTML 均可）
 * @param {string} name  数组名
 * @returns {{ok:true, nums:number[], startIdx:number, endIdx:number} | {ok:false, reason:string}}
 */
function extractArrayLiteral(text, name) {
  const src = String(text || '');
  if (!name) return { ok: false, reason: '未指定数组名' };
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // 名字后面允许出现 "=" / ":" / 空白，然后是 "["
  const re = new RegExp('\\b' + esc + '\\s*[:=]\\s*\\[', 'i');
  const m = re.exec(src);
  if (!m) return { ok: false, reason: `未找到数组 ${name} 的字面量（形如 ${name} = [ ... ]）` };

  const arrStart = src.indexOf('[', m.index);
  // 括号配平找到数组结尾（数组内可能有嵌套数组）
  let depth = 0, end = -1;
  for (let i = arrStart; i < src.length; i++) {
    const c = src[i];
    if (c === '[') depth++;
    else if (c === ']') { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end < 0) return { ok: false, reason: `数组 ${name} 的方括号未闭合（文件可能被截断）` };

  const body = src.slice(arrStart + 1, end);
  const nums = [];
  // 逐字符扫描，只取数字 token（跳过字符串、注释、嵌套结构里的非数字）
  const numRe = /-?\s*(?:0x[0-9a-fA-F]+|\d+)/g;
  let t;
  while ((t = numRe.exec(body)) !== null) {
    const raw = t[0].replace(/\s+/g, '');
    const v = /^0x/i.test(raw) ? parseInt(raw, 16) : parseInt(raw, 10);
    if (Number.isFinite(v)) nums.push(v);
  }
  return { ok: true, nums, startIdx: arrStart, endIdx: end };
}

// ── 变长指令解码（按操作数符号位）────────────────────────────
//
// ⚠️ 这是实测逼出来的：D3CTF AncientGameV2 的 m_mem 有 190702 项，
//    定长切分（每 N 个元素一条）只会切出 40490 种"opcode"、1 个基本块、0 条边——
//    完全无用。真实指令是**变长**的，长度由前两个操作数的符号决定。
//
// 这类解释器的典型结构（从反编译可读出同一套判据）：
//     a = mem[ip]; b = mem[ip+1];
//     if (a <= 0) { if (b >= 0) { ip = b; continue; }        // J：跳到 b
//                   else { c = mem[ip+2]; output(mem[c]); } } // O：输出 mem[c]
//     else        { if (b < 0)  { mem[a] = input(); }          // R：读输入进 mem[a]
//                   else { c = mem[ip+2]; mem[c] = ~(mem[a] & mem[b]); } } // N：NAND
//
// 即：长度只看前两位的符号 —— (a<=0,b>=0) 和 (a>0,b<0) 是 2 元素，其余 3 元素。
// 这条规则不依赖具体 opcode 取值，适用于"用符号位区分指令类型"的一类 VM。
//
// 只有在定长切分明显不合理（opcode 种数爆炸 / 切不出块）时才用，避免误伤定长 VM。

/**
 * 按符号位变长解码。
 * @param {number[]} nums
 * @returns {{insns:Array<{pc,a,b,c,len,type}>, covered:number, total:number}}
 */
function decodeVariableLength(nums) {
  const insns = [];
  let ip = 0, covered = 0;
  while (ip < nums.length) {
    const a = nums[ip];
    const b = ip + 1 < nums.length ? nums[ip + 1] : 0;
    // 长度：a<=0 且 b>=0（J）或 a>0 且 b<0（R）→ 2；否则 3
    const len = (a <= 0) ? (b >= 0 ? 2 : 3) : (b < 0 ? 2 : 3);
    if (ip + len > nums.length) break;
    const c = len === 3 ? nums[ip + 2] : null;
    let type;
    if (a <= 0) type = (b >= 0) ? 'J' : 'O';
    else type = (b < 0) ? 'R' : 'N';
    insns.push({ pc: ip, a, b, c, len, type });
    ip += len;
    covered = ip;
  }
  return { insns, covered, total: nums.length };
}

/**
 * 判断该不该用变长解码：符号模式解码若"覆盖率高 + 类型分布合理"，
 * 就明显优于定长切分。
 * @param {{insns:Array, covered:number, total:number}} vl
 * @returns {boolean}
 */
function preferVariableLength(vl) {
  if (!vl || !vl.insns.length) return false;
  // 覆盖率：解出的指令应几乎吃满整个数组（否则说明规则不对）
  const coverRatio = vl.covered / Math.max(1, vl.total);
  if (coverRatio < 0.98) return false;
  // 每个元素平均 ≥2 项才算"指令流"（若平均 1 项，等于没切分）
  const avgLen = vl.covered / vl.insns.length;
  if (avgLen < 1.8 || avgLen > 5) return false;
  // 四种类型都应出现（J/O/R/N）；至少 3 种，说明确实是"多类型指令"
  const types = new Set(vl.insns.map(x => x.type));
  return types.size >= 3;
}

// ── 指令切分 ──────────────────────────────────────────────────

/**
 * 把平坦数组按固定元组宽度切成指令序列。
 * @param {number[]} nums
 * @param {number[]} layout  每条指令占几个元素（如 [op,a,b,c] → 长度 4）
 * @returns {Array<{pc:number, args:number[]}>}
 */
function splitInstructions(nums, layout) {
  const width = layout.length;
  const out = [];
  for (let i = 0; i + width <= nums.length; i += width) {
    out.push({ pc: i, args: nums.slice(i, i + width) });
  }
  return out;
}

/**
 * 自动推断指令宽度。
 *
 * 做法：对每个候选宽度 w ∈ {1,2,3,4,5}，把数组切成指令，
 * 统计"第 0 个元素（opcode 位）的取值集中度"——真实 VM 的 opcode
 * 只有少数几种取值（8~20 种），而操作数位则几乎每个值都不同。
 * 选"opcode 种数最少且远小于指令数"的那个宽度。
 *
 * ⚠️ 这是启发式，不是定论。返回值里带 confidence，AI 应结合反编译确认。
 *
 * @param {number[]} nums
 * @param {number} maxElem  数组最大值（决定是否需要多字节）
 * @returns {{width:number, opcodeCount:number, insnCount:number, confidence:string, scores:object}}
 */
function inferInstructionWidth(nums, maxElem) {
  const n = nums.length;
  const scores = {};
  let best = null;
  for (let w = 1; w <= 5; w++) {
    if (n < w * 4) continue;                 // 太少，切不出有意义的指令
    const ops = new Map();
    const insnCount = Math.floor(n / w);
    for (let i = 0; i + w <= n; i += w) {
      const op = nums[i];
      ops.set(op, (ops.get(op) || 0) + 1);
    }
    const opcodeCount = ops.size;
    // 判据：opcode 种数应远小于指令数，且不应接近"所有值都不同"
    const ratio = opcodeCount / Math.max(1, insnCount);
    scores['w' + w] = { opcodeCount, insnCount, ratio: Number(ratio.toFixed(3)) };
    if (opcodeCount >= 2 && opcodeCount <= 40 && ratio < 0.35) {
      if (!best || opcodeCount < best.opcodeCount) best = { width: w, opcodeCount, insnCount };
    }
  }
  if (best) {
    return {
      width: best.width,
      opcodeCount: best.opcodeCount,
      insnCount: best.insnCount,
      confidence: best.opcodeCount <= 24 ? 'medium' : 'low',
      scores,
    };
  }
  // 兜底：默认 1（单元素一指令），并如实标注低置信度
  return {
    width: 1,
    opcodeCount: new Set(nums).size,
    insnCount: n,
    confidence: 'low',
    scores,
  };
}

// ── 控制流图 ──────────────────────────────────────────────────

/**
 * 从指令序列里识别"绝对跳转"并构建基本块图。
 *
 * ⚠️ 判据必须严格，否则假边会淹没真信号。
 *    实测第一版：6 条指令切出 12 条边——因为操作数里的 0 恰好等于 pc=0，
 *    于是每条含 0 的指令都被当成"跳回开头"。
 *
 * 三条约束同时成立才算跳转候选：
 *   ① 目标必须是**某条指令的起始 pc**；
 *   ② 该 opcode 是"少数派"——真跳转指令通常只有几条，
 *      不会像数据 opcode 那样密集出现（用 ≤ 指令数/4 过滤）；
 *   ③ 若某 opcode 的目标**全是 0**，判为误报（0 更像未初始化的操作数/清零填充）。
 *
 * 仍然只是**结构候选**，不是语义断定。真正的跳转 opcode 需结合反编译确认。
 *
 * @param {Array<{pc:number,args:number[]}>} insns
 * @param {number[]} layout
 * @returns {{blocks:Array, edges:Array, loops:Array, jumpishOp:number[]}}
 */
function buildControlFlow(insns, layout) {
  const pcSet = new Set(insns.map(x => x.pc));
  const insnCount = insns.length;

  // 第一轮：按 opcode 分组，统计它的每个操作数位"落在指令边界上的比例"
  const byOp = new Map();        // opcode -> {insns:[args...], boundaryHits:[{from,to,at}]}
  for (const cur of insns) {
    const op = cur.args[0];
    if (!byOp.has(op)) byOp.set(op, { insns: [], hits: [] });
    const rec = byOp.get(op);
    rec.insns.push(cur.args);
    for (let k = 1; k < cur.args.length; k++) {
      const target = cur.args[k];
      if (target === cur.pc) continue;
      if (!pcSet.has(target)) continue;
      rec.hits.push({ from: cur.pc, to: target, at: k });
    }
  }

  // 第二轮：判据是**命中率**而不是命中次数。
  //
  // 为什么改：上一版用"命中次数 ≤ 指令数/4"过滤，在小样本上把真跳转（op=9）
  // 滤掉了、反而留下数据 opcode（op=1，因为它的操作数 8 恰好是边界）。
  // 真实特征是：**跳转指令的操作数几乎每次都在指令边界上**（它本来就该是地址），
  // 而数据指令的操作数只有偶然命中。所以看"该 opcode 的操作数总个数里，
  // 有多大比例落在边界上"——真跳转接近 100%，数据类通常很低。
  //
  // 另外：真跳转指令通常只在**固定的一个操作数位**上送目标（如 `J target` 只用第 1 位）。
  // 若同一 opcode 在多个位置都命中，多半是操作数恰好撞上边界，只保留命中最多的那一列。
  const edges = [];
  const jumpishOp = [];
  for (const [op, rec] of byOp) {
    const operandTotal = rec.insns.length * Math.max(0, (rec.insns[0] || []).length - 1);
    if (!operandTotal) continue;
    if (!rec.hits.length) continue;

    // 按"操作数第几位"分组，找出主列
    const byPos = new Map();
    for (const h of rec.hits) {
      if (!byPos.has(h.at)) byPos.set(h.at, []);
      byPos.get(h.at).push(h);
    }
    let bestPos = null;
    for (const [pos, list] of byPos) {
      if (!bestPos || list.length > bestPos.list.length) bestPos = { pos, list };
    }
    if (!bestPos) continue;

    // 命中率按"该列出现次数 / 该 opcode 的指令数"算：真跳转应接近 1
    const colRate = bestPos.list.length / rec.insns.length;
    const distinct = new Set(bestPos.list.map(h => h.to));

    // 跳转判据：①该列命中率 ≥ 0.5  ②至少 2 次  ③目标不能全是 0
    if (colRate >= 0.5 && bestPos.list.length >= 2 && !(distinct.size === 1 && distinct.has(0))) {
      for (const h of bestPos.list) edges.push({ ...h, opcode: op });
      jumpishOp.push(op);
    }
  }

  // 基本块：以"跳转目标"与"跳转指令的下一条"为界切分
  const blockStarts = new Set();
  if (insns.length) blockStarts.add(insns[0].pc);
  const pcToIdx = new Map(insns.map((x, i) => [x.pc, i]));
  for (const e of edges) {
    blockStarts.add(e.to);
    const idx = pcToIdx.get(e.from);
    if (idx != null && idx + 1 < insns.length) blockStarts.add(insns[idx + 1].pc);
  }
  const starts = [...blockStarts].filter(p => pcSet.has(p)).sort((a, b) => a - b);
  const blocks = starts.map((s, i) => ({
    start: s,
    end: i + 1 < starts.length ? starts[i + 1] - 1 : insns[insns.length - 1].pc,
    insnCount: 0,
  }));
  for (const b of blocks) {
    b.insnCount = insns.filter(x => x.pc >= b.start && x.pc <= b.end).length;
  }

  // 环检测（DFS，只报"回边"）
  const adj = new Map();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e.to);
  }
  const state = new Map();  // 0=未访问 1=在栈上 2=已完成
  const loops = [];
  const dfs = (node, stack) => {
    state.set(node, 1);
    stack.push(node);
    for (const nx of (adj.get(node) || [])) {
      if (state.get(nx) === 1) {
        loops.push({ from: node, to: nx, stackDepth: stack.length });
      } else if (!state.has(nx)) {
        dfs(nx, stack);
      }
    }
    stack.pop();
    state.set(node, 2);
  };
  for (const b of blocks) if (!state.has(b.start)) dfs(b.start, []);

  return { blocks, edges, loops, jumpishOp };
}

// ── opcode 统计 ──────────────────────────────────────────────

/**
 * 统计每个 opcode 的出现次数与操作数形态。纯统计，不做语义判断。
 * @param {Array<{pc:number,args:number[]}>} insns
 * @returns {Array<{op:number,count:number,operandProfile:string}>}
 */
function profileOpcodes(insns) {
  const stat = new Map();
  for (const ins of insns) {
    const op = ins.args[0];
    if (!stat.has(op)) stat.set(op, { op, count: 0, operands: [] });
    const s = stat.get(op);
    s.count++;
    if (s.operands.length < 200) s.operands.push(ins.args.slice(1));
  }
  const out = [];
  for (const s of stat.values()) {
    // 描述操作数形态：小整数（疑似寄存器/单元号）vs 大整数（疑似地址/常量）
    let small = 0, large = 0, zero = 0;
    for (const ops of s.operands) {
      for (const v of ops) {
        if (v === 0) zero++;
        else if (Math.abs(v) < 1000) small++;
        else large++;
      }
    }
    const total = small + large + zero || 1;
    let profile;
    if (large / total > 0.3) profile = '含大整数（疑似地址/常量）';
    else if (small / total > 0.7) profile = '多为小整数（疑似寄存器/单元号）';
    else profile = '混合';
    out.push({ op: s.op, count: s.count, operandProfile: profile });
  }
  return out.sort((a, b) => b.count - a.count);
}

// ── 模拟器骨架生成 ────────────────────────────────────────────

/**
 * 生成可直接跑的 Python 模拟器骨架。
 *
 * ⚠️ 每个 opcode 都是 TODO 占位：本工具**不知道** op 0x03 是加法还是输出。
 *    这必须由 AI 从反编译确认后填。生成"看起来能跑但其实乱猜"的代码是害人。
 *
 * @param {{nums:number[], layout:number[], opcodes:Array, cf:{blocks:Array,edges:Array}, arrayName:string}} p
 * @returns {string}
 */
function buildVmSimulatorSkeleton(p) {
  const { nums, layout, opcodes, cf, arrayName } = p;
  const L = [];
  L.push('#!/usr/bin/env python3');
  L.push('# -*- coding: utf-8 -*-');
  L.push('"""');
  L.push('自定义 VM 模拟器骨架 —— 由 vm_disasm 自动生成');
  L.push('');
  L.push('⚠️ 每个 opcode 的语义都是 TODO。本工具只做了结构切分（数组 → 指令 → 基本块），');
  L.push('   不知道 op 0x03 是加法还是输出。请从反编译逐 case 确认后填入 TODO。');
  L.push('"""');
  L.push('import sys');
  L.push('');
  L.push('# 原始程序数组（' + nums.length + ' 项）');
  L.push('MEM_INIT = ' + JSON.stringify(nums));
  L.push('');
  L.push('# 指令布局：每 ' + layout.length + ' 个元素一条指令 = ' + JSON.stringify(layout));
  L.push('LAYOUT = ' + JSON.stringify(layout));
  L.push('');
  L.push('def run(input_bytes, max_steps=20_000_000, trace=None):');
  L.push('    mem = list(MEM_INIT)');
  L.push('    pc = 0');
  L.push('    ip = 0            # input 游标');
  L.push('    out = bytearray()');
  L.push('    steps = 0');
  L.push('    while 0 <= pc < len(mem) and steps < max_steps:');
  L.push('        steps += 1');
  L.push('        op = mem[pc]');
  L.push('        args = mem[pc + 1:pc + len(LAYOUT)]');
  L.push('        if trace is not None:');
  L.push('            trace.append((pc, op, list(args)))');
  L.push('        pc += len(LAYOUT)');
  L.push('');
  L.push('        # ---- 以下每个分支都需要你从反编译确认语义 ----');
  opcodes.forEach((o, idx) => {
    L.push(`        ${idx === 0 ? 'if' : 'elif'} op == ${o.op}:`);
    L.push(`            # TODO: op ${o.op}（出现 ${o.count} 次；${o.operandProfile}）`);
    L.push('            pass');
  });
  L.push('        else:');
  L.push('            raise SystemExit("未知 opcode: %r @pc=%d" % (op, pc - len(LAYOUT)))');
  L.push('');
  L.push('    return bytes(out), steps');
  L.push('');
  L.push('');
  L.push('if __name__ == "__main__":');
  L.push('    data = sys.argv[1].encode() if len(sys.argv) > 1 else b""');
  L.push('    res, steps = run(data)');
  L.push('    print("STEPS", steps)');
  L.push('    print("OUT", repr(res))');
  return L.join('\n');
}

// ── 变长指令的控制流 ──────────────────────────────────────────
//
// J 型（a<=0 且 b>=0）的目标直接是 b；O 型（a<=0 且 b<0）输出 mem[c] 后顺序执行；
// R/N 型顺序执行。所以边只来自 J 型，判据比定长版简单得多、也准得多。
/**
 * @param {Array<{pc:number,a:number,b:number,c:number|null,len:number,type:string}>} insns
 */
function buildControlFlowVariable(insns) {
  const pcSet = new Set(insns.map(x => x.pc));
  const pcToIdx = new Map(insns.map((x, k) => [x.pc, k]));
  const edges = [];
  let jumpTotal = 0, jumpHit = 0;
  for (const x of insns) {
    if (x.type !== 'J') continue;
    jumpTotal++;
    if (x.b === x.pc) continue;
    if (!pcSet.has(x.b)) continue;
    jumpHit++;
    edges.push({ from: x.pc, to: x.b, opcode: 'J', at: 1 });
  }

  // 基本块：跳转目标 + 跳转指令的下一条
  const blockStarts = new Set();
  if (insns.length) blockStarts.add(insns[0].pc);
  for (const e of edges) {
    blockStarts.add(e.to);
    const idx = pcToIdx.get(e.from);
    if (idx != null && idx + 1 < insns.length) blockStarts.add(insns[idx + 1].pc);
  }
  const starts = [...blockStarts].filter(p => pcSet.has(p)).sort((a, b) => a - b);
  const blocks = starts.map((s, k) => ({
    start: s,
    end: k + 1 < starts.length ? starts[k + 1] - 1 : insns[insns.length - 1].pc,
    insnCount: 0,
  }));
  for (const b of blocks) b.insnCount = insns.filter(x => x.pc >= b.start && x.pc <= b.end).length;

  // 环检测（回边）
  const adj = new Map();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e.to);
  }
  const state = new Map();
  const loops = [];
  const dfs = (node, stack) => {
    if (state.get(node) === 1) return;
    state.set(node, 1);
    stack.push(node);
    for (const nx of (adj.get(node) || [])) {
      if (state.get(nx) === 1) loops.push({ from: node, to: nx, stackDepth: stack.length });
      else if (!state.has(nx)) dfs(nx, stack);
    }
    stack.pop();
    state.set(node, 2);
  };
  for (const b of blocks) if (!state.has(b.start)) dfs(b.start, []);

  return { blocks, edges, loops, jumpTotal, jumpHit };
}

// 变长解码的四种指令类型（来自符号位组合，不含具体语义）
const TYPE_HINT = {
  J: '跳转（a<=0 且 b>=0）→ ip = b',
  O: '输出（a<=0 且 b<0）→ 输出 mem[c]',
  R: '读输入（a>0 且 b<0）→ mem[a] = 输入字节',
  N: '运算（a>0 且 b>=0）→ mem[c] 由 mem[a]、mem[b] 计算',
};

/**
 * 变长 VM 的模拟器骨架。结构来自符号判据，运算语义仍是 TODO。
 */
function buildVariableLenSkeleton(p) {
  const { nums, insns, typeCount, arrayName } = p;
  const L = [];
  L.push('#!/usr/bin/env python3');
  L.push('# -*- coding: utf-8 -*-');
  L.push('"""');
  L.push('变长指令 VM 模拟器骨架 —— 由 vm_disasm 自动生成');
  L.push('');
  L.push('指令长度由"前两个操作数的符号"决定（实测这类 VM 的通用结构）：');
  L.push('  a<=0, b>=0  → J：ip = b                     （' + (typeCount.J || 0) + ' 条）');
  L.push('  a<=0, b<0   → O：输出 mem[c]                （' + (typeCount.O || 0) + ' 条）');
  L.push('  a>0,  b<0   → R：mem[a] = 读输入            （' + (typeCount.R || 0) + ' 条）');
  L.push('  a>0,  b>=0  → N：mem[c] = f(mem[a], mem[b]) （' + (typeCount.N || 0) + ' 条）');
  L.push('');
  L.push('⚠️ N 型用的是哪种运算（NAND / 加法 / 异或…）本工具**不知道**，');
  L.push('   必须从反编译确认后填入 compute()。');
  L.push('"""');
  L.push('import sys');
  L.push('');
  L.push('# 程序数组（' + nums.length + ' 项）');
  L.push('MEM_INIT = ' + JSON.stringify(nums));
  L.push('');
  L.push('');
  L.push('def compute(x, y):');
  L.push('    """N 型指令的运算。TODO: 从反编译确认。');
  L.push('    常见：return ~(x & y) & 0xFFFFFFFF   # NAND');
  L.push('    """');
  L.push('    raise NotImplementedError("先确认 N 型语义")');
  L.push('');
  L.push('');
  L.push('def run(input_bytes, max_steps=50_000_000, trace=None):');
  L.push('    # ⚠️ 关键：程序数组只是内存的**一部分**。真实 VM 的 mem 是一大片可写区，');
  L.push('    #    指令会把输入/中间结果写到程序区**之外**的下标（如 mem[10] / mem[5000]）。');
  L.push('    #    直接 list(MEM_INIT) 会 IndexError，所以先按需扩容。');
  L.push('    mem = list(MEM_INIT)');
  L.push('    MEM_CAP = len(MEM_INIT) + 1024 * 1024   # 预留可写区');
  L.push('');
  L.push('    def ensure(idx):');
  L.push('        """把 mem 扩到能容纳 idx（含负下标保护）。"""');
  L.push('        if idx < 0:');
  L.push('            raise IndexError("mem 下标为负: %d（若这是常量单元，需按反编译单独处理）" % idx)');
  L.push('        while idx >= len(mem):');
  L.push('            mem.append(0)');
  L.push('            if len(mem) > MEM_CAP:');
  L.push('                raise MemoryError("mem 超过 %d 项，疑似死循环或下标算错" % MEM_CAP)');
  L.push('');
  L.push('    ip = 0');
  L.push('    pos = 0            # 输入游标');
  L.push('    out = bytearray()');
  L.push('    steps = 0');
  L.push('    while 0 <= ip < len(mem) and steps < max_steps:');
  L.push('        steps += 1');
  L.push('        a = mem[ip]');
  L.push('        b = mem[ip + 1] if ip + 1 < len(mem) else 0');
  L.push('        if a <= 0:');
  L.push('            if b >= 0:');
  L.push('                # J：跳转');
  L.push('                if trace is not None: trace.append((ip, "J", b))');
  L.push('                nxt = b');
  L.push('                if nxt == ip:      # 自跳 = 停机');
  L.push('                    break');
  L.push('                ip = nxt');
  L.push('            else:');
  L.push('                # O：输出');
  L.push('                c = mem[ip + 2]');
  L.push('                ensure(c)');
  L.push('                out.append(mem[c] & 0xFF)');
  L.push('                if trace is not None: trace.append((ip, "O", c))');
  L.push('                ip += 3');
  L.push('        else:');
  L.push('            if b < 0:');
  L.push('                # R：读输入');
  L.push('                ensure(a)');
  L.push('                if pos < len(input_bytes):');
  L.push('                    mem[a] = input_bytes[pos]');
  L.push('                    pos += 1');
  L.push('                if trace is not None: trace.append((ip, "R", a))');
  L.push('                ip += 2');
  L.push('            else:');
  L.push('                # N：运算');
  L.push('                c = mem[ip + 2]');
  L.push('                ensure(a); ensure(b); ensure(c)');
  L.push('                mem[c] = compute(mem[a], mem[b])');
  L.push('                if trace is not None: trace.append((ip, "N", a, b, c))');
  L.push('                ip += 3');
  L.push('');
  L.push('    return bytes(out), steps');
  L.push('');
  L.push('');
  L.push('if __name__ == "__main__":');
  L.push('    data = sys.argv[1].encode() if len(sys.argv) > 1 else b""');
  L.push('    tr = []');
  L.push('    res, steps = run(data, trace=tr)');
  L.push('    print("STEPS", steps)');
  L.push('    print("OUT", repr(res))');
  return L.join('\n');
}

// ── 主入口 ────────────────────────────────────────────────────

/**
 * @param {object} input
 *   input.source      源文本（JS/HTML 内容）或文件路径
 *   input.array       数组名
 *   input.layout      可选，显式指令布局（数组长度即指令宽度）
 *   input.max_blocks  报告中最多展示多少个块（默认 20）
 */
function vmDisasm(input) {
  const i = input || {};
  const name = String(i.array || '').trim();
  if (!name) return { error: '缺少 array 参数（数组名，如 m_mem / nums / opcode）' };

  let text = String(i.source || '');
  if (!text.trim()) return { error: '缺少 source 参数（源文件路径或直接给数组文本）' };

  const ex = extractArrayLiteral(text, name);
  if (!ex.ok) return { error: ex.reason };
  const nums = ex.nums;
  if (nums.length < 8) return { error: `数组 ${name} 只提取到 ${nums.length} 项，太少，无法切分指令` };

  const maxElem = nums.reduce((a, b) => Math.max(a, Math.abs(b)), 0);

  // ── 先试变长解码（符号位判型）──────────────────────────────
  // 为什么优先：定长切分对"变长指令 VM"会产生天量假 opcode 与 0 条边。
  // 实测 AncientGameV2：定长 40490 种 opcode / 1 个块 / 0 条边；
  // 符号变长 → 72704 条指令 / 4 种类型 / 覆盖率 99.999%。
  const vl = decodeVariableLength(nums);
  if (!Array.isArray(i.layout) && preferVariableLength(vl)) {
    const insnsV = vl.insns;
    const cfV = buildControlFlowVariable(insnsV);
    const typeCount = {};
    for (const x of insnsV) typeCount[x.type] = (typeCount[x.type] || 0) + 1;
    const opcodesV = Object.keys(typeCount).sort().map(t => ({
      op: t,
      count: typeCount[t],
      operandProfile: TYPE_HINT[t] || '',
    }));
    const skeletonV = buildVariableLenSkeleton({ nums, insns: insnsV, typeCount, arrayName: name });
    return {
      ok: true,
      kind: 'vm-disasm',
      array: name,
      mode: 'variable-length',
      summary: {
        items: nums.length,
        min: Math.min(...nums.slice(0, 5000)),
        max: maxElem,
        mode: 'variable-length',
        instructionCount: insnsV.length,
        covered: vl.covered,
        coverRatio: Number((vl.covered / nums.length).toFixed(4)),
        types: typeCount,
        blockCount: cfV.blocks.length,
        edgeCount: cfV.edges.length,
        loopCount: cfV.loops.length,
      },
      head: nums.slice(0, 40),
      opcodes: opcodesV,
      blocks: cfV.blocks.slice(0, Math.max(1, Number(i.max_blocks) || 20)),
      edges: cfV.edges.slice(0, 200),
      loops: cfV.loops.slice(0, 20),
      disasmSample: insnsV.slice(0, 40).map(x => ({
        pc: x.pc,
        insn: [x.a, x.b].concat(x.c != null ? [x.c] : []),
        type: x.type,
      })),
      skeleton: skeletonV,
    };
  }

  // 指令布局：显式给出则用之，否则推断
  let layout, width, confidence, scores;
  if (Array.isArray(i.layout) && i.layout.length >= 2) {
    layout = i.layout.map(String);
    width = layout.length;
    confidence = 'explicit';
    scores = {};
  } else {
    const inf = inferInstructionWidth(nums, maxElem);
    width = inf.width;
    confidence = inf.confidence;
    scores = inf.scores;
    layout = ['op'].concat(Array.from({ length: width - 1 }, (_, k) => 'a' + k));
  }

  const insns = splitInstructions(nums, layout);
  const cf = buildControlFlow(insns, layout);
  const opcodes = profileOpcodes(insns);
  const skeleton = buildVmSimulatorSkeleton({ nums, layout, opcodes, cf, arrayName: name });

  return {
    ok: true,
    kind: 'vm-disasm',
    array: name,
    summary: {
      items: nums.length,
      min: Math.min(...nums.slice(0, 5000)),
      max: maxElem,
      width,
      layout,
      confidence,
      insnCount: insns.length,
      opcodeCount: opcodes.length,
      blockCount: cf.blocks.length,
      edgeCount: cf.edges.length,
      loopCount: cf.loops.length,
      widthScores: scores,
    },
    head: nums.slice(0, 40),
    opcodes,
    blocks: cf.blocks.slice(0, Math.max(1, Number(i.max_blocks) || 20)),
    edges: cf.edges.slice(0, 200),
    loops: cf.loops.slice(0, 20),
    disasmSample: insns.slice(0, 40).map(x => ({ pc: x.pc, insn: x.args })),
    skeleton,
  };
}

/**
 * 把 vmDisasm 的结果渲染成给 AI 看的文本报告。
 */
function formatVmReport(r) {
  if (!r || r.error) return `vm_disasm 失败: ${(r && r.error) || '未知错误'}`;
  const s = r.summary;
  const L = [];
  L.push(`## vm_disasm：${r.array}（${s.items} 项）`);
  L.push('');
  L.push(`- 指令宽度：**${s.width}**（布局 ${JSON.stringify(s.layout)}，置信度 **${s.confidence}**）`);
  L.push(`- 切出指令：${s.insnCount} 条，不同 opcode：${s.opcodeCount} 种`);
  L.push(`- 基本块：${s.blockCount} 个，跳转边：${s.edgeCount} 条，检测到回边（环）：${s.loopCount} 条`);
  L.push(`- 数组头部 40 项：\`${r.head.join(', ')}\``);
  if (s.widthScores && Object.keys(s.widthScores).length) {
    L.push(`- 宽度候选评分：\`${JSON.stringify(s.widthScores)}\``);
    L.push('  （判据：真实 VM 的 opcode 种数远小于指令数；若置信度低，请结合反编译确认）');
  }
  L.push('');
  L.push('### opcode 统计（纯计数，不含语义）');
  L.push('| op | 出现次数 | 操作数形态 |');
  L.push('|---|---|---|');
  for (const o of r.opcodes.slice(0, 40)) {
    L.push(`| ${o.op} | ${o.count} | ${o.operandProfile} |`);
  }
  if (r.opcodes.length > 40) L.push(`\n（其余 ${r.opcodes.length - 40} 种已省略）`);
  L.push('');
  L.push('### 前 40 条指令');
  L.push('```');
  for (const d of r.disasmSample) L.push(`pc=${String(d.pc).padStart(6)}  ${JSON.stringify(d.insn)}`);
  L.push('```');
  L.push('');
  L.push('### 前若干个基本块');
  L.push('```');
  for (const b of r.blocks) L.push(`块 ${b.start}..${b.end}（${b.insnCount} 条）`);
  L.push('```');
  if (r.loops.length) {
    L.push('');
    L.push('### 检测到的回边（循环）');
    L.push('```');
    for (const lp of r.loops) L.push(`${lp.from} → ${lp.to}`);
    L.push('```');
  }
  L.push('');
  L.push('### 重要：本工具不做语义猜测');
  L.push('下面骨架里每个 opcode 都是 TODO 占位。**它不知道 op 0x03 是加法还是输出**，');
  L.push('必须由你从反编译的 switch/case 逐条确认后填入。');
  L.push('把"看起来合理"的语义硬塞进去只会产出假结果。');
  L.push('');
  L.push('```python');
  L.push(r.skeleton);
  L.push('```');
  return L.join('\n');
}

module.exports = {
  vmDisasm,
  formatVmReport,
  extractArrayLiteral,
  splitInstructions,
  inferInstructionWidth,
  buildControlFlow,
  profileOpcodes,
  buildVmSimulatorSkeleton,
  decodeVariableLength,
  preferVariableLength,
  buildControlFlowVariable,
  buildVariableLenSkeleton,
  TYPE_HINT,
};
