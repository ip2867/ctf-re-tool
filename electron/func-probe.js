'use strict';
// **算法函数探针**：在 stripped 二进制里定位密码函数，并在调用点批量 dump 参数。
//
// 为什么需要（qwb2026 firmware 实战）：
//   fw_a 是 1MB stripped 静态链接二进制，7 次 SM3 调用的输入输出**完全无法从反汇编
//   快速看出**（变参、SIMD、内联）。但把断点设在 SM3 函数入口，一次就拿到：
//     #2 SM3(keymat, 16) → 与 0x4b3200 比
//     #4 SM3("QWB2026::TWIN::DEVICE-A", 23) → P
//     #5 SM3(keymat‖P‖vm_out8, 40) → A      ← vm_out8 就在这 40 字节的第 32..39
//   比读 8000 行反汇编快两个数量级。
//
// 本模块做两件事：
//   1. **按特征常量定位算法函数**（SM3/SM4/AES/MD5/SHA 的 IV / S 盒 / 轮常量，
//      两种字节序都试）→ 找到引用它的指令 → 往前找函数序言，得函数入口
//   2. **生成 gdb 脚本**：在函数入口下断，每次命中打印 (参数寄存器, 内存内容)，
//      支持按第 N 次调用筛选
//
// 设计原则：只做"定位 + 取证"，不猜语义。输出是"这个函数被调了 N 次，每次输入是这些"。

const { execFileSync } = require('child_process');

// ── 可定位的算法特征常量（value + 说明 + 该常量的"归属"）──
// 只列**强特征**：IV / S 盒前 8 字节 / 轮常量。单条常量不足以定位函数，
// 但配合"引用它的代码"就够了。
const SIGNATURES = {
  SM3: {
    // IV 四个 word
    words: [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600],
    note: 'SM3 IV',
    // 常见调用约定下的参数形态：rdi=data, rsi=len, rdx=out
    argRegs: ['rdi', 'rsi', 'rdx'],
  },
  SM4: {
    words: null,
    sboxHead: [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7],
    note: 'SM4 S 盒',
    argRegs: ['rdi', 'rsi', 'rdx'],
  },
  AES: {
    words: null,
    sboxHead: [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
    note: 'AES S 盒',
    argRegs: ['rdi', 'rsi', 'rdx'],
  },
  MD5: {
    words: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
    note: 'MD5 IV',
    argRegs: ['rdi', 'rsi', 'rdx'],
  },
  SHA256: {
    words: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
    note: 'SHA256 IV',
    argRegs: ['rdi', 'rsi', 'rdx'],
  },
  CHACHA: {
    words: null,
    ascii: 'expand 32-byte k',
    note: 'ChaCha/Salsa sigma',
    argRegs: ['rdi', 'rsi', 'rdx'],
  },
};

function leWords(words) {
  const b = Buffer.alloc(words.length * 4);
  words.forEach((v, i) => b.writeUInt32LE(v >>> 0, i * 4));
  return b;
}
function beWords(words) {
  const b = Buffer.alloc(words.length * 4);
  words.forEach((v, i) => b.writeUInt32BE(v >>> 0, i * 4));
  return b;
}

/**
 * 在某个二进制里定位算法的特征常量（两种字节序都试）。
 * @param {Buffer} buf
 * @returns {Array<{algo, note, offset, order, hex}>}
 */
function locateSignatures(buf) {
  const hits = [];
  for (const [algo, sig] of Object.entries(SIGNATURES)) {
    if (sig.words) {
      for (const [order, enc] of [['LE', leWords], ['BE', beWords]]) {
        let from = 0, at;
        while ((at = buf.indexOf(enc(sig.words), from)) !== -1) {
          hits.push({ algo, note: `${sig.note}（${order} word）`, offset: at, order,
            hex: enc(sig.words).toString('hex') });
          from = at + 1;
          if (hits.length > 40) return hits;
        }
      }
    }
    if (sig.sboxHead) {
      let from = 0, at;
      const pat = Buffer.from(sig.sboxHead);
      while ((at = buf.indexOf(pat, from)) !== -1) {
        hits.push({ algo, note: sig.note, offset: at, order: 'raw', hex: pat.toString('hex') });
        from = at + 1;
        if (hits.length > 40) return hits;
      }
    }
    if (sig.ascii) {
      const pat = Buffer.from(sig.ascii, 'latin1');
      const at = buf.indexOf(pat);
      if (at >= 0) hits.push({ algo, note: sig.note, offset: at, order: 'ascii', hex: pat.toString('hex') });
    }
  }
  return hits;
}

/**
 * 把 argv 安全地拼成 gdb `run` 行的参数串。
 *
 * ⚠️ 这些参数来自 AI（不可信），会被拼进 shell 里执行的 gdb 脚本 ——
 * 必须转义，否则 `a; shell` 会在 gdb 的 run 行注入新命令。
 * gdb 的 `run` 行本身按 shell 风格解析，用单引号包裹 + 转义内部单引号即可。
 */
function quoteGdbArgs(args) {
  if (!Array.isArray(args) || !args.length) return '';
  return args.map((a) => {
    const s = String(a == null ? '' : a);
    // 单引号包裹；内部的单引号写成 '\'' (结束-转义-重开)
    return "'" + s.replace(/'/g, "'\\''") + "'";
  }).join(' ');
}

/**
 * 生成 gdb 脚本：在指定地址下断，每次命中打印参数寄存器与内存。
 *
 * @param {object} o {
 *   binary,            // 远端路径
 *   breakAddr,         // 断点地址（函数入口）
 *   argRegs=['rdi','rsi','rdx'],  // 参数寄存器
 *   maxHits=20,        // 最多打印几次
 *   dumpBytes=64,      // 对指针型参数 dump 多少字节
 *   onlyNth=0,         // 只打印第 N 次（0=全部）
 *   followCalls=[]     // 额外要打印的调用点
 * }
 */
function buildProbeScript(o) {
  const opt = o || {};
  const bin = opt.binary || './target';
  const addr = opt.breakAddr || '0x0';
  const regs = Array.isArray(opt.argRegs) && opt.argRegs.length ? opt.argRegs : ['rdi', 'rsi', 'rdx'];
  const maxHits = Number(opt.maxHits) || 20;
  const dumpBytes = Number(opt.dumpBytes) || 64;
  const onlyNth = Number(opt.onlyNth) || 0;

  // 对每个参数寄存器：如果是"长度"型（名字像 rsi/rdx 且值很小）就按数值打印；
  // 否则按指针 dump。gdb 脚本里用条件判断，避免把长度当指针解引用崩溃。
  const lines = [];
  for (let i = 0; i < regs.length; i++) {
    const r = regs[i];
    lines.push(`printf "  ${r} = %p (%lu)\\n", $${r}, (unsigned long)$${r}`);
  }
  // 对第一个寄存器（通常是 data 指针）dump
  if (regs[0]) {
    lines.push(`printf "  data[0..${Math.min(dumpBytes, 32) - 1}]: "`);
    lines.push(`x/${Math.min(dumpBytes, 32)}xb $${regs[0]}`);
  }
  // 对第二个寄存器若像个合理长度，也把前 N 字节 dump（N 上限 64）
  if (regs[1]) {
    lines.push(`if $${regs[1]} > 4 && $${regs[1]} < 4096`);
    lines.push(`  printf "  in[0..15] (len=%lu): ", (unsigned long)$${regs[1]}`);
    lines.push(`  x/16xb $${regs[0]}`);
    lines.push('end');
  }

  return `set pagination off
set confirm off
set $n = 0
break *${addr}
commands
silent
set $n = $n + 1
${onlyNth ? `if $n == ${onlyNth}` : ''}
${onlyNth ? '' : `if $n <= ${maxHits}`}
printf "=== hit #%d ===\\n", $n
${lines.map((l) => '  ' + l).join('\n')}
end
${onlyNth ? '' : `if $n > ${maxHits}\n  printf "（已达上限 ${maxHits} 次，停止打印）\\n"\nend`}
continue
end
run ${quoteGdbArgs(opt.programArgs)}
`;
}

/**
 * 从 gdb 的 `x/Nxb` 输出里解析字节（与 riscv-probe 同款，按地址分块）。
 */
function parseGdbXOutput(text) {
  const lines = String(text || '').split('\n');
  const blocks = [];
  let cur = null;
  const flush = () => { if (cur && cur.bytes.length) blocks.push(cur); cur = null; };
  for (const l of lines) {
    const m = l.match(/^\s*(0x[0-9a-f]+):\s*(.+)$/i);
    if (!m) { if (cur) flush(); continue; }
    const addr = m[1].toLowerCase();
    if (cur) {
      const prevEnd = parseInt(cur.addr, 16) + cur.bytes.length;
      if (parseInt(addr, 16) !== prevEnd) flush();
    }
    if (!cur) cur = { addr, bytes: [] };
    for (const h of (m[2].match(/0x[0-9a-f]{1,2}\b/gi) || [])) cur.bytes.push(parseInt(h, 16) & 0xff);
  }
  flush();
  return blocks.map((b) => ({ addr: b.addr, bytes: b.bytes, hex: Buffer.from(b.bytes).toString('hex') }));
}

/**
 * 从"反汇编文本里出现某常量地址"的上下文，提取函数入口（往前找最近的 endbr64）。
 * 这是定位 stripped 二进制里算法函数的通用手法。
 *
 * @param {string} disasmText  整段反汇编文本（objdump/gdb 的）
 * @param {string} targetAddr  特征常量的 VA（如 '0x4d3280'）
 * @returns {{refs:string[], guessEntry:string|null}}
 */
function findFuncByConstRef(disasmText, targetAddr) {
  const lines = String(disasmText || '').split('\n');
  const tgt = String(targetAddr).toLowerCase().replace(/^0x0*/, '0x');
  const refs = [];
  let lastEntry = null;
  let bestEntry = null;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    // 函数边界：`0000000000403140 <name>:` 或 objdump 的 `.text+0xNNNN>`
    const fn = l.match(/^([0-9a-f]+)\s+</i);
    if (fn) lastEntry = '0x' + fn[1].replace(/^0+/, '');
    if (l.toLowerCase().includes(tgt)) {
      refs.push(l.trim());
      if (!bestEntry && lastEntry) bestEntry = lastEntry;
    }
  }
  return { refs, guessEntry: bestEntry };
}

module.exports = { SIGNATURES, locateSignatures, buildProbeScript, parseGdbXOutput, findFuncByConstRef, quoteGdbArgs };
