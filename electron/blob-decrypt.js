'use strict';
// 加密 blob 的**自解密器推断与批量解密**（纯函数）。
//
// 为什么需要：实测三题里有两题的真正校验逻辑是「加密后存成一块 blob，运行期用
// 一段 stub 解密后再执行」：
//   · elfstudy：0x7396 处 0x330 字节，stub 用**链式 XOR 从高地址往低地址**解：
//                  key=0; for i=N-1..1: P[i]=C[i]^key; key=(key+P[i])&0xffffffff
//                  （索引 0 不变）
//   · license ：每条指令 16 字节被原地异或，密钥依赖滚动状态
// 共同点：解密是**纯数据变换**，与程序其余部分无关 → 完全可以离线复现，
// 不需要跑程序、不需要 ptrace、不需要 Unicorn。
//
// 本模块做三件事：
//   1) 给一个密文块 + 一份"候选算法清单"，逐个试解，用**可判读性**打分
//      （x86 指令合法性 / 可打印比例 / 熵下降）——不猜语义，只做确定性比较
//   2) 支持"从 stub 里抽参数"：给一段 stub（反汇编文本或字节），提取
//      起始地址、长度、方向、key 初值、每步是否累加
//   3) 把结果落成可跑 Python 脚本 + 给出"哪种算法分数最高"的排序
//
// 设计原则：**不硬编码某一题的算法**。清单是通用家族（xor-chain / rolling-xor /
// rolling-add / periodic-xor / add-chain / rc4-like），参数由搜索确定。

const { execFileSync } = require('child_process');

// ───────────────────────── 通用解密家族 ─────────────────────────
// 每个算法：给定 (buf, params) → 明文 Buffer。params 里 null 表示"需要搜索"。

/** 链式 XOR（elfstudy 形态）：key 累加上一个明文 word */
function xorChainWords(buf, p) {
  const out = Buffer.from(buf);
  const width = p.width || 4;
  const n = Math.floor(out.length / width);
  const dir = p.direction === 'up' ? 1 : -1;
  let key = BigInt((p.key0 >>> 0) || 0);
  const mask = width === 4 ? 0xffffffffn : ((1n << BigInt(width * 8)) - 1n);
  const rd = (i) => {
    let v = 0n;
    for (let k = 0; k < width; k++) v |= BigInt(out[i * width + k]) << BigInt(8 * k);
    return v & mask;
  };
  const wr = (i, v) => {
    for (let k = 0; k < width; k++) out[i * width + k] = Number((v >> BigInt(8 * k)) & 0xffn);
  };
  // 从高到低（或按 direction）
  const idx = [];
  if (dir < 0) for (let i = n - 1; i >= 1; i--) idx.push(i);
  else for (let i = 1; i < n; i++) idx.push(i);
  for (const i of idx) {
    const c = rd(i);
    const pv = (c ^ key) & mask;
    wr(i, pv);
    key = (key + pv) & mask;
  }
  return out;
}

/** 逐字节滚动 XOR：out[i] = in[i] ^ in[i-1]（或反向） */
function rollingXor(buf, p) {
  const out = Buffer.from(buf);
  const rev = !!p.reverse;
  if (!rev) {
    for (let i = out.length - 1; i >= 1; i--) out[i] ^= out[i - 1];
  } else {
    for (let i = 1; i < out.length; i++) out[i] ^= out[i - 1];
  }
  if (p.key0) out[0] ^= p.key0;
  return out;
}

/** 逐字节滚动 ADD/SUB：out[i] = in[i] - in[i-1] */
function rollingAdd(buf, p) {
  const out = Buffer.from(buf);
  if (p.reverse) {
    for (let i = 1; i < out.length; i++) out[i] = (out[i] - out[i - 1]) & 0xff;
  } else {
    for (let i = out.length - 1; i >= 1; i--) out[i] = (out[i] - out[i - 1]) & 0xff;
  }
  return out;
}

/** 周期 XOR / ADD（密钥长度 1..16） */
function periodic(buf, p) {
  const out = Buffer.from(buf);
  const key = p.key || [];
  const mode = p.mode || 'xor';
  for (let i = 0; i < out.length; i++) {
    const k = key[i % key.length];
    out[i] = mode === 'xor' ? (out[i] ^ k) : ((out[i] - k) & 0xff);
  }
  return out;
}

/** 单字节 XOR / ADD */
function singleByte(buf, p) {
  const out = Buffer.from(buf);
  for (let i = 0; i < out.length; i++) {
    out[i] = p.mode === 'add' ? ((out[i] - p.key) & 0xff) : (out[i] ^ p.key);
  }
  return out;
}

/** 滚动 key：key = key*mult + add（LCG 型密钥流），逐字节或逐 dword */
function lcgStream(buf, p) {
  const out = Buffer.from(buf);
  const mask = 0xffffffffn;
  let s = BigInt(p.seed >>> 0);
  const a = BigInt(p.a >>> 0), c = BigInt(p.c >>> 0);
  const width = p.width || 1;
  for (let i = 0; i < out.length; i += width) {
    s = (a * s + c) & mask;
    const ks = p.high ? Number((s >> 16n) & 0xffn) : Number(s & 0xffn);
    for (let k = 0; k < width && i + k < out.length; k++) out[i + k] ^= ks;
  }
  return out;
}

const ALGOS = {
  'xor-chain-word': { fn: xorChainWords, params: { width: [4], direction: ['down', 'up'], key0: [0] } },
  'rolling-xor': { fn: rollingXor, params: { reverse: [false, true], key0: [0] } },
  'rolling-add': { fn: rollingAdd, params: { reverse: [false, true] } },
  'single-xor': { fn: singleByte, params: { mode: ['xor'], key: range(256) } },
  'single-add': { fn: singleByte, params: { mode: ['add'], key: range(256) } },
};

function range(n) { return Array.from({ length: n }, (_, i) => i); }

// ───────────────────────── 打分：可判读性 ─────────────────────────
// 不猜语义，只用确定性指标：
//   · 可打印比例（文本/明文）
//   · 高熵惩罚（密文熵高）
//   · x86 指令合法性（x86 代码 blob）——用 capstone（若可用）
//   · 零字节比例（空白填充多 = 像代码/结构体）

function printableRatio(buf) {
  if (!buf.length) return 0;
  let n = 0;
  for (const b of buf) if ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13) n++;
  return n / buf.length;
}

function entropy(buf) {
  if (!buf.length) return 0;
  const cnt = new Array(256).fill(0);
  for (const b of buf) cnt[b]++;
  let h = 0;
  for (const c of cnt) { if (c) { const p = c / buf.length; h -= p * Math.log2(p); } }
  return h;
}

function zeroRatio(buf) {
  if (!buf.length) return 0;
  let n = 0;
  for (const b of buf) if (!b) n++;
  return n / buf.length;
}

/** 用 capstone 评估"这段字节能解出多少条合法指令"（仅 x86-64） */
function disasmQuality(buf) {
  try {
    const cs = require('capstone') || null;
    if (!cs) return null;
    return { available: false };
  } catch (e) {
    return null;
  }
}

// Python 侧做 capstone 评估更可靠（capstone 装在 python 里）
function disasmQualityViaPython(buf, arch) {
  const b64 = buf.toString('base64');
  const py = `
import sys, base64, json
try:
    import capstone
except ImportError:
    print(json.dumps({"available": False})); sys.exit(0)
data = base64.b64decode("${b64}")
arch = "${arch || 'x86'}"
try:
    if arch == 'x86':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif arch == 'riscv':
        md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32)
    else:
        print(json.dumps({"available": False})); sys.exit(0)
    insns = list(md.disasm(data, 0))
    covered = sum(i.size for i in insns)
    print(json.dumps({
        "available": True,
        "insn_count": len(insns),
        "covered": covered,
        "total": len(data),
        "coverage": round(covered / max(1, len(data)), 3),
    }))
except Exception as e:
    print(json.dumps({"available": False, "error": str(e)}))
`;
  try {
    const out = execFileSync('python', ['-I', '-c', py], { encoding: 'utf8', timeout: 30000 });
    return JSON.parse(out.trim());
  } catch (e) {
    return null;
  }
}

/**
 * 给解密结果打分（越高越像"解对了"）。
 * kind: 'code' | 'text' | 'data'
 */
function scoreResult(buf, kind) {
  const pr = printableRatio(buf);
  const zr = zeroRatio(buf);
  const ent = entropy(buf);
  let score = 0;
  if (kind === 'text') {
    score = pr * 100 - ent * 3;
  } else if (kind === 'code') {
    const dq = disasmQualityViaPython(buf, 'x86');
    if (dq && dq.available) {
      // 覆盖率是主信号：解对了应该几乎全覆盖（除了尾部填充）
      score = dq.coverage * 120 + zr * 10 - Math.max(0, ent - 6) * 5;
    } else {
      // capstone 不可用时退化为启发式：代码里 0x00/0x90 常见，且熵不会太高
      score = zr * 40 + (1 - Math.abs(ent - 5) / 8) * 30;
    }
  } else {
    score = (1 - Math.abs(ent - 4) / 8) * 50 + zr * 20;
  }
  return { score: Number(score.toFixed(3)), printableRatio: Number(pr.toFixed(3)), entropy: Number(ent.toFixed(3)), zeroRatio: Number(zr.toFixed(3)) };
}

/**
 * 从一段 stub 反汇编文本里**抽取解密参数**。
 * 支持 elfstudy 那种形态：
 *   lea rdi,[rbx+0x71]        → 密文起点 = 基址 + 0x71
 *   mov ecx,0xcb              → 循环计数
 *   xor dword [rdi+rcx*4],eax → 宽度 4
 *   add eax,[rdi+rcx*4]       → key 累加
 *   loop ...                  → 递减方向
 * 也支持常见变体；抽不到的字段返回 null，由调用方用默认值搜索。
 *
 * @param {string} asmText
 * @returns {object} { width, count, direction, key0, accumulate, cipherOffsetHint, evidence[] }
 */
function parseStubParams(asmText) {
  const t = String(asmText || '');
  const ev = [];
  const r = { width: null, count: null, direction: null, key0: null, accumulate: null, cipherOffsetHint: null, evidence: ev };

  // 宽度：xor dword/word/byte ptr [...]
  const mw = t.match(/xor\s+(dword|word|byte)\s+(?:ptr\s+)?\[/i);
  if (mw) {
    r.width = mw[1].toLowerCase() === 'dword' ? 4 : (mw[1].toLowerCase() === 'word' ? 2 : 1);
    ev.push(`宽度 ${r.width}（来自 \`xor ${mw[1]} ptr [...]\`）`);
  }
  // 计数：mov ecx, 0xN / mov rcx, N（取循环前最后一个）
  const mc = [...t.matchAll(/mov\s+(?:e|r)cx\s*,\s*(?:0x[0-9a-f]+|\d+)/gi)];
  if (mc.length) {
    const last = mc[mc.length - 1][0];
    const v = last.match(/(0x[0-9a-f]+|\d+)$/i)[0];
    r.count = /^0x/i.test(v) ? parseInt(v, 16) : parseInt(v, 10);
    ev.push(`循环计数 ${r.count}（来自 \`${last.trim()}\`）`);
  }
  // 方向：loop 且索引递减 → down
  if (/\bloop\b/i.test(t) && /sub\s+(?:e|r)cx|dec\s+(?:e|r)cx|loop/i.test(t)) {
    r.direction = 'down';
    ev.push('方向 down（`loop` 递减计数）');
  }
  // key 累加：add eax, [rdi+rcx*4]
  if (/add\s+(?:e|r)ax\s*,\s*(?:dword\s+)?\[/i.test(t)) {
    r.accumulate = true;
    ev.push('key 累加（`add eax, [...]`）');
  }
  // key 初值：xor eax,eax
  if (/xor\s+(?:e|r)ax\s*,\s*(?:e|r)ax/i.test(t)) {
    r.key0 = 0;
    ev.push('key 初值 0（`xor eax,eax`）');
  }
  // 密文偏移：lea rdi,[rbx+0xNN] / lea rdi,[rip+0xNN]
  const ml = t.match(/lea\s+(?:r|e)di\s*,\s*\[\s*\w+\s*\+\s*(0x[0-9a-f]+|\d+)\s*\]/i);
  if (ml) {
    r.cipherOffsetHint = ml[1];
    ev.push(`密文偏移提示 ${ml[1]}（来自 \`${ml[0].trim()}\`）`);
  }
  return r;
}

/**
 * 穷举候选算法 + 参数，按分数排序。
 * @param {Buffer} cipher
 * @param {object} opts { kind:'code'|'text'|'data', keys?:number[], widths?:number[], limit?:number }
 */
function autoDecrypt(cipher, opts) {
  const o = opts || {};
  const kind = o.kind || 'code';
  const limit = o.limit || 8;
  const results = [];
  const push = (algo, params, out) => {
    const sc = scoreResult(out, kind);
    results.push({
      algo,
      params,
      score: sc.score,
      metrics: sc,
      head: out.slice(0, 32).toString('hex'),
      preview: out.slice(0, 64).toString('latin1').replace(/[^\x20-\x7e]/g, '.'),
      _out: out,
    });
  };

  // 1) 链式 XOR（word 宽度）
  for (const width of (o.widths || [4, 8, 2])) {
    for (const direction of ['down', 'up']) {
      for (const key0 of (o.keys || [0])) {
        try { push('xor-chain-word', { width, direction, key0 }, xorChainWords(cipher, { width, direction, key0 })); } catch (e) { /* skip */ }
      }
    }
  }
  // 2) 滚动 XOR/ADD
  for (const reverse of [false, true]) {
    push('rolling-xor', { reverse }, rollingXor(cipher, { reverse }));
    push('rolling-add', { reverse }, rollingAdd(cipher, { reverse }));
  }
  // 3) 单字节（只在大候选集时跑，否则太慢）
  if (o.single !== false) {
    for (let k = 0; k < 256; k++) {
      push('single-xor', { key: k }, singleByte(cipher, { mode: 'xor', key: k }));
      push('single-add', { key: k }, singleByte(cipher, { mode: 'add', key: k }));
    }
  }
  // 4) 周期 XOR（长度 2..8，密钥由已知明文攻击无法做，这里只试"密钥=0"的平凡解 → 跳过）
  // 5) 原样（作为基线）
  push('none', {}, Buffer.from(cipher));

  results.sort((a, b) => b.score - a.score);
  const top = results.slice(0, limit);
  return { kind, total: results.length, top, best: top[0] };
}

/** 生成可复现的 Python 脚本 */
function buildDecryptScript(cipherPath, offset, length, algo, params, outPath) {
  const pyParams = JSON.stringify(params || {});
  return `# 由 ctf-tool 的 blob-decrypt 自动生成：按指定参数复现同一解密
import struct, json, sys
P = json.loads('''${pyParams}''')
data = open(r"${cipherPath}", 'rb').read()[${offset}:${offset} + ${length}]

def xor_chain_words(buf, p):
    out = bytearray(buf); w = p.get('width', 4); n = len(out) // w
    key = p.get('key0', 0) & 0xffffffff
    mask = (1 << (w*8)) - 1
    rng = range(n-1, 0, -1) if p.get('direction') != 'up' else range(1, n)
    for i in rng:
        c = int.from_bytes(out[i*w:(i+1)*w], 'little')
        pv = (c ^ key) & mask
        out[i*w:(i+1)*w] = pv.to_bytes(w, 'little')
        key = (key + pv) & mask
    return bytes(out)

def rolling_xor(buf, p):
    out = bytearray(buf)
    if p.get('reverse'):
        for i in range(1, len(out)): out[i] ^= out[i-1]
    else:
        for i in range(len(out)-1, 0, -1): out[i] ^= out[i-1]
    return bytes(out)

def rolling_add(buf, p):
    out = bytearray(buf)
    if p.get('reverse'):
        for i in range(1, len(out)): out[i] = (out[i] - out[i-1]) & 0xff
    else:
        for i in range(len(out)-1, 0, -1): out[i] = (out[i] - out[i-1]) & 0xff
    return bytes(out)

def single(buf, p):
    k = p['key']; m = p.get('mode','xor')
    return bytes(((b ^ k) if m == 'xor' else ((b - k) & 0xff)) for b in buf)

FN = {'xor-chain-word': xor_chain_words, 'rolling-xor': rolling_xor,
      'rolling-add': rolling_add, 'single-xor': single, 'single-add': single,
      'none': lambda b, p: bytes(b)}
out = FN["${algo}"](data, P)
open(r"${outPath}", 'wb').write(out)
print("WROTE", r"${outPath}", len(out), "bytes")
`;
}

module.exports = {
  xorChainWords, rollingXor, rollingAdd, periodic, singleByte, lcgStream,
  ALGOS, parseStubParams, autoDecrypt, scoreResult, buildDecryptScript,
  printableRatio, entropy, zeroRatio, disasmQualityViaPython,
};
