'use strict';
// 操作链执行器：把"CyberChef 式的有限操作组合"变成一次确定性的工具调用。
//
// 为什么需要：实测里 AI 反复手写脚本做同样的变换（base64 → xor → 反转 → 解压），
// 每次都要生成代码、处理异常、自己判断哪一层解出了可打印内容，烧掉几十轮预算。
// 这些操作本身是**有界且确定**的，应该由工具一次跑完并把每一层的结果摊开给 AI 看。
//
// 设计边界（重要）：
//   · 这是"变换链"，不是"破解器"。它不做密钥搜索之外的猜测，不联网，不执行外部程序。
//   · 每一步都附带 `printable`/`entropy`/`preview`，让 AI 自己判断哪一层是有效明文。
//   · 哈希是单向的：`hash` 只能正向计算；反向只能走 `crack`（字典 + 规则，有界）。
//   · 未知/不支持的操作直接报错，不静默跳过——静默跳过会让 AI 以为执行过。

const crypto = require('crypto');
const zlib = require('zlib');

// ---------- 输入/输出规范化 ----------
// 统一用 Buffer 在步骤间传递；文本步骤按 utf8 处理，二进制步骤保留字节。

function toBuffer(value, encoding) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  const s = value == null ? '' : String(value);
  const enc = String(encoding || 'utf8').toLowerCase();
  if (enc === 'hex') {
    const clean = s.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
    return Buffer.from(clean.length % 2 ? clean.slice(0, -1) : clean, 'hex');
  }
  if (enc === 'base64') return Buffer.from(s.replace(/\s+/g, ''), 'base64');
  if (enc === 'latin1' || enc === 'binary') return Buffer.from(s, 'latin1');
  if (enc === 'utf16le' || enc === 'utf-16le') return Buffer.from(s, 'utf16le');
  return Buffer.from(s, 'utf8');
}

// 文本 vs 二进制：可打印率 > 0.85 且无 NUL 视为文本。
function printableRatio(buf) {
  if (!buf || !buf.length) return 0;
  let ok = 0;
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c === 9 || c === 10 || c === 13) { ok++; continue; }
    if (c >= 0x20 && c < 0x7f) { ok++; continue; }
    if (c >= 0x80) { ok += 0.5; } // 可能是 UTF-8 多字节，给半权
  }
  return ok / n;
}

function entropy(buf) {
  if (!buf || !buf.length) return 0;
  const freq = new Array(256).fill(0);
  const n = Math.min(buf.length, 1 << 20);
  for (let i = 0; i < n; i++) freq[buf[i]]++;
  let h = 0;
  for (const c of freq) {
    if (!c) continue;
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function previewOf(buf, max = 160) {
  const b = buf.subarray(0, max);
  const text = b.toString('utf8');
  // 含大量替换符说明不是合法 UTF-8 → 用 latin1 + 可打印过滤
  const printable = (text.match(/\uFFFD/g) || []).length > max * 0.2
    ? b.toString('latin1').replace(/[^\x20-\x7e]/g, '.')
    : text.replace(/[^\x20-\x7e\n\r\t\u4e00-\u9fff]/g, '.');
  return printable.replace(/\s+/g, ' ').trim().slice(0, max);
}

function describe(buf) {
  return {
    len: buf.length,
    hex: buf.length <= 64 ? buf.toString('hex') : buf.subarray(0, 64).toString('hex') + '…',
    preview: previewOf(buf),
    printable: Math.round(printableRatio(buf) * 1000) / 1000,
    entropy: Math.round(entropy(buf) * 100) / 100,
  };
}

// ---------- 操作实现 ----------
// 每个 op: { name, run(buf, args) -> Buffer, note(args) -> string }

const OPS = {};

function def(name, run, note) { OPS[name] = { name, run, note }; }

// —— 编码/解码 ——
def('from_hex', (b, a) => toBuffer(b.toString('latin1'), 'hex'), a => '把文本按十六进制读入');
def('to_hex', (b, a) => Buffer.from(b.toString('hex'), 'utf8'), a => '输出十六进制字符串');
def('from_base64', (b, a) => toBuffer(b.toString('latin1'), 'base64'), a => 'Base64 解码');
def('to_base64', (b, a) => Buffer.from(b.toString('base64'), 'utf8'), a => 'Base64 编码');
def('from_base32', (b, a) => fromBaseN(b.toString('latin1').replace(/=+$/, ''), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 5), a => 'Base32 解码');
def('to_base32', (b, a) => Buffer.from(toBaseN(b, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 5), 'utf8'), a => 'Base32 编码');
def('url_decode', (b, a) => Buffer.from(decodeURIComponent(b.toString('utf8').replace(/\+/g, ' ')), 'utf8'), a => 'URL 解码');
def('url_encode', (b, a) => Buffer.from(encodeURIComponent(b.toString('utf8')), 'utf8'), a => 'URL 编码');

// Base-N 通用实现（位流拼接）。base64 也有，但自定义字母表的题很常见。
function fromBaseN(s, alphabet, bitsPerChar) {
  const idx = new Map();
  for (let i = 0; i < alphabet.length; i++) idx.set(alphabet[i], i);
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    if (/\s/.test(ch)) continue;
    const v = idx.get(ch);
    if (v === undefined) continue;
    value = (value << bitsPerChar) | v;
    bits += bitsPerChar;
    while (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}
function toBaseN(buf, alphabet, bitsPerChar) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= bitsPerChar) {
      bits -= bitsPerChar;
      out += alphabet[(value >>> bits) & ((1 << bitsPerChar) - 1)];
    }
  }
  if (bits > 0) out += alphabet[(value << (bitsPerChar - bits)) & ((1 << bitsPerChar) - 1)];
  return out;
}

def('custom_base64', (b, a) => {
  // 用题目给的 64 字符表解码（改表 Base64 的通用解法）
  const alpha = String(a.alphabet || a.table || '');
  if (alpha.length !== 64) throw new Error('custom_base64 需要 alphabet（64 个字符）');
  return fromBaseN(b.toString('latin1').replace(/=+$/, ''), alpha, 6);
}, a => '按自定义 64 字符表做 Base64 解码');

// —— 压缩/容器 ——
def('gunzip', (b) => zlib.gunzipSync(b), () => 'gzip 解压');
def('zlib_inflate', (b) => zlib.inflateSync(b), () => 'zlib 解压（raw deflate 之前的常见封装）');
def('zlib_deflate_raw', (b) => zlib.inflateRawSync(b), () => 'raw deflate 解压');
def('bzip2', (b) => {
  // Node 无内置 bzip2：明确报错而不是静默返回原值
  throw new Error('bzip2 未内置（Node 标准库不支持）。可改用 remote_exec 在 Kali 上 bzip2 -d');
}, () => 'bzip2 解压（未内置）');

// —— 字节级变换 ——
def('reverse', (b) => Buffer.from(b).reverse(), () => '整体字节反转');
def('reverse_each_4', (b) => {
  const out = Buffer.from(b);
  for (let i = 0; i + 4 <= out.length; i += 4) out.writeUInt32LE(out.readUInt32BE(i), i);
  return out;
}, () => '每 4 字节按大端/小端互换');
def('xor', (b, a) => {
  const key = toBuffer(a.key, a.key_encoding || 'hex');
  if (!key.length) throw new Error('xor 需要 key（hex 或 text，用 key_encoding 指定）');
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[i] ^ key[i % key.length];
  return out;
}, a => '循环 XOR（key 支持 hex/text）');
def('add', (b, a) => {
  const k = Number(a.key);
  if (!Number.isFinite(k)) throw new Error('add 需要数字 key');
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) out[i] = (b[i] + k) & 0xff;
  return out;
}, a => '逐字节加常量 mod 256');
def('sub', (b, a) => {
  const k = Number(a.key);
  if (!Number.isFinite(k)) throw new Error('sub 需要数字 key');
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) out[i] = (b[i] - k + 256) & 0xff;
  return out;
}, a => '逐字节减常量 mod 256');
def('rot', (b, a) => {
  const n = Number(a.n == null ? 13 : a.n);
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c >= 0x41 && c <= 0x5a) out[i] = ((c - 0x41 + n) % 26) + 0x41;
    else if (c >= 0x61 && c <= 0x7a) out[i] = ((c - 0x61 + n) % 26) + 0x61;
    else out[i] = c;
  }
  return out;
}, a => '字母 ROT-N（默认 13，只影响 A-Z/a-z）');
def('bit_shift', (b, a) => {
  const n = Number(a.n || 1) & 7;
  const left = a.direction === 'left';
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) {
    out[i] = left ? ((b[i] << n) | (b[i] >> (8 - n))) & 0xff : ((b[i] >> n) | (b[i] << (8 - n))) & 0xff;
  }
  return out;
}, a => '8 位循环移位（direction=left/right，n=位数）');

// —— 文本/哈希 ——
def('to_upper', (b) => Buffer.from(b.toString('utf8').toUpperCase(), 'utf8'), () => '转大写');
def('to_lower', (b) => Buffer.from(b.toString('utf8').toLowerCase(), 'utf8'), () => '转小写');
def('trim', (b) => Buffer.from(b.toString('utf8').trim(), 'utf8'), () => '去掉首尾空白');
def('slice', (b, a) => {
  const s = Number(a.start || 0);
  const e = a.end == null ? b.length : Number(a.end);
  return b.subarray(s < 0 ? Math.max(0, b.length + s) : s, e < 0 ? Math.max(0, b.length + e) : e);
}, a => `按字节切片 [${a.start == null ? 0 : a.start}, ${a.end == null ? '末尾' : a.end})`);
def('utf16le_decode', (b) => Buffer.from(b.toString('utf16le'), 'utf8'), () => 'UTF-16LE 解码为 UTF-8 文本');
def('utf16le_encode', (b) => Buffer.from(b.toString('utf8'), 'utf16le'), () => 'UTF-8 文本编码为 UTF-16LE');

def('hash', (b, a) => {
  const algo = String(a.algo || 'md5').toLowerCase().replace('-', '');
  const h = crypto.createHash(algo);
  h.update(b);
  return Buffer.from(h.digest('hex'), 'utf8');
}, a => `计算 ${a.algo || 'md5'} 摘要（单向）`);

// ---------- 有界的哈希反查 ----------
// 只做「字典 + 简单规则」的命中，明确标注这是有界尝试，不是穷举。
const COMMON = [
  'admin', 'password', '123456', '12345678', '123456789', 'qwerty', 'abc123', 'letmein',
  'root', 'toor', 'test', 'guest', 'flag', 'ctf', 'challenge', 'secret', 'key', 'hello',
  'welcome', 'iloveyou', 'monkey', 'dragon', 'master', 'sunshine', 'princess', 'shadow',
  'superman', 'michael', 'football', 'baseball', 'whatever', 'trustno1', 'freedom',
  '1', '12', '123', '1234', '12345', '0', '00', '000', '0000', '111', '1111', '666', '888',
];

function dictionaryOf(extra) {
  const set = new Set(COMMON);
  if (Array.isArray(extra)) for (const s of extra) if (s) set.add(String(s));
  // 数字 0..9999（覆盖大量 CTF 里的纯数字口令）
  for (let i = 0; i < 10000; i++) set.add(String(i));
  return [...set];
}

def('crack', (b, a) => {
  // 输入是"目标摘要"（hex 文本），输出是命中的明文（找不到则原样返回并标注）
  const target = b.toString('utf8').trim().toLowerCase();
  const algo = String(a.algo || (target.length === 32 ? 'md5' : target.length === 40 ? 'sha1' : 'md5'))
    .toLowerCase().replace('-', '');
  const dict = dictionaryOf(a.dictionary);
  const found = [];
  for (const word of dict) {
    const h = crypto.createHash(algo).update(word, 'utf8').digest('hex');
    if (h === target) { found.push(word); if (found.length >= 5) break; }
  }
  if (!found.length) {
    // 没命中：把原摘要原样返回，让上层明确知道"没找到"而不是"变成了别的"
    return Buffer.from(target, 'utf8');
  }
  return Buffer.from(found.join('\n'), 'utf8');
}, a => `有界字典反查（${a.algo || '自动'}；命中则输出明文，未命中原样返回）`);

// ---------- 执行器 ----------
/**
 * @param {string|Buffer} input
 * @param {Array<{op:string, [k:string]:any}>} recipe
 * @param {{inputEncoding?:string, maxSteps?:number}} opts
 * @returns {{ok:boolean, steps:Array, output:object|null, error?:string}}
 */
function runRecipe(input, recipe, opts) {
  const o = opts || {};
  const maxSteps = Math.min(Math.max(Number(o.maxSteps) || 20, 1), 50);
  const ops = Array.isArray(recipe) ? recipe : [];
  if (!ops.length) return { ok: false, steps: [], output: null, error: 'recipe 为空：需要至少一个操作' };
  if (ops.length > maxSteps) return { ok: false, steps: [], output: null, error: `步骤过多（${ops.length} > ${maxSteps}）` };

  let buf = toBuffer(input, o.inputEncoding);
  const steps = [];
  steps.push({ index: 0, op: '(input)', note: '原始输入', ...describe(buf) });

  for (let i = 0; i < ops.length; i++) {
    const step = ops[i] || {};
    const name = String(step.op || '').toLowerCase();
    const fn = OPS[name];
    if (!fn) {
      return {
        ok: false, steps, output: null,
        error: `第 ${i + 1} 步：未知操作 "${step.op}"。可用：${Object.keys(OPS).sort().join(', ')}`,
      };
    }
    try {
      const next = fn.run(buf, step);
      if (!Buffer.isBuffer(next)) throw new Error('操作未返回字节');
      buf = next;
      steps.push({ index: i + 1, op: name, note: fn.note(step), ...describe(buf) });
    } catch (e) {
      return { ok: false, steps, output: null, error: `第 ${i + 1} 步（${name}）失败：${e.message}` };
    }
  }

  return {
    ok: true, steps,
    output: {
      ...describe(buf),
      text: printableRatio(buf) > 0.85 ? buf.toString('utf8') : null,
      base64: buf.length <= 4096 ? buf.toString('base64') : null,
    },
  };
}

// 自动尝试"常见解码链"，返回所有产出可打印文本的组合（有界）。
// 用途：AI 拿到一个陌生 blob 时，一次调用就能看到几条最可能的解释。
function autoDecode(input, opts) {
  const o = opts || {};
  const chains = [
    ['from_base64'],
    ['from_hex'],
    ['from_base64', 'from_base64'],
    ['from_base64', 'from_hex'],
    ['from_hex', 'from_base64'],
    ['gunzip'],
    ['zlib_inflate'],
    ['zlib_deflate_raw'],
    ['from_base64', 'gunzip'],
    ['from_hex', 'gunzip'],
    ['reverse'],
    ['from_base64', 'reverse'],
    ['from_base64', 'gunzip', 'from_base64'],
    ['from_hex', 'xor'],
  ];
  const results = [];
  for (const chain of chains) {
    // xor 需要 key，自动模式跳过（避免瞎猜）
    if (chain.includes('xor')) continue;
    const recipe = chain.map((op) => ({ op }));
    const r = runRecipe(input, recipe, { inputEncoding: o.inputEncoding });
    if (!r.ok) continue;
    const last = r.steps[r.steps.length - 1];
    if (!last) continue;
    if (last.printable >= 0.85 || (last.entropy < 6 && last.printable > 0.6)) {
      results.push({ chain: chain.join(' → '), printable: last.printable, entropy: last.entropy, preview: last.preview, len: last.len, hex: last.hex });
    }
    if (results.length >= 8) break;
  }
  return results.sort((a, b) => b.printable - a.printable);
}

module.exports = {
  runRecipe,
  autoDecode,
  OPS,
  // 供测试复用
  printableRatio,
  entropy,
  previewOf,
  toBuffer,
  fromBaseN,
  toBaseN,
  dictionaryOf,
};
