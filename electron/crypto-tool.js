'use strict';
// 对称/摘要算法工具箱（离线，等价于 toolhelper / CyberChef 的加解密页）。
//
// 为什么不用在线站点：
//   · toolhelper 的加解密是**服务端**计算（前端只发 POST /SymmetricEncryption/AesEncrypt），
//     实测带 cookie/Referer 仍返回「非法访问」——它有反自动化校验，不适合工具内嵌。
//   · 在线站还意味着题目数据外发；CTF 样本/密文不应离开本机。
//   · CyberChef 官方 npm 包体量巨大（含 tesseract/argon2 等），为一个 decrypt 操作不值得。
//
// 本模块用 crypto-js（AES/DES/3DES/RC4/Rabbit/哈希/HMAC）与 sm-crypto（SM2/SM3/SM4）离线实现，
// 覆盖 toolhelper 对称加密与摘要页的全部算法，且是确定性的、可在单测里逐字节验证。
//
// 边界：不做"解密 MD5"这种不成立的操作。哈希是单向的；能做的只有**有界字典反查**
// （见 recipe.js 的 crack），且必须如实告知未命中。

const crypto = require('crypto');

let CryptoJS = null;
let smCrypto = null;
function libs() {
  if (!CryptoJS) {
    // 延迟加载：只有真正调用时才 require，避免影响启动时间
    CryptoJS = require('crypto-js');
    smCrypto = require('sm-crypto');
  }
  return { CryptoJS, smCrypto };
}

// ---------- 编码 ----------
// ⚠️ crypto-js 的 WordArray 是 **big-endian word** 语义：
// C.lib.WordArray.create([...bytes]) 会把 4 个字节拼成一个 word 时按 BE 解释，
// 直接拿它喂 MD5 会得到**错误的摘要**（实测 MD5('abc') 变成 2fd36776… 而非 90015098…）。
// 因此文本一律走 C.enc.Utf8.parse(s)（它内部按字节正确排布），
// 二进制一律先转 Latin1 字符串再 parse —— 这样每个 char 恰好一个字节。
function parseBytes(value, format) {
  const { CryptoJS: C } = libs();
  const f = String(format || 'utf8').toLowerCase();
  if (Buffer.isBuffer(value)) {
    const buf = value;
    return { buf, wa: C.enc.Latin1.parse(buf.toString('latin1')) };
  }
  const s = value == null ? '' : String(value);
  if (f === 'hex') {
    const clean = s.replace(/[^0-9a-fA-F]/g, '');
    const buf = Buffer.from(clean, 'hex');
    return { buf, wa: C.enc.Latin1.parse(buf.toString('latin1')) };
  }
  if (f === 'base64') {
    const buf = Buffer.from(s, 'base64');
    return { buf, wa: C.enc.Latin1.parse(buf.toString('latin1')) };
  }
  if (f === 'latin1' || f === 'binary') {
    return { buf: Buffer.from(s, 'latin1'), wa: C.enc.Latin1.parse(s) };
  }
  if (f === 'utf16le') {
    const buf = Buffer.from(s, 'utf16le');
    return { buf, wa: C.enc.Latin1.parse(buf.toString('latin1')) };
  }
  return { buf: Buffer.from(s, 'utf8'), wa: C.enc.Utf8.parse(s) };
}

// WordArray（BE word 语义）→ Buffer。必须按 BE 逐字节展开，
// 不能直接 wordArrayToBuffer 之类按 LE 处理。
function waToBuffer(wa) {
  const words = wa.words || [];
  const sigBytes = wa.sigBytes != null ? wa.sigBytes : words.length * 4;
  const buf = Buffer.alloc(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    buf[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return buf;
}

function formatOut(buf, wa, format) {
  const f = String(format || 'hex').toLowerCase();
  if (f === 'hex') return buf.toString('hex');
  if (f === 'base64') return buf.toString('base64');
  if (f === 'utf8' || f === 'text') return buf.toString('utf8');
  if (f === 'latin1') return buf.toString('latin1');
  if (f === 'utf16le') return buf.toString('utf16le');
  if (f === 'wordarray') return wa;
  return buf.toString('hex');
}

// ---------- 对称加密 ----------
const CIPHER_MODES = {
  cbc: (C) => C.mode.CBC,
  ecb: (C) => C.mode.ECB,
  cfb: (C) => C.mode.CFB,
  ofb: (C) => C.mode.OFB,
  ctr: (C) => C.mode.CTR,
};

const PADDINGS = {
  pkcs7: (C) => C.pad.Pkcs7,
  none: (C) => C.pad.NoPadding,
  zeros: (C) => C.pad.ZeroPadding,
  iso10126: (C) => C.pad.Iso10126,
  iso97971: (C) => C.pad.Iso97971,
  ansix923: (C) => C.pad.AnsiX923,
};

// algo: aes | des | tripledes | rc4 | rabbit
// opts: { mode, padding, key, keyFormat, iv, ivFormat, inputFormat, outputFormat }
function symmetric(algo, action, input, opts) {
  const { CryptoJS: C } = libs();
  const o = opts || {};
  const a = String(algo || 'aes').toLowerCase().replace(/[-_]/g, '');
  const act = String(action || 'encrypt').toLowerCase();

  const keyParsed = parseBytes(o.key, o.keyFormat);
  const keyWA = keyParsed.wa;

  // 流密码：没有 mode/iv
  if (a === 'rc4' || a === 'rabbit') {
    const Block = a === 'rc4' ? C.RC4 : C.Rabbit;
    if (act === 'encrypt') {
      const r = Block.encrypt(parseBytes(input, o.inputFormat).wa, keyWA);
      const buf = waToBuffer(r.ciphertext);
      return { ok: true, algo: a, action: act, output: formatOut(buf, r.ciphertext, o.outputFormat || 'hex'), bytes: buf.length };
    }
    const ct = o.inputFormat === 'base64'
      ? C.enc.Base64.parse(String(input))
      : C.enc.Hex.parse(String(input).replace(/[^0-9a-fA-F]/g, ''));
    const r = Block.decrypt({ ciphertext: ct }, keyWA);
    const buf = waToBuffer(r);
    return { ok: true, algo: a, action: act, output: formatOut(buf, r, o.outputFormat || 'utf8'), bytes: buf.length };
  }

  const Blocks = { aes: C.AES, des: C.DES, tripledes: C.TripleDES };
  const Block = Blocks[a];
  if (!Block) return { ok: false, error: `不支持的算法: ${algo}（可用 aes/des/tripledes/rc4/rabbit）` };

  const modeName = String(o.mode || 'cbc').toLowerCase();
  const padName = String(o.padding || 'pkcs7').toLowerCase();
  const mode = (CIPHER_MODES[modeName] || CIPHER_MODES.cbc)(C);
  const padding = (PADDINGS[padName] || PADDINGS.pkcs7)(C);
  const cfg = { mode, padding };
  if (modeName !== 'ecb') {
    if (o.iv == null || o.iv === '') return { ok: false, error: `${modeName.toUpperCase()} 模式需要 iv` };
    cfg.iv = parseBytes(o.iv, o.ivFormat).wa;
  }

  if (act === 'encrypt') {
    const r = Block.encrypt(parseBytes(input, o.inputFormat).wa, keyWA, cfg);
    const buf = waToBuffer(r.ciphertext);
    return { ok: true, algo: a, action: act, output: formatOut(buf, r.ciphertext, o.outputFormat || 'hex'), bytes: buf.length };
  }

  const ctWA = parseBytes(input, o.inputFormat === 'utf8' ? 'hex' : (o.inputFormat || 'hex')).wa;
  const r = Block.decrypt({ ciphertext: ctWA }, keyWA, cfg);
  const buf = waToBuffer(r);
  // 解密结果常常是二进制；text 只在可打印时给
  const printable = buf.length ? buf.every(b => b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) : false;
  return {
    ok: true, algo: a, action: act,
    output: formatOut(buf, r, o.outputFormat || (printable ? 'utf8' : 'hex')),
    bytes: buf.length,
    printable,
  };
}

// ---------- SM4 ----------
// sm-crypto 的 sm4 只支持 ECB/CBC。输入必须是**字节数组**：
// 传字符串时它走 utf8ToArray，>=0x80 的字节会被扩成 2 字节，密文必然错位。
function sm4(action, input, opts) {
  const { smCrypto: S } = libs();
  const o = opts || {};
  const keyHex = normalizeKeyHex(o.key, o.keyFormat, 32);
  if (keyHex.error) return { ok: false, error: keyHex.error };
  const mode = String(o.mode || 'ecb').toLowerCase();
  const padName = String(o.padding || 'pkcs7').toLowerCase();

  const inBuf = parseBytes(input, o.inputFormat).buf;
  let ivHex = null;
  if (mode === 'cbc') {
    const iv = normalizeKeyHex(o.iv, o.ivFormat, 32);
    if (iv.error) return { ok: false, error: 'CBC 需要 iv（16 字节 / 32 hex）' };
    ivHex = iv.value;
  } else if (mode !== 'ecb') {
    return { ok: false, error: `sm-crypto 仅支持 sm4 的 ecb/cbc（请求 ${mode}）` };
  }

  // sm-crypto 的 padding 只认 'pkcs#5' / 'pkcs#7' / 'none'
  const opt = {};
  if (ivHex) { opt.mode = 'cbc'; opt.iv = ivHex; }
  if (padName === 'none' || padName === 'zero' || padName === 'zeros') opt.padding = 'none';

  if (String(action).toLowerCase() === 'encrypt') {
    // ⚠️ 必须传**字节数组**，不能传字符串：sm-crypto 对字符串输入走 utf8ToArray，
    // 任何 >=0x80 的字节会被扩成 2 字节，导致密文错位（实测国标向量对不上）。
    let ct;
    try { ct = S.sm4.encrypt(Array.from(inBuf), keyHex.value, opt); }
    catch (e) { return { ok: false, error: 'SM4 加密失败: ' + e.message }; }
    if (!ct) return { ok: false, error: 'SM4 加密失败（检查 key/iv 长度）' };
    return { ok: true, algo: 'sm4', action: 'encrypt', output: ct, bytes: ct.length / 2 };
  }

  let ptLatin1;
  // ⚠️ 必须显式 output:'array'：默认输出是"把字节当 Unicode 码点拼成字符串"，
  // 0x80~0xFF 的字节会变成多字节序列，转回 Buffer 时已经损坏
  // （实测 16 字节明文解密后变成 20 字节，0x89 变 c289）。
  try { ptLatin1 = S.sm4.decrypt(Array.from(inBuf), keyHex.value, Object.assign({ output: 'array' }, opt)); }
  catch (e) {
    return {
      ok: false,
      error: 'SM4 解密失败: ' + e.message +
        '（常见原因：密文不是 16 字节倍数、key 不对，或密文本身没做 PKCS7 填充却按默认去填充——' +
        '这种情况下传 padding:"none" 再试）',
    };
  }
  // ⚠️ 传数组时 sm-crypto 的 decrypt 返回**数组**（传字符串才返回字符串）；
  // 若这里按 latin1 处理数组，>=0x80 的字节会被 UTF-8 重新编码而损坏。
  const buf = Buffer.isBuffer(ptLatin1)
    ? ptLatin1
    : (Array.isArray(ptLatin1)
      ? Buffer.from(ptLatin1)
      : (typeof ptLatin1 === 'string' ? Buffer.from(ptLatin1, 'latin1') : Buffer.alloc(0)));
  if (!buf.length) {
    return { ok: false, error: 'SM4 解密失败（密文/密钥不匹配，或长度不是 16 的倍数）' };
  }
  const printable = buf.length ? buf.every(b => b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) : false;
  return {
    ok: true, algo: 'sm4', action: 'decrypt',
    output: formatOut(buf, null, o.outputFormat || (printable ? 'utf8' : 'hex')),
    bytes: buf.length,
    printable,
  };
}

// 把 key/iv 归一成 hex。utf8 输入按字节转 hex；hex 输入校验长度。
function normalizeKeyHex(v, format, hexLen) {
  if (v == null || v === '') return { error: 'key 不能为空' };
  const f = String(format || 'utf8').toLowerCase();
  let hex;
  if (f === 'hex') hex = String(v).replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  else hex = Buffer.from(String(v), 'utf8').toString('hex');
  if (hex.length !== hexLen) {
    return { error: `key 长度不符：需要 ${hexLen / 2} 字节（${hexLen} hex），实际 ${hex.length / 2} 字节` };
  }
  return { value: hex };
}

// ---------- 摘要 ----------
// algo: md5 | sha1 | sha256 | sha512 | sha3 | ripemd160 | sm3 | crc32
function digest(algo, input, opts) {
  const { CryptoJS: C, smCrypto: S } = libs();
  const o = opts || {};
  const a = String(algo || 'md5').toLowerCase().replace(/[-_]/g, '');
  const bytes = parseBytes(input, o.inputFormat).buf;

  if (a === 'sm3') return { ok: true, algo: 'sm3', output: S.sm3(Array.from(bytes)) };
  if (a === 'crc32') {
    // CRC32（IEEE，与 zlib/crc32 一致）
    let c;
    const table = (() => {
      const t = new Int32Array(256);
      for (let n = 0; n < 256; n++) {
        c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c;
      }
      return t;
    })();
    let crc = -1;
    for (const b of bytes) crc = (crc >>> 8) ^ table[(crc ^ b) & 0xff];
    return { ok: true, algo: 'crc32', output: ((crc ^ -1) >>> 0).toString(16).padStart(8, '0') };
  }

  const map = {
    md5: () => C.MD5, sha1: () => C.SHA1, sha224: () => C.SHA224,
    sha256: () => C.SHA256, sha384: () => C.SHA384, sha512: () => C.SHA512,
    sha3: () => C.SHA3, ripemd160: () => C.RIPEMD160,
  };
  const get = map[a];
  if (!get) return { ok: false, error: `不支持的摘要算法: ${algo}` };
  // 用 Utf8.parse 喂 ASCII 结果无差异；二进制已在 parseBytes 里转成 Latin1 一对一字节
  const msgWA = parseBytes(input, o.inputFormat).wa;
  const out = get().call(C, msgWA).toString(C.enc.Hex);
  return { ok: true, algo: a, output: out };
}

// ---------- HMAC ----------
function hmac(algo, input, opts) {
  const { CryptoJS: C } = libs();
  const o = opts || {};
  const a = String(algo || 'sha256').toLowerCase().replace(/[-_]/g, '');
  const keyWA = parseBytes(o.key, o.keyFormat).wa;
  const msgWA = parseBytes(input, o.inputFormat).wa;
  const map = { md5: C.HmacMD5, sha1: C.HmacSHA1, sha256: C.HmacSHA256, sha512: C.HmacSHA512, sha3: C.HmacSHA3 };
  const fn = map[a];
  if (!fn) return { ok: false, error: `不支持的 HMAC 算法: ${algo}` };
  return { ok: true, algo: `hmac-${a}`, output: fn(msgWA, keyWA).toString(C.enc.Hex) };
}

// ---------- 统一入口 ----------
/**
 * @param {object} input
 *   { op: 'symmetric'|'sm4'|'digest'|'hmac',
 *     algo, action, data, data_format,
 *     key, key_format, iv, iv_format, mode, padding, output_format }
 */
function runCryptoTool(input) {
  const i = input || {};
  const op = String(i.op || '').toLowerCase();
  const data = i.data != null ? i.data : (i.input != null ? i.input : '');
  try {
    if (op === 'symmetric') {
      return symmetric(i.algo, i.action, data, {
        key: i.key, keyFormat: i.key_format, iv: i.iv, ivFormat: i.iv_format,
        mode: i.mode, padding: i.padding, inputFormat: i.data_format, outputFormat: i.output_format,
      });
    }
    if (op === 'sm4') {
      return sm4(i.action, data, {
        key: i.key, keyFormat: i.key_format, iv: i.iv, ivFormat: i.iv_format,
        mode: i.mode, padding: i.padding, inputFormat: i.data_format, outputFormat: i.output_format,
      });
    }
    if (op === 'digest') {
      return digest(i.algo, data, { inputFormat: i.data_format });
    }
    if (op === 'hmac') {
      return hmac(i.algo, data, { key: i.key, keyFormat: i.key_format, inputFormat: i.data_format });
    }
    return { ok: false, error: `未知 op: ${i.op}（可用 symmetric/sm4/digest/hmac）` };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

module.exports = {
  runCryptoTool, symmetric, sm4, digest, hmac,
  parseBytes, normalizeKeyHex,
  // 供测试
  _libs: libs,
};
