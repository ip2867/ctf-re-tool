// 中间值自动推进（P2）
//
// 背景：工具原先只把「这是 32 位 hex，可能是 md5」写进提示词，让 AI 自己去爆破。
// 实测（CrackMe 系列）AI 往往不会主动爆破，于是整题停在"已算出 md5"。
// 这里把「形态可判 → 动作可定」的那部分**直接执行掉**：
//   哈希长度 → 字典/短串爆破；Base64 → 解码；短 hex → ASCII/UTF-16 解码；单字节 XOR 试解。
// 原则：只做**确定性、可验证**的推进（md5(x)==目标 就是硬证据），不猜题目。
const crypto = require('crypto');

// 通用弱口令/提示词字典：只放 CTF 里高频出现的，不针对具体题目。
// 放到这里而不是散落在提示词里，是为了复用与可测试。
const COMMON_WORDS = [
  'flag', 'ctf', 'admin', 'root', 'password', 'passwd', 'pwd', 'secret', 'key', 'test',
  'guest', 'user', 'username', 'login', 'welcome', 'hello', 'world', 'china', 'chinese',
  'love', 'happy', 'iloveyou', 'letmein', 'qwerty', 'abc123', '123456', '12345678',
  '123456789', '111111', '000000', '888888', '666666', 'admin123', 'root123',
  'reverse', 'crackme', 'crypto', 'ctfshow', 'dasctf', 'nssctf', 'buuctf', 'moectf',
  'success', 'correct', 'right', 'yes', 'ok', 'true', 'false', 'null', 'none',
  'input', 'output', 'data', 'value', 'string', 'char', 'byte', 'int', 'main',
  'CrackMe', 'CrackMe1', 'CrackMe2', 'CrackMe3', 'CrackMe4', 'CrackMe5',
];

const ALPHABET = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digit: '0123456789',
};

function hashOf(kind, text) {
  return crypto.createHash(kind).update(text).digest('hex');
}

function normalizeHex(v) {
  return String(v || '').trim().replace(/^0x/i, '').toLowerCase();
}

// 从二进制里抽可打印串当字典：CTF 的 key/口令几乎总是以字符串常量形式出现在文件里。
function extractStringsFromBuffer(buf, { minLen = 4, maxCount = 4000 } = {}) {
  const out = [];
  let cur = '';
  for (let i = 0; i < buf.length && out.length < maxCount; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

// 生成候选明文：常见词 + 文件内字符串 + 短数字 + 简单大小写变体。
// 有上限，避免把 300s 预算烧穿。
function buildDictionary(extraStrings) {
  const set = new Set();
  const add = (s) => {
    const t = String(s == null ? '' : s).trim();
    if (!t || t.length > 64) return;
    set.add(t);
    set.add(t.toLowerCase());
    if (t.length <= 32) set.add(t.toUpperCase());
  };
  for (const w of COMMON_WORDS) add(w);
  for (const s of (extraStrings || [])) add(s);
  // 短数字（0..99999）：注册码/口令题里极高发
  for (let i = 0; i <= 99999 && set.size < 120000; i++) set.add(String(i));
  // 1~4 位纯字母组合（仅小写，控制规模）
  const lower = ALPHABET.lower;
  for (const a of lower) {
    set.add(a);
    for (const b of lower) {
      set.add(a + b);
      if (set.size > 200000) break;
    }
  }
  return Array.from(set);
}

// 对单个哈希目标做爆破。返回明文或 null。
function crackHash(target, kind, dictionary) {
  const t = normalizeHex(target);
  for (const cand of dictionary) {
    if (hashOf(kind, cand) === t) return cand;
  }
  return null;
}

function printableRatio(buf) {
  if (!buf || !buf.length) return 0;
  let ok = 0;
  for (const b of buf) {
    if ((b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x0d || b === 0x09) ok++;
  }
  return ok / buf.length;
}

// 判断一段解码后的文本是否"像人写的"：不只看 ASCII 可打印率，
// 还要接受中文（CTF 中文题很多，UTF-8 字节全在 0x80+，纯字节比例会误判）。
function looksLikeText(s) {
  const str = String(s || '').replace(/\u0000/g, '');
  if (!str.trim()) return false;
  let good = 0, total = 0;
  for (const ch of str) {
    total++;
    const code = ch.codePointAt(0);
    if (code === 0x09 || code === 0x0a || code === 0x0d) { good++; continue; }
    if (code >= 0x20 && code <= 0x7e) { good++; continue; }
    if (code >= 0x4e00 && code <= 0x9fff) { good++; continue; }   // CJK 统一表意
    if (code >= 0x3000 && code <= 0x303f) { good++; continue; }   // CJK 标点
    if (code >= 0xff00 && code <= 0xffef) { good++; continue; }   // 全角
  }
  return total > 0 && good / total > 0.9;
}

function tryDecodeBuffer(buf) {
  const out = [];
  if (printableRatio(buf) > 0.9) {
    const s = buf.toString('latin1');
    if (looksLikeText(s)) out.push({ encoding: 'latin1/ascii', text: s });
  }
  // UTF-16LE：中文题常见（字节里大量 0x00 交错）
  if (buf.length >= 4 && buf.length % 2 === 0) {
    const u = buf.toString('utf16le').replace(/\u0000/g, '');
    if (looksLikeText(u) && /\S/.test(u)) out.push({ encoding: 'utf-16le', text: u });
  }
  // UTF-8：中文按 UTF-8 存储时这里才解得对
  try {
    const u8 = buf.toString('utf8');
    if (!u8.includes('\uFFFD') && looksLikeText(u8) && /\S/.test(u8)) {
      if (!out.some(o => o.text === u8)) out.push({ encoding: 'utf-8', text: u8 });
    }
  } catch (e) { /* 非法 UTF-8 */ }
  return out;
}

function tryBase64(v) {
  const s = String(v || '').trim();
  if (!/^[A-Za-z0-9+/]{8,}={0,2}$/.test(s) || s.length % 4 !== 0) return [];
  const results = [];
  let cur = s;
  for (let depth = 1; depth <= 3; depth++) {
    let buf;
    try { buf = Buffer.from(cur, 'base64'); } catch (e) { break; }
    if (!buf || !buf.length) break;
    const decoded = tryDecodeBuffer(buf);
    if (!decoded.length) break;
    for (const d of decoded) results.push({ ...d, depth });
    // 再往下一层（可能又是 base64）
    const next = decoded[0].text.trim();
    if (!/^[A-Za-z0-9+/]{8,}={0,2}$/.test(next) || next === cur) break;
    cur = next;
  }
  return results;
}

// 英文双字母频率（每 1000 个字母中出现的次数，取高频部分）。
// 单字节 XOR 会解出多个"可打印"候选（如 HelloThere 用 key 0x5a，
// 用 key 0x47 得到 UxqqrIuxox 也一样可打印），必须按语言统计量挑真正像人话的那个。
const EN_BIGRAMS = {
  th: 35.6, he: 30.7, in: 24.4, er: 22.1, an: 20.6, re: 18.5, on: 17.6, at: 16.0,
  en: 15.8, nd: 15.5, ti: 15.3, es: 15.0, or: 13.9, te: 13.7, of: 13.5, ed: 13.0,
  is: 12.8, it: 12.5, al: 12.0, ar: 11.7, st: 11.5, to: 11.0, nt: 10.9, ng: 10.7,
  se: 10.5, ha: 10.4, as: 10.1, ou: 9.9, io: 9.5, le: 9.4, ve: 9.2, co: 9.0,
  me: 8.8, de: 8.7, hi: 8.6, ri: 8.5, ro: 8.4, ic: 8.2, ne: 8.0, ea: 7.9,
  ra: 7.8, ce: 7.7, li: 7.6, ch: 7.5, ll: 7.4, be: 7.2, ma: 7.1, si: 7.0,
  om: 6.9, ur: 6.8, ca: 6.6, el: 6.5, ta: 6.4, la: 6.3, ns: 6.2, di: 6.1,
  fo: 6.0, ho: 5.9, pe: 5.8, ec: 5.7, pr: 5.6, no: 5.5, ct: 5.4, us: 5.3,
  ac: 5.2, ot: 5.1, il: 5.0, tr: 4.9, ly: 4.8, nc: 4.7, et: 4.6, ut: 4.5,
  ss: 4.4, so: 4.3, rs: 4.2, un: 4.1, lo: 4.0, wa: 3.9, ge: 3.8, ie: 3.7,
  wh: 3.6, ee: 3.5, wi: 3.4, em: 3.3, ad: 3.2, ol: 3.1, rt: 3.0, po: 2.9,
};

// 给"解出来的文本像不像人话"打分。返回越高越像。
function textLikeness(s) {
  const str = String(s || '');
  if (!str) return -1;
  const lower = str.toLowerCase();
  let letters = 0, digits = 0, symbols = 0, separators = 0, spaces = 0;
  for (const ch of str) {
    if (/[A-Za-z]/.test(ch)) letters++;
    else if (/[0-9]/.test(ch)) digits++;
    else if (/[_\-{}.@#]/.test(ch)) separators++;
    else if (ch === ' ') spaces++;
    else symbols++;
  }
  const n = str.length || 1;
  // 中文题：明文可能是纯中文/中英混排，字母占比 0 不代表"不像人话"。
  // 这里先看 CJK 占比，足够高就直接给正分（并叠加少量 ASCII 结构分）。
  let cjk = 0;
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if ((code >= 0x4e00 && code <= 0x9fff) || (code >= 0x3000 && code <= 0x303f) || (code >= 0xff00 && code <= 0xffef)) cjk++;
  }
  const cjkRatio = cjk / n;
  // 阈值取 0.25：中英混排（"密钥ab"）也应当被当成可读文本，不能要求纯中文
  if (cjkRatio >= 0.25) {
    return 3 + cjkRatio * 3 + (letters / n) * 1.5 + (digits / n) * 0.5 + (separators / n) * 0.8;
  }
  if (letters === 0) return -5;

  // 双字母频率：把每对相邻字母的 log 频率累加
  let bi = 0;
  for (let i = 0; i + 1 < lower.length; i++) {
    const pair = lower.slice(i, i + 2);
    if (!/^[a-z]{2}$/.test(pair)) continue;
    bi += Math.log((EN_BIGRAMS[pair] || 0.02) + 1);
  }
  const bigramAvg = bi / Math.max(1, lower.length - 1);

  // 大小写质量：XOR key 差 0x20 会得到"大小写整体翻转"的版本
  //（RecoveredKeyText ↔ rECOVEREDkEYtEXT），双字母频率完全相同，只有大小写不同。
  // 行内标识符/口令的常态是小写占多数；大写占比过半就明显异常。
  let upper = 0, alpha = 0;
  for (const ch of str) {
    if (/[A-Za-z]/.test(ch)) { alpha++; if (/[A-Z]/.test(ch)) upper++; }
  }
  const upperRatio = alpha ? upper / alpha : 0;
  let caseScore = 0;
  if (upperRatio > 0.6) caseScore -= 3;
  else if (upperRatio > 0.45) caseScore -= 1.5;
  else if (upperRatio <= 0.4) caseScore += 0.5;
  // 全大写缩写（如 "KEY"）不算问题，但整串全大写要轻扣
  if (upperRatio === 1 && alpha > 6) caseScore -= 1;

  return bigramAvg * 2
    + caseScore * 1.5
    + (letters / n) * 3
    + (digits / n) * 0.5
    + (separators / n) * 0.8
    + (spaces / n) * 1.0
    - (symbols / n) * 6;
}

// 单字节 XOR / 单字节 ADD 试解：短密文最常见的两层壳。
function trySingleByteXor(buf) {
  const scored = [];
  for (let k = 1; k < 256; k++) {
    const dec = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) dec[i] = buf[i] ^ k;
    if (printableRatio(dec) < 0.9) continue;
    const s = dec.toString('latin1');
    const score = textLikeness(s);
    if (score <= 0) continue;
    scored.push({ key: k, text: s, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, 3);
}

// 对一段字节给出"最像人话"的解释：直接解码 vs 单字节 XOR 解码，按语言统计量择优。
// 为什么必须择优而不是先到先得：XOR 一个可打印串得到的字节往往仍然可打印
//（如 RecoveredKeyText ^ 0x33），"能按 ASCII 读"并不等于"读出来的就是原文"。
function interpretBytes(buf) {
  const candidates = [];
  for (const d of tryDecodeBuffer(buf)) {
    candidates.push({ action: d.encoding === 'utf-16le' || d.encoding === 'utf-8' ? 'hex-decode' : 'hex-decode', plaintext: d.text, encoding: d.encoding, score: textLikeness(d.text) });
  }
  for (const x of trySingleByteXor(buf)) {
    candidates.push({ action: 'single-byte-xor', plaintext: x.text, encoding: 'latin1', note: `XOR 0x${x.key.toString(16)}`, score: x.score });
  }
  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score);
  const best = candidates[0];
  if (best.score <= 0) return null;
  return best;
}

// 主入口：对一组命中的中间值逐个推进。
// 返回 [{ value, kind, action, ok, plaintext?, note }]
function advanceIntermediates(hits, opts = {}) {
  const dictionary = opts.dictionary || buildDictionary(opts.extraStrings);
  const results = [];
  const seen = new Set();

  for (const raw of (Array.isArray(hits) ? hits : []).slice(0, 8)) {
    const v = String(raw == null ? '' : raw).trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);

    const hex = /^(0x)?[0-9a-fA-F]+$/.test(v);
    const h = hex ? normalizeHex(v) : '';

    if (hex && (h.length === 32 || h.length === 40 || h.length === 64)) {
      const kind = h.length === 32 ? 'md5' : h.length === 40 ? 'sha1' : 'sha256';
      const plain = crackHash(h, kind, dictionary);
      if (plain) {
        results.push({ value: v, kind: kind.toUpperCase(), action: 'dictionary-crack', ok: true, plaintext: plain, note: `${kind}(${JSON.stringify(plain)}) 命中` });
        continue;
      }
      // 长度有歧义：32 hex 既可能是 MD5 摘要，也可能就是 16 字节原始数据（密文/密钥）。
      // 爆破没命中时必须再按"原始字节"解释一次，否则 16 字节 XOR 密文会被永久漏掉
      //（实测：RecoveredKeyText XOR 0x33 的 hex 正好 32 字符）。
      const interpAmb = interpretBytes(Buffer.from(h, 'hex'));
      if (interpAmb) {
        results.push({
          value: v, kind: 'HEX-BYTES', action: interpAmb.action, ok: true,
          plaintext: interpAmb.plaintext,
          note: `${kind} 长度但按原始 ${h.length / 2} 字节解释：${interpAmb.note || interpAmb.encoding}`
        });
        continue;
      }
      results.push({
        value: v, kind: kind.toUpperCase(), action: 'dictionary-crack', ok: false,
        note: `${kind} 字典/短串爆破未命中；按原始 ${h.length / 2} 字节解码也不可读。下一步：扩大字典（优先用程序内字符串常量），或确认它是否是密钥/密文`
      });
      continue;
    }

    if (hex && h.length >= 8 && h.length % 2 === 0) {
      const interp = interpretBytes(Buffer.from(h, 'hex'));
      if (interp) {
        results.push({
          value: v, kind: 'HEX-BYTES', action: interp.action, ok: true,
          plaintext: interp.plaintext,
          note: interp.note || `按 ${interp.encoding} 解码`
        });
        continue;
      }
      results.push({ value: v, kind: 'HEX-BYTES', action: 'hex-decode', ok: false, note: '按 ASCII/UTF-16 解码不可打印，单字节 XOR 也无英文可读结果' });
      continue;
    }

    if (/^[A-Za-z0-9+/]{8,}={0,2}$/.test(v) && v.length % 4 === 0) {
      const dec = tryBase64(v);
      if (dec.length) {
        const best = dec[dec.length - 1];
        results.push({ value: v, kind: 'BASE64', action: 'base64-decode', ok: true, plaintext: best.text, note: `${best.encoding}，解了 ${best.depth} 层` });
      } else {
        results.push({ value: v, kind: 'BASE64', action: 'base64-decode', ok: false, note: '解码结果不可打印' });
      }
      continue;
    }
  }
  return results;
}

module.exports = {
  COMMON_WORDS,
  buildDictionary,
  extractStringsFromBuffer,
  advanceIntermediates,
  crackHash,
  tryBase64,
  tryDecodeBuffer,
  trySingleByteXor,
};
