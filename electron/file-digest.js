'use strict';
// 任意文件 → 可读摘要（纯 Node，零第三方依赖）
//
// ── 设计目标：把"判断哪个文件是什么"的能力交给 AI，而不是工具替它挑 ──
// 实测（驱动逆向）目录里有两个文件：
//     DancingKeys.sys           22KB   要反汇编的驱动
//     题面（必须给出）.docx     13KB   题目描述（含要解的 16 字节密文）
// 工具如果"固定挑一个主文件"，就必然丢掉另一半信息；而"哪个是题面"这种事
// AI 看内容一眼就能判断，工具却猜不准。
// 所以这里只负责：**把每个文件变成人能读的摘要**，判断交给 AI。
//
// ── 支持的类型（覆盖 CTF 附件常见形态）────────────────────────
//   文本/代码   txt md json xml yml py c cpp h go rs js ts java php rb lua sh html css csv log
//   OOXML       docx xlsx pptx（走 office-text）
//   PDF         pdf（解 FlateDecode 流，抽 Tj/TJ 文本算子）
//   图片        png jpg jpeg gif bmp webp（尺寸 + 类型 + 是否含文本块提示）
//   归档        zip jar apk xlsx(也是 zip)（列条目名）
//   二进制      任意其它（魔数识别 + strings + 熵 + 头 64 字节 hex）
//   源码/脚本   直接给全文（超长截断，保留头尾）

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const TEXT_EXT = new Set([
  '.txt', '.md', '.markdown', '.rst', '.json', '.xml', '.yml', '.yaml', '.toml', '.ini', '.conf',
  '.py', '.pyw', '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.go', '.rs', '.rb', '.php', '.pl',
  '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue', '.java', '.kt', '.swift', '.cs', '.m',
  '.lua', '.sh', '.bash', '.zsh', '.bat', '.ps1', '.html', '.htm', '.css', '.scss', '.less',
  '.csv', '.tsv', '.log', '.enc', '.b64', '.hex', '.pem', '.key', '.crt', '.pub', '.sql',
  '.asm', '.s', '.v', '.sv', '.proto', '.gradle', '.cmake', '.mk', '.makefile',
]);

// ── 必须排除的"工具中间产物" ─────────────────────────────────
// 实测（驱动逆向）：题目目录里除了 DancingKeys.sys 和题面.docx，还有 IDA 生成的
//   DancingKeys.sys.id0 / .id1 / .id2 / .nam / .til
// 这些不是题目材料，而且 IDA 正占着它们 → 读取报 EBUSY，污染摘要、误导 AI。
// 判据：扩展名在黑名单里，或整体名形如 "<某文件>.<ida后缀>"。
const TOOL_ARTIFACT_EXT = new Set([
  '.id0', '.id1', '.id2', '.idb', '.i64', '.nam', '.til', '.idc', '.ids', '.idp', '.idh',
  '.asd', '.ddb', '.pyc', '.pyo', '.o', '.obj', '.pdb', '.ilk', '.exp', '.lib',
  '.class', '.log1', '.log2', '.swp', '.tmp', '.temp', '.lock', '.crc',
]);

function isToolArtifact(filePath) {
  const name = path.basename(String(filePath)).toLowerCase();
  const ext = path.extname(name);
  if (TOOL_ARTIFACT_EXT.has(ext)) return true;
  // "<name>.sys.id0" 这种双重扩展名
  const parts = name.split('.');
  for (let i = 1; i < parts.length; i++) {
    if (TOOL_ARTIFACT_EXT.has('.' + parts[i])) return true;
  }
  // 编辑器/系统的临时与备份
  if (/^~\$/.test(name)) return true;              // Office 锁文件 ~$xxx.docx
  if (/\.(bak|orig|save|autosave)$/.test(name)) return true;
  return false;
}

const IMG_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.tif', '.tiff']);
const ARCHIVE_EXT = new Set(['.zip', '.jar', '.apk', '.rar', '.7z', '.tar', '.gz', '.xz', '.bz2']);
const OOXML_EXT = new Set(['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm']);
const PDF_EXT = new Set(['.pdf']);

const MAX_TEXT = 60000;      // 文本类最多给这么多字符
const MAX_STORE = 8 * 1024 * 1024;  // 超过这个大小只给摘要，不读全文

function safeStat(p) {
  try { return fs.statSync(p); } catch (e) { return null; }
}

// ── 二进制识别 ──────────────────────────────────────────────
function detectMagic(buf) {
  if (!buf || buf.length < 2) return '空/过短';
  const h4 = buf.length >= 4 ? buf.toString('hex', 0, 4).toUpperCase() : '';
  const h8 = buf.length >= 8 ? buf.toString('hex', 0, 8).toUpperCase() : '';
  if (h4.startsWith('4D5A')) return 'PE（Windows 可执行/DLL/驱动 .sys）';
  if (h8 === '7F454C46') return 'ELF';
  if (h4 === '6465780A') return 'DEX（Android）';
  if (h4 === '504B0304') return 'ZIP 容器（可能是 apk/jar/docx/xlsx）';
  if (h4 === 'CAFEBABE') return 'Java class / Mach-O fat';
  if (h4 === '0061736D') return 'WebAssembly';
  if (h4.startsWith('1F8B')) return 'gzip';
  if (h4 === '377ABCAF') return '7z';
  if (h4 === '52617221') return 'RAR';
  if (h4 === 'D4C3B2A1' || h4 === 'A1B2C3D4' || h4 === '0A0D0D0A') return 'pcap/pcapng';
  if (h4 === '7F454C46') return 'ELF';
  if (h8.startsWith('89504E47')) return 'PNG';
  if (h4.startsWith('FFD8FF')) return 'JPEG';
  if (h4 === '47494638') return 'GIF';
  if (h4.startsWith('424D')) return 'BMP';
  if (/^[0-9A-F]{0,4}$/.test(h4) && buf.length && buf[0] === 0x1B && buf[1] === 0x4C) return 'Lua 字节码';
  return '未知二进制';
}

function shannonEntropy(buf) {
  if (!buf || !buf.length) return 0;
  const freq = new Array(256).fill(0);
  const n = Math.min(buf.length, 256 * 1024);
  for (let i = 0; i < n; i++) freq[buf[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / n;
    e -= p * Math.log2(p);
  }
  return +e.toFixed(2);
}

function extractStrings(buf, minLen = 4, limit = 80) {
  const out = [];
  let cur = '';
  const n = Math.min(buf.length, 512 * 1024);
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
    else {
      if (cur.length >= minLen) out.push(cur);
      cur = '';
      if (out.length >= limit) break;
    }
  }
  if (cur.length >= minLen && out.length < limit) out.push(cur);
  return out;
}

// ── PDF 文本抽取（best-effort）────────────────────────────────
// 解 FlateDecode 流后抓 Tj/TJ 里的字符串。不追求完整 PDF 语义，
// 但足以读出"题面写了什么"。
function extractPdfText(buf) {
  const chunks = [];
  const s = buf.toString('latin1');
  const re = /stream\r?\n/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    const start = m.index + m[0].length;
    const end = s.indexOf('endstream', start);
    if (end < 0) break;
    let raw = buf.slice(start, end);
    // 去掉尾部换行
    while (raw.length && (raw[raw.length - 1] === 0x0a || raw[raw.length - 1] === 0x0d)) {
      raw = raw.slice(0, -1);
    }
    let txt = null;
    try { txt = zlib.inflateSync(raw).toString('latin1'); } catch (e) {
      try { txt = zlib.inflateRawSync(raw).toString('latin1'); } catch (e2) { txt = null; }
    }
    if (txt && /(Tj|TJ)/.test(txt)) chunks.push(txt);
  }
  // 未压缩的文本算子也可能直接出现在正文
  if (!chunks.length && /BT[\s\S]{0,2000}ET/.test(s)) chunks.push(s);

  const out = [];
  for (const c of chunks) {
    // ( ... ) Tj   与  [ (..) 123 (..) ] TJ
    const reTj = /\((?:\\.|[^\\()])*\)/g;
    let mm;
    while ((mm = reTj.exec(c)) !== null) {
      let t = mm[0].slice(1, -1)
        .replace(/\\([nrtbf])/g, (x, ch) => ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' }[ch] || ''))
        .replace(/\\([()\\])/g, '$1')
        .replace(/\\(\d{1,3})/g, (x, o) => String.fromCharCode(parseInt(o, 8)));
      if (t.trim()) out.push(t);
    }
  }
  let text = out.join(' ').replace(/\s{2,}/g, ' ').trim();
  // 中文 PDF 常见 CID 编码，抽出来会是乱码；给个明确判断而不是丢乱码
  const cjk = (text.match(/[\u4e00-\u9fa5]/g) || []).length;
  const printable = (text.match(/[\x20-\x7e]/g) || []).length;
  const looksGarbled = text.length > 20 && cjk === 0 && printable / text.length < 0.6;
  return { text, looksGarbled, streams: chunks.length };
}

// ── 主入口 ───────────────────────────────────────────────────
/**
 * 把任意文件变成可读摘要。
 * @param {string} filePath
 * @param {{maxText?:number, wantFull?:boolean}} [opts]
 */
function digestFile(filePath, opts = {}) {
  const st = safeStat(filePath);
  if (!st) return { ok: false, path: filePath, name: path.basename(filePath), error: '文件不存在或无法访问' };

  const ext = path.extname(filePath).toLowerCase();
  const base = {
    ok: true,
    path: filePath,
    name: path.basename(filePath),
    ext,
    size: st.size,
    mtime: st.mtime ? st.mtime.toISOString() : '',
  };

  if (st.isDirectory()) return { ...base, kind: 'directory', note: '这是目录' };

  // 1) 文本/代码：直接读
  if (TEXT_EXT.has(ext)) {
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const maxText = Math.min(Math.max(Number(opts.maxText) || MAX_TEXT, 1000), 400000);
      let text = raw;
      let truncated = false;
      if (text.length > maxText) {
        const head = Math.floor(maxText * 0.7);
        const tail = maxText - head;
        text = text.slice(0, head) + `\n...(中间省略 ${raw.length - maxText} 字符)...\n` + text.slice(-tail);
        truncated = true;
      }
      return { ...base, kind: 'text', text, chars: raw.length, truncated };
    } catch (e) {
      return { ...base, kind: 'text', error: e.message, ok: false };
    }
  }

  // 2) OOXML
  if (OOXML_EXT.has(ext)) {
    try {
      const { extractOfficeText } = require('./office-text');
      const r = extractOfficeText(filePath);
      if (r.ok) return { ...base, kind: r.kind, text: r.text, chars: r.text.length, parts: r.parts };
      return { ...base, kind: r.kind || 'ooxml', error: r.error, ok: false };
    } catch (e) {
      return { ...base, kind: 'ooxml', error: e.message, ok: false };
    }
  }

  // 3) PDF
  if (PDF_EXT.has(ext)) {
    try {
      const buf = fs.readFileSync(filePath);
      const r = extractPdfText(buf);
      return {
        ...base, kind: 'pdf', text: r.text, chars: r.text.length,
        pdfStreams: r.streams,
        note: r.looksGarbled
          ? 'PDF 抽出的文本像 CID 编码（中文 PDF 常见），内容可能不可读；如需正文请用 pdftotext -enc UTF-8'
          : '',
      };
    } catch (e) {
      return { ...base, kind: 'pdf', error: e.message, ok: false };
    }
  }

  // 4) 图片
  if (IMG_EXT.has(ext)) {
    try {
      const buf = fs.readFileSync(filePath);
      let w = 0, h = 0;
      if (buf.length > 24 && buf.readUInt32BE(0) === 0x89504E47) {
        w = buf.readUInt32BE(16); h = buf.readUInt32BE(20);
      } else if (buf.length > 4 && buf[0] === 0xFF && buf[1] === 0xD8) {
        // JPEG: 扫 SOF 段
        let p = 2;
        while (p + 9 < buf.length) {
          if (buf[p] !== 0xFF) { p++; continue; }
          const mk = buf[p + 1];
          if (mk >= 0xC0 && mk <= 0xCF && mk !== 0xC4 && mk !== 0xC8 && mk !== 0xCC) {
            h = buf.readUInt16BE(p + 5); w = buf.readUInt16BE(p + 7);
            break;
          }
          p += 2 + buf.readUInt16BE(p + 2);
        }
      }
      return {
        ...base, kind: 'image', width: w, height: h,
        note: '这是图片：可能是题面截图/流程图像/密文图。'
          + '如需读图中文字，先用 OCR（tesseract 或系统截图识别）；'
          + '若图是棋盘/迷宫这类结构，直接看图判断比 OCR 更准。',
      };
    } catch (e) {
      return { ...base, kind: 'image', error: e.message, ok: false };
    }
  }

  // 5) 归档：列条目
  if (ARCHIVE_EXT.has(ext)) {
    try {
      const { readZipEntries } = require('./office-text');
      const buf = fs.readFileSync(filePath);
      if (buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50) {
        const ents = readZipEntries(buf).map(e => e.name).slice(0, 200);
        return { ...base, kind: 'archive', entries: ents, entryCount: ents.length };
      }
      return { ...base, kind: 'archive', note: '非 zip 系归档（rar/7z/tar），用对应工具解包' };
    } catch (e) {
      return { ...base, kind: 'archive', error: e.message, ok: false };
    }
  }

  // 6) 其它：当二进制看
  try {
    const want = Math.min(st.size, MAX_STORE);
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(want);
    try { fs.readSync(fd, buf, 0, want, 0); } finally { fs.closeSync(fd); }
    const magic = detectMagic(buf);
    const ent = shannonEntropy(buf);
    const strs = extractStrings(buf);
    return {
      ...base, kind: 'binary',
      magic,
      entropy: ent,
      headHex: buf.slice(0, 64).toString('hex'),
      strings: strs,
      note: ent >= 7.5
        ? '熵 ≥7.5：内容高度随机 —— 加壳/加密/压缩过的概率高'
        : (ent >= 6 ? '熵偏高：可能有压缩数据段' : '熵偏低：更像普通代码/数据'),
    };
  } catch (e) {
    return { ...base, kind: 'binary', error: e.message, ok: false };
  }
}

/**
 * 批量摘要：一次处理多个文件。单个失败不影响其它。
 * 自动跳过工具中间产物（IDA 数据库、编译中间文件、Office 锁文件等）。
 * @returns {{items:Array, ok:number, failed:number, skipped:Array<{path:string,why:string}>}}
 */
function digestMany(paths, opts = {}) {
  const list = (Array.isArray(paths) ? paths : []).filter(Boolean).slice(0, 200);
  const items = [];
  const skipped = [];
  for (const p of list) {
    if (opts.skipArtifacts !== false && isToolArtifact(p)) {
      skipped.push({ path: p, why: '工具中间产物（IDA 数据库/编译中间文件/Office 锁文件），不是题目材料' });
      continue;
    }
    try {
      items.push(digestFile(p, opts));
    } catch (e) {
      items.push({ ok: false, path: p, name: path.basename(String(p)), error: e.message });
    }
  }
  return {
    items,
    ok: items.filter(x => x.ok).length,
    failed: items.filter(x => !x.ok).length,
    skipped,
  };
}

module.exports = {
  digestFile, digestMany, detectMagic, shannonEntropy, extractStrings, extractPdfText,
  isToolArtifact, TEXT_EXT, TOOL_ARTIFACT_EXT,
};
