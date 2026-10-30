'use strict';
// Office 文档文本提取（docx/xlsx/pptx）—— 纯 Node，零依赖
//
// ── 为什么需要（驱动逆向 实测）──────────────────────────────────
// 题目目录里常同时有「可分析二进制」和「题面」：
//     DancingKeys.sys              22KB     ← 真正要分析
//     题面（必须给出）.docx        13KB     ← 题目描述，含关键提示
// 旧流程只读被挑中的那个二进制，题面完全没进上下文 —— AI 只能猜题目要求什么。
// 而 read-file 用 utf8 读 .docx 只会得到 zip 二进制乱码。
//
// OOXML（.docx/.xlsx/.pptx）本质是 ZIP + XML：
//   · docx 正文在 word/document.xml
//   · xlsx 共享字符串在 xl/sharedStrings.xml，表在 xl/worksheets/*.xml
//   · pptx 每页在 ppt/slides/slideN.xml
// 只要把 ZIP 里那几个 XML 解出来、剥掉标签，就能拿到人可读的文字。
//
// 这里只做"提取文本"，不追求版式还原 —— 目的是让 AI 看到题目要求。

const fs = require('fs');
const zlib = require('zlib');

// ── 极简 ZIP 读取（只支持 store / deflate，够 OOXML 用）──────────
function readZipEntries(buf) {
  const out = [];
  // 定位 EOCD
  let eocd = -1;
  const tailStart = Math.max(0, buf.length - 66000);
  for (let i = buf.length - 22; i >= tailStart; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return out;
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const cdCount = buf.readUInt16LE(eocd + 10);
  let p = cdOffset;
  for (let n = 0; n < cdCount && p + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString('utf8');
    out.push({ name, method, compSize, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

function extractZipEntry(buf, entry) {
  const lo = entry.localOffset;
  if (lo + 30 > buf.length) return null;
  if (buf.readUInt32LE(lo) !== 0x04034b50) return null;
  const nameLen = buf.readUInt16LE(lo + 26);
  const extraLen = buf.readUInt16LE(lo + 28);
  const dataStart = lo + 30 + nameLen + extraLen;
  const data = buf.slice(dataStart, Math.min(dataStart + entry.compSize, buf.length));
  try {
    if (entry.method === 0) return data;                    // stored
    if (entry.method === 8) return zlib.inflateRawSync(data); // deflate
  } catch (e) {
    return null;
  }
  return null;
}

// ── XML → 纯文本 ──────────────────────────────────────────────
function xmlToText(xml) {
  let s = String(xml || '');
  // 段落/换行/制表
  s = s.replace(/<w:p[ >]/g, '\n<w:p ');
  s = s.replace(/<a:p[ >]/g, '\n<a:p ');
  s = s.replace(/<\/w:p>/g, '\n');
  s = s.replace(/<\/a:p>/g, '\n');
  s = s.replace(/<w:br\s*\/>/g, '\n');
  s = s.replace(/<w:tab\s*\/>/g, '\t');
  // <w:t>内容</w:t> 是文字节点；其余标签全部剥掉
  s = s.replace(/<[^>]+>/g, '');
  // 反转义常见实体
  s = s.replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (m, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&amp;/g, '&');
  // 收敛空白
  s = s.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n');
  return s.trim();
}

/**
 * 从 OOXML 文件里提取可读文本。
 * @param {string} filePath
 * @returns {{ok:boolean, kind:string, text:string, parts?:string[], error?:string}}
 */
function extractOfficeText(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.length < 4 || buf.readUInt32LE(0) !== 0x04034b50) {
      return { ok: false, kind: 'unknown', text: '', error: '不是 ZIP 容器（不是 OOXML）' };
    }
    const entries = readZipEntries(buf);
    if (!entries.length) return { ok: false, kind: 'unknown', text: '', error: 'ZIP 中央目录解析失败' };

    const pick = (re) => entries.filter(e => re.test(e.name)).sort((a, b) => a.name.localeCompare(b.name));
    let targets = [];
    let kind = 'unknown';

    if (entries.some(e => /^word\/document\.xml$/i.test(e.name))) {
      kind = 'docx';
      targets = pick(/^word\/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$/i);
    } else if (entries.some(e => /^xl\/workbook\.xml$/i.test(e.name))) {
      kind = 'xlsx';
      // 共享字符串在前（单元格通过索引引用它），再按表顺序
      const ss = pick(/^xl\/sharedStrings\.xml$/i);
      const sheets = pick(/^xl\/worksheets\/sheet\d+\.xml$/i)
        .sort((a, b) => {
          const na = Number((a.name.match(/(\d+)/) || [])[1] || 0);
          const nb = Number((b.name.match(/(\d+)/) || [])[1] || 0);
          return na - nb;
        });
      targets = ss.concat(sheets);
    } else if (entries.some(e => /^ppt\/presentation\.xml$/i.test(e.name))) {
      kind = 'pptx';
      targets = pick(/^ppt\/slides\/slide\d+\.xml$/i)
        .sort((a, b) => {
          const na = Number((a.name.match(/(\d+)/) || [])[1] || 0);
          const nb = Number((b.name.match(/(\d+)/) || [])[1] || 0);
          return na - nb;
        });
    } else {
      return { ok: false, kind: 'unknown', text: '', error: 'ZIP 里没有 OOXML 正文（不是 docx/xlsx/pptx）' };
    }

    const parts = [];
    const names = [];
    for (const e of targets.slice(0, 40)) {
      const raw = extractZipEntry(buf, e);
      if (!raw) continue;
      const t = xmlToText(raw.toString('utf8'));
      if (t) { parts.push(t); names.push(e.name); }
    }
    const text = parts.join('\n\n---\n\n');
    if (!text) return { ok: false, kind, text: '', error: '正文 XML 解出来是空的' };
    return { ok: true, kind, text, parts: names };
  } catch (e) {
    return { ok: false, kind: 'unknown', text: '', error: e.message };
  }
}

module.exports = { extractOfficeText, readZipEntries, extractZipEntry, xmlToText };
