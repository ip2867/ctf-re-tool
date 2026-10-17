// Agent 运行时支撑模块（借鉴 openclaude v0.33.0 的上下文/可靠性设计）
//
// 四块能力，全部与 Electron 解耦，便于单测：
//   A1 persistToolResult   大工具输出落盘 + 60/40 头尾预览
//   A2 microcompact        旧 tool_result 清理（零模型调用）
//   B1/B2 DoomLoopGuard    连续相同调用 / 按错误类别的跨轮失败环
//   D1 SessionLog          追加式 JSONL 会话日志 + 恢复时清洗
//
// 参数均对照 openclaude 源码标定：
//   · 头尾比例 0.6 / 0.4，省略标记 "… N bytes omitted …"      （toolResultStorage.ts）
//   · 清理占位串 "[Old tool result content cleared]"          （microCompact.ts）
//   · doom loop 阈值 3、sha256(完整入参)                      （doomLoop.ts）
//   · 失败环阈值 3、第 2 次 advisory、成功写操作重置           （toolFailureLoopGuard.ts）
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OMITTED_MARK = (n) => `\n… ${n} bytes omitted …\n`;
const CLEARED = '[Old tool result content cleared]';
const PERSISTED_OPEN = (file, chars) => `<persisted-output file="${file}" chars="${chars}">`;
const PERSISTED_CLOSE = '</persisted-output>';

// ---------- A1：大输出落盘 + 头尾预览 ----------

// 按字符数生成头尾预览（openclaude 是字节；这里用字符，避免中文被切断）
function headTailPreview(text, maxChars) {
  const s = String(text == null ? '' : text);
  if (s.length <= maxChars) return s;
  const marker = OMITTED_MARK(s.length);
  const avail = Math.max(0, maxChars - marker.length);
  let headEnd = Math.floor(avail * 0.6);
  // 断行对齐：优先切在行尾，但保留量不能少于目标的 50%（否则退回硬切）
  const nl = s.lastIndexOf('\n', headEnd);
  if (nl > 0 && nl + 1 >= headEnd * 0.5) headEnd = nl + 1;
  let tailStart = s.length - (avail - headEnd);
  const nl2 = s.indexOf('\n', tailStart);
  if (nl2 !== -1 && s.length - nl2 >= (avail - headEnd) * 0.5) tailStart = nl2 + 1;
  return s.slice(0, headEnd) + marker + s.slice(tailStart);
}

// 超过阈值 → 写盘，返回"预览 + 文件路径 + 如何读回"。
// 为什么不只截断：错误堆栈/最终 flag 常在尾部，只截头会丢掉关键信息。
function persistToolResult(text, opts = {}) {
  const s = String(text == null ? '' : text);
  const maxChars = opts.maxChars || 24000;
  if (s.length <= maxChars) return s;
  const dir = opts.dir;
  if (!dir) return headTailPreview(s, maxChars);
  try {
    fs.mkdirSync(dir, { recursive: true });
    const name = String(opts.id || crypto.randomUUID()).replace(/[^\w.-]/g, '_') + '.txt';
    const file = path.join(dir, name);
    fs.writeFileSync(file, s, 'utf8');
    return PERSISTED_OPEN(file, s.length) + '\n'
      + headTailPreview(s, maxChars)
      + '\n' + PERSISTED_CLOSE
      + '\n（完整内容已落盘。需要细节时用 read_file 读取上面的路径，可按行 offset/limit 分段读。）';
  } catch (e) {
    return headTailPreview(s, maxChars);
  }
}

// ---------- A2：旧工具结果微压缩 ----------

// 只清理"内容可重取"的工具；不动 is_error（错误信息是模型纠错的依据），
// 不动最近 keepRecent 条（模型当前推理的现场）。
const COMPACTABLE_TOOLS = new Set([
  'read_file', 'bash', 'run_python', 'run_command', 'grep', 'glob',
  'scan_crypto', 'extract_payload', 'analyze_structure',
  'ida_decompile', 'ida_get_bytes', 'ida_list_functions', 'ida_xrefs',
  'gen_block_cipher_solver', 'gen_sm4_solver', 'bash_output',
]);

function toolResultSlots(history) {
  const slots = [];
  history.forEach((m, i) => {
    if (!m || m.role !== 'user' || !Array.isArray(m.content)) return;
    m.content.forEach((b, j) => {
      if (b && b.type === 'tool_result') slots.push({ i, j, block: b });
    });
  });
  return slots;
}

function microcompact(history, keepRecent = 6) {
  const slots = toolResultSlots(history);
  const drop = slots.slice(0, Math.max(0, slots.length - keepRecent));
  let cleared = 0;
  for (const { block } of drop) {
    if (block.is_error) continue;
    const body = typeof block.content === 'string' ? block.content
      : JSON.stringify(block.content);
    if (body && body.includes(CLEARED)) continue;
    block.content = CLEARED;
    cleared++;
  }
  return { cleared, total: slots.length, kept: slots.length - cleared };
}

// ---------- B1/B2：重复调用与失败环 ----------

function sha256(v) {
  return crypto.createHash('sha256').update(v == null ? '' : String(v)).digest('hex');
}

function signatureOf(toolName, input) {
  let serialized;
  try { serialized = JSON.stringify(input == null ? {} : input); }
  catch (e) { serialized = String(input); }
  // 哈希完整入参（不做前缀截断——否则"同文件不同尾部内容的两次写"会被误判相同）
  return `${toolName}::${sha256(serialized)}`;
}

// 错误类别归一化：让"同一类失败"能跨不同错误文案累计
const ERROR_PATTERNS = [
  [/no such file|not found|cannot find|文件不存在|找不到/i, 'NotFound'],
  [/permission denied|access is denied|拒绝访问/i, 'Permission'],
  [/timeout|timed out|超时/i, 'Timeout'],
  [/no such function|function not found|未找到函数|NoSymbol/i, 'NoSymbol'],
  [/arch|architecture|架构|32-bit|64-bit/i, 'WrongArch'],
  [/syntaxerror|indentationerror|traceback|脚本|script error/i, 'ScriptError'],
  [/invalid|missing|required|参数|schema/i, 'InputValidation'],
];
function normalizeErrorCategory(text) {
  const s = String(text || '');
  for (const [re, cat] of ERROR_PATTERNS) if (re.test(s)) return cat;
  return 'ToolCrash';
}

// 连续相同调用（openclaude: 阈值 3，签名变化即重置）
class DoomLoopGuard {
  constructor(threshold = 3) {
    this.threshold = threshold;
    this.lastSig = null;
    this.consecutive = 0;
    this.blocked = false;
  }

  check(toolName, input) {
    const sig = signatureOf(toolName, input);
    if (sig === this.lastSig) this.consecutive++;
    else { this.lastSig = sig; this.consecutive = 1; this.blocked = false; }
    if (this.consecutive >= this.threshold && !this.blocked) {
      this.blocked = true;
      return { blocked: true, count: this.consecutive, threshold: this.threshold };
    }
    return { blocked: this.blocked, count: this.consecutive, threshold: this.threshold };
  }

  reset() { this.lastSig = null; this.consecutive = 0; this.blocked = false; }
}

// 跨轮失败环：按 (工具, 错误类别) / 错误类别 / 路径 三键累计。
// 第 threshold-1 次给 advisory，第 threshold 次 trip（要求换路线）。
class FailureLoopGuard {
  constructor(threshold = 3) {
    this.threshold = threshold;
    this.byToolCategory = new Map();
    this.byCategory = new Map();
    this.byPath = new Map();
    this.advisories = [];
  }

  _bump(map, key) {
    const n = (map.get(key) || 0) + 1;
    map.set(key, n);
    return n;
  }

  recordFailure(toolName, errorText, filePath) {
    const category = normalizeErrorCategory(errorText);
    const nTool = this._bump(this.byToolCategory, `${toolName}\0${category}`);
    const nCat = this._bump(this.byCategory, category);
    let nPath = 0;
    if (filePath) nPath = this._bump(this.byPath, String(filePath));

    const message = `${toolName} 连续同类失败（${category}）`;
    const worst = Math.max(nTool, nCat, nPath);
    if (worst >= this.threshold) {
      return { tripped: true, category, count: worst, tool: toolName, message };
    }
    if (worst === this.threshold - 1) {
      const advisory = `${message} 已 ${worst}/${this.threshold} 次。请换工具或换假设，不要用同样方式重试。`
        + (category === 'NoSymbol' ? '（IDA 找不到函数时，改试候选名 main/_main/WinMain/_WinMainCRTStartup/start，或先 strings/xrefs 定位）' : '')
        + (category === 'ScriptError' ? '（脚本连续报错：检查 import idaapi/idc、是否用了 Py2 语法）' : '')
        + (category === 'WrongArch' ? '（先确认 x86/x64/ARM，再换对应 IDA 实例）' : '');
      this.advisories.push(advisory);
      return { tripped: false, advisory, category, count: worst, tool: toolName };
    }
    return { tripped: false, category, count: worst, tool: toolName };
  }

  // 成功的"写操作"重置该路径与对应工具计数（状态已改变，旧失败不再代表当前状态）
  recordSuccess(toolName, filePath) {
    this.byToolCategory.forEach((_, k) => {
      if (k.startsWith(toolName + '\0')) this.byToolCategory.set(k, 0);
    });
    this.byCategory.clear();
    if (filePath) this.byPath.delete(String(filePath));
  }

  takeAdvisories() {
    const out = this.advisories.slice();
    this.advisories.length = 0;
    return out;
  }

  reset() {
    this.byToolCategory.clear();
    this.byCategory.clear();
    this.byPath.clear();
    this.advisories.length = 0;
  }
}

// ---------- 上下文预算 ----------

// 粗略 token 估算：中文≈1 字符/token，英文≈4 字符/token。
// 取保守值，宁可早压缩。openclaude 也有同类 roughTokenCountEstimation。
function estimateTokens(history) {
  let chars = 0;
  for (const m of history || []) {
    if (!m || m.content == null) continue;
    if (typeof m.content === 'string') { chars += m.content.length; continue; }
    if (Array.isArray(m.content)) {
      for (const b of m.content) {
        if (!b) continue;
        if (typeof b.text === 'string') chars += b.text.length;
        else if (typeof b.content === 'string') chars += b.content.length;
        else if (b.input) chars += JSON.stringify(b.input).length;
      }
    }
  }
  return Math.ceil(chars / 2.5);
}

// ---------- D1：会话日志 ----------

class SessionLog {
  constructor(dir, sessionId) {
    this.dir = dir;
    this.sessionId = sessionId || new Date().toISOString().replace(/[:.]/g, '-');
    this.file = path.join(dir, `${this.sessionId}.jsonl`);
  }

  append(role, content, extra = {}) {
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const rec = { ts: Date.now(), role, content, ...extra };
      fs.appendFileSync(this.file, JSON.stringify(rec) + '\n', 'utf8');
      return true;
    } catch (e) { return false; }
  }

  static list(dir) {
    try {
      return fs.readdirSync(dir)
        .filter((f) => f.endsWith('.jsonl'))
        .map((f) => {
          const full = path.join(dir, f);
          const st = fs.statSync(full);
          return { id: f.replace(/\.jsonl$/, ''), path: full, size: st.size, mtime: st.mtimeMs };
        })
        .sort((a, b) => b.mtime - a.mtime);
    } catch (e) { return []; }
  }

  static load(file) {
    try {
      const raw = fs.readFileSync(file, 'utf8');
      return raw.split('\n').filter(Boolean).map((l) => {
        try { return JSON.parse(l); } catch (e) { return null; }
      }).filter(Boolean);
    } catch (e) { return []; }
  }
}

// 恢复清洗：剥离未完成的 tool_use / 孤立 tool_result（否则 API 直接 400）
function sanitizeHistoryForResume(records) {
  const msgs = records.map((r) => ({ role: r.role, content: r.content }));
  const out = [];
  for (let i = 0; i < msgs.length; i++) {
    const m = msgs[i];
    if (m.role === 'assistant' && Array.isArray(m.content)) {
      const uses = m.content.filter((b) => b && b.type === 'tool_use');
      if (uses.length) {
        const next = msgs[i + 1];
        const results = (next && next.role === 'user' && Array.isArray(next.content))
          ? next.content.filter((b) => b && b.type === 'tool_result') : [];
        const answered = new Set(results.map((r) => r.tool_use_id));
        const kept = m.content.filter((b) => b.type !== 'tool_use' || answered.has(b.id));
        // 一个 tool_use 都没被回答 → 整条 assistant 消息丢弃（否则留下悬空 tool_use）
        const keptUses = kept.filter((b) => b && b.type === 'tool_use');
        if (uses.length && keptUses.length === 0) continue;
        if (kept.length) out.push({ role: 'assistant', content: kept });
        continue;
      }
    }
    if (m.role === 'user' && Array.isArray(m.content)) {
      const results = m.content.filter((b) => b && b.type === 'tool_result');
      if (results.length) {
        // 只有存在对应 tool_use 的结果才保留
        const prev = out[out.length - 1];
        const uses = (prev && prev.role === 'assistant' && Array.isArray(prev.content))
          ? prev.content.filter((b) => b && b.type === 'tool_use').map((b) => b.id) : [];
        const keep = m.content.filter((b) => b.type !== 'tool_result' || uses.includes(b.tool_use_id));
        if (!keep.length) continue;
        out.push({ role: 'user', content: keep });
        continue;
      }
    }
    // 纯文本消息原样保留（跳过空内容）
    if (typeof m.content === 'string' && !m.content.trim()) continue;
    out.push(m);
  }
  // 末尾是 user（无 assistant 回应）→ 注入续跑指令
  const last = out[out.length - 1];
  if (last && last.role === 'user') {
    out.push({ role: 'user', content: [{ type: 'text', text: 'Continue from where you left off.（从上次中断处继续，不要重复已完成的步骤。）' }] });
  }
  return out;
}

// ---------- C1：结构化经验检索 ----------
// 经验库两种格式并存（向后兼容）：
//   旧：`- [2026-10-17] SM4 变体 → 先看 CK 差分 → 直接读题目表`
//   新：`- [technique] applies_to=SM4,AES | Rule: ... | Why: ... | How: ...`
// 检索：按当前题特征词（骨架/文件类型/S 盒关系…）打分，命中标签优先，
// 输出截断到 maxChars（默认 600）——只注入 top 几条，不把整个经验库塞进提示词。
function parseExperienceLine(line) {
  const s = String(line || '').trim();
  if (!s) return null;
  const m = s.match(/^-\s*\[(\w+)\]\s*(.*)$/);
  if (m && /^(technique|pitfall|layout|tool-usage|fact)$/i.test(m[1])) {
    const body = m[2];
    const tags = [];
    const tagMatch = body.match(/applies_to\s*=\s*([^|]+)/i);
    if (tagMatch) tagMatch[1].split(/[,，\s]+/).forEach((t) => { if (t) tags.push(t.trim()); });
    const rule = (body.match(/Rule:\s*(.+?)(?=\||$)/i) || [])[1] || body;
    const why = (body.match(/Why:\s*(.+?)(?=\||$)/i) || [])[1] || '';
    const how = (body.match(/How:\s*(.+?)(?=\||$)/i) || [])[1] || '';
    return { kind: m[1].toLowerCase(), tags, rule: rule.trim(), why: why.trim(), how: how.trim(), raw: s };
  }
  // 旧自由文本：整行就是规则
  return { kind: 'legacy', tags: [], rule: s.replace(/^-\s*(\[[^\]]+\]\s*)?/, ''), why: '', how: '', raw: s };
}

function rankExperience(expText, keywords, opts = {}) {
  const limit = opts.limit || 6;
  const maxChars = opts.maxChars || 600;
  const kws = (keywords || []).map((k) => String(k).toLowerCase()).filter(Boolean);
  const lines = String(expText || '').split('\n').filter((l) => /^\s*-/.test(l));
  const scored = lines.map((l, i) => {
    const e = parseExperienceLine(l);
    if (!e) return null;
    const hay = (e.raw + ' ' + e.tags.join(' ')).toLowerCase();
    const hits = kws.reduce((n, k) => n + (hay.includes(k) ? 1 : 0), 0);
    // 必须先**命中关键词**才有资格被注入；结构化条目的 0.5 只作为同分时的排序加成
    // （早期实现把它加进 score 再判断 >0，导致零命中的结构化条目永远被注入）。
    if (hits === 0) return null;
    return { e, score: hits + (e.kind !== 'legacy' ? 0.5 : 0), hits, idx: i };
  }).filter(Boolean);

  const picked = scored
    .sort((a, b) => (b.hits - a.hits) || (b.score - a.score) || (b.idx - a.idx))
    .slice(0, limit);
  if (!picked.length) return '';

  const out = [];
  let used = 0;
  for (const { e } of picked) {
    let text;
    if (e.kind === 'legacy') {
      text = '- ' + e.rule;
    } else {
      text = `- [${e.kind}] ${e.rule}`;
      if (e.why) text += `\n  为什么：${e.why}`;
      if (e.how) text += `\n  怎么做：${e.how}`;
    }
    if (used + text.length > maxChars) break;
    out.push(text);
    used += text.length;
  }
  return out.join('\n');
}

module.exports = {
  headTailPreview,
  persistToolResult,
  microcompact,
  signatureOf,
  normalizeErrorCategory,
  DoomLoopGuard,
  FailureLoopGuard,
  estimateTokens,
  SessionLog,
  sanitizeHistoryForResume,
  parseExperienceLine,
  rankExperience,
  compactHistoryDeterministic,
  CLEARED,
  COMPACTABLE_TOOLS,
};

// ---------- A3：确定性压缩（供主循环使用）----------
// 用规则抽取"硬事实"而不是再调一次模型摘要：CTF 场景里偏移/常量/已排除路线
// 才是必须保留的，原文细节可以丢；这样压缩不花 token、不会失败。
const FACT_PATTERNS = [
  /0x[0-9a-f]{3,}/i,
  /S\s*盒|SBOX|CK|FK|Rcon|非线性度/,
  /骨架|SM4|AES|DES|Blowfish|Base64|Base91|TEA|RC4/,
  /key\s*[=:：]|密钥|口令/,
  /flag\{|xmctf\{|\[FLAG\]/i,
  /已排除|不要再试|失败原因/,
  /stage\d|内嵌|载荷|loader/i,
];

function isFactLine(line) {
  const s = String(line || '');
  if (!s || s.length > 400) return false;
  return FACT_PATTERNS.some((re) => re.test(s));
}

function compactHistoryDeterministic(history, keepRecent = 10) {
  if (!Array.isArray(history) || history.length <= keepRecent + 2) return null;
  const head = history.slice(0, 1);
  const recent = history.slice(-keepRecent);
  const middle = history.slice(1, history.length - keepRecent);

  const facts = [];
  const seen = new Set();
  for (const m of middle) {
    const blocks = Array.isArray(m.content)
      ? m.content
      : [{ type: 'text', text: String(m.content || '') }];
    for (const b of blocks) {
      if (!b || b.type === 'tool_result') continue;   // 工具输出不抽（体积大且多为原始数据）
      const text = b.text || '';
      for (const line of String(text).split('\n')) {
        if (!isFactLine(line)) continue;
        const key = line.trim().slice(0, 120);
        if (seen.has(key)) continue;
        seen.add(key);
        facts.push(line.trim());
        if (facts.length >= 60) break;
      }
      if (facts.length >= 60) break;
    }
    if (facts.length >= 60) break;
  }

  const summary = {
    role: 'user',
    content: [{
      type: 'text',
      text: '【上下文已压缩】以下是此前对话中提取的**关键事实**（原文细节已省略）：\n'
        + (facts.length ? facts.map((f) => '- ' + f).join('\n') : '（无）')
        + '\n\n请基于这些事实继续；如需原始数据，重新调用相应工具获取。',
    }],
  };
  return [...head, summary, ...recent];
}
