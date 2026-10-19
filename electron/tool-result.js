// 工具结果的可信性层：错误判定、MCP 返回形态解析、以及可在纯 Node 下测试的 case 体。
// 零 Electron 依赖——外部工具（IDA/Burp/JEB/浏览器 MCP）的返回形态差异极大，
// 只有把"什么算失败"和"怎么读出字节"变成纯函数，才能在无 GUI 的环境里钉住这些契约。
const fs = require('fs');
const path = require('path');
const os = require('os');

const MAX_OUTPUT_CHARS = 8000;
function truncateOutput(text) {
  const s = String(text || '');
  if (s.length <= MAX_OUTPUT_CHARS) return s;
  return s.slice(0, MAX_OUTPUT_CHARS) + `\n...[已截断，原始长度 ${s.length} 字符]`;
}

// 结构化异常：调用方（executeToolCall / 主循环）据此区分"工具内部失败"与"真正的异常"。
class ToolCallError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ToolCallError';
    this.__toolError = true;
  }
}

// 工具层以字符串返回失败是历史约定；主循环必须能识别它并标记 is_error。
// 只认**行首**的固定前缀：正文里出现"失败"字样的分析结论不能被误判成工具失败。
const FAILURE_PREFIXES = [
  '工具调用失败', 'IDA MCP调用失败', 'Burp MCP调用失败', 'JEB MCP调用失败',
  'Python执行失败', 'Python启动失败', 'Python执行超时', 'Python被信号终止',
  '命令执行失败', '命令执行超时',
  '扫描失败', '读取文件失败', '写入文件失败', '读取技能失败',
  '搜索失败', '浏览器MCP搜索失败', 'ADB命令失败', '读取失败',
  '浏览器MCP打开失败', 'browser_js 失败', '提取失败', '未找到技能',
  '未在文件中找到可提取的载荷', '不支持的编码方式', '未找到自定义分组密码结构',
  '无结构推理输入', '未找到知识页',
  '阶段接力失败', '未知工具', '文件不存在', '参数错误',
];

// 前缀表列不全时兜底：行首 16 字符内出现「失败/错误」且紧跟冒号的，是工具报错而不是分析结论。
// 阈值刻意取短：真正的分析文本不会在开头这么写，而工具侧的错误文案几乎都长这样
// （`搜索失败: EPERM`、`读取失败: EACCES`、`ADB命令失败: device offline`）。
const FAILURE_LINE_PATTERN = /^[^\n:：]{0,16}(?:失败|错误)\s*[:：]/;

function hasText(v) {
  if (v == null) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v).length > 0;
  return String(v).trim() !== '';
}

// error 字段的"有值"判定：0 / false / '0' 在多数 MCP 实现里表示"没有错误"，
// 用 hasText 会把它们当失败（实测 {success:true,error:0} 曾被判 isError:true）。
function hasErrorValue(v) {
  if (v == null || v === false) return false;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'object') return hasText(v);
  const s = String(v).trim();
  if (!s || s === '0' || s === 'false' || s === 'null' || s === 'undefined') return false;
  return true;
}

// 返回 null 表示"没有失败证据"；返回字符串表示失败原因（可直接喂给模型/日志）。
// opts.pythonExec：{result,stdout,stderr} 形态的执行结果——退出码 0 但 stderr 非空且无任何
// stdout/result 时，实际是把错误写进了 stderr，不能当成"成功但无输出"。
function toolFailureReason(value, opts) {
  const o = opts || {};
  if (value == null) return null;

  if (Array.isArray(value)) {
    if (!value.length) return null;
    // 数组项的 error 用了值域判定（error:0 表示成功）；data===null 不再单独判失败——
    // "多段返回里有一段为空"是正常形态，由 parseBytesReply 跳过即可。
    // 只有**整组都没有可用数据**才由调用方（idaGetBytes / parseBytesReply）判失败。
    for (const item of value) {
      if (item == null) continue;
      if (typeof item !== 'object') continue;
      if (hasErrorValue(item.error)) return String(item.error);
      if (item.success === false) return 'success=false';
    }
    return null;
  }

  if (typeof value === 'string') {
    const head = value.replace(/^\s+/, '');
    const hit = FAILURE_PREFIXES.find(p => head.startsWith(p));
    if (hit) return head.split('\n')[0];
    if (FAILURE_LINE_PATTERN.test(head)) return head.split('\n')[0];
    return null;
  }

  if (typeof value === 'object') {
    if (value.__toolError) return String(value.message || '工具调用失败');
    if (value.success === false) return hasErrorValue(value.error) ? String(value.error) : 'success=false';
    if (hasErrorValue(value.error)) return String(value.error);
    if (o.pythonExec) {
      const stderr = value.stderr == null ? '' : String(value.stderr);
      if (stderr.trim() && !hasText(value.stdout) && !hasText(value.result)) {
        return stderr.trim().split('\n')[0];
      }
    }
  }
  return null;
}

// get_bytes 的真实 schema 在不同 ida-pro-mcp 版本间差异很大：
// 地址键有 addr/address、长度键有 size/count/无 两种；regions 的元素既可能是
// {addr,size} 对象（新版）也可能只是"起始地址"裸字符串（旧版）。
// 按"最贴近实测"到"旧兼容"排序，逐个尝试；参数被拒时换下一个，而不是把整次调用判死。
function buildGetBytesAttempts(addr, size) {
  const raw = String(addr == null ? '' : addr).trim();
  const addrNum = /^[0-9a-fA-Fx]+$/.test(raw) ? '0x' + raw.replace(/^0x/i, '') : raw;
  return [
    { regions: [{ addr: addrNum, size }] },   // 新版：对象形态
    { regions: [{ addr: addrNum }] },         // 新版但 size 由服务端默认
    { regions: [addrNum] },                   // 旧版：裸字符串形态
    { address: addrNum, size },
    { address: addrNum, count: size },
  ];
}

function pyExecArgs(filePath) {
  return { file_path: filePath };
}

// 从一段文本里提出字节。必须能分辨 hexdump 的三种列：
//   地址列（00401000 / 0x00401000 / 00401000:）、字节列（55 8b ec / 0x55 0x8b）、ASCII 列（.@..U...）。
// 早期实现把"任意偶数长度十六进制 token"一律当字节，于是 hexdump 的地址列被前置到数据里
// （`00401000  55 8b ec 83` 被解析成 00 40 10 00 55 8b ec 83），取证取字节时静默错位。
function bytesFromData(data) {
  if (data == null) return null;
  const text = String(data).trim();
  if (!text) return null;

  // 形态 A：标准 hexdump 行（地址 + 若干 2 位字节 + 可选 ASCII 列）。
  // 逐行解析：只取"地址后面、ASCII 列之前"的那些字节。
  const hexdumpLine = /^\s*(?:0x)?[0-9a-fA-F]{4,16}\s*[:|]?\s+((?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2})\s*(?:\|.*\||\s{2,}.*)?$/;
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const dumpBytes = [];
  let dumpLines = 0;
  for (const line of lines) {
    const m = line.match(hexdumpLine);
    if (!m) continue;
    const seg = m[1].trim().split(/\s+/);
    // 所有 token 都必须是 2 位；否则这行不是字节行
    if (!seg.every(t => /^[0-9a-fA-F]{2}$/.test(t))) continue;
    for (const t of seg) dumpBytes.push(parseInt(t, 16));
    dumpLines++;
  }
  if (dumpLines && dumpBytes.length) return Buffer.from(dumpBytes);

  // 形态 B：单行或多行，只有字节（无地址列）："0x55 0x8b" / "55 8b ec" / "558bec"
  const tokens = text.split(/[\s,]+/).filter(Boolean);
  const out = [];
  for (const tok of tokens) {
    // "0x401000:" 这类显式地址标签不是数据
    if (/^0x?[0-9a-fA-F]+:$/i.test(tok)) continue;
    // "0x401000"（无冒号、且值域明显超出单字节）是地址，不是字节
    if (/^0x[0-9a-fA-F]{5,}$/i.test(tok)) continue;
    const t = tok.replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]+$/.test(t)) return null;
    if (t.length === 2) { out.push(parseInt(t, 16)); continue; }
    // 无分隔的连续十六进制串（部分实现直接返回 "558bec"）
    if (t.length > 2 && t.length % 2 === 0) { out.push(...Buffer.from(t, 'hex')); continue; }
    return null;
  }
  return out.length ? Buffer.from(out) : null;
}

function formatHexdump(buf) {
  const lines = [];
  for (let i = 0; i < buf.length; i += 16) {
    const seg = buf.slice(i, i + 16);
    const ascii = [...seg].map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
    lines.push(('0000' + i.toString(16)).slice(-4) + '  ' + seg.toString('hex').replace(/(..)/g, '$1 ').trim() + '  ' + ascii);
  }
  return lines.join('\n');
}

// get_bytes 的主形态是数组 [{addr, data:'0x55 0x8b'}]（可能多段）。
// 多段必须**按返回顺序**拼接：它们是同一段内存的不同区间，顺序即地址顺序。
function parseBytesReply(reply) {
  if (reply == null) return null;

  if (typeof reply === 'string') {
    const buf = bytesFromData(reply);
    return buf && buf.length ? formatHexdump(buf) : null;
  }

  const items = Array.isArray(reply) ? reply : [reply];
  const chunks = [];
  for (const item of items) {
    if (typeof item === 'string') {
      const b = bytesFromData(item);
      if (b && b.length) chunks.push(b);
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    const b = bytesFromData(item.data);
    if (b && b.length) chunks.push(b);
  }
  if (!chunks.length) return null;
  return formatHexdump(Buffer.concat(chunks));
}

// py_exec_file 的返回是 {result, stdout, stderr}（stdout 不一定是字符串，按需取用）。
// 只认 BYTES 标记：没有标记就说明脚本没走到打印那一步，stderr 才是真实原因。
function parsePyExecReply(reply) {
  if (reply == null) return null;
  const readBytes = (s) => {
    if (typeof s !== 'string') return null;
    const m = s.match(/BYTES\s+([0-9a-fA-F]+)/);
    return m ? Buffer.from(m[1], 'hex') : null;
  };
  if (typeof reply === 'string') return readBytes(reply);
  if (typeof reply !== 'object') return null;

  const fromStdout = readBytes(reply.stdout);
  if (fromStdout && fromStdout.length) return fromStdout;
  const resultText = typeof reply.result === 'string'
    ? reply.result
    : (reply.result == null ? '' : JSON.stringify(reply.result));
  const fromResult = readBytes(resultText);
  if (fromResult && fromResult.length) return fromResult;
  return null;
}

// 把工具返回值归一成 {text,isError}。字符串失败（历史约定）与结构化 __toolError
// 都必须变成 is_error，否则模型会把错误当成"工具成功了但结果是这句话"。
function toToolResult(value) {
  if (value && typeof value === 'object' && value.__toolError) {
    return { text: String(value.message || '工具调用失败'), isError: true };
  }
  if (typeof value === 'string') {
    return { text: value, isError: !!toolFailureReason(value) };
  }
  let text;
  if (value === undefined) text = '';
  else if (typeof value === 'object') {
    try { text = JSON.stringify(value, null, 2); } catch (e) { text = String(value); }
  } else text = String(value);
  return { text, isError: !!toolFailureReason(value) };
}

// ida_get_bytes 的可注入 case 体：callMcp 与 writeTemp 由调用方提供，
// 因此纯 Node 就能断言"参数形态的试探顺序"和"终兜底 py_exec_file"。
async function idaGetBytes(deps, input) {
  const { callMcp, writeTemp, topLevelDir } = deps || {};
  const i = input || {};
  const addr = String(i.address == null ? '' : i.address).trim();
  const size = Math.min(parseInt(i.size, 10) || 256, 65536);

  let lastResp = '';
  for (const args of buildGetBytesAttempts(addr, size)) {
    try {
      const r = await callMcp('get_bytes', args);

      // 先把能读出来的字节取走，再看是否算失败。
      // 顺序很关键：多段返回里"某段 data 为 null、其余段有数据"是正常形态
      //（实测 [{data:null},{data:'0x55 0x8b'}]），若先判失败就会整体拒绝、
      // 永远走不到下面的跳过逻辑，把已经拿到的字节也丢掉。
      const parsed = parseBytesReply(r);
      if (parsed) return parsed;

      const failReason = toolFailureReason(r);
      lastResp = failReason || (typeof r === 'string' && r.trim() ? r.trim().slice(0, 200) : '返回结构不含字节数据');
      // 参数被拒（schema 不匹配）时 MCP 可能以普通文本返回，不是我们的失败前缀，
      // 但也不能当字节数据接受——继续换下一个形态。
      if (typeof r === 'string' && /missing|required param|invalid|Expected/i.test(r.slice(0, 300))) continue;
    } catch (e) {
      lastResp = e && e.message ? e.message : String(e);
    }
  }

  // 终兜底：走 IDAPython，返回形态是 {result,stdout,stderr}，与 get_bytes 完全不同。
  let tmp = null;
  try {
    const py = `import ida_bytes
ea=${/^[0-9a-fA-F]+$/.test(addr.replace(/^0x/i, '')) ? '0x' + addr.replace(/^0x/i, '') : JSON.stringify(addr)}
n=${size}
data=ida_bytes.get_bytes(ea,n) or b''
print('BYTES '+data.hex())
`;
    tmp = writeTemp(`ctf_get_bytes_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`, py);
    const r = await callMcp('py_exec_file', pyExecArgs(tmp));
    const buf = parsePyExecReply(r);
    if (buf && buf.length) return formatHexdump(buf);
    const reason = toolFailureReason(r, { pythonExec: true });
    if (reason) lastResp = reason;
  } catch (e2) {
    lastResp = e2 && e2.message ? e2.message : String(e2);
  } finally {
    // 兜底脚本是每次调用现生成的，留着只会攒垃圾（复核指出从未删除）。
    if (tmp) { try { fs.unlinkSync(tmp); } catch (e) { /* 清理失败不影响结果 */ } }
  }

  throw new ToolCallError('ida_get_bytes 全部形态失败（最后错误: ' + String(lastResp || '').slice(0, 150)
    + '）。替代方案：用 run_python 直接解析本地 ELF 文件读该地址（文件在 ' + (topLevelDir || '(未知)') + '）');
}

// scan_crypto 的可注入 case 体。结构推理必须读**文件原始字节**：
// 早期实现引用了不存在的 buf/size，导致每个带常量分析的样本都在此处抛
// "buf is not defined"，整条扫描结果被 catch 改写成一行错误文本。
function scanCryptoCase(deps, input) {
  const { fs: fsDep, scanCrypto, inferCipherStructure } = deps || {};
  const i = input || {};
  const f = String(i.path == null ? '' : i.path).trim();
  if (!f) return '参数错误：path 为空';
  if (!fsDep.existsSync(f)) return `文件不存在: ${f}`;

  let raw;
  try { raw = fsDep.readFileSync(f); } catch (e) { return `读取文件失败: ${e.message}`; }
  const r = scanCrypto(f);
  if (!r || !r.success) return `扫描失败: ${r && r.error}`;
  const size = r.size || raw.length;

  const lines = [];
  lines.push(`文件: ${f}  (${size} 字节)`);
  lines.push('');
  lines.push('## 主结论');
  for (const s of (r.summary || [])) {
    lines.push(`- 【${s.algo}】置信度 ${s.confidence}`);
    if (s.evidence) lines.push(`  证据: ${s.evidence}`);
    if (s.note) lines.push(`  建议: ${String(s.note).replace(/\n/g, '\n        ')}`);
  }
  if ((r.payloads || []).length) {
    lines.push('');
    lines.push('## 内嵌载荷（可用 extract_payload 提取）');
    for (const p of r.payloads) {
      const e = p.encode || {};
      lines.push(`- ${String(p.type).toUpperCase()} @0x${p.offset.toString(16)}` +
        ` 编码=${e.kind || 'none'}${e.key != null ? ' key=0x' + Number(e.key).toString(16) : ''}` +
        `${e.stride ? ' stride=' + e.stride : ''}${p.length ? ' len=' + p.length : ''}` +
        ` 置信度=${p.confidence || 'high'}`);
    }
  }
  const ca = (r.fingerprints || []).map(x => x.constantAnalysis).filter(Boolean);
  if (ca.length) {
    lines.push('');
    lines.push('## 常量差分分析（确定性推导）');
    for (const c of ca) {
      for (const n of (c.notes || [])) lines.push(`- ${n}`);
      if (c.decryptScript) {
        lines.push(`- 已生成 SM4 变体解密脚本（可用 gen_sm4_solver 取用）`);
        lines.push(`  密文候选: ${(c.decryptScript.ciphertextCandidates || []).map(x => x.offset + '(' + x.length + 'B)').join('、')}`);
      }
    }
    // 结构推理（Phase B）：给 AI 一个"骨架假设 + 置信度"，由 AI 决定路线
    const structs = inferCipherStructure(raw, size, ca[0]);
    if (structs.length) {
      lines.push('');
      lines.push('## 结构推理（假设，按证据强度排序——最终判断由你做）');
      for (const st of structs) {
        lines.push(`- 【${st.skeleton} 骨架】置信度 ${st.confidence}`);
        lines.push(`  证据: ${st.evidence}`);
        lines.push(`  建议: ${st.advice}`);
      }
    }
  }
  if ((r.fingerprints || []).length) {
    lines.push('');
    lines.push('## 原始命中（前 20）');
    lines.push((r.fingerprints || []).slice(0, 20).map(x => `${x.fp || x.algo}@${x.offset}${x.stride ? '(stride' + x.stride + ')' : ''}`).join('  '));
  }
  if ((r.highEntropy || []).length) {
    lines.push('');
    lines.push('## 高熵常量块（疑似 key/密文）');
    lines.push((r.highEntropy || []).map(h => `${h.offset}(${h.len}B) ${h.hex}`).join('\n'));
  }
  return lines.join('\n');
}

// 多行 `python -c "..."` 在 cmd.exe 下经常出现 err=null / stdout='' / stderr=''：
// 换行被 cmd 当成命令分隔，脚本实际没跑起来。识别这种形态并改写成临时 .py 文件执行。
// 前导 `cd /d X &&` 原样保留（cwdPrefix），否则相对路径的语义会丢。
//
// ⚠️ 只在「整条命令就是一个 python -c、后面没有任何东西」时才改写。
// 早期版本用"首个引号到末个引号"截取脚本体，于是
//   python -c "..." && echo DONE   → DONE 被静默丢弃
//   python -c "..." > out.txt      → 重定向被静默丢弃（文件没写，却报成功）
//   python -c "..." alpha beta     → 位置参数被丢弃（sys.argv[1:] 为空）
// 这些都会让模型以为"文件已写出/参数已传入"。宁可退回 shell 模式（保持原有行为），
// 也不能给出语义被悄悄改过的"成功"。
function rewriteMultilinePython(command) {
  const cmd = String(command == null ? '' : command);
  const shellMode = { mode: 'shell', script: null, cwdPrefix: '', command: cmd, interpreter: null };

  const cd = cmd.match(/^(\s*cd\s+(?:\/d\s+)?("[^"]+"|'[^']+'|[^&]*?)\s*&&\s*)/i);
  const cwdPrefix = cd ? cd[1] : '';
  const rest = (cd ? cmd.slice(cwdPrefix.length) : cmd).trim();

  const m = rest.match(/^(\S+)\s+-c\s+([\s\S]*)$/);
  if (!m) return shellMode;
  const exe = m[1].replace(/^["']|["']$/g, '');
  if (!/^(?:.*[\\/])?(?:python3?|py)(?:\.exe)?$/i.test(exe)) return shellMode;

  const body = m[2];
  const q = body[0];
  if (q !== '"' && q !== "'") return shellMode;

  // 找与开头配对的那个引号（尊重反斜杠转义），而不是最后一个引号。
  let end = -1;
  for (let i = 1; i < body.length; i++) {
    if (body[i] === '\\') { i++; continue; }
    if (body[i] === q) { end = i; break; }
  }
  if (end < 0) return shellMode;

  const script = body.slice(1, end);
  // 引号之后的东西（&&、|、>、位置参数）**原样保留**：改写成临时文件后接回同样的尾部，
  // 语义才等价。早期实现直接丢弃尾部，导致 `&& echo DONE` 消失、
  // `> out.txt` 报成功但文件不存在、`alpha beta` 的 sys.argv 变空。
  const tail = body.slice(end + 1);
  if (!script.includes('\n')) return shellMode;

  return { mode: 'file', script, cwdPrefix, command: cmd, interpreter: exe, tail };
}

// bash 的可注入 case 体：exec/tempDir/cwd 注入后可在纯 Node 下真实跑命令。
// 空 stdout 必须仍带 exit 码与 stderr——"无输出"不等于"命令成功"。
function runBash(deps, command) {
  const { exec, tempDir, cwd } = deps || {};
  const cmd = String(command == null ? '' : command);
  const rw = rewriteMultilinePython(cmd);
  const opts = { timeout: 120000, maxBuffer: 32 * 1024 * 1024 };
  if (cwd) opts.cwd = cwd;

  let tmpFile = null;
  let finalCmd = cmd;
  if (rw.mode === 'file') {
    tmpFile = path.join(tempDir || os.tmpdir(), `ctf_bash_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
    try {
      fs.writeFileSync(tmpFile, rw.script, 'utf8');
    } catch (e) {
      return Promise.resolve(`命令执行失败: 无法写入临时脚本 ${tmpFile}（${e.message}）`);
    }
    finalCmd = rw.cwdPrefix + '"' + (rw.interpreter || 'python') + '" "' + tmpFile + '"' + (rw.tail || '');
  }

  return new Promise((resolve) => {
    exec(finalCmd, opts, (error, stdout, stderr) => {
      if (tmpFile) { try { fs.unlinkSync(tmpFile); } catch (e) { /* 清理失败不影响结果 */ } }
      if (error) {
        const timedOut = error.killed || /timed out|ETIMEDOUT/i.test(error.message || '');
        resolve(timedOut
          ? `命令执行超时（120s 上限，已终止）。请改用更省时的命令或拆分执行。\n${truncateOutput(stderr)}`
          : `命令执行失败: ${error.message}\n${truncateOutput(stderr)}`);
        return;
      }
      if (stdout && stdout.trim()) {
        resolve(truncateOutput(stdout));
        return;
      }
      resolve(`命令执行结束（exit=0，无输出；stderr=${stderr && stderr.trim() ? truncateOutput(stderr) : '(空)'}；mode=${rw.mode}）`);
    });
  });
}

module.exports = {
  ToolCallError,
  toolFailureReason,
  hasErrorValue,
  bytesFromData,
  buildGetBytesAttempts,
  pyExecArgs,
  parseBytesReply,
  parsePyExecReply,
  toToolResult,
  rewriteMultilinePython,
  idaGetBytes,
  scanCryptoCase,
  runBash,
};
