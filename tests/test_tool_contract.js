// 工具契约一致性测试：precheck 引用的参数名必须与 getToolDefinitions 的 schema 一致。
// 这类缺陷不会在单测里自然暴露，但会在真实 API 调用中让工具全面失效
// （v1.7.3 复查抓到的两个真 bug：run_python/ida_decompile 被误判缺 path；
//  ida_decompile 真实参数名是 function_name 而非 function）。
const fs = require('fs'), p = require('path');

const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

// ---- 从 getToolDefinitions() 抽取每个工具的 schema ----
function extractSchema(src, name) {
  const i = src.indexOf('name: "' + name + '"');
  if (i < 0) return null;
  // 限制在当前工具定义范围内（到下一个 name: "..." 或数组结束）
  const rest = src.slice(i);
  const nextName = rest.indexOf('\n      name: "', 10);
  const seg = nextName > 0 ? rest.slice(0, nextName) : rest.slice(0, 2000);
  // properties 块：从 "properties: {" 到同级的 "}, required:" 之前
  const propsBlock = (seg.match(/properties:\s*\{([\s\S]*?)\},\s*required:/) || [])[1] || '';
  const props = [...propsBlock.matchAll(/^\s*(\w+):\s*\{/gm)].map(m => m[1]);  const reqRaw = (seg.match(/required:\s*\[([^\]]*)\]/) || [])[1] || '';
  const required = [...reqRaw.matchAll(/"([^"]+)"/g)].map(m => m[1]);
  return { props, required };
}

const TOOLS = ['read_file', 'write_file', 'bash', 'run_python', 'glob', 'grep',
  'scan_crypto', 'extract_payload', 'analyze_structure', 'gen_block_cipher_solver',
  'gen_sm4_solver', 'ida_decompile', 'ida_get_bytes', 'ida_list_globals'];

console.log('A) schema 可解析');
const schemas = {};
for (const t of TOOLS) {
  const s = extractSchema(mainSrc, t);
  schemas[t] = s;
  ok(!!s && s.props.length > 0, `${t} schema 解析成功（props: ${s ? s.props.join(',') : '无'}）`);
}

console.log('\nB) precheck 的 needPath 只能包含真正有 path 的工具');
{
  const m = mainSrc.match(/const needPath = \[([\s\S]*?)\];/);
  ok(!!m, '找到 needPath 定义');
  const list = [...(m ? m[1] : '').matchAll(/'([^']+)'/g)].map(x => x[1]);
  ok(list.length > 0, `needPath 共 ${list.length} 项`);
  for (const t of list) {
    const s = schemas[t];
    ok(!!s && s.props.includes('path'),
      `${t} 在 needPath 中且确有 path 参数${s ? '（props: ' + s.props.join(',') + '）' : '（schema 未找到）'}`);
  }
  // 反向：有 path 且必填的工具都应该被覆盖（漏了只是少一层预检，不算错，只提示）
  const shouldHave = TOOLS.filter(t => schemas[t] && schemas[t].required.includes('path'));
  for (const t of shouldHave) {
    ok(list.includes(t), `必填 path 的 ${t} 已纳入 needPath`);
  }
  // 关键回归：这两个工具**没有** path 字段，绝不能出现在 needPath
  ok(!list.includes('run_python'), 'run_python 不在 needPath（它的参数是 script）');
  ok(!list.includes('ida_decompile'), 'ida_decompile 不在 needPath（它的参数是 function_name）');
}

console.log('\nC) IDA 工具的参数名校验必须与 schema 一致');
{
  const seg = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'));
  ok(/i\.function_name/.test(seg), 'ida_decompile 用 function_name（与 schema 一致）');
  ok(!/i\.function\b/.test(seg), '不再使用不存在的 i.function 字段');
  ok(/i\.address/.test(seg), 'ida_get_bytes 用 address');
  ok(schemas.ida_get_bytes.required.includes('address'), 'schema 确认 address 必填');
  ok(schemas.ida_decompile.required.includes('function_name'), 'schema 确认 function_name 必填');
}

console.log('\nD) grep 的 path 是可选的，不能因缺 path 拦截');
{
  ok(schemas.grep.required.includes('pattern'), 'grep 必填 pattern');
  ok(!schemas.grep.required.includes('path'), 'grep 的 path 非必填');
  const seg = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'));
  const grepBlock = seg.slice(seg.indexOf("name === 'grep'"), seg.indexOf("name === 'grep'") + 160);
  ok(!/!i\.path/.test(grepBlock), 'grep 预检不再要求 path');
}

console.log('\nE) tool_result 必须一对一（不得伪造 tool_use_id）');
{
  // 任何 `tool_use_id: 表达式 + '-xxx'` 都会让 API 找不到对应 tool_use → 400
  const bad = [...mainSrc.matchAll(/tool_use_id:\s*\w+\s*\+\s*'-/g)];
  ok(bad.length === 0, `无伪造 id（发现 ${bad.length} 处）`);
  const pushCount = (mainSrc.match(/toolResults\.push\(/g) || []).length;
  ok(pushCount > 0, `toolResults.push 共 ${pushCount} 处（正常路径）`);
}

console.log('\nF) 压缩后的上下文结构（静态检查）');
{
  const rt = fs.readFileSync(p.join(__dirname, '..', 'electron', 'agent-runtime.js'), 'utf8');
  ok(/alignToToolPair/.test(rt), '压缩切分点做了 tool_use/tool_result 对齐');
  ok(/function sanitizeHistoryForResume/.test(rt), '会话恢复有结构清洗');
  ok(/is_error/.test(rt.slice(rt.indexOf('function microcompact'), rt.indexOf('function sha256'))),
    '微压缩显式跳过 is_error');
}

console.log('\nG) toolLabel 的 case 必须对应真实工具名');
{
  // 之前的真 bug：写的是 ida_xrefs，而定义是 ida_get_xrefs → UI 显示裸工具名
  const seg = mainSrc.slice(mainSrc.indexOf('function toolLabel'), mainSrc.indexOf('// 执行命令（渲染层'));
  const caseNames = [...seg.matchAll(/case '([a-z_0-9]+)'/g)].map(m => m[1]);
  const defined = [...mainSrc.matchAll(/^\s{6}name: "([a-z_0-9]+)"/gm)].map(m => m[1]);
  const unknown = caseNames.filter(n => !defined.includes(n));
  ok(unknown.length === 0, `toolLabel 无未知工具名（未知: ${unknown.join(',') || '无'}）`);

  // 覆盖率：核心工具必须有中文标签（default 分支会显示裸名）
  const MUST = ['read_file', 'write_file', 'bash', 'run_python', 'scan_crypto',
    'extract_payload', 'analyze_structure', 'gen_block_cipher_solver',
    'ida_decompile', 'ida_get_bytes', 'ida_get_xrefs', 'ida_find_strings'];
  for (const t of MUST) ok(caseNames.includes(t), `toolLabel 覆盖 ${t}`);
}

console.log('\nH) MCP 字节读取的参数形态与解析（从 tool-result.js require）');{
  const { buildGetBytesAttempts, pyExecArgs } = require('../electron/tool-result.js');
  const at = buildGetBytesAttempts('0x401000', 16);
  ok(at.length === 5, `五形态（实际 ${at.length}）`);
  ok(at[0].regions && at[0].regions[0].addr === '0x401000' && at[0].regions[0].size === 16,
    '形态1 = regions[{addr,size}]（实测形态优先）');
  // 新版插件 regions 元素是对象但可能不接受 size：单独一档试探，
  // 否则"只认 {addr} 对象形态"的服务端会在第 1 档失败后直接跳到裸串形态。
  ok(at[1].regions && at[1].regions[0].addr === '0x401000' && !('size' in at[1].regions[0]),
    '形态2 = regions[{addr}]（无 size 的对象形态）');
  ok(Array.isArray(at[2].regions) && at[2].regions[0] === '0x401000', '形态3 = regions[{addr}] 的字符串简写');
  ok(at[3].address === '0x401000' && at[3].size === 16 && !('count' in at[3]), '形态4 = {address,size}');
  ok(at[4].address === '0x401000' && at[4].count === 16 && !('size' in at[4]), '形态5 = {address,count}');
  const py = pyExecArgs('X');
  ok(Object.keys(py).length === 1 && py.file_path === 'X', 'pyExecArgs 深等于 {file_path:"X"}');
}

console.log('\nI) ida_list_globals 的 schema 与 dispatch');
{
  const s = schemas.ida_list_globals;
  ok(!!s, 'ida_list_globals schema 可解析');
  for (const p of ['queries', 'filter', 'offset', 'count']) {
    ok(s && s.props.includes(p), `schema 含 ${p}`);
  }
  ok(/case 'ida_list_globals':[\s\S]{0,120}idaMcpCallPaged\('list_globals'/.test(mainSrc),
    'dispatch 调用 list_globals（分页）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
