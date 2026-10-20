// 工具登记一致性单测：每个新 AI 工具必须同时登记 7 处，
// 否则"AI 看不到 / 文本解析器认不出 / precheck 不拦 / UI 显示裸名"。
const fs = require('fs');
const path = require('path');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');

const NEW_TOOLS = ['ida_dbg', 'ida_dbg_mem', 'ida_disasm', 'ida_list_globals', 'remote_exec', 'traffic_extract'];

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

function sliceBetween(src, startMark, endMark, len) {
  const i = src.indexOf(startMark);
  if (i < 0) return '';
  if (endMark) {
    const j = src.indexOf(endMark, i);
    if (j > i) return src.slice(i, j);
  }
  return src.slice(i, i + (len || 2000));
}

const KNOWN = sliceBetween(mainSrc, 'const KNOWN = new Set([', ']);');
const MAP = sliceBetween(mainSrc, 'const MAP = {', '\n  };');
const LABEL = sliceBetween(mainSrc, 'function toolLabel', '// 执行命令（渲染层');
const PRECHECK = sliceBetween(mainSrc, 'function precheckToolCall', 'function levenshtein');
const PROMPT = appSrc;

for (const t of NEW_TOOLS) {
  console.log(`\n[${t}] 七处登记`);
  // ① getToolDefinitions schema（6 空格缩进）
  ok(new RegExp(`^\\s{6}name: "${t}"`, 'm').test(mainSrc), '① getToolDefinitions schema');
  // ② dispatch case
  ok(mainSrc.includes(`case '${t}':`), "② executeToolCall dispatch case");
  // ③ KNOWN 集合
  ok(KNOWN.includes(`'${t}'`), '③ parseTextToolCalls KNOWN');
  // ④ MAP（有裸参的工具）
  if (['ida_disasm', 'ida_dbg', 'ida_dbg_mem', 'remote_exec', 'traffic_extract', 'ida_list_globals'].includes(t)) {
    ok(new RegExp(`${t}: '[a-z_]+'`).test(MAP), '④ MAP 裸参映射');
  } else {
    ok(true, '④ MAP 不适用（无裸参）');
  }
  // ⑤ toolLabel
  ok(LABEL.includes(`case '${t}'`), '⑤ toolLabel');
  // ⑥ precheck：必填参数的中文提示
  ok(PRECHECK.includes(`name === '${t}'`), '⑥ precheck 分支');
  // ⑦ 提示词里给出可调用示例
  ok(PROMPT.includes(t), `⑦ 提示词/渲染层提到 ${t}`);
}

console.log('\n[ida_list_globals] schema 含 queries/filter/offset/count');
{
  const seg = sliceBetween(mainSrc, 'name: "ida_list_globals"', 'name: "ida_dbg"');
  ok(/queries: \{/.test(seg), 'schema 含 queries 对象');
  ok(/filter: \{ type: "string"/.test(seg), 'schema 含 filter');
  ok(/offset: \{ type: "number"/.test(seg), 'schema 含 offset');
  ok(/count: \{ type: "number"/.test(seg), 'schema 含 count');
}

console.log('\n[提示词] 固定小节 + 逐条示例');
{
  ok(/## 动态调试\/流量\/远程工具（仅在证据需要时使用）/.test(appSrc), '固定小节存在');
  const hint = sliceBetween(appSrc, '## 动态调试/流量/远程工具（仅在证据需要时使用）', '⏱ **预算纪律', 6000);
  for (const t of NEW_TOOLS) {
    ok(hint.includes(t), `提示词小节含 ${t} 的示例`);
  }
  // ida_list_globals 的说明改为分页参数
  ok(/ida_list_globals[\s\S]{0,200}(分页|count|offset)/.test(appSrc), 'ida_list_globals 说明提到分页参数');
}

console.log('\n[preload] 渲染层感知');
{
  ok(/idaMcpCallPaged:/.test(preloadSrc), 'preload 暴露 idaMcpCallPaged');
  ok(/detectCapabilities:/.test(preloadSrc), 'preload 暴露 detectCapabilities');
  ok(/trafficExtract:/.test(preloadSrc), 'preload 暴露 trafficExtract');
  ok(/analyzeSmc:/.test(preloadSrc), 'preload 暴露 analyzeSmc');
  ok(/setCaseDir:/.test(preloadSrc), 'preload 暴露 setCaseDir');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
