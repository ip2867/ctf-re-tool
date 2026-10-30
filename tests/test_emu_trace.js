// 执行轨迹原语回归（emu-trace）
//
// 这批断言锁的是 Obfuscating Macros II 那轮暴露的核心缺口：
// 程序被切成 92 段、跳转目标运行期算出来 → 静态 CFG 是碎的 → 反编译读不懂。
// 题目作者给的人类解法是 "record a execution trace and set those jump targets"，
// 也就是本模块的两个工具：
//   emu_trace       —— Unicorn 真跑，记录每次间接跳转 src → 实际 dst
//   ida_apply_trace —— 把轨迹回填成 create_insn + add_cref + add_func
//
// 生成物是 Python / IDAPython 源码，所以除结构断言外还要真跑语法解析。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const { buildEmuTraceScript, buildApplyTraceScript, summarizeTrace, parseIntLoose } =
  require('../electron/emu-trace.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function pySyntaxOk(code) {
  const tmp = path.join(os.tmpdir(), 'ctf-emu-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.py');
  fs.writeFileSync(tmp, code);
  try {
    execSync('python -c "import ast,sys; ast.parse(open(sys.argv[1],encoding=\'utf-8\').read())" "' + tmp + '"',
      { stdio: 'pipe' });
    return { ok: true };
  } catch (e) {
    return { ok: false, err: String(e.stderr || e.message).slice(0, 400) };
  } finally {
    try { fs.unlinkSync(tmp); } catch (x) { }
  }
}

console.log('[1] 参数校验');
{
  ok(buildEmuTraceScript({}).error, '缺 binary 返回 error');
  ok(/需要 binary/.test(buildEmuTraceScript({}).error), '错误信息说明缺 binary');
  ok(buildEmuTraceScript({ binary: '/x' }).error, 'mode=function 缺 start 返回 error');
  ok(/mode=function 需要 start/.test(buildEmuTraceScript({ binary: '/x' }).error), '错误信息提示需要 start');
  const e = buildEmuTraceScript({ binary: '/x', mode: 'entry' });
  ok(!e.error, 'mode=entry 不需要 start', e.error);
  ok(buildEmuTraceScript({ binary: '/x', start: 1, mode: 'bogus' }).error, '非法 mode 返回 error');
  ok(parseIntLoose('0x401006') === 0x401006 && parseIntLoose('100') === 100, 'parseIntLoose 十六/十进制');
}

console.log('\n[2] emu_trace 脚本结构（运行时地面真值）');
{
  const r = buildEmuTraceScript({ binary: '/tmp/chall', start: 0x401006, mode: 'function' });
  ok(r.ok && r.script, '生成成功');
  const c = r.script;

  // —— 依赖与架构 ——
  ok(/from unicorn import/.test(c), '用 unicorn');
  ok(/from capstone import/.test(c), '用 capstone（识别间接跳转）');
  ok(/from elftools\.elf\.elffile import ELFFile/.test(c), '用 pyelftools 解析 ELF');
  ok(/UC_MODE_64 if BITS == 64 else UC_MODE_32/.test(c), '按 ELF 位数选 32/64 模式');
  ok(/PT_INTERP/.test(c) && /has_interp/.test(c), '检测动态链接（PT_INTERP）');

  // —— 通用 PLT / GOT 打桩（C++ 题不被 operator new 挡住）——
  ok(/_Znwm/.test(c), '打桩 operator new（_Znwm）');
  ok(/"memset"/.test(c) && /"memcpy"/.test(c), '打桩 memset / memcpy');
  ok(/"strlen"/.test(c), '打桩 strlen');
  ok(/UC_X86_REG_FS_BASE/.test(c), '设置 TLS 基址（fs:[0x28] canary 否则读失败）');
  ok(/TLS_BASE \+ 0x28/.test(c), '写入 canary 槽');
  ok(/TRAMP_BASE/.test(c) && /struct\.pack\(PK, tramp\)/.test(c), 'GOT 槽重定向到跳板（-fno-plt/BIND_NOW 也兜住）');
  ok(/_names\[_k\]/.test(c), '.plt 桩按 .rela.plt 顺序对应（PLT0 偏移已处理）');

  // —— 间接跳转识别：这是核心 ——
  ok(/S\["pending"\]/.test(c), '记录上一条分支指令，用于配对 src→dst');
  ok(/S\["ind"\]\.setdefault\(src, \{\}\)/.test(c), '按 src 汇总间接跳转目标');
  ok(/CS_GRP_JUMP/.test(c) && /CS_GRP_CALL/.test(c), '识别 jump / call 组');
  ok(/X86_OP_MEM/.test(c) && /rd_ptr\(uc, ea\)/.test(c), '支持 jmp [mem] 形式（读指针得目标）');
  ok(/ins\.reg_name\(op\.reg\)/.test(c), '支持 jmp reg 形式（读寄存器得目标）');

  // —— 输出契约 ——
  ok(/TRACE_JSON=/.test(c), '输出 TRACE_JSON 路径');
  ok(/IND %s -> %d targets/.test(c), '打印 "间接跳转源 -> N 个目标"');
  ok(/"indirect_sites"/.test(c) && /"edges"/.test(c) && /"exec_ranges"/.test(c),
    'JSON 含 indirect_sites / edges / exec_ranges 三张表');
  ok(/"stop"/.test(c) && /"error"/.test(c), 'JSON 含停止原因与错误');
  ok(/to_ranges/.test(c), '执行地址压缩成区间（减小体积）');

  // —— 32/64 位调用约定 ——
  ok(/cdecl/.test(c) && /push_arg/.test(c), '32 位按 cdecl 压栈传参');
  ok(/regs = \["rdi", "rsi", "rdx", "rcx", "r8", "r9"\]/.test(c), '64 位按 SysV 寄存器传参');

  const syn = pySyntaxOk(c);
  ok(syn.ok, 'python 语法通过', syn.err);

  // —— 参数真的写进了脚本 ——
  ok(new RegExp('START = ' + 0x401006).test(c), 'start 写入脚本');
  const r2 = buildEmuTraceScript({ binary: '/tmp/c', start: 1, mode: 'function', max_insns: 5000, stop_at: ['0x402000'] });
  ok(/MAX_INSNS = 5000/.test(r2.script), 'max_insns 生效');
  ok(/STOP_AT = \[4202496\]/.test(r2.script), 'stop_at 归一化成十进制', String(0x402000));
  const r3 = buildEmuTraceScript({ binary: '/tmp/c', start: 1, mode: 'function', stdin: '41424344' });
  ok(/STDIN_BYTES = bytes\.fromhex\("41424344"\)/.test(r3.script), '带数字的 hex stdin 直接透传');
  const r4 = buildEmuTraceScript({ binary: '/tmp/c', start: 1, mode: 'function', stdin: 'ABCD' });
  ok(/STDIN_BYTES = bytes\.fromhex\("41424344"\)/.test(r4.script), '纯字母串按文本处理（不误判成 hex）');
  const r5 = buildEmuTraceScript({ binary: '/tmp/c', start: 1, mode: 'function', stdin: '0xdeadbeef' });
  ok(/STDIN_BYTES = bytes\.fromhex\("deadbeef"\)/.test(r5.script), '0x 前缀强制按 hex');
}

console.log('\n[3] 体积上限与钳制');
{
  const r = buildEmuTraceScript({ binary: '/x', start: 1, mode: 'function', max_insns: 1e12, heap_size: 1 });
  ok(/MAX_INSNS = 50000000/.test(r.script), 'max_insns 上限 5000 万');
  ok(/HEAP_SIZE = 65536/.test(r.script), 'heap_size 下限 64KB');
  const r2 = buildEmuTraceScript({ binary: '/x', start: 1, mode: 'function', max_insns: 1 });
  ok(/MAX_INSNS = 1000/.test(r2.script), 'max_insns 下限 1000');
}

console.log('\n[4] ida_apply_trace：回填轨迹');
{
  ok(buildApplyTraceScript({}).error, '缺 trace 返回 error');
  ok(/需要 trace/.test(buildApplyTraceScript({}).error), '错误信息说明缺 trace');

  const trace = {
    stop: 'return',
    indirect_sites: [
      { src: '0x401138', targets: [{ value: '0x2', dst: '0x4011bf', count: 1 }, { value: '0x4', dst: '0x40120a', count: 1 }] },
    ],
    edges: [['0x401131', '0x401138'], ['0x401138', '0x4011bf'], ['0x40115d', '0x401200']],
    exec_ranges: [['0x401006', '0x403000']],
  };
  const r = buildApplyTraceScript({ trace });
  ok(r.ok && r.tool === 'py_eval', '走 py_eval', r.error);
  const c = r.args.code;

  ok(/import ida_bytes, ida_ua, ida_funcs, ida_xref/.test(c), '引入 MakeCode / xref / 函数 API');
  ok(/ida_ua\.create_insn/.test(c), '用 create_insn 建代码');
  ok(/ida_xref\.add_cref/.test(c), '用 add_cref 连边');
  ok(/ida_funcs\.add_func/.test(c), '用 add_func 建函数');
  ok(/del_items\(h, ida_bytes\.DELIT_SIMPLE/.test(c), '目标落在别的指令内部时先 del_items（否则 create_insn 必失败）');
  ok(/_exec_seg/.test(c) && /SEGPERM_EXEC/.test(c), '只在可执行段建代码（不污染 .rodata）');

  // 顺序很重要：先建代码再挂 xref
  const iInd = c.indexOf('for _d in IND_TARGETS');
  const iEdge = c.indexOf('for _e in EDGES');
  ok(iInd !== -1 && iEdge !== -1 && iInd < iEdge, '先处理间接跳转目标，再连通用边');

  ok(r.stats.indTargets === 2, '统计出 2 个间接跳转目标', String(r.stats.indTargets));
  ok(r.stats.edges === 3, '统计出 3 条边', String(r.stats.edges));
  ok(/IND_TARGETS = \[4202943, 4199482\]|IND_TARGETS = \[/.test(c), '目标地址写入脚本');
  ok(/print\("APPLY insn_made/.test(c), '打印回填统计');
  ok(/NEXT /.test(c), '给出下一步指引');

  const syn = pySyntaxOk(c);
  ok(syn.ok, 'python 语法通过', syn.err);

  // 去重
  const dup = buildApplyTraceScript({ trace: { edges: [['0x1', '0x2'], ['0x1', '0x2']], indirect_sites: [] } });
  ok(dup.stats.edges === 1, '重复边去重', String(dup.stats.edges));

  // 只有间接跳转目标也应当能回填
  const onlyInd = buildApplyTraceScript({ trace: { indirect_sites: trace.indirect_sites, edges: [] } });
  ok(!onlyInd.error, '只有 indirect_sites 也能回填', onlyInd.error);

  // 什么都没有要报错
  ok(buildApplyTraceScript({ trace: { edges: [], indirect_sites: [] } }).error, '空轨迹返回 error');

  // JSON 文本形式
  const asText = buildApplyTraceScript({ trace: JSON.stringify(trace) });
  ok(!asText.error && asText.stats.edges === 3, 'trace 传 JSON 文本也能用', asText.error);

  // make_funcs / code_ranges / auto_wait 开关
  ok(/MAKE_FUNCS = False/.test(buildApplyTraceScript({ trace, make_funcs: false }).args.code), 'make_funcs=false 生效');
  ok(/CODE_RANGES = True/.test(buildApplyTraceScript({ trace, code_ranges: true }).args.code), 'code_ranges=true 生效');
  ok(/if True:\n    try:\n        ida_auto\.auto_wait/.test(buildApplyTraceScript({ trace, auto_wait: true }).args.code),
    'auto_wait=true 生效');
}

console.log('\n[5] 体积截断（防 py_eval 撑爆 MCP）');
{
  const edges = [];
  for (let i = 0; i < 45000; i++) edges.push(['0x' + (0x401000 + i).toString(16), '0x' + (0x402000 + i).toString(16)]);
  const r = buildApplyTraceScript({ trace: { edges, indirect_sites: [] } });
  ok(r.stats.edges === 40000, '边数截断到 40000', String(r.stats.edges));
  ok(r.stats.truncated.length > 0 && /edges 45000->40000/.test(r.stats.truncated[0]), '记录截断信息', String(r.stats.truncated));
}

console.log('\n[6] summarizeTrace：摘要给人看');
{
  const s = summarizeTrace({
    stop: 'return', insn_count: 137310, regs: { rax: '0xa1e8895eb916b732', rdx: '0x50a2dcc51ed6c4a2' },
    indirect_sites: [{ src: '0x401138', distinct: 2, targets: [{ value: '0x2', dst: '0x4011bf', count: 1 }] }],
    stubs: { _Znwm: 12 }, stdout: 'hello',
  });
  ok(/停止原因: return/.test(s), '摘要含停止原因');
  ok(/137310/.test(s), '摘要含指令数');
  ok(/0xa1e8895eb916b732/.test(s), '摘要含返回寄存器值（可直接当算法输出核对）');
  ok(/0x401138/.test(s) && /0x2→0x4011bf/.test(s), '摘要含间接跳转映射（段号→段地址）');
  ok(/_Znwm/.test(s), '摘要含打桩函数');
}

console.log('\n[7] 接线：两个工具在 main.js 里可达');
{
  ok(/name: "emu_trace"/.test(mainSrc), 'emu_trace 工具已定义');
  ok(/name: "ida_apply_trace"/.test(mainSrc), 'ida_apply_trace 工具已定义');
  ok(/case 'emu_trace'/.test(mainSrc), 'emu_trace 有 dispatch 分支');
  ok(/case 'ida_apply_trace'/.test(mainSrc), 'ida_apply_trace 有 dispatch 分支');
  ok(/'emu_trace', 'ida_apply_trace'/.test(mainSrc), '两个名字进 KNOWN 集合（文本工具调用可解析）');
  ok(/emu_trace: 'binary'/.test(mainSrc) && /ida_apply_trace: 'trace'/.test(mainSrc), '进 MAP 裸参映射');
  ok(/if \(name === 'emu_trace'\)/.test(mainSrc), 'precheck 有 emu_trace 分支');
  ok(/if \(name === 'ida_apply_trace'\)/.test(mainSrc), 'precheck 有 ida_apply_trace 分支');
  ok(/case 'emu_trace': return '执行轨迹/.test(mainSrc), 'toolLabel 有 emu_trace');
  ok(/case 'ida_apply_trace': return '回填轨迹/.test(mainSrc), 'toolLabel 有 ida_apply_trace');
  ok(/require\('\.\/emu-trace'\)/.test(mainSrc), 'main.js 惰性 require emu-trace');
}

console.log('\n[8] 文档/提示词可达性');
{
  const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
  ok(appSrc.includes('emu_trace'), '渲染层提示词提及 emu_trace');
  ok(appSrc.includes('ida_apply_trace'), '渲染层提示词提及 ida_apply_trace');
  const skillPath = path.join(__dirname, '..', 'skills', 'ctf-obfuscation', 'SKILL.md');
  const skill = fs.readFileSync(skillPath, 'utf8');
  ok(/emu_trace/.test(skill), 'skill 提及 emu_trace');
  ok(/ida_apply_trace/.test(skill), 'skill 提及 ida_apply_trace');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
