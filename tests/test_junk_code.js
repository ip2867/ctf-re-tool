// 花指令识别与修补（通用能力，非特解）
//
// 设计立场：只实现"花指令之所以成立"的一般原理，不针对任何具体题目字节序列。
// 判据（来自公开方法论 + x86 反汇编原理）：
//   L1 跳转可达性：确定标志位（xor/test/cmp/clc）+ 短跳过（≤2 字节）/ 目标非边界
//   L1' 互补跳转对：jz/jnz 成对、条件互斥、一侧落进垃圾
//   L2 边界歧义：跳转目标不落在指令边界（解码错位证据）
//   L3 段边界：push/pop 栈平衡
//
// 同时锁定"不要重犯的错误"：
//   · 不得仅凭 "xor reg,reg 后跟 jcc" 就判花指令（会把正常清零当垃圾 → SIGSEGV）
//   · 不得把 "call $+5; pop reg"（PIC 取址）当花指令
//   · 线性扫描在解码已偏时结果不可信 → 默认走递归下降
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const { scanJunk, scanJunkRecursive, patchJunk, decodeInsn } = require('../electron/junk-code.js');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

console.log('[1] 模块与接线');
{
  ok(typeof scanJunk === 'function' && typeof scanJunkRecursive === 'function' && typeof patchJunk === 'function', '导出 scanJunk / scanJunkRecursive / patchJunk');
  ok(/require\('\.\/junk-code'\)/.test(mainSrc), 'main.js require junk-code');
  ok(/name: "junk_scan"/.test(mainSrc) && /name: "junk_patch"/.test(mainSrc), '两个 AI 工具定义');
  ok(/case 'junk_scan'/.test(mainSrc) && /case 'junk_patch'/.test(mainSrc), '两个 executeToolCall 分支');
  ok(/case 'junk_scan': return/.test(mainSrc), 'toolLabel 有中文标签');
  ok(/entries:/.test(mainSrc) && /mode: \{ type: "string"/.test(mainSrc), 'junk_scan 支持 entries / mode 参数');
  ok(/name: "junk_repair"/.test(mainSrc) && /case 'junk_repair'/.test(mainSrc), 'junk_repair 工具已注册（推荐路径）');
  // 知识库
  const skill = fs.readFileSync(path.join(__dirname, '..', 'skills', 'ctf-obfuscation', 'SKILL.md'), 'utf8');
  ok(/花指令/.test(skill) && /互补|永真|非对齐/.test(skill) && /push|esp/.test(skill), 'skill ctf-obfuscation 内容完整');
  ok(['F01', 'F02', 'F03', 'F04', 'F05', 'F06', 'F07', 'F08', 'F09', 'F10', 'F11'].every(x => skill.includes(x)),
    'skill 覆盖 11 类特征编号');
  ok(/CODE XREF/.test(skill) && /不等于/.test(skill), 'skill 写明"XREF 不等于花指令"的纪律');
  const wiki = fs.readFileSync(path.join(__dirname, '..', 'wiki', 'reverse', 'method_junk_code.md'), 'utf8');
  ok(/attack_chain/.test(wiki) && /failed_attempts/.test(wiki) && /key_payload/.test(wiki), 'wiki 方法论条目含结构化 meta');
  const idx = fs.readFileSync(path.join(__dirname, '..', 'wiki', 'AI-SEARCH-INDEX.md'), 'utf8');
  ok(/method_junk_code\.md/.test(idx), 'AI-SEARCH-INDEX 已登记');
  ok(/reverse\/method_junk_code\.md/.test(appSrc), '提示词 METHOD_PAGES 已点名');
  ok(/'花指令'/.test(appSrc) && /'sp-analysis'/.test(appSrc), '预取 POOL 含花指令检索词');
}

console.log('\n[2] 指令解码基础');
{
  const b = Buffer.from([0x55, 0x89, 0xe5, 0x31, 0xc0, 0x75, 0x01, 0x90, 0xc3]);
  const d0 = decodeInsn(b, 0);
  ok(d0 && d0.op === 0x55 && d0.len === 1, 'push ebp 解码');
  const d1 = decodeInsn(b, 1);
  ok(d1 && d1.op === 0x89 && d1.len === 2, 'mov ebp,esp 解码');
  const d2 = decodeInsn(b, 3);
  ok(d2 && d2.op === 0x31 && d2.modrm && d2.modrm.mod === 3 && d2.modrm.reg === 0, 'xor eax,eax 解码（ModRM mod=3）');
  const d3 = decodeInsn(b, 5);
  ok(d3 && d3.kind === 'jcc8' && d3.rel === 1, 'jnz +1 解码（rel 正确）');
}

console.log('\n[3] 行为：经典花指令（自清零 + 短跳过）');
{
  // push ebx; xor ebx,ebx; test ebx,ebx; jnz+1; (垃圾 0xE8); pop ebx
  const b = Buffer.from([0x53, 0x31, 0xdb, 0x85, 0xdb, 0x75, 0x01, 0xe8, 0x5b, 0x90, 0x90, 0x90]);
  const r = scanJunkRecursive(b, { start: 0, end: b.length, entries: [0] });
  ok(r.ok === true, '扫描成功');
  ok(r.candidates.length >= 1, '识别出候选', String(r.candidates.length));
  const c = r.candidates[0];
  ok(c && /flagset_short_skip|complementary_pair/.test(c.type), '类型是确定标志位/互补跳转', c && c.type);
  ok(c && c.nopRange && (c.nopRange.to - c.nopRange.from) <= 4, 'nop 范围很小（只清垃圾）', c && JSON.stringify(c.nopRange));
  const pr = patchJunk(b, r.candidates, { minConfidence: 'high' });
  ok(pr.applied.length >= 1, 'patch 应用到至少 1 处');
  // 修补后：push/pop 必须还在（栈平衡不能破坏）
  ok(pr.buffer[0] === 0x53, 'push ebx 保留');
  ok(pr.buffer.includes(0x5b), 'pop ebx 保留');
  ok(pr.buffer.includes(0x90), '垃圾已变 nop');
}

console.log('\n[4] 反面：不得误判正常代码');
{
  // 正常：xor eax,eax; jnz 远处（rel=20）→ 不是花指令
  const b = Buffer.alloc(40, 0x90);
  b[0] = 0x31; b[1] = 0xc0;              // xor eax,eax
  b[2] = 0x75; b[3] = 0x14;              // jnz +20
  const r = scanJunkRecursive(b, { start: 0, end: b.length, entries: [0] });
  const bad = r.candidates.filter(c => c.type === 'flagset_short_skip');
  ok(bad.length === 0, 'xor+jcc 且 rel 大 → 不判花指令（防 SIGSEGV 重演）', JSON.stringify(bad));

  // PIC 取址：call $+5; pop eax → 不是花指令
  const b2 = Buffer.alloc(32, 0x90);
  b2[0] = 0xe8; b2.writeInt32LE(0, 1);   // call $+5
  b2[5] = 0x58;                          // pop eax
  const r2 = scanJunkRecursive(b2, { start: 0, end: b2.length, entries: [0] });
  ok(r2.stats.picCallPop === 1, 'PIC 取址被统计但不报花指令');
  ok(r2.candidates.length === 0, 'PIC 取址不进候选');
}

console.log('\n[5] 递归下降 vs 线性扫描（核心差异）');
{
  ok(/mode: 'recursive'/.test(fs.readFileSync(path.join(__dirname, '..', 'electron', 'junk-code.js'), 'utf8')), '递归下降模式有标记');
  const b = Buffer.alloc(200, 0x90);
  // entry 处 ret，后面全是"未触及"数据 → 递归下降只走少量指令，报大块不可达
  b[0] = 0xc3;
  const r = scanJunkRecursive(b, { start: 0, end: b.length, entries: [0] });
  ok(r.stats.unreachedRegions >= 1, '识别出不可达区间（花指令块候选）');
  ok(r.stats.unreachedBytes > 100, '不可达字节数正确', String(r.stats.unreachedBytes));
}

console.log('\n[6] patch 安全性');
{
  const b = Buffer.from([0x90, 0x90, 0x90, 0x90]);
  const pr = patchJunk(b, [
    { off: 0, type: 'x', confidence: 'high', nopRange: { from: 0, to: 2 } },
    { off: 1, type: 'y', confidence: 'high', nopRange: { from: 1, to: 3 } },   // 重叠
    { off: 2, type: 'z', confidence: 'low', nopRange: { from: 2, to: 3 } },    // 低置信度
    { off: 3, type: 'w', confidence: 'high', nopRange: null },                 // 无范围
    { off: 4, type: 'v', confidence: 'high', nopRange: { from: 0, to: 200 } }, // 越界
  ], { minConfidence: 'high' });
  ok(pr.applied.length === 1, '只应用 1 处（重叠/低置信度/无范围/越界都被拒）', String(pr.applied.length));
  ok(pr.skipped.length === 4, '4 处被跳过', String(pr.skipped.length));
  ok(b[0] === 0x90, '原 buffer 未被修改');
}

console.log('\n[7] 修复后交接链（本轮新增，防止 AI 在旧 IDB 上误判）');
{
  // 工具必须自己能把 IDA 切到修补后的文件，不能指望模型记得调
  ok(/async function idaReloadAndWait/.test(mainSrc), '存在 idaReloadAndWait（写盘后自动重载）');
  ok(/idaReloadAndWait\(outPath/.test(mainSrc), 'junk_repair 写盘后调用 idaReloadAndWait');
  ok(/name: "ida_open_file"/.test(mainSrc), 'ida_open_file 工具已定义');
  ok(/case 'ida_open_file'/.test(mainSrc), 'ida_open_file 有 executeToolCall 分支');
  // open_file 必须开 autonomous：否则新实例弹模态框，MCP 端口注册不上
  const openSeg = mainSrc.slice(mainSrc.indexOf("case 'open_file':"), mainSrc.indexOf("case 'open_file':") + 600);
  ok(/autonomous: args\.autonomous !== false/.test(openSeg), 'open_file 默认 autonomous=true');
  // 重载前删旧 .i64，否则 -A 模式下"是否覆盖"对话框可能被拒
  ok(/\.i64/.test(mainSrc) && /unlinkSync/.test(mainSrc), '重载前清理旧 .i64/.idb');
  // 不能假装成功：open_file 没注册上端口时必须报失败
  ok(/opened\.port/.test(mainSrc) || /未注册 MCP 端口/.test(mainSrc), '未注册端口时明确报失败而非假装成功');

  // 判读口径：必须告诉模型"百分比下降不代表变差"
  ok(/函数数会变多/.test(appSrc) && /不是变差|百分比反而可能下降/.test(appSrc),
    '提示词说明"修补后成功率下降是正常现象"');
  ok(/绝对数/.test(appSrc), '提示词要求看可反编译函数的绝对数');

  // 硬禁令：禁止自写 nop 脚本
  ok(/禁止自己写脚本 nop 花指令/.test(appSrc), '提示词禁止自写 nop 脚本');
  ok(/禁止在调用 junk_repair 之前下任何算法结论/.test(appSrc), '提示词禁止提前下算法结论');
  // junk_repair 必须输出同口径对比
  ok(/修补效果（工具自测，同口径对比）/.test(mainSrc), 'junk_repair 输出修复前后对比表');
  ok(/非对齐跳转下降/.test(mainSrc), 'junk_repair 报告下降百分比');

  // 多实例兜底：open_file 拿不到端口时必须自己找回来（实测 4 个 IDA 实例时静默返回 undefined）
  ok(/idaMcpCallTool\('list_instances'/.test(mainSrc), 'open_file 无端口时用 list_instances 兜底');
  ok(/idaMcpCallTool\('select_instance'/.test(mainSrc), '兜底后用 select_instance 精确切换');
  ok(/'list_instances': \['list_instances'\]/.test(mainSrc), 'list_instances 已登记到逻辑名映射');
  ok(/'open_file': \['open_file'\]/.test(mainSrc), 'open_file 已登记到逻辑名映射');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
