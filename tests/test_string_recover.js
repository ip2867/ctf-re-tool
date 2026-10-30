// 字符串还原 + 环境适配回归
//
// 本轮（NaughtyBoy）暴露的三个通用缺口：
//   ① 前缀靠"读伪代码"记，一字之差全盘皆错（bytecf{ vs bytectf{）
//      → 新增 recover_string：从 cmp 立即数确定性还原
//   ② Nox `-clone:Nox_1` 在只有默认实例的机器上直接退出（player is not exist）
//      → 三档回落
//   ③ frida 客户端/服务端版本不一致 → "connection closed"，
//      现象与"服务没起来"完全一样 → 版本检测 + 明确提示
const fs = require('fs');
const path = require('path');

const {
  assembleByteComparisons, extractByteCompares, recoverComparedString, prefixWarnings,
} = require('../electron/string-recover.js');

const ROOT = path.join(__dirname, '..');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// 实测的 IDA 反汇编片段（x86_64 SignTools_check）
const REAL_DISASM = `
0x1c68  cmp     byte ptr [rax], 0x62
0x1c71  cmp     byte ptr [rbx+1], 0x79
0x1c7b  cmp     byte ptr [rbx+2], 0x74
0x1c85  cmp     byte ptr [rbx+3], 0x65
0x1c8f  cmp     byte ptr [rbx+4], 0x63
0x1c99  cmp     byte ptr [rbx+5], 0x74
0x1ca3  cmp     byte ptr [rbx+6], 0x66
0x1cad  cmp     byte ptr [rbx+7], 0x7b
`;

console.log('[1] 从真实反汇编还原前缀');
{
  const pairs = extractByteCompares(REAL_DISASM);
  ok(pairs.length === 8, '抽到 8 条比较', String(pairs.length));
  ok(pairs[0].offset === 0 && pairs[0].value === 0x62, '第 1 条 offset=0 value=0x62');

  const r = recoverComparedString(REAL_DISASM);
  ok(r.ok, '还原成功', r.reason);
  ok(r.text === 'bytectf{', '还原出 bytectf{（不是 bytecf{）', JSON.stringify(r.text));
}

console.log('\n[2] 关键：能指出"你抄错了"');
{
  const w = prefixWarnings('bytectf{');
  ok(Array.isArray(w) && w.length === 0, '完全正确时无警告', JSON.stringify(w));
  const w2 = prefixWarnings('bytecf{');
  ok(w2.length > 0, 'bytecf{ 会触发警告（与 bytectf{ 差 1 字符）', JSON.stringify(w2));
  ok(w2[0].known === 'bytectf{', '指出最接近的是 bytectf{', JSON.stringify(w2[0]));
  ok(w2[0].distance === 1, '距离为 1（少一个 t）', String(w2[0].distance));
  // 反向：正确拼写不该被告警
  ok(prefixWarnings('bytectf{').length === 0, 'bytectf{ 无告警');
  // 易混淆拼写不能出现在已知前缀表里（否则等于承认它合法）
  const { KNOWN_PREFIXES } = require('../electron/string-recover.js');
  ok(!KNOWN_PREFIXES.includes('bytecf{'), '已知前缀表不含错误拼写 bytecf{');
}

console.log('\n[3] 真实 IDA 格式（62h 后缀 h）也能识别');
{
  // IDA 默认反汇编格式是 `62h`，不是 `0x62`。实测若不支持这种格式，
  // 工具会对真实 IDA 输出提取出乱码（我第一版就踩了）。
  const ida = `
.text:0000000000001C68                 cmp     byte ptr [rax], 62h ; 'b'
.text:0000000000001C71                 cmp     byte ptr [rbx+1], 79h ; 'y'
.text:0000000000001C7B                 cmp     byte ptr [rbx+2], 74h ; 't'
.text:0000000000001C85                 cmp     byte ptr [rbx+3], 65h ; 'e'
.text:0000000000001C8F                 cmp     byte ptr [rbx+4], 63h ; 'c'
.text:0000000000001C99                 cmp     byte ptr [rbx+5], 74h ; 't'
.text:0000000000001CA3                 cmp     byte ptr [rbx+6], 66h ; 'f'
.text:0000000000001CAD                 cmp     byte ptr [rbx+7], 7Bh ; '{'
`;
  const r = recoverComparedString(ida);
  ok(r.ok, 'IDA 格式还原成功', r.reason);
  ok(r.text === 'bytectf{', 'IDA 格式还原出 bytectf{', JSON.stringify(r.text));
  ok(r.printableRatio === 1, '可打印率 100%', String(r.printableRatio));
}

console.log('\n[3b] AT&T 语法也能识别');
{
  const att = `
   cmpb   $0x62,0x0(%rbx)
   cmpb   $0x79,0x1(%rbx)
   cmpb   $0x74,0x2(%rbx)
   cmpb   $0x65,0x3(%rbx)
  `;
  const r = recoverComparedString(att);
  ok(r.ok, 'AT&T 还原成功', r.reason);
  ok(r.text === 'byte', 'AT&T 文本正确', JSON.stringify(r.text));
}

console.log('\n[4] 边界：非字符串 / 空 / 偏移不连续');
{
  const junk = `
  cmp byte ptr [rbx], 0x01
  cmp byte ptr [rbx+1], 0x02
  cmp byte ptr [rbx+2], 0x03
  `;
  const r = recoverComparedString(junk);
  ok(!r.ok, '不可打印字节不判为字符串', `ratio=${r.printableRatio}`);

  ok(recoverComparedString('').ok === false, '空文本不崩且返回 false');

  const gap = `
  cmp byte ptr [rbx], 0x41
  cmp byte ptr [rbx+3], 0x44
  `;
  const g = recoverComparedString(gap);
  ok(g.ok, '带空洞也能还原');
  ok(g.text === 'A..D', '空洞用 . 占位', JSON.stringify(g.text));
  ok(g.gaps.length === 1, '报告 1 处空洞', JSON.stringify(g.gaps));
}

console.log('\n[5] assembleByteComparisons 直接喂 pairs');
{
  const a = assembleByteComparisons([{ offset: 2, value: 0x43 }, { offset: 0, value: 0x41 }, { offset: 1, value: 0x42 }]);
  ok(a.ok && a.text === 'ABC', '乱序输入按偏移排序', JSON.stringify(a.text));
  const b = assembleByteComparisons([]);
  ok(!b.ok, '空数组返回 ok=false');
}

console.log('\n[6] 接线：recover_string 工具可达');
{
  ok(/name: "recover_string"/.test(mainSrc), '工具已定义');
  ok(/case 'recover_string'/.test(mainSrc), '有 dispatch 分支');
  ok(/'recover_string'/.test(mainSrc), '进 KNOWN 集合');
  ok(/recover_string: 'func'/.test(mainSrc), '进 MAP 裸参映射');
  ok(/if \(name === 'recover_string'\)/.test(mainSrc), 'precheck 有分支');
  ok(/case 'recover_string': return '还原比较字符串/.test(mainSrc), 'toolLabel 有');
  ok(/require\('\.\/string-recover'\)/.test(mainSrc), '惰性 require string-recover');
}

console.log('\n[7] Nox 启动：三档回落');
{
  ok(/三档回落/.test(appSrc) || /attempts/.test(appSrc), '有回落逻辑');
  ok(/-clone:\$\{noxInstance\}/.test(appSrc), '第一档：带 -clone');
  ok(/默认实例（不带 -clone）/.test(appSrc), '第二档：不带 -clone');
  ok(/同目录 Nox\.exe/.test(appSrc), '第三档：直接 Nox.exe');
  ok(/player is not exist|实例名/.test(appSrc), '错误里点明实例名可能不存在');
  // 不能再用单个 result 变量（回落循环里是 att/result）
  ok(!/if \(result\.success\) \{\s*addLog\('info', '安卓9模拟器启动中/.test(appSrc),
    '不再用旧的单次启动判断');
}

console.log('\n[8] Frida 版本不匹配检测');
{
  ok(/async function checkFridaVersionMatch/.test(appSrc), '有版本检测函数');
  ok(/frida-server --version/.test(appSrc), '读设备端版本');
  ok(/'frida', '--version'/.test(appSrc), '读本机客户端版本');
  ok(/版本不匹配/.test(appSrc), '不匹配时明确告警');
  ok(/connection closed/.test(appSrc), '解释 connection closed 的真正原因');
  ok(/pip install -U "frida==/.test(appSrc), '给出具体修复命令');
  ok(/checkFridaVersionMatch\(\)/.test(appSrc), '在服务就绪后被调用');
  // main.js 侧也要识别
  ok(/connection closed/.test(mainSrc), 'main.js 也识别 connection closed');
  ok(/移除了内置 Java bridge|Java is not defined/.test(mainSrc), 'main.js 说明 Frida 17 的 Java bridge 移除');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
