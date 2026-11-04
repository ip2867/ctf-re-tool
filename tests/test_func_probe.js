#!/usr/bin/env node
'use strict';

/**
 * func_probe 契约测试：**stripped 二进制里定位密码函数 + 批量 dump 调用参数**。
 *
 * 来源（qwb2026 firmware 实战）：fw_a 是 1MB stripped 静态链接二进制，
 * 7 次 SM3 调用的输入输出无法从反汇编快速看出。把断点设在 SM3 函数入口
 * （0x403140），一次就拿到全部：
 *   #2 SM3(keymat,16)  #4 SM3("QWB2026::TWIN::DEVICE-A",23)  #5 SM3(40 字节 = keymat‖P‖vm_out8)
 * vm_out8 就在第 5 次的第 32..39 字节 —— 这比读 8000 行反汇编快两个数量级。
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const FP = require(path.join(ROOT, 'electron', 'func-probe.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

const FW_A = 'C:\\Users\\Administrator\\Desktop\\工具\\_work\\fw\\fw_a';

console.log('=== 算法特征常量定位 ===');

t('SM3 IV 两种字节序都能定位（LE word 是关键：fw_a 就是这种）', () => {
  const le = Buffer.alloc(16);
  [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600].forEach((v, i) => le.writeUInt32LE(v >>> 0, i * 4));
  const be = Buffer.alloc(16);
  [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600].forEach((v, i) => be.writeUInt32BE(v >>> 0, i * 4));

  const rLe = FP.locateSignatures(Buffer.concat([Buffer.alloc(64), le, Buffer.alloc(64)]));
  const rBe = FP.locateSignatures(Buffer.concat([Buffer.alloc(64), be, Buffer.alloc(64)]));
  assert.ok(rLe.some((h) => h.algo === 'SM3' && h.order === 'LE'), 'LE word 形态未命中');
  assert.ok(rBe.some((h) => h.algo === 'SM3' && h.order === 'BE'), 'BE 形态未命中');
});

t('SM4 / AES S 盒能定位', () => {
  const sm4 = Buffer.from('d690e9fecce13db7', 'hex');
  const aes = Buffer.from('637c777bf26b6fc5', 'hex');
  assert.ok(FP.locateSignatures(Buffer.concat([Buffer.alloc(32), sm4])).some((h) => h.algo === 'SM4'));
  assert.ok(FP.locateSignatures(Buffer.concat([Buffer.alloc(32), aes])).some((h) => h.algo === 'AES'));
});

t('ChaCha sigma 字符串能定位', () => {
  const s = Buffer.from('expand 32-byte k', 'latin1');
  const r = FP.locateSignatures(Buffer.concat([Buffer.alloc(32), s]));
  assert.ok(r.some((h) => h.algo === 'CHACHA'));
});

t('负向断言：不含任何特征常量的随机数据不得报命中', () => {
  let s = 0x12345678;
  const buf = Buffer.alloc(4096);
  for (let i = 0; i < buf.length; i++) { s = (s * 1664525 + 1013904223) >>> 0; buf[i] = s & 0xff; }
  const r = FP.locateSignatures(buf);
  assert.strictEqual(r.length, 0, '随机数据被误报：' + JSON.stringify(r.map((h) => h.algo)));
});

console.log('\n=== gdb 脚本生成 ===');

t('生成脚本含断点、计数、参数打印、内存 dump', () => {
  const s = FP.buildProbeScript({
    binary: '/tmp/x/fw_a', breakAddr: '0x403140',
    argRegs: ['rdi', 'rsi', 'rdx'], maxHits: 10, dumpBytes: 32,
    programArgs: ['a.bin', 'key'],
  });
  assert.ok(/break \*0x403140/.test(s), '缺断点');
  assert.ok(/set \$n = \$n \+ 1/.test(s), '缺命中计数');
  assert.ok(/\$rdi/.test(s) && /\$rsi/.test(s), '缺参数寄存器打印');
  assert.ok(/x\/32xb \$rdi/.test(s), '缺内存 dump');
  assert.ok(/'a\.bin' 'key'/.test(s), '缺运行参数（应带引号转义）');
  assert.ok(/\$n <= 10/.test(s), '缺命中上限');
});

t('onlyNth 模式只打印第 N 次', () => {
  const s = FP.buildProbeScript({ binary: 'x', breakAddr: '0x1000', onlyNth: 5 });
  assert.ok(/if \$n == 5/.test(s), '未生成 onlyNth 条件');
  assert.ok(!/\$n <= /.test(s), 'onlyNth 模式不该有上限判断');
});

t('负向断言：参数字符串里的分号必须被引号包裹（防 gdb 命令注入）', () => {
  const s = FP.buildProbeScript({ binary: 'x', breakAddr: '0x1000', programArgs: ['a; shell'] });
  const runLine = s.split('\n').find((l) => l.startsWith('run ')) || '';
  // 必须被单引号包住（gdb 的 run 行按 shell 风格解析）
  assert.ok(/'a; shell'/.test(runLine), '参数未被引号包裹，存在注入风险：' + runLine);
  assert.ok(!/^run a; shell/.test(runLine), '分号未被隔离：' + runLine);
});

t('负向断言：参数内含单引号时正确转义（不能提前闭合）', () => {
  const s = FP.buildProbeScript({ binary: 'x', breakAddr: '0x1000', programArgs: ["it's"] });
  const runLine = s.split('\n').find((l) => l.startsWith('run ')) || '';
  // '\'' 形态：结束单引号 + 转义单引号 + 重开
  assert.ok(/'it'\\''s'/.test(runLine), '单引号未转义：' + runLine);
});

t('正向：正常参数不被打扰', () => {
  const s = FP.buildProbeScript({ binary: 'x', breakAddr: '0x1000', programArgs: ['ota.bin', 'dd97cb2d'] });
  const runLine = s.split('\n').find((l) => l.startsWith('run ')) || '';
  assert.ok(/'ota\.bin' 'dd97cb2d'/.test(runLine), '正常参数被改坏：' + runLine);
});

console.log('\n=== gdb 输出解析 ===');

t('按地址分块解析（多块不拼接）', () => {
  const txt = [
    '0x1000:\t0x11\t0x22\t0x33\t0x44',
    '0x1004:\t0x55\t0x66\t0x77\t0x88',
    '=== 分隔 ===',
    '0x2000:\t0xaa\t0xbb',
  ].join('\n');
  const r = FP.parseGdbXOutput(txt);
  assert.strictEqual(r.length, 2, `应切成 2 块，实际 ${r.length}`);
  assert.strictEqual(r[0].hex, '1122334455667788');
  assert.strictEqual(r[1].hex, 'aabb');
});

t('负向断言：不留分隔时按地址连续性切分', () => {
  const txt = [
    '0x1000:\t0x11\t0x22',
    '0x1010:\t0x33\t0x44',   // 地址跳了（1002 != 1010）
  ].join('\n');
  const r = FP.parseGdbXOutput(txt);
  assert.strictEqual(r.length, 2, '地址不连续应切成两块');
});

t('空输入返回空数组，不崩', () => {
  assert.deepStrictEqual(FP.parseGdbXOutput(''), []);
  assert.deepStrictEqual(FP.parseGdbXOutput(null), []);
});

console.log('\n=== 常量引用 → 函数入口 ===');

t('从反汇编文本里按常量地址找引用，并回推函数入口', () => {
  const dis = [
    '0000000000403140 <sm3_func>:',
    '  403144:  push r15',
    '  403158:  movdqa xmm0, [rip+0xd0120]   # 0x4d3280',
    '  403160:  mov r12, rdx',
    '',
    '0000000000404000 <other>:',
    '  404010:  xor eax, eax',
  ].join('\n');
  const r = FP.findFuncByConstRef(dis, '0x4d3280');
  assert.ok(r.refs.length === 1, '未找到引用');
  assert.strictEqual(r.guessEntry, '0x403140', '函数入口推断错误：' + r.guessEntry);
});

t('负向断言：常量没被引用时 guessEntry 为 null', () => {
  const dis = '0000000000403140 <f>:\n  403144:  push r15\n';
  const r = FP.findFuncByConstRef(dis, '0xdeadbeef');
  assert.strictEqual(r.refs.length, 0);
  assert.strictEqual(r.guessEntry, null);
});

console.log('\n=== 真实样本（fw_a）===');

t('fw_a 里能定位到 SM3 IV（小端 word）', () => {
  if (!fs.existsSync(FW_A)) { console.log('     （样本不存在，跳过）'); return; }
  const buf = fs.readFileSync(FW_A);
  const hits = FP.locateSignatures(buf);
  const sm3 = hits.find((h) => h.algo === 'SM3');
  assert.ok(sm3, 'fw_a 里没定位到 SM3 —— 字节序处理有问题');
  assert.strictEqual(sm3.order, 'LE', 'fw_a 的 SM3 IV 是小端 word，实际 ' + sm3.order);
  assert.strictEqual(sm3.offset, 0xd3280, 'SM3 IV 偏移应为 0xd3280，实际 0x' + sm3.offset.toString(16));
});

t('六层注册完整', () => {
  const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
  assert.ok(/name:\s*"func_probe"/.test(mainSrc), 'schema 缺');
  assert.ok(/case 'func_probe':/.test(mainSrc), 'dispatch 缺');
  const ki = mainSrc.indexOf('const KNOWN = new Set([');
  assert.ok(mainSrc.slice(ki, ki + 1600).includes("'func_probe'"), 'KNOWN 缺');
  assert.ok(/func_probe:\s*'binary'/.test(mainSrc), 'MAP 缺');
  assert.ok(/case 'func_probe':\s*return '算法函数探针/.test(mainSrc), 'toolLabel 缺');
  assert.ok(/name === 'func_probe'/.test(mainSrc), 'precheck 缺');
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
