// 失败归因单测（Phase 3）：把"全部失败"变成"哪一步、为什么失败"的可操作信息。
const { attributeFailure } = require('./failure_attribution_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

const attempts = [
  { algo: 'aes_ecb', key_encoding: 'ascii', key: 'notakey' },
  { algo: 'aes_cbc', key_encoding: 'hex', key: '00112233' },
  { algo: 'sm4_ecb', key_encoding: 'ascii', key: 'notakey' },
  { algo: 'rc4', key_encoding: 'ascii', key: 'x' },
];

console.log('A) 解密报错 → 归因为"参数形态问题"，不是算法错');
{
  const out = [
    '[FAIL] attempt=0 algo=aes_ecb keyenc=ascii stage=decrypt reason=ValueError: Incorrect AES key length (8 bytes)',
    '[FAIL] attempt=1 algo=aes_cbc keyenc=hex stage=decrypt reason=ValueError: IV must be 16 bytes long',
  ].join('\n');
  const r = attributeFailure(out, attempts);
  ok(r.summary.errFails === 2, `报错计数 ${r.summary.errFails} == 2`);
  ok(/参数形态不匹配/.test(r.text), '归因指出参数形态问题');
  ok(/ValueError/.test(r.text), '归因包含错误类型');
  ok(r.fails[0].algo === 'aes_ecb' && r.fails[0].keyenc === 'ascii', '解析出具体候选');
}

console.log('\nB) 解出乱码 → 归因为"算法/key/iv 选错"');
{
  const out = [
    '[MISS] attempt=2 algo=sm4_ecb keyenc=ascii stage=verify result=garbage preview=00ff9a...',
    '[MISS] attempt=3 algo=rc4 keyenc=ascii stage=verify result=garbage preview=13a0...',
  ].join('\n');
  const r = attributeFailure(out, attempts);
  ok(r.summary.garbage === 2, '乱码计数正确');
  ok(/算法或 key\/iv 选错/.test(r.text), '归因指算法/key/iv');
  ok(/优先换算法族/.test(r.text), '给出可执行建议（换算法族而不是换 key）');
}

console.log('\nC) 可打印但无 flag → 归因为"中间值层或模式错"');
{
  const out = '[MISS] attempt=0 algo=aes_ecb keyenc=ascii stage=verify result=no-flag preview=hello world';
  const r = attributeFailure(out, attempts);
  ok(r.summary.noFlag === 1, 'no-flag 计数正确');
  ok(/中间值层|ECB\/CBC/.test(r.text), '归因指中间值层或模式');
}

console.log('\nD) 空串 → 归因为"密文/偏移取错"');
{
  const out = '[MISS] attempt=1 algo=aes_cbc keyenc=hex stage=verify result=empty preview=';
  const r = attributeFailure(out, attempts);
  ok(r.summary.empty === 1, 'empty 计数正确');
  ok(/密文\/偏移取错/.test(r.text), '归因指密文/偏移');
}

console.log('\nE) 多种失败混合 → 归因同时给出多条');
{
  const out = [
    '[FAIL] attempt=0 algo=aes_ecb keyenc=ascii stage=decrypt reason=ValueError: key length',
    '[MISS] attempt=1 algo=aes_cbc keyenc=hex stage=verify result=garbage preview=zz',
    '[MISS] attempt=2 algo=sm4_ecb keyenc=ascii stage=verify result=no-flag preview=abc',
  ].join('\n');
  const r = attributeFailure(out, attempts);
  ok(r.summary.errFails === 1 && r.summary.garbage === 1 && r.summary.noFlag === 1, '三类计数独立准确');
  ok(r.hints.length >= 3, `给出 ${r.hints.length} 条归因提示`);
  ok(r.summary.algos.length === 3, '去重后的算法列表正确');
}

console.log('\nF) 无结构化输出（旧模板）→ 明确说明，不编造归因');
{
  const r = attributeFailure('Random output without markers', attempts);
  ok(r.fails.length === 0 && r.misses.length === 0, '无伪造数据');
  ok(/未输出结构化归因/.test(r.text), '明确说明缺失');
}

console.log('\nG) 空输出/空候选不崩');
{
  ok(attributeFailure('', []).total === 0, '空输入不崩');
  ok(attributeFailure(null, null).total === 0, 'null 输入不崩');
}

console.log('\nH) 解出机器码 → 归因为"这是下一层代码"，而不是"换算法"（CrackMe3 实测）');
{
  // 真实输出：AI 用自定义 RC4 变体解出一段 x86 函数（sub esp,0x18 … ret nop nop）
  const x86 = '83ec18b065b163884424048844240d88442410884424128d442400b273884c2402884c2403884c240e8b4c241c5088542404885424098854240a6a00b2726a0c51c644241175c644241721c644241879c64424196fc644241a75c644241b618854241cc644241f6cc64424217688542423c644242400ff54243083c418c39090';
  const out = [
    '[MISS] attempt=0 algo=custom keyenc=ascii stage=verify result=no-flag preview=' + x86.slice(0, 96),
    '[OUT] attempt=0 keyenc=ascii: ' + x86,
  ].join('\n');
  const r = attributeFailure(out, [{ algo: 'custom', key_encoding: 'ascii', key: '771535' }]);
  ok(r.summary.decodedLayer >= 1, `识别出解码层 ${r.summary.decodedLayer} 处`);
  ok(/可执行机器码/.test(r.text), '归因指出解出的是机器码');
  ok(/不要换算法/.test(r.text), '明确禁止换算法');
  ok(/switch_to_next_stage/.test(r.text), '给出接力下一层的具体动作');
  // 关键：不能同时出现"优先换算法族"这种反向建议
  ok(!/优先换算法族/.test(r.text), '不出现反向建议（换算法族）');
}

console.log('\nI) 普通明文不可被误判为机器码');
{
  const out = '[MISS] attempt=0 algo=aes_ecb keyenc=ascii stage=verify result=no-flag preview=flag{hello_world_123}';
  const r = attributeFailure(out, attempts);
  ok(r.summary.decodedLayer === 0, '明文不触发解码层归因');
  ok(!/可执行机器码/.test(r.text), '不误报机器码');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
