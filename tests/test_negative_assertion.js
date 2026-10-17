// 负面断言反证单测（Phase 2）：AI 说"没有 X"时，工具有没有用数据反驳。
// 这是"自主"的转折点——工具开始**质疑 AI 的结论**，而不是被动采信。
const { checkNegativeAssertions, buildNegativeAssertionRules } = require('./negative_assertion_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

// 模拟 Disguise 第一层的扫描结果（与真实扫描器输出同形）
const scanWithPayload = {
  success: true, size: 464384,
  payloads: [{ type: 'pe', offset: 0xa200, length: 86016, confidence: 'high', head: '4d5a',
    encode: { kind: 'xor', key: 7, stride: 4, period: 1 } }],
  embeddedPE: [{ type: 'pe', offset: 0xa200, length: 86016 }],
  summary: [{ algo: '内嵌 PE（编码存储，已定位）', confidence: 'high', evidence: '@0xa200', note: '...' }],
};
const scanEmpty = { success: true, summary: [{ algo: '(未发现算法指纹)', confidence: 'n/a', evidence: '无', note: '' }], payloads: [] };
const scanWithAlgo = {
  success: true, summary: [{ algo: 'SM4', confidence: 'high', evidence: 'FK+S盒双命中', note: '' }], payloads: [],
};
const scanCustomBlock = {
  success: true, summary: [{ algo: '自定义分组密码（已确认）', confidence: 'high', evidence: 'SBOX-256@0xd630', note: '' }], payloads: [],
};

console.log('\nA) 规则表结构');
{
  const rules = buildNegativeAssertionRules();
  ok(rules.length >= 5, `至少 5 条规则（实际 ${rules.length}）`);
  ok(rules.every(r => r.id && typeof r.detect === 'function' && typeof r.verify === 'function'), '每条规则都有 id/detect/verify');
  const ids = rules.map(r => r.id);
  ok(ids.includes('no-second-carrier') && ids.includes('no-crypto') && ids.includes('no-decoding'), '覆盖核心断言类型');
  ok(ids.includes('delegates-to-user'), '覆盖"把活推给用户"类型');
}

console.log('\nA2) 真实事故原文："stage2 未提供 + 请用户提供" 必须被反驳');
{
  // 摘自真机日志（Disguise 2026-10-17）：AI 诊断正确，但行动是推给用户。
  const text = `而 stage2 的内容没有提供给我。上面所有反编译代码都是壳层代码，不含任何加密常量。
请用户在提取出 stage2 之后提供以下内容（这是唯一可行路径）：
1. stage2 提取并确认魔数；2. 对 stage2 重新做指纹扫描；3. stage2 的关键函数反编译。`;
  const r = checkNegativeAssertions(text, { algScan: scanWithPayload });
  ok(r.refuted.length >= 1, `被反驳（${r.refuted.length} 条）`);
  ok(r.refuted.some(x => x.id === 'delegates-to-user' || x.id === 'no-second-carrier'), '命中"推给用户/缺 stage2"规则');
  ok(/0xa200/.test(r.refuted[0].evidence), '反驳证据含确定性偏移');
  ok(r.retryPrompt && /run_python|提取脚本/.test(r.retryPrompt), '要求 AI 自己提取，而不是要用户提供');
}

console.log('\nA3) "请用户提供"但确实没有载荷 → 不反驳（防误伤）');
{
  const text = '需要用户提供题目描述，当前文件里没有可用线索。';
  const r = checkNegativeAssertions(text, { algScan: scanEmpty });
  ok(r.refuted.length === 0, '无载荷时不反驳（确实需要人工）');
}

console.log('\nB) "没有第二载体" —— 有载荷时必须反驳（Disguise 实测场景）');
{
  const text = '经全面静态排查，文件内无第二可执行载体（无第二个 MZ、无自定义资源）。真 flag 不在此文件中。';
  const r = checkNegativeAssertions(text, { algScan: scanWithPayload });
  ok(r.refuted.length >= 1, '被反驳');
  ok(r.refuted.some(x => x.id === 'no-second-carrier'), '命中 no-second-carrier 规则');
  ok(/0xa200/.test(r.refuted[0].evidence), '证据含确定性偏移 0xa200');
  ok(/XOR 0x7/.test(r.refuted[0].evidence), '证据含编码方式（XOR 0x7）');
  ok(/提取脚本|解码写出|重新分析/.test(r.refuted[0].evidence), '给出下一步动作');
  ok(r.retryPrompt && /立即按提取脚本/.test(r.retryPrompt), '生成强制重试提示');
}

console.log('\nC) "没有第二载体" —— 确实没有时不得反驳（防误伤）');
{
  const text = '文件内无第二可执行载体（无内嵌 PE、无资源段）。';
  const r = checkNegativeAssertions(text, { algScan: scanEmpty });
  ok(r.refuted.length === 0, '无载荷 → 不反驳（断言成立）');
}

console.log('\nD) "没有加密" —— 识别到算法时必须反驳');
{
  const text = '这个程序没有加密，只是简单的输入比较。';
  const r = checkNegativeAssertions(text, { algScan: scanWithAlgo });
  ok(r.refuted.some(x => x.id === 'no-crypto'), '命中 no-crypto');
  ok(/SM4/.test(r.refuted.find(x => x.id === 'no-crypto').evidence), '证据含识别到的算法');
}
{
  const text = '这个程序没有加密，只是简单的输入比较。';
  const r = checkNegativeAssertions(text, { algScan: scanEmpty });
  ok(r.refuted.length === 0, '无算法证据 → 不反驳');
}

console.log('\nE) 模糊表述不得触发（避免用猜测反驳猜测）');
{
  const text = '可能没有加密，需要进一步确认。';
  const r = checkNegativeAssertions(text, { algScan: scanWithAlgo });
  ok(r.refuted.length === 0, '"可能/待确认"不算确定性断言 → 不反驳');
}

console.log('\nF) "没有解码逻辑" —— 有编码载荷时必须反驳');
{
  const text = '程序中没有发现解密或解码逻辑。';
  const r = checkNegativeAssertions(text, { algScan: scanWithPayload });
  ok(r.refuted.some(x => x.id === 'no-decoding'), '命中 no-decoding');
}

console.log('\nG) "没有 VM" —— 已确认分组密码时必须提醒');
{
  const text = '这里没有 VM，也没有解释器。';
  const r = checkNegativeAssertions(text, { algScan: scanCustomBlock });
  ok(r.refuted.some(x => x.id === 'no-vm'), '命中 no-vm');
  ok(/分组密码/.test(r.refuted.find(x => x.id === 'no-vm').evidence), '证据指向分组密码结构');
}
{
  const text = '这里没有 VM，也没有解释器。';
  const r = checkNegativeAssertions(text, { algScan: scanEmpty });
  ok(r.refuted.length === 0, '无分组密码证据 → 不反驳');
}

console.log('\nH) 正常结论不得被打扰');
{
  const texts = [
    '使用 SM4 解密，密钥为 We1c0me_t0_xmctf。',
    '提取 stage2 后重新扫描，发现自定义 S 盒。',
    '',
    '需要继续分析。',
  ];
  let clean = true;
  for (const t of texts) {
    const r = checkNegativeAssertions(t, { algScan: scanWithPayload });
    if (r.refuted.length) { clean = false; console.log('    误伤: ' + t); }
  }
  ok(clean, '正常/肯定性结论不触发反证');
}

console.log('\nI) 一次最多反驳 2 条（防止提示词被撑爆）');
{
  const text = '没有第二载体。没有加密。没有解码逻辑。没有 VM。真 flag 不在此文件。';
  const r = checkNegativeAssertions(text, { algScan: { ...scanWithPayload, summary: [...scanWithPayload.summary, ...scanCustomBlock.summary] } });
  ok(r.refuted.length <= 2, `反驳条数 ${r.refuted.length} <= 2`);
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
