// 本地枚举纪律单测：只 require 纯模块，不加载 app.js（它依赖 DOM/window）。
const fs = require('fs');
const path = require('path');
const {
  shouldRunHypotheses, validateCandidateAttempt, algoRequiresCiphertext,
  isDegenerateDigest, recordAttempt,
} = require('../electron/verify-discipline.js');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] 门控：有假设就跑，与 vr 是否为 null 无关');
{
  ok(shouldRunHypotheses(null, 2) === true, '(null,2) → true');
  ok(shouldRunHypotheses(null, 0) === false, '(null,0) → false');
  ok(shouldRunHypotheses({ verified: false }, 1) === true, '({verified:false},1) → true');
  ok(shouldRunHypotheses({ verified: true }, 3) === true, '已 verified 但有假设也执行');
}

console.log('\n[2] 候选形态校验');
{
  const a = validateCandidateAttempt({ algo: 'aes_ecb', ciphertext: '', output: '' });
  ok(a.ok === false, '空 ciphertext + aes_ecb → invalid');
  ok(/需要密文/.test(a.reason), `reason 说明缺密文（${a.reason}）`);

  const b = validateCandidateAttempt({ algo: 'custom', code: 'def decrypt(x): return x', ciphertext: '', output: 'ok' });
  ok(b.ok === true, '空 ciphertext + custom + code → ok（无密钥/无密文的合法变换放行）');

  const c = validateCandidateAttempt({ algo: 'xor', ciphertext: '41424344', output: '' });
  ok(c.ok === false, '输入非空但输出为空 → invalid');

  const d = validateCandidateAttempt({ algo: 'md5', ciphertext: 'abc', output: 'd41d8cd98f00b204e9800998ecf8427e' });
  ok(d.ok === false, '输出等于 md5("") → invalid');
  ok(isDegenerateDigest('d41d8cd98f00b204e9800998ecf8427e') === true, '退化摘要集合含 md5("")');

  const e = validateCandidateAttempt({ algo: 'node_js', code: 'function f(x){return x}', ciphertext: '', output: 'flag{ok}' });
  ok(e.ok === true, 'node_js + code + 非空输出 → ok');

  const f = validateCandidateAttempt({ algo: 'base64', ciphertext: '', output: '' });
  ok(f.ok === false, 'base64 需要密文 → invalid');
}

console.log('\n[3] algoRequiresCiphertext 覆盖标准族');
{
  for (const a of ['aes_ecb', 'des_cbc', 'sm4', 'rc4', 'tea', 'chacha20', 'base64']) {
    ok(algoRequiresCiphertext(a) === true, `${a} 需要密文`);
  }
  ok(algoRequiresCiphertext('custom') === false, 'custom 不需要密文');
  ok(algoRequiresCiphertext('node_js') === false, 'node_js 不需要密文');
}

console.log('\n[4] 结构化尝试记录');
{
  const r = recordAttempt({ algo: 'aes_ecb', key: 'k', key_encoding: 'ascii', ciphertext: '0011' }, { valid: true, hit: false, output: 'xx' });
  ok(r.algo === 'aes_ecb' && r.key === 'k' && r.ciphertext_len === 4 && r.output_len === 2 && r.valid === true,
    '记录含 algo/key/ct 长度/输出长度/valid');
  ok(typeof r.ts === 'string' && r.ts.length > 0, '带时间戳');
}

console.log('\n[5] app.js 源码：门控与日志');
{
  ok(/shouldRunHypotheses\(vr, hypotheses\.length \+ synthCount\)/.test(appSrc),
    'runHypotheses 调用点使用 shouldRunHypotheses');
  ok(!/if \(vr && !vr\.verified\) await runHypotheses/.test(appSrc),
    '不再使用 `if (vr && ...)` 门控');
  ok(appSrc.includes('`[本地枚举] 无 [VERIFY] 但仍执行 ${hypotheses.length || synthCount} 组假设`'),
    '日志含「[本地枚举] 无 [VERIFY] 但仍执行 N 组假设」');
  ok(appSrc.includes('`[本地枚举] 候选无效: ${v.reason}`'),
    '日志含「[本地枚举] 候选无效: <reason>」');
  ok(/function validateCandidateAttempt\(a\)/.test(appSrc), 'app.js 内联 validateCandidateAttempt');
  ok(/function shouldRunHypotheses\(vr, hypothesisCount\)/.test(appSrc), 'app.js 内联 shouldRunHypotheses');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
