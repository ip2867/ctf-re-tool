'use strict';
// 本地枚举的"门控与校验"纪律（纯函数，零 Electron / DOM 依赖）。
//
// 两个真实缺陷：
//   ① app.js 的门控是 `if (vr && !vr.verified) await runHypotheses(...)`。
//      没有 [VERIFY] 时 runVerification 返回 null → vr=null → 假设永远不会在本地执行，
//      于是"最终轮没有任何契约被本地执行"。
//   ② "空 key 一律 invalid"会误杀合法无密钥变换（algo=custom/node_js 且带 code，
//      或 ciphertext 与其消费者都不存在时，本来就不需要 key）。
//
// 这里把判定做成纯函数，供 app.js 调用，测试也能在无 DOM 下直接跑。

const DEGENERATE_DIGESTS = new Set([
  'd41d8cd98f00b204e9800998ecf8427e',                                  // md5("")
  'da39a3ee5e6b4b0d3255bfef95601890afd80709',                          // sha1("")
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  // sha256("")
  '00000000000000000000000000000000',
  '0cc175b9c0f1b6a831c399e269772661',                                  // md5("a")
  '900150983cd24fb0d6963f7d28e17f72',                                  // md5("abc")
]);

// 需要密文才有意义的算法（无密文的"解密"必然产出空/退化结果）
const CIPHERTEXT_ALGOS = /^(aes|des|3des|blowfish|sm4|rc4|tea|xtea|xxtea|chacha|salsa|camellia|twofish|present|aria|base64|hex)/i;

function algoRequiresCiphertext(algo) {
  return CIPHERTEXT_ALGOS.test(String(algo || '').trim());
}

// 只要"存在假设"就必须跑：与 vr 是否为 null 无关。
function shouldRunHypotheses(vr, hypothesisCount) {
  return Number(hypothesisCount) > 0;
}

function isDegenerateDigest(v) {
  const t = String(v == null ? '' : v).trim().toLowerCase();
  const inner = (t.match(/\{([^}]+)\}/) || [, t])[1];
  return DEGENERATE_DIGESTS.has(inner.trim());
}

// 返回 {ok, reason}。invalid 的三种情形（且仅这三种）：
//   (a) 算法需要密文但 ciphertext 为空
//   (b) 输入非空但输出为空
//   (c) 输出命中退化摘要（空串/占位哈希）
function validateCandidateAttempt(a) {
  const att = a || {};
  const algo = String(att.algo || '').trim();
  const ct = String(att.ciphertext == null ? '' : att.ciphertext).trim();
  const out = String(att.output == null ? '' : att.output).trim();

  if (algoRequiresCiphertext(algo) && !ct) {
    return { ok: false, reason: `algo=${algo} 需要密文，但 ciphertext 为空` };
  }
  // (b) 只对"确实有输入"的尝试成立；无输入的合法变换（纯 code 生成）不算失败
  if (ct && !out) {
    return { ok: false, reason: '输入非空但输出为空（解密/变换未真正执行）' };
  }
  if (out && isDegenerateDigest(out)) {
    return { ok: false, reason: `输出是退化摘要 ${out}（说明输入没取到）` };
  }
  return { ok: true, reason: '' };
}

// 每次尝试的结构化记录（algo/key/ct/错误/结论）。
function recordAttempt(a, result) {
  const att = a || {};
  const r = result || {};
  return {
    algo: String(att.algo || ''),
    key: att.key == null ? '' : String(att.key),
    key_encoding: String(att.key_encoding || ''),
    ciphertext_len: String(att.ciphertext == null ? '' : att.ciphertext).replace(/\s+/g, '').length,
    error: r.error == null ? '' : String(r.error),
    output_len: String(r.output == null ? '' : r.output).length,
    valid: r.valid === undefined ? true : !!r.valid,
    hit: !!r.hit,
    reason: r.reason == null ? '' : String(r.reason),
    ts: new Date().toISOString(),
  };
}

module.exports = {
  shouldRunHypotheses, validateCandidateAttempt, algoRequiresCiphertext,
  isDegenerateDigest, recordAttempt, DEGENERATE_DIGESTS,
};
