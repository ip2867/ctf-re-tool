// LCG 参数恢复公式的**实测**验证。
//
// 背景：skills/ctf-crypto-identify 里原本写了两条 LCG 公式，实测都是错的：
//   ① "模数未知时用 t_n = x[n+2]*x[n] - x[n+1]^2 的 gcd" → 模 2^31/2^32/2^64 时 gcd 恒为 1
//   ② "模 2^k 时 pow(x1-x0,-1,m) 必然抛 ValueError"      → glibc/mmix 参数下 200/200 全成功
//
// 本测试把正确公式与错误公式**同时**跑出来对比：错误版本必须失败，
// 正确版本必须精确还原参数。这样文档与实现以后不会再漂移。
const assert = require('assert');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}

// ── 大整数工具（JS 用 BigInt，避免 2^64 精度问题）──
const gcdBig = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) { [a, b] = [b, a % b]; } return a; };
const norm = (v, m) => ((v % m) + m) % m;      // 负数 → 规范化为最小非负剩余

function gen(a, c, m, seed, n) {
  let x = seed; const s = [];
  for (let i = 0; i < n; i++) { x = (a * x + c) % m; s.push(x); }
  return s;
}

// 扩展欧几里得求模逆（不互素时返回 null，等价 python pow(-1) 抛 ValueError）
function modInverse(a, m) {
  a = norm(a, m);
  let [oldR, r] = [a, m], [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return oldR === 1n ? norm(oldS, m) : null;
}

const v2 = (d) => { if (d === 0n) return 999; let k = 0; while ((d & 1n) === 0n) { d >>= 1n; k++; } return k; };

const CASES = {
  'glibc 2^31':     [1103515245n, 12345n, 1n << 31n],
  '2^32 (a,c odd)': [1664525n, 1013904223n, 1n << 32n],
  'mmix 2^64':      [6364136223846793005n, 1442695040888963407n, 1n << 64n],
  'prime 1e9+7':    [1103515245n, 12345n, 1000000007n],
  'prime 2^31-1':   [48271n, 0n, 2147483647n],
};

console.log('=== LCG 参数恢复：正确公式 vs 抄错公式 ===');

// ① 原始值消元（技能里抄错的版本）：t_n = x[n+2]*x[n] - x[n+1]^2
const wrongFormula = (s) => {
  let g = 0n;
  for (let n = 0; n + 2 < s.length; n++) g = gcdBig(g, s[n + 2] * s[n] - s[n + 1] * s[n + 1]);
  return g;
};
// ② 差分版（正确）：u_n = x[n+1]-x[n]; t_n = u[n+2]*u[n] - u[n+1]^2
const rightFormula = (s) => {
  const u = s.slice(1).map((v, i) => v - s[i]);
  let g = 0n;
  for (let n = 0; n + 2 < u.length; n++) g = gcdBig(g, u[n + 2] * u[n] - u[n + 1] * u[n + 1]);
  return g;
};

console.log('\nA) 已知模数：差分求逆还原 a、c');
t('五种参数下 a/c 均精确还原', () => {
  for (const tag of Object.keys(CASES)) {
    const [a, c, m] = CASES[tag];
    const s = gen(a, c, m, 987654321n, 6);
    const d1 = norm(s[1] - s[0], m), d2 = norm(s[2] - s[1], m);
    const inv = modInverse(d1, m);
    assert.ok(inv !== null, tag + ': 这组参数（a,c 均奇）应可直接求逆');
    const aHat = (d2 * inv) % m;
    const cHat = norm(s[1] - aHat * s[0], m);
    // a 本身可能 >= m（1e9+7 用例），只能按同余类比较
    assert.strictEqual(aHat, norm(a, m), tag + ': a 还原错误');
    assert.strictEqual(cHat, norm(c, m), tag + ': c 还原错误');
    console.log(`     ${tag}: a/c 精确还原`);
  }
});

console.log('\nB) 抄错公式①必须失败：原始值消元的 gcd 给不出 m');
t('差分版精确给出 m，原始值版给不出（c≠0 时）', () => {
  for (const tag of ['glibc 2^31', '2^32 (a,c odd)', 'mmix 2^64', 'prime 1e9+7']) {
    const [a, c, m] = CASES[tag];
    const s = gen(a, c, m, 123456789n, 10);
    const gWrong = wrongFormula(s), gRight = rightFormula(s);
    console.log(`     ${tag}: 错版 gcd=${gWrong}  正版 gcd=${gRight}  m=${m}`);
    assert.notStrictEqual(gWrong, m, `${tag}: 抄错公式竟然给出正确模数 —— 测试前提失效`);
    assert.strictEqual(gRight, m, `${tag}: 差分版必须精确给出 m`);
  }
});
t('已知例外：c=0 的乘法同余生成器上错版碰巧成立（不能推广）', () => {
  const [a, c, m] = CASES['prime 2^31-1'];
  assert.strictEqual(c, 0n, '前置条件：该用例 c 必须为 0');
  const s = gen(a, c, m, 555n, 10);
  const g = wrongFormula(s);
  console.log(`     prime 2^31-1 (c=0): 错版 gcd=${g} —— 碰巧等于 m`);
  assert.strictEqual(g, m, 'c=0 时错版确实成立，这是唯一例外，必须如实记录');
});

console.log('\nC) 抄错公式②必须失败："模 2^k 一定求不出逆"不成立');
t('a、c 均为奇数 → 差分恒为奇数 → 求逆必成功', () => {
  for (const tag of ['glibc 2^31', '2^32 (a,c odd)', 'mmix 2^64']) {
    const [a, c, m] = CASES[tag];
    let fails = 0;
    for (let seed = 1n; seed <= 200n; seed++) {
      const s = gen(a, c, m, seed * 7919n, 3);
      if (modInverse(norm(s[1] - s[0], m), m) === null) fails++;
    }
    console.log(`     ${tag}: 200 次中求逆失败 ${fails} 次`);
    assert.strictEqual(fails, 0, `${tag}: a,c 均为奇数时不应失败，实测却失败 ${fails} 次`);
  }
});
t('c 为偶数 → 差分恒为偶数 → 求逆必失败（才有 2-adic 救济的必要）', () => {
  const [a, , m] = CASES['2^32 (a,c odd)'];
  const cEven = 1013904222n;
  let fails = 0;
  for (let seed = 1n; seed <= 200n; seed++) {
    const s = gen(a, cEven, m, seed * 7919n, 3);
    if (modInverse(norm(s[1] - s[0], m), m) === null) fails++;
  }
  console.log(`     2^32 但 c 为偶数 → 200 次中求逆失败 ${fails} 次`);
  assert.strictEqual(fails, 200, 'c 为偶数时必须全部失败');
});

console.log('\nD) 2-adic 救济：求不出逆时仍能解出 a mod (m>>v)');
t('消掉 2 因子后求解，a 落在正确同余类', () => {
  const [a, , m] = CASES['2^32 (a,c odd)'];
  const cEven = 1013904222n;
  const s = gen(a, cEven, m, 20261016n, 5);
  const d1 = norm(s[1] - s[0], m), d2 = norm(s[2] - s[1], m);
  assert.strictEqual(modInverse(d1, m), null, '前置条件：应求不出逆');
  const k = v2(d1);
  assert.strictEqual(v2(d2), k, 'd1、d2 的 2-adic 赋值应相同（可作为自检）');
  const mm = m >> BigInt(k);
  const invOdd = modInverse(d1 >> BigInt(k), mm);
  assert.ok(invOdd !== null, '消掉 2 因子后应能求逆');
  const aHat = ((d2 >> BigInt(k)) * invOdd) % mm;
  assert.strictEqual(norm(a - aHat, mm), 0n, '解出的 a 必须落在正确同余类');
  console.log(`     2-adic=${k}，解出 a mod 2^${32 - k} = ${aHat}（真 a=${a}）`);
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
