// 回归：抽取 app.js 的 buildSolvePython 生成的 Python 脚本，按生产用法注入 ATTEMPTS，
// 对 SM4-ECB / SM4-CBC 正例 + 错 key 负例 + SM3 负例跑真实枚举。
const fs = require('fs'), p = require('path'), os = require('os'), cp = require('child_process');

const app = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

// 忠实复现生产路径：抽取 buildSolvePython 里的**模板字面量原文**并用 JS 求值
//（app.js 的模板字面量会被 JS 反转义；直接抓文件原文写盘会多一层反斜杠，
//  使 Python 正则 `flag\{...\}` 变成 `flag\\{...\\}` 而失效——这是脚手架的坑，不是产品 bug）。
function extractTemplateLiteral(src, fnName) {
  const fn = src.indexOf('function ' + fnName + '(');
  if (fn < 0) return null;
  const open = src.indexOf('`', src.indexOf('return', fn));
  if (open < 0) return null;
  let i = open + 1;
  while (i < src.length) {
    if (src[i] === '\\') { i += 2; continue; }        // 转义（\` \\ 等）
    if (src[i] === '`') return src.slice(open, i + 1); // 闭合反引号
    i++;
  }
  return null;
}
const tmplSrc = extractTemplateLiteral(app, 'buildSolvePython');
if (!tmplSrc) { console.log('❌ 未能抽取 buildSolvePython 模板字面量'); process.exit(1); }
const utf8ToBase64 = (s) => Buffer.from(String(s), 'utf8').toString('base64');
function build(attempts) {
  const payload = utf8ToBase64(JSON.stringify(attempts));
  return eval(tmplSrc);            // 模板里的 ${payload} 由 JS 求值替换（与生产一致）
}

// 用 Python 正向加密出密文
const genPy = `
import json
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
key = b"We1c0me_t0_xmctf"
pt = b"flag{SM4_regression_ok!!}"
c = CryptSM4(); c.set_key(key, SM4_ENCRYPT)
ct_ecb = c.crypt_ecb(pt)
iv = bytes(range(16))
c2 = CryptSM4(); c2.set_key(key, SM4_ENCRYPT)
ct_cbc = c2.crypt_cbc(iv, pt)
c3 = CryptSM4(); c3.set_key(b"wrong_key_123456", SM4_ENCRYPT)
ct_bad = c3.crypt_ecb(pt)
print("@@J@@" + json.dumps({
  "key": key.decode(), "pt": pt.decode(),
  "ecb": ct_ecb.hex(), "cbc": ct_cbc.hex(), "iv": iv.hex(), "bad": ct_bad.hex()
}))
`;
const genFile = p.join(os.tmpdir(), 'ctf_regress_gen.py');
fs.writeFileSync(genFile, genPy, 'utf8');
const g = cp.spawnSync('python', [genFile], { encoding: 'utf8', timeout: 60000 });
const gi = (g.stdout || '').indexOf('@@J@@');
if (gi < 0) { console.log('❌ 生成密文失败:\n' + (g.stdout || '') + (g.stderr || '')); process.exit(1); }
const d = JSON.parse((g.stdout).slice(gi + 5).split('\n')[0]);
console.log('用例：key=' + d.key + ' pt=' + d.pt);
console.log('  SM4-ECB ct=' + d.ecb);

function runAttempts(label, attempts) {
  const py = build(attempts);
  const f = p.join(os.tmpdir(), 'ctf_regress_run.py');
  fs.writeFileSync(f, py, 'utf8');
  const r = cp.spawnSync('python', [f], { encoding: 'utf8', timeout: 120000 });
  const out = (r.stdout || '') + (r.stderr || '');
  const hits = [...out.matchAll(/\[HIT\][^\n]*?flag=([^\r\n]+)/gi)].map(x => x[1].trim());
  return { out, hits };
}

let pass = 0, fail = 0;
const check = (n, c, x) => { if (c) { pass++; console.log('  ✅ ' + n); } else { fail++; console.log('  ❌ ' + n + (x ? '  → ' + x : '')); } };

console.log('\n1) SM4-ECB 正例（应命中 flag）');
{
  const { hits, out } = runAttempts('ecb', [{ algo: 'sm4_ecb', key: d.key, ciphertext: d.ecb, encoding: 'hex' }]);
  check('SM4-ECB 命中正确 flag', hits.some(h => h.includes('flag{SM4_regression_ok')), 'hits=' + JSON.stringify(hits) + ' | ' + out.slice(0, 300));
}

console.log('\n2) SM4-CBC 正例（应命中 flag）');
{
  const { hits, out } = runAttempts('cbc', [{ algo: 'sm4_cbc', key: d.key, ciphertext: d.cbc, encoding: 'hex', iv: d.iv, iv_encoding: 'hex' }]);
  check('SM4-CBC 命中正确 flag', hits.some(h => h.includes('flag{SM4_regression_ok')), 'hits=' + JSON.stringify(hits) + ' | ' + out.slice(0, 300));
}

console.log('\n3) SM4 错 key 负例（必须不报假 flag）');
{
  // 负例构造：密文用**真 key** 加密，解密时给**错 key** → 应得乱码，不得报出 flag
  const { hits, out } = runAttempts('bad', [{ algo: 'sm4_ecb', key: 'wrong_key_123456', ciphertext: d.ecb, encoding: 'hex' }]);
  check('错 key 不报 flag{SM4_regression_ok', !hits.some(h => h.includes('flag{SM4_regression_ok')), 'hits=' + JSON.stringify(hits));
  check('错 key 不报任何 flag{ 形态假阳性', !hits.some(h => /flag\{/i.test(h)), 'hits=' + JSON.stringify(hits));
}

console.log('\n4) SM3 负例（哈希不可逆，不得产假 flag）');
{
  const { hits, out } = runAttempts('sm3', [{ algo: 'sm3', key: 'x', ciphertext: d.ecb, encoding: 'hex' }]);
  check('SM3 不报 flag', !hits.some(h => /flag\{/i.test(h)), 'hits=' + JSON.stringify(hits) + ' | ' + out.slice(0, 200));
}

console.log('\n5) 既有算法回归（AES-ECB 正例）');
{
  const aesGen = `
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key=b"0123456789abcdef"; pt=b"flag{aes_regression_ok}"
print("@@J@@"+json.dumps({"ct": AES.new(key, AES.MODE_ECB).encrypt(pad(pt,16)).hex(), "key": key.decode()}))
`;
  const f = p.join(os.tmpdir(), 'ctf_regress_aes.py');
  fs.writeFileSync(f, aesGen, 'utf8');
  const r = cp.spawnSync('python', [f], { encoding: 'utf8', timeout: 60000 });
  const o = (r.stdout || '');
  const ii = o.indexOf('@@J@@');
  if (ii < 0) { check('AES 用例生成', false, (r.stdout || '') + (r.stderr || '')); }
  else {
    const ad = JSON.parse(o.slice(ii + 5).split('\n')[0]);
    const { hits } = runAttempts('aes', [{ algo: 'aes_ecb', key: ad.key, ciphertext: ad.ct, encoding: 'hex' }]);
    check('AES-ECB 命中正确 flag', hits.some(h => h.includes('flag{aes_regression_ok')), 'hits=' + JSON.stringify(hits));
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
