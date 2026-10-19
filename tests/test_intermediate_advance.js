// P2 中间值自动推进 —— 单测
const assert = require('assert');
const path = require('path');
const crypto = require('crypto');
const ia = require(path.join(__dirname, '..', 'electron', 'intermediate-advance.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log('  ok  ' + name); }
  catch (e) { fail++; console.log('  FAIL ' + name + ' -> ' + e.message); }
}

console.log('intermediate-advance');

// --- 字典构造 ---
t('dictionary contains common CTF words', () => {
  const d = ia.buildDictionary([]);
  for (const w of ['flag', 'admin', 'password']) assert.ok(d.includes(w), w);
});

t('dictionary includes strings from the binary', () => {
  const d = ia.buildDictionary(['Th1sIsTheKey']);
  assert.ok(d.includes('Th1sIsTheKey'));
  assert.ok(d.includes('th1sisthekey'));   // 小写变体
});

t('dictionary includes short numbers', () => {
  const d = ia.buildDictionary([]);
  assert.ok(d.includes('0'));
  assert.ok(d.includes('1234'));
  assert.ok(d.includes('99999'));
});

// --- 哈希爆破 ---
t('crack md5 of a dictionary word', () => {
  const target = crypto.createHash('md5').update('admin').digest('hex');
  const r = ia.advanceIntermediates([target]);
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].ok, true);
  assert.strictEqual(r[0].plaintext, 'admin');
  assert.strictEqual(r[0].kind, 'MD5');
});

t('crack sha1 of a dictionary word', () => {
  const target = crypto.createHash('sha1').update('guest').digest('hex');
  const r = ia.advanceIntermediates([target]);
  assert.strictEqual(r[0].ok, true);
  assert.strictEqual(r[0].plaintext, 'guest');
});

t('crack sha256 of a short number', () => {
  const target = crypto.createHash('sha256').update('8888').digest('hex');
  const r = ia.advanceIntermediates([target]);
  assert.strictEqual(r[0].ok, true);
  assert.strictEqual(r[0].plaintext, '8888');
});

t('crack using a string taken from the binary (not in generic dict)', () => {
  const secret = 'Zx9Qm_TrapKey';
  const target = crypto.createHash('md5').update(secret).digest('hex');
  const r = ia.advanceIntermediates([target], { extraStrings: ['noise', secret] });
  assert.strictEqual(r[0].ok, true);
  assert.strictEqual(r[0].plaintext, secret);
});

t('unbroken hash reports ok=false with a non-final note', () => {
  const target = crypto.createHash('md5').update('a-very-unlikely-preimage-zzz').digest('hex');
  const r = ia.advanceIntermediates([target]);
  assert.strictEqual(r[0].ok, false);
  assert.ok(/未命中/.test(r[0].note));
});

// --- hex 解码 ---
t('short hex decoded as ASCII', () => {
  const hex = Buffer.from('MyKey123', 'latin1').toString('hex');
  const r = ia.advanceIntermediates([hex]);
  assert.strictEqual(r[0].ok, true);
  assert.strictEqual(r[0].plaintext, 'MyKey123');
  assert.strictEqual(r[0].action, 'hex-decode');
});

t('short hex decoded as UTF-16LE for CJK', () => {
  const s = '密钥ab';
  const hex = Buffer.from(s, 'utf16le').toString('hex');
  const r = ia.advanceIntermediates([hex]);
  assert.strictEqual(r[0].ok, true);
  assert.ok(r[0].plaintext.includes('密钥') || r[0].note.includes('utf-16le'));
});

t('hex that is not printable falls back to single-byte XOR', () => {
  const plain = 'HelloThere';
  const buf = Buffer.from(plain, 'latin1');
  for (let i = 0; i < buf.length; i++) buf[i] ^= 0x5a;
  const r = ia.advanceIntermediates([buf.toString('hex')]);
  const hit = r.find(x => x.ok && x.plaintext.includes('HelloThere'));
  assert.ok(hit, 'expected XOR recovery, got ' + JSON.stringify(r));
  assert.ok(/XOR/i.test(hit.note));
});

// --- Base64 ---
t('base64 decoded one layer', () => {
  const b64 = Buffer.from('flag_in_base64', 'utf8').toString('base64');
  const r = ia.advanceIntermediates([b64]);
  assert.strictEqual(r[0].ok, true);
  assert.ok(r[0].plaintext.includes('flag_in_base64'));
});

t('base64 decoded multiple layers', () => {
  let s = 'nested_secret';
  for (let i = 0; i < 2; i++) s = Buffer.from(s, 'utf8').toString('base64');
  const r = ia.advanceIntermediates([s]);
  assert.strictEqual(r[0].ok, true);
  assert.ok(r[0].plaintext.includes('nested_secret'), r[0].plaintext);
  assert.ok(r[0].note.includes('2 层'), r[0].note);
});

// --- 通用性 ---
t('processes multiple distinct values and de-duplicates', () => {
  const a = crypto.createHash('md5').update('flag').digest('hex');
  const b = Buffer.from('AnotherKey', 'latin1').toString('hex');
  const r = ia.advanceIntermediates([a, b, a]);
  assert.strictEqual(r.length, 2);
});

t('ignores too-short / empty values', () => {
  assert.strictEqual(ia.advanceIntermediates(['', 'ab', null]).length, 0);
});

t('extractStringsFromBuffer finds printable runs', () => {
  const buf = Buffer.concat([
    Buffer.from([0x00, 0x01]),
    Buffer.from('CrackMeKey'),
    Buffer.from([0xff, 0xfe]),
    Buffer.from('admin'),
    Buffer.from([0x00]),
  ]);
  const s = ia.extractStringsFromBuffer(buf);
  assert.ok(s.includes('CrackMeKey'));
  assert.ok(s.includes('admin'));
});

t('dictionary size stays bounded', () => {
  const d = ia.buildDictionary([]);
  assert.ok(d.length < 300000, 'dictionary too large: ' + d.length);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
