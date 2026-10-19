// 回归：P1 augmentSynth —— 契约失败后追加工具合成的维度。
// 为什么需要：AI 的 [HYPOTHESES] 往往在同一组假设里打转（同样 key/编码只换顺序），
// 工具合成能补上它想不到的维度（全零 IV、扫描器抽的其他密文、TEA 字节序）。
// 但只在"契约已失败"时追加，避免 AI 首次给假设就把候选池撑爆。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

function extract(name) {
  const s = src.indexOf('function ' + name + '(');
  if (s < 0) throw new Error('未定位 ' + name);
  let depth = 0, e = -1, inS = null, inRe = false, esc = false, prev = '';
  for (let i = src.indexOf('{', s); i < src.length; i++) {
    const c = src[i];
    if (inS) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === inS) inS = null; continue; }
    if (inRe) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === '/') { inRe = false; prev = '/'; } continue; }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '/' && /[=(:,!&|?{;\n]|return|=>/.test(prev)) { inRe = true; prev = ''; continue; }
    if (!/\s/.test(c)) prev = c;
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { e = i + 1; break; } }
  }
  return src.slice(s, e);
}

// 只测 augment 的合并逻辑：抽出 runHypotheses 里那段（不含异步部分）
const mod = { exports: {} };
new Function('module', 'exports',
  'let state = { lastAlgScan: null };\n'
  + 'function setState(s){ state = s; }\n'
  + 'function addLog(){}\n'
  + extract('synthesizeHypotheses') + '\n'
  + `function augment(attempts, synthFrom) {
      const synth = synthesizeHypotheses(synthFrom);
      if (!synth.length) return { attempts, added: 0 };
      const seen = new Set(attempts.map(a => [a.algo, a.key_encoding, a.key, a.iv, a.variant, String(a.ciphertext || '').slice(0, 32)].join('|')));
      let added = 0;
      for (const s of synth) {
        const k = [s.algo, s.key_encoding, s.key, s.iv, s.variant, String(s.ciphertext || '').slice(0, 32)].join('|');
        if (seen.has(k)) continue;
        seen.add(k); attempts.push(s); added++;
      }
      return { attempts, added };
    }\n`
  + 'module.exports={augment,setState};')(mod, mod.exports);
const { augment, setState } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

const contract = { algo: 'aes_cbc', key: 'secret', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff' };

console.log('[契约失败后追加维度]');
{
  setState({ lastAlgScan: null });
  const aiHyp = [{ algo: 'aes_cbc', key: 'secret', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff' }];
  const before = aiHyp.length;
  const r = augment(aiHyp.slice(), [contract]);
  ok(r.attempts.length > before, `从 ${before} 增加到 ${r.attempts.length}`);
  ok(r.added > 0, `追加 ${r.added} 组`);
  const ivs = new Set(r.attempts.map(x => x.iv));
  ok(ivs.has('0000000000000000'), '补充了全零 IV（AI 没给）');
}

console.log('[与 AI 已有假设去重]');
{
  setState({ lastAlgScan: null });
  const aiHyp = [
    { algo: 'aes_cbc', key: 'secret', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff', iv: '' },
    { algo: 'aes_ecb', key: 'secret', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff', iv: '' },
  ];
  const r = augment(aiHyp.slice(), [contract]);
  const keys = r.attempts.map(x => [x.algo, x.key_encoding, x.key, x.iv, x.variant, String(x.ciphertext || '').slice(0, 32)].join('|'));
  ok(new Set(keys).size === keys.length, '无重复');
}

console.log('[无扫描结果时仍能补充 IV/字节序]');
{
  setState({ lastAlgScan: null });
  const r = augment([], [{ algo: 'xtea', key: '00112233445566778899aabbccddeeff', key_encoding: 'hex', ciphertext: 'aabbccdd11223344' }]);
  ok(r.attempts.length > 0, `产生 ${r.attempts.length} 组`);
  ok(r.attempts.some(x => x.variant === 'be32'), '包含 be32 变体');
}

console.log('[边界]');
{
  setState({ lastAlgScan: null });
  ok(augment([], []).added === 0, '空 synthFrom 不追加');
  ok(augment([], null).added === 0, 'null 不崩');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
