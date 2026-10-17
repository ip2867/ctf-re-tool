// SM4 变体解密脚本生成器单测（本次真机失败的核心修复）
// 关键验收：工具生成的脚本**真的能解出真实题目的 flag**，而不是只输出描述。
const fs = require('fs'), os = require('os'), p = require('path');
const { spawnSync } = require('child_process');
const { scanCryptoFingerprints } = require('./scanner_loader.js');
const { buildSM4VariantDecryptScript } = require('./sm4_script_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = os.tmpdir();

console.log('A) 脚本生成：关键要素齐全');
{
  const script = buildSM4VariantDecryptScript({
    sboxOff: 0xd630, sboxStride: 4, ckOff: 0xda30,
    fkOffs: [0x10a10], ctCands: [{ off: 0xfa18, len: 48 }], keyHints: ['We1c0me_t0_xmctf'],
  });
  ok(typeof script === 'string' && script.length > 500, '生成了脚本');
  ok(/SBOX = \[d\[\d+ \+ i \* 4\]/.test(script), 'S 盒按 stride=4 读取');
  ok(/S 盒=0xd630/.test(script), 'S 盒偏移以十六进制注明（0xd630）');
  ok(/CK\s*=\s*\[struct\.unpack_from\("<I", d, \d+ \+ i \* 4\)\[0\] for i in range\(32\)\]/.test(script), 'CK 按小端读 32 项');
  ok(/CK=0xda30/.test(script), 'CK 偏移以十六进制注明（0xda30）');
  ok(/0x10a10/.test(script), 'FK 候选写入');
  ok(/0xfa18, 48/.test(script), '密文候选写入');
  ok(/We1c0me_t0_xmctf/.test(script), 'key 提示写入');
  ok(/itertools\.product\(\[False, True\], repeat=4\)/.test(script), '枚举 16 种字节序/状态组合');
  ok(/def rev_words/.test(script) && /def rev_bytes/.test(script), '包含块内排列的 3 种变体');
}

console.log('\nB) 端到端：对真实 Disguise stage2 跑生成的脚本，必须解出 flag');
{
  const stage2 = p.join(__dirname, '..', 'cases', 'Disguise.exe_2c0c118b', 'extracted', 'stage_pe_a200.bin');
  if (!fs.existsSync(stage2)) {
    console.log('  ⚠️ 跳过（stage2 不存在，需先跑一次 Disguise 提取）');
  } else {
    const r = scanCryptoFingerprints(stage2);
    const ca = (r.fingerprints || []).map(f => f.constantAnalysis).find(c => c && c.decryptScript);
    ok(!!ca, '扫描器为该文件生成了 decryptScript');
    if (ca) {
      const py = p.join(tmp, 't_sm4_e2e.py');
      fs.writeFileSync(py, ca.decryptScript.script, 'utf8');
      const out = spawnSync('python', [py, stage2], { encoding: 'utf8', timeout: 180000 });
      const txt = (out.stdout || '') + (out.stderr || '');
      const m = txt.match(/xmctf\{[^}]+\}/);
      ok(!!m, `脚本解出 flag：${m ? '(命中，内容已脱敏)' : '(未命中)'}`);
      // 答案以 SHA256 比对，避免在公开仓库里直接暴露题解
      const KNOWN_SHA256 = 'f48d1c813f4f37a08316efb9b772980fd5777aecb4662cbc26a04d0d21df8b49';
      const got = m ? require('crypto').createHash('sha256').update(m[0]).digest('hex') : '';
      ok(got === KNOWN_SHA256, 'flag 内容与官方题解一致（SHA256 比对）');
      ok(/rev_words/.test(txt), '命中路径使用了块内 dword 反序（与真实结构一致）');
    }
  }
}

console.log('\nC) 生成的脚本语法可解析（py_compile）');
{
  const script = buildSM4VariantDecryptScript({
    sboxOff: 0x100, sboxStride: 4, ckOff: 0x200, fkOffs: [0x300],
    ctCands: [{ off: 0x400, len: 48 }], keyHints: ['abcdefgh12345678'],
  });
  const py = p.join(tmp, 't_sm4_syntax.py');
  fs.writeFileSync(py, script, 'utf8');
  const out = spawnSync('python', ['-m', 'py_compile', py], { encoding: 'utf8' });
  ok(out.status === 0, 'py_compile 通过' + (out.status ? '：' + (out.stderr || '').slice(0, 200) : ''));
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);

