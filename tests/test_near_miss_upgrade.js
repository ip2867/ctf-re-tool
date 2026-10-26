// 近失升级（40 题实测缺陷修复）：
//   ① 答案值 = 本地复现命中（vr.hits）→ verified（verify-hit-match）
//   ② 答案值出现在复现原始输出且不是密文回显 → verified（verify-output-match）
//   ③ 平台轮区分 note：near-miss-answer / no-verified-flag / blocked-by-av，
//      且近失候选不提交（未验证不提交的原则不变），但进报告（results[].near_miss）
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

console.log('[1] 判定链：byKey 之外新增 byHit / byOutput');
{
  ok(/const byHit = hits\.some\(/.test(appSrc), 'byHit：答案与复现命中逐字比对');
  ok(/const byOutput = t\.length >= 6 && rawOut\.includes\(t\)/.test(appSrc), 'byOutput：答案出现在复现原始输出');
  ok(/ciphertext == null \? '' : c\.ciphertext\)\.replace\(\/\\s\+\/g, ''\)/.test(appSrc.replace(/\r/g, '')), 'byOutput 排除密文回显（归一化空白后比对）', '未找到密文排除子句');
  ok(/const okVerified = \(byKey \|\| byHit \|\| byOutput\) && \(hits\.length > 0 \|\| byOutput\)/.test(appSrc), '三条路任一命中才算 verified（byKey 仍要求有 hits）');
  ok(/'verify-hit-match'/.test(appSrc) && /'verify-output-match'/.test(appSrc), 'source 标注区分新通道');
}

console.log('\n[2] 行为验证：判定式对四种情形的取值');
{
  const expr = `
    function judge(t, hits, contracts, rawOut) {
      const byKey = contracts.some(c => c && String(c.key == null ? '' : c.key).trim() === t);
      const byHit = hits.some(h => h != null && String(h).trim() === t);
      const byOutput = t.length >= 6 && rawOut.includes(t)
        && !rawOut.includes('keyenc=' + t)
        && !contracts.some(c => c && String(c.ciphertext == null ? '' : c.ciphertext).replace(/\\s+/g, '').trim() === t.replace(/\\s+/g, ''));
      return { v: (byKey || byHit || byOutput) && (hits.length > 0 || byOutput), why: byKey ? 'key' : (byHit ? 'hit' : (byOutput ? 'out' : '')) };
    }
    module.exports = judge;`;
  const mod = { exports: null };
  new Function('module', expr)(mod);
  const judge = mod.exports;
  ok(judge('771535', ['771535'], [], '').v === true, '答案=命中值 → verified（CrackMe3 形态）');
  ok(judge('flag{z3_solved}', [], [], 'attempt=1 output=flag{z3_solved}\n').v === true, '答案出现在输出（无 hits）→ verified（equation 形态）');
  ok(judge('AAAABBBBCCCC', [], [{ key: 'x', ciphertext: 'AAAABBBBCCCC' }], 'ct=AAAABBBBCCCC').v === false, '密文回显不算 verified');
  ok(judge('base64x', [], [], '[OUT] attempt=0 keyenc=base64x: abc').v === false, '编码标签自证不算 verified');
  ok(judge('abc', [], [], 'no match').v === false, '无证据 → 不 verified');
}

console.log('\n[3] 平台轮 near-miss 标注');
{
  ok(/'near-miss-answer'/.test(appSrc), "note 有 near-miss-answer 档位");
  ok(/near_miss: nearMiss\.map\(x => String\(x\.value\)\)/.test(appSrc), '轮结果带 near_miss 候选数组');
  ok(/near_miss: Array\.isArray\(r\.near_miss\) \? r\.near_miss : \[\]/.test(appSrc), '__ctfAutoTest 报告透传 near_miss');
  ok(/state\.lastBlockedReason \? 'blocked-by-av'\s*:\s*\(nearMiss\.length \? 'near-miss-answer' : 'no-verified-flag'\)/.test(appSrc.replace(/\r/g, '').replace(/\n\s*/g, ' ')), '优先级：AV 阻断 > 近失 > 颗粒无收');
  // 近失不提交：提交候选仍只来自 verified
  ok(/const verifiedAnswers = .*\.filter\(a => a\.verified\)/.test(appSrc.replace(/\r/g, '')), '提交候选仍只取 verified（近失只记录不提交）');
  ok(/near_miss: last\.near_miss \|\| \[\]/.test(mainSrc), '主进程轮次日志记录 near_miss');
}
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
