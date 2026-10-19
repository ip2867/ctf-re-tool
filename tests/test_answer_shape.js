// rank 5 单测：末公里候选闭环
//
// 实测（CrackMe3）：AI 第一轮就给出并自证了答案 771535（本地复现 sum==0x2979），
// 但 recordFlag 因它不是 `xxx{...}` 形态直接丢弃 → flags 为空 → 整题记为未解出。
// 同时第二轮重试的返回值被直接丢掉，它产生的定向提示没有任何消费方。
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

// 从 "function name(" 开始，按行累计到括号配平为止。
// 不用花括号配平：函数体里的对象字面量 `{ value: v, ... }` 会被误当成函数结束。
function grab(name) {
  const startIdx = appSrc.search(new RegExp('^function\\s+' + name + '\\s*\\(', 'm'));
  if (startIdx < 0) throw new Error('未找到函数 ' + name);
  const lines = appSrc.slice(startIdx).split(/\r?\n/);
  const out = [];
  let depth = 0, started = false;
  for (const line of lines) {
    out.push(line);
    for (const ch of line) {
      if (ch === '{') { depth++; started = true; }
      else if (ch === '}') depth--;
    }
    if (started && depth === 0) break;
  }
  return out.join('\n');
}

console.log('[1] newFindings 必须带 answers 容器');
{
  ok(/answers:\s*\[\]/.test(appSrc), 'newFindings 初始化 answers: []');
  const body = grab('newFindings');
  ok(/answers/.test(body), 'answers 在 newFindings 函数体内');
}

console.log('\n[2] recordAnswer 不经 looksLikeFlag 过滤');
{
  const body = grab('recordAnswer');
  ok(!/looksLikeFlag\(v\)\)\s*return/.test(body.replace(/\s+/g, ' ')),
    '没有"不是 flag 形态就 return"的早退');
  ok(/findings\.answers/.test(body), '写入 findings.answers');
  ok(/verified:\s*!!opts\.verified/.test(body.replace(/\s+/g, ' ')), 'verified 由调用方显式给出，默认 false');
  ok(/looksLikeFlag\(v\)\)\s*\{\s*recordFlag/.test(body.replace(/\s+/g, ' ')),
    '已是 flag 形态的转交 recordFlag（不重复记录）');
}

// 抽出 recordAnswer 做真实行为验证
const Mod = {};
{
  const stateObj = { findings: { flags: [], answers: [] } };
  const code = [
    'const persistFindings = () => {};',
    'function looksLikeFlag(v){ const s=String(v||"").trim(); return /^[A-Za-z][A-Za-z0-9_]*\\{[^}]{1,250}\\}$/.test(s); }',
    'function recordFlag(f,s,ver){ const ex=state.findings.flags.find(x=>x.flag===f); if(ex){if(ver)ex.verified=true;} else state.findings.flags.push({flag:f,verified:!!ver,source:s||"ai"}); }',
    grab('recordAnswer'),
    'exports.recordAnswer = recordAnswer;',
  ].join('\n');
  new Function('state', 'exports', code)(stateObj, Mod);
  Mod.state = stateObj;
}

console.log('\n[3] recordAnswer 行为：裸答案能入库');
{
  Mod.recordAnswer('771535', { source: 'verify-contract-key', verified: true });
  const a = Mod.state.findings.answers.find(x => x.value === '771535');
  ok(!!a, '771535 已登记为 answer');
  ok(a && a.verified === true, 'verified 为 true');
  ok(a && a.source === 'verify-contract-key', 'source 记录正确');

  Mod.recordAnswer('771535', { source: 'other', verified: false });
  const dup = Mod.state.findings.answers.filter(x => x.value === '771535');
  ok(dup.length === 1, '同值不重复登记');
  ok(dup[0].verified === true, '已验证标记不被后续 false 覆盖');

  Mod.recordAnswer('flag{abc}', { source: 'ai', verified: false });
  ok(Mod.state.findings.flags.some(f => f.flag === 'flag{abc}'), 'flag 形态转交 recordFlag');
  ok(!Mod.state.findings.answers.some(x => x.value === 'flag{abc}'), '不在 answers 里重复');

  Mod.recordAnswer('', {});
  Mod.recordAnswer('x', {});
  ok(!Mod.state.findings.answers.some(x => x.value === '' || x.value === 'x'), '空值与过短值被拒');
}

console.log('\n[4] 契约驱动 verified 的三条件');
{
  const body = appSrc.slice(appSrc.indexOf('契约驱动的"裸答案"判定'));
  ok(body.length > 0, '找到契约驱动判定段');
  const seg = body.slice(0, 3000);
  ok(/contracts\.some\(c => c && String\(c\.key/.test(seg.replace(/\s+/g, ' ')),
    '条件②：存在契约 key 等于该值');
  ok(/hits\.length > 0/.test(seg), '条件③：契约本地复现有命中');
  ok(/byKey && hits\.length > 0/.test(seg.replace(/\s+/g, ' ')), '两个条件必须同时成立');
  ok(/verified:\s*true/.test(seg), '命中时标 verified:true');
  ok(/verified:\s*false/.test(seg), '未命中时标 verified:false（不冒充已验证）');
  ok(/裸答案 .* 经契约复现确认/.test(seg), '有可观察日志');
  // 条件①：值必须来自 extractFlags(aiText)
  ok(/flags\.length/.test(seg) && /for \(const v of flags\)/.test(seg),
    '条件①：只对 extractFlags 抽出的候选判定');
}

console.log('\n[5] 提交路径：裸答案按外壳包装后提交');
{
  const i = appSrc.indexOf('const submitCandidates');
  const seg = i >= 0 ? appSrc.slice(i, i + 6000) : '';
  ok(!!seg, '存在 submitCandidates 构造');
  ok(/verifiedAnswers/.test(seg), '收集 verified answers');
  ok(/_platformWrapTemplate/.test(seg), '使用平台包装模板');
  ok(/applyWrap\(a\.value, tpl\)/.test(seg), '按模板包装');
  ok(/裸答案经平台外壳规则包装/.test(seg), '成功文案可观察');
  ok(/包装后提交未通过，已降级为未验证/.test(seg), '失败时降级（不污染正确率）');
  ok(/origin === 'answer'/.test(seg), '区分裸答案与 flag 来源');
  ok(/if \(!submitCandidates\.length\)/.test(seg), '空候选判断改用 submitCandidates');
  // 早退分支必须用 submitCandidates，不能再用旧的 verified
  const guardIdx = seg.indexOf('if (!submitCandidates.length)');
  const afterGuard = seg.slice(guardIdx, guardIdx + 600);
  ok(/no-verified-flag/.test(afterGuard), '空候选分支返回 no-verified-flag');
  ok(!/if \(!verified\.length\)/.test(seg), '旧的 verified 早退已移除');
}

console.log('\n[6] 重试循环：返回值必须被消费');
{
  ok(/const MAX_RETRY_ROUNDS = 2/.test(appSrc), '定义重试上限 2 轮');
  ok(/retryFin = await finalizeSolve\(/.test(appSrc), '第二轮返回值被接住（此前直接丢弃）');
  ok(/第 \$\{round\} 轮定向提示已消费/.test(appSrc), '每轮有可观察日志');
  ok(/已达上限（\$\{MAX_RETRY_ROUNDS\} 轮）/.test(appSrc), '达到上限有日志');
  ok(/ai-deep-retry-\$\{?round|'ai-deep-retry-' \+ round/.test(appSrc), 'reason/source 随轮次变化');
  // 旧写法必须已消失
  ok(!/await finalizeSolve\(r2\.text, \{ source: 'ai-deep-retry' \}\);\s*\n\s*const vf2/.test(appSrc),
    '旧的"丢弃返回值"写法已移除');
}

console.log('\n[7] 机器码优先于通用 hex 分类');
{
  const i = appSrc.indexOf('机器码优先于通用 hex 分类');
  const seg = i >= 0 ? appSrc.slice(i, i + 1800) : '';
  ok(!!seg, '存在机器码优先分支');
  ok(/findDecodedLayer\(vr\.rawOutput/.test(seg), '用 findDecodedLayer 判机器码');
  const typedIdx = appSrc.indexOf('const typed = classifyIntermediateValues(vr.hits)');
  const mcIdx = appSrc.indexOf('机器码优先于通用 hex 分类');
  ok(mcIdx > 0 && typedIdx > mcIdx, '机器码判断在 classifyIntermediateValues 之前');
  ok(/不要换算法、不要换 key/.test(seg), '给出正确动作');
  ok(/写盘为新文件/.test(seg), '要求写盘接力');
  ok(/机器码结论优先于通用 hex 分类/.test(seg), '有可观察日志');
  ok(!/attributeFailure/.test(seg), '不再引用不在作用域的 attributeFailure');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
