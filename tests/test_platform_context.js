// rank 4 单测：平台题目契约贯穿 + 零指纹措辞
//
// 两条实测缺陷：
//   1) CrackMe3 题面「请包上 flag{} 提交」存进 state 后被 analyzeFile 的换题清理立刻清空
//      （实测 22/22 份会话 prompt 里都没有题面），于是包装指令从未变成动作。
//   2) 零指纹被断言成"本层极可能是壳/加载器/decoy"——而 CrackMe2 的真实算法（MD5）
//      和 K 表就在本层、payloads 为空，方向完全相反。
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

function grab(name) {
  const re = new RegExp('function ' + name + '\\s*\\(', 'g');
  const m = re.exec(appSrc);
  if (!m) throw new Error('未找到函数 ' + name);
  let i = appSrc.indexOf('{', m.index);
  let depth = 0, inS = null, inRe = false, esc = false, prev = '';
  for (let j = i; j < appSrc.length; j++) {
    const c = appSrc[j];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inS) inS = null;
      continue;
    }
    // 正则字面量里也可能出现 { }，不识别就会把函数体截断
    if (inRe) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === '/') { inRe = false; prev = '/'; }
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '/' && /[=(:,!&|?{;\n]|return|=>/.test(prev)) { inRe = true; prev = ''; continue; }
    if (!/\s/.test(c)) prev = c;
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return appSrc.slice(m.index, j + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

const R = {};
new Function('exports', [grab('restorePlatformContext'), grab('parseWrapDirective'), grab('applyWrap')].join('\n')
  + '\nexports.restorePlatformContext=restorePlatformContext;exports.parseWrapDirective=parseWrapDirective;exports.applyWrap=applyWrap;')(R);

console.log('[1] parseWrapDirective：从题面识别包装模板');
{
  const a = R.parseWrapDirective('注意：得到的 flag 请包上 flag{} 提交');
  ok(!!a && a.template === 'flag{%s}', 'flag{} → flag{%s}', JSON.stringify(a));
  ok(!!a && /flag\{\}/.test(a.evidence), '保留原文依据', a && a.evidence);

  const b = R.parseWrapDirective('请把结果包成 CTF{}');
  ok(!!b && b.template === 'CTF{%s}', '自定义前缀 CTF{}', JSON.stringify(b));

  ok(R.parseWrapDirective('Run with pppp -n [threads] -i [input] -o [output]') === null,
    '运行用法不误判为包装指令');
  ok(R.parseWrapDirective('提取完整邮箱即为 flag') === null, '无包装词 → null');
  ok(R.parseWrapDirective('') === null, '空串 → null');
  ok(R.parseWrapDirective(null) === null, 'null → null');
  // 只有前缀名没有"包上"这类动作词的，不应误判
  ok(R.parseWrapDirective('格式参考 flag{} 示例') === null, '无动作词 → null（避免误判）');
}

console.log('\n[2] applyWrap：包装语义');
{
  ok(R.applyWrap('771535', 'flag{%s}') === 'flag{771535}', '裸值 → flag{771535}');
  ok(R.applyWrap('771535', 'CTF{%s}') === 'CTF{771535}', '自定义模板');
  ok(R.applyWrap('flag{abc}', 'flag{%s}') === 'flag{abc}', '已带外壳不重复套');
  // 历史缺陷 A（[WUSTCTF2020]level1）：内层前缀与目标前缀不同时，
  // 必须**先脱内层再套目标壳**。旧行为是"任意 xxx{...} 都算外壳直接返回"，
  // 会产出 x{y} 这种不符合目标形态的答案 → 平台判错。
  ok(R.applyWrap('x{y}', 'flag{%s}') === 'flag{y}', '异前缀 xxx{...} 先脱壳再套目标模板');
  ok(R.applyWrap('hack1ng_fo1_fun{abc}', 'flag{%s}') === 'flag{abc}', '题目自定义壳被正确剥离');
  ok(R.applyWrap('x{y}', 'x{%s}') === 'x{y}', '同前缀仍不重复套');
  ok(R.applyWrap('', 'flag{%s}') === '', '空值不包装');
  ok(R.applyWrap('  v  ', 'flag{%s}') === 'flag{v}', '两端空白被裁掉');
}

console.log('\n[3] restorePlatformContext：三项都恢复');
{
  const target = {};
  R.restorePlatformContext(target, { challenge: { name: 'CrackMe3' }, desc: '请包上 flag{}', files: ['a.exe', 'flag.out'] });
  ok(target._platformChallenge && target._platformChallenge.name === 'CrackMe3', 'challenge 恢复');
  ok(target._platformChallengeDesc === '请包上 flag{}', 'desc 恢复');
  ok(Array.isArray(target._platformFiles) && target._platformFiles.includes('flag.out'), 'files 恢复');

  // undefined 不应覆盖已有值
  const t2 = { _platformChallengeDesc: 'keep' };
  R.restorePlatformContext(t2, { desc: undefined });
  ok(t2._platformChallengeDesc === 'keep', 'undefined 不覆盖已有值');
}

console.log('\n[4] analyzeFile 的清理必须可 opt-out（静态断言）');
{
  ok(/if \(!opts\.keepPlatformContext\)/.test(appSrc), 'analyzeFile 清理段带 keepPlatformContext 守卫');
  // 平台流程调用点
  ok(/await analyzeFile\(localFile, \{ keepPlatformContext: true \}\)/.test(appSrc),
    '平台流程 analyzeFile 传 keepPlatformContext:true');
  ok(/restorePlatformContext\(state, savedPlatform\)/.test(appSrc), '平台流程之后恢复上下文');
  // zip 手包调用点
  ok(/await analyzeFile\(main, \{ keepPlatformContext: true \}\)/.test(appSrc),
    'zip 手包 analyzeFile 传 keepPlatformContext:true');
  // 用户拖入新文件的路径仍应清空（不能全部放开）
  ok(/await analyzeFile\(filePath\)/.test(appSrc), '用户拖入路径仍使用默认清理');
}

console.log('\n[5] 零指纹措辞：不再断言"一定是壳"');
{
  // main.js 的 summary note
  const i = mainSrc.indexOf("algo: '(未发现算法指纹)'");
  const seg = i >= 0 ? mainSrc.slice(i, i + 1400) : '';
  ok(!!seg, '找到零指纹 summary 分支');
  ok(!/极可能是\*\*壳/.test(seg), 'main.js 不再写「极可能是**壳」');
  ok(/自实现算法|轮常量/.test(seg), '改为中性解释（自实现算法/轮常量）');
  ok(/hasPayload|noPayload/.test(seg), '按 payload 是否存在分支');

  // app.js 两处注入
  ok(!/本层极可能是\*\*壳\/加载器\/decoy/.test(appSrc), 'app.js 不再写「本层极可能是壳」');
  ok(/本层没有内嵌载荷/.test(appSrc), '无载荷时明确说"本层没有内嵌载荷"');
  ok(/这不等于"是壳"|这不等于"本层是壳"/.test(appSrc), '明确否定"等于壳"的推断');
  // 有载荷时仍应保留 loader 提示
  ok(/确有内嵌载荷|有内嵌载荷/.test(appSrc), '有载荷时仍提示提取下一层');
}

console.log('\n[6] 包装指令进入提示词');
{
  ok(/wrapHint/.test(appSrc), '构造了 wrapHint');
  ok(/parseWrapDirective\(descRaw\)/.test(appSrc), '从题面解析包装指令');
  ok(/_platformWrapTemplate/.test(appSrc), '模板写入 state 供提交路径使用');
  ok(/检测到包装指令/.test(appSrc), '有可观察日志');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
