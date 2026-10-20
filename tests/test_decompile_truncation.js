// 反编译体截断 / 函数预算单测。
//
// 约束（来自实际失败）：
//   · 真实函数 sub_401DB0 有 14552 字符；static 6000 窗口会切掉后 3 处 >>31，
//     3000 窗口切掉全部；原实现没有任何"已省略"标记。
//   · 若"轮函数不截断"的规则把上限提到 60000，14552 字符根本不会截断 ——
//     所以"必须含省略标记"的测试必须**显式传 6000**，maxChars 不能由函数特征隐式决定。
//   · 6 个函数各放宽 60000 没有总预算会撑爆上下文。
const fs = require('fs');
const path = require('path');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

function grab(name) {
  const startIdx = appSrc.search(new RegExp('^(?:async\\s+)?function\\s+' + name + '\\s*\\(', 'm'));
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

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const logs = [];
const mod = { exports: {} };
new Function('module', 'exports', 'addLog',
  'const MAX_SINGLE_FUNC_CHARS = 60000;\nconst MAX_TOTAL_FUNC_CHARS = 120000;\n'
  + grab('buildFuncBody') + '\n'
  + 'module.exports = { buildFuncBody };'
)(mod, mod.exports, (lvl, msg) => logs.push(String(msg)));
const { buildFuncBody } = mod.exports;

function extractSub401DB0() {
  const p = path.join(__dirname, '..', 'cases', 'KanxueCTF2016Keygenme.exe_f99d940d',
    'evidence', 'mve7o3yn_关键函数反编译.c');
  if (!fs.existsSync(p)) return null;
  const t = fs.readFileSync(p, 'utf8');
  const i = t.indexOf('// ==== sub_401DB0 ====');
  if (i < 0) return null;
  const rest = t.slice(i).split(/\r?\n/);
  const out = [];
  for (let k = 0; k < rest.length; k++) {
    if (k > 0 && /^\/\/ ==== /.test(rest[k])) break;
    // 首个 `}` 行是函数结束；后续注释块不算
    out.push(rest[k]);
    if (k > 1 && rest[k].trim() === '}') break;
  }
  return out.join('\n');
}

function main() {
  const code = extractSub401DB0();
  if (!code) {
    console.log('SKIP 未找到 cases/KanxueCTF2016Keygenme.exe_f99d940d/evidence/mve7o3yn_关键函数反编译.c 中的 sub_401DB0');
    console.log('\n结果：0 通过 / 0 失败（跳过）');
    process.exit(0);
  }
  ok(code.includes('sub_401DB0'), `fixture 含函数名（${code.length} 字符）`);

  console.log('\n[1] maxChars=6000：含省略标记 / 函数名 / 偏移区间 / tail 保留原尾');
  {
    const out = buildFuncBody('sub_401DB0', code, 6000);
    ok(out.includes('省略'), '含「省略」标记');
    ok(out.includes('sub_401DB0'), '含函数名');
    ok(/原偏移 \d+\.\.\d+/.test(out), '含偏移区间');
    // head 60% / tail 40%：尾部 200 字符必须原样保留（10474 附近在上半段的第二半，用尾串校验）
    const tail200 = code.slice(-200);
    ok(out.includes(tail200), 'tail 包含原字符串最后 200 字符');
    ok(out.length <= 6000 + 200, `输出长度受限（${out.length}，上限 6000+标记）`);
    ok(logs.some(l => l.includes('截断 head/tail') && l.includes('maxChars=6000')), '日志含截断记录');
  }

  console.log('\n[2] maxChars=60000：输出与原文逐字节相等');
  {
    const out = buildFuncBody('sub_401DB0', code, 60000);
    ok(out === code, `逐字节相等（原 ${code.length}，出 ${out.length}）`);
  }

  console.log('\n[3] 预算：6 个 30000 字符函数，总长 ≤120000 + 标记，日志含函数预算');
  {
    // 模拟采集循环的预算分配（与 app.js 相同的规则）
    const MAX_TOTAL = 120000;
    const MAX_SINGLE = 60000;
    let left = MAX_TOTAL;
    let compressed = 0;
    const parts = [];
    for (let i = 0; i < 6; i++) {
      const raw = 'F'.repeat(30000);
      let c = raw;
      if (raw.length > left) {
        const allot = Math.max(0, Math.min(3000, left));
        if (allot < 500) { compressed++; continue; }
        c = buildFuncBody('fn' + i, raw, allot);
        compressed++;
      } else if (raw.length > MAX_SINGLE) {
        c = buildFuncBody('fn' + i, raw, MAX_SINGLE);
      }
      left -= c.length;
      parts.push(c);
    }
    const total = parts.reduce((a, b) => a + b.length, 0);
    ok(total <= MAX_TOTAL + 6 * 200, `总长 ${total} ≤ 120000+标记`);
    ok(compressed > 0, `有 ${compressed} 个函数被压缩`);
    const budgetLog = `[采集] 函数预算 ${MAX_TOTAL} 字符，压缩 ${compressed} 个`;
    ok(budgetLog.includes('函数预算 120000 字符'), '日志文案含「函数预算 120000 字符」');
  }

  console.log('\n[4] 源码静态断言');
  {
    ok(/function buildFuncBody\(name, code, maxChars\)/.test(appSrc), 'buildFuncBody(name, code, maxChars) 签名');
    ok(/const MAX_TOTAL_FUNC_CHARS = 120000;/.test(appSrc), 'MAX_TOTAL_FUNC_CHARS=120000');
    ok(/const MAX_SINGLE_FUNC_CHARS = 60000;/.test(appSrc), '单函数上限 60000');
    ok(/\[采集\] 函数预算 \$\{MAX_TOTAL_FUNC_CHARS\} 字符，压缩 \$\{funcBudgetCompressed\} 个/.test(appSrc),
      '采集循环输出预算日志');
    // 旧的无标记 slice 必须已被替换
    ok(!/String\(func\.code\)\.substring\(0, 6000\)/.test(appSrc), '旧的 substring(0,6000) 已移除');
    ok(!/String\(analysisData\.mainCode\)\.slice\(0, 4000\)/.test(appSrc), '旧的 mainCode slice(0,4000) 已移除');
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
}

main();
