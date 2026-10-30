// 长流程入口护栏回归
//
// 实测问题：
//   · btn-auto-analyze 直接绑 autoAnalyze，没有重入锁 → 连点两次并行跑两条求解流程，
//     同时写 findings/mcpCache/lastAiText，findings.json 会回退。
//   · 没有 catch → 流程中途抛错变成 unhandled rejection，UI 只表现成"点了没反应"。
//
// 难点：autoAnalyze 会被阶段接力**有意重入**（runStageHandoff → analyzeFile → autoAnalyze），
// 所以不能简单上一把布尔锁，否则合法的接力链被挡死。
// 判据：_inStageHandoff 为真时放行，否则拦截。
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function fnBody(name) {
  let i = appSrc.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('未找到 function ' + name);
  // async 前缀在 "function" 之前；丢掉会得到 "await is only valid in async functions"
  if (appSrc.slice(Math.max(0, i - 6), i) === 'async ') i -= 6;
  // 定位参数列表右括号（默认参数里的 {} 不算函数体）
  let p = appSrc.indexOf('(', i), pDepth = 0, j = -1;
  for (let k = p; k < appSrc.length; k++) {
    if (appSrc[k] === '(') pDepth++;
    else if (appSrc[k] === ')') { pDepth--; if (pDepth === 0) { j = appSrc.indexOf('{', k); break; } }
  }
  if (j < 0) throw new Error('参数列表未闭合: ' + name);

  // 简化策略：只跟踪字符串/模板串/正则，不跟踪 $ 插值之外的嵌套。
  // 关键点：模板串里的 ${...} 要整体跳过（`[safeEntry] ${name}` 里的 } 不能计入配平）。
  let depth = 0, inS = null, esc = false;
  for (let k = j; k < appSrc.length; k++) {
    const c = appSrc[k];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (inS === '`' && c === '$' && appSrc[k + 1] === '{') {
        // 跳过整个 ${...}（内部大括号平衡）
        let d = 0;
        for (let m = k + 1; m < appSrc.length; m++) {
          if (appSrc[m] === '{') d++;
          else if (appSrc[m] === '}') { d--; if (d === 0) { k = m; break; } }
        }
        continue;
      }
      if (c === inS) inS = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return appSrc.slice(i, k + 1); }
  }
  throw new Error('函数 ' + name + ' 未闭合');
}

// 构造一个可执行的 safeEntry：注入最小的 addLog/addSystemMessage/state
function buildSafeEntry() {
  const logs = [];
  const sys = [];
  const state = { _inStageHandoff: false };
  const env = {
    state,
    addLog: (lvl, msg) => logs.push([lvl, msg]),
    addSystemMessage: (m) => sys.push(m),
    console: { log: () => {} },
    logs, sys,
  };
  const code = fnBody('safeEntry');
  // new Function 的函数体不会返回最后一句表达式的值，必须显式挂到全局对象上再取回。
  const holder = {};
  const wrapper = `
    const safeEntryRunning = Object.create(null);
    ${code}
    __holder.safeEntry = safeEntry;
    __holder.safeEntryRunning = safeEntryRunning;
  `;
  const fn = new Function('state', 'addLog', 'addSystemMessage', 'console', '__holder', wrapper);
  fn(env.state, env.addLog, env.addSystemMessage, env.console, holder);
  return { p: Promise.resolve(holder), env };
}

console.log('[1] 并发误触被拦截（同一流程不会并行跑两条）');
(async () => {
  {
    const { p, env } = buildSafeEntry();
    const { safeEntry } = await p;
    let runCount = 0;
    const slow = async () => { runCount++; await new Promise(r => setTimeout(r, 120)); return 'done'; };

    const [a, b] = await Promise.all([
      safeEntry('autoAnalyze', slow),
      safeEntry('autoAnalyze', slow),
    ]);
    ok(runCount === 1, '连点两次只跑了一条流程', 'runCount=' + runCount);
    ok(a === 'done', '第一次正常返回', String(a));
    ok(b === undefined, '第二次被拦住返回 undefined', String(b));
    ok(env.logs.some(([lvl, m]) => lvl === 'warning' && /还没结束/.test(m)), '拦住时给出明确 warning 日志',
      JSON.stringify(env.logs));
  }

  console.log('\n[2] 阶段接力必须放行（否则合法的多阶段链被挡死）');
  {
    const { p, env } = buildSafeEntry();
    const { safeEntry } = await p;
    let runCount = 0;
    const chain = async () => { runCount++; await new Promise(r => setTimeout(r, 100)); return 'stage'; };

    // 模拟接力：外层跑到一半时 _inStageHandoff = true，内部再调一次
    const outer = safeEntry('autoAnalyze', async () => {
      env.state._inStageHandoff = true;
      const inner = await safeEntry('autoAnalyze', chain);
      env.state._inStageHandoff = false;
      return inner;
    });
    const r = await outer;
    ok(runCount === 1, '接力重入没有被拦截（内层正常执行）', 'runCount=' + runCount);
    ok(r === 'stage', '内层结果正确返回', String(r));
    ok(!env.logs.some(([lvl, m]) => lvl === 'warning' && /还没结束/.test(m)), '接力路径不应出现拦截日志');
  }

  console.log('\n[3] 异常必须落日志，不能静默');
  {
    const { p, env } = buildSafeEntry();
    const { safeEntry } = await p;
    const boom = async () => { throw new Error('IPC 返回了非预期结构'); };
    const r = await safeEntry('runHook', boom);
    ok(r === null, '异常时返回 null 而不是把 rejection 抛给调用方', String(r));
    ok(env.logs.some(([lvl, m]) => lvl === 'error' && /执行失败/.test(m) && /IPC 返回了非预期结构/.test(m)),
      '错误写进日志且带原始信息', JSON.stringify(env.logs));
    ok(env.sys.some(m => /执行失败/.test(m)), '同时给出用户可见的提示消息');
  }

  console.log('\n[4] 异常后锁必须释放（否则一次失败后按钮永久失效）');
  {
    const { p, env } = buildSafeEntry();
    const { safeEntry, safeEntryRunning } = await p;
    await safeEntry('generateScript', async () => { throw new Error('x'); });
    ok(safeEntryRunning['generateScript'] === false, '失败后锁已释放', String(safeEntryRunning['generateScript']));
    // 再来一次应当能跑
    let ran = false;
    await safeEntry('generateScript', async () => { ran = true; });
    ok(ran === true, '失败后可以再次执行（不会被永久锁死）');
  }

  console.log('\n[5] 结构性断言：按钮都走 safeEntry，且不再直接绑长流程');
  {
    ok(/btn-auto-analyze'\)\.addEventListener\('click', \(\) => safeEntry\('autoAnalyze'/.test(appSrc),
      'autoAnalyze 按钮经 safeEntry 包裹');
    ok(/btn-run-hook'\)\.addEventListener\('click', \(\) => safeEntry\('runHook'/.test(appSrc),
      'runHook 按钮经 safeEntry 包裹');
    // 精确检查"真实绑定行"，排除注释里的反例说明（注释里会写旧写法做对照）
    const bindLines = appSrc.split('\n').filter(l => /addEventListener\('click'/.test(l) && !/^\s*\/\//.test(l));
    ok(!bindLines.some(l => /addEventListener\('click', (autoAnalyze|runHook|generateScript)\)/.test(l)),
      '按钮绑定行里没有裸传长流程函数', bindLines.filter(l => /autoAnalyze|runHook|generateScript/.test(l)).join(' | '));

    const body = fnBody('safeEntry');
    ok(/finally/.test(body), '锁在 finally 里释放');
    ok(/_inStageHandoff/.test(body), '识别接力重入');
    ok(!/state\.aiBusy\s*=/.test(body), '不碰 state.aiBusy（各流程内部已成对管理，覆盖会卡死按钮）');
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})();
