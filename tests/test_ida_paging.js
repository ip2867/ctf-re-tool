// 分页契约单测：list_funcs / list_globals 默认 count=100，只取一页会得到残缺表。
// 纯模块 electron/ida-paging.js 可在无 Electron 的 Node 下直接 require。
const fs = require('fs');
const p = require('path');
const { normalizePages, shouldContinue, callPaged } = require('../electron/ida-paging.js');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

async function main() {
  console.log('[1] normalizePages 识别 [{data,next_offset}] 并保留游标');
  {
    const pages = normalizePages([{ data: [{ name: 'a' }], next_offset: 100 }]);
    ok(pages.length === 1, `1 页（实际 ${pages.length}）`);
    ok(pages[0].next_offset === 100, 'next_offset 保留为 100');
    ok(pages[0].data.length === 1, 'data 保留');
  }

  console.log('\n[2] 单页信封 / 裸数组 / null');
  {
    const one = normalizePages({ data: [1, 2], next_offset: null });
    ok(one.length === 1 && one[0].data.length === 2, '单对象信封');
    const bare = normalizePages([{ name: 'x' }, { name: 'y' }]);
    ok(bare.length === 1 && bare[0].data.length === 2, '裸数组视为一页');
    ok(normalizePages(null).length === 0, 'null 返回空');
  }

  console.log('\n[3] shouldContinue');
  {
    ok(shouldContinue(100) === true, '100 继续');
    ok(shouldContinue(null) === false, 'null 停止');
    ok(shouldContinue(undefined) === false, 'undefined 停止');
    ok(shouldContinue('200') === true, '字符串数字继续');
    ok(shouldContinue(0) === false, '0 停止');
    ok(shouldContinue('null') === false, "'null' 停止");
  }

  console.log('\n[4] 桩数据 3 页各 100 条、next_offset 依次 100/200/null');
  {
    const calls = [];
    const mk = (base) => Array.from({ length: 100 }, (_, i) => ({ name: 'sub_' + (base + i) }));
    const responses = [
      { data: mk(0), next_offset: 100 },
      { data: mk(100), next_offset: 200 },
      { data: mk(200), next_offset: null },
    ];
    const logs = [];
    const r = await callPaged(async (queries) => {
      calls.push(queries);
      return responses[calls.length - 1];
    }, {}, { tool: 'list_funcs', log: (t) => logs.push(t) });
    ok(calls.length === 3, `调用 3 次（实际 ${calls.length}）`);
    ok(r.items.length === 300, `合并 300 条（实际 ${r.items.length}）`);
    ok(calls[0].offset === 0 && calls[1].offset === 100 && calls[2].offset === 200,
      `offset 依次 0/100/200（实际 ${calls.map(c => c.offset).join('/')}）`);
    ok(calls.every(c => c.count === 500), 'count 一律 500（覆盖插件默认 100）');
    ok(logs.some(l => l.includes('分页 3 页/300 条')), `日志含「分页 3 页/300 条」（实际 ${logs.join(' | ')}）`);
  }

  console.log('\n[5] 单页 next_offset=null → 只调用 1 次');
  {
    let n = 0;
    const r = await callPaged(async () => { n++; return { data: [{ name: 'main' }], next_offset: null }; }, {}, { tool: 'list_funcs' });
    ok(n === 1, `只调用 1 次（实际 ${n}）`);
    ok(r.items.length === 1, '合并 1 条');
  }

  console.log('\n[6] 游标不前进时必须停止（防服务端回同一个 next_offset）');
  {
    let n = 0;
    await callPaged(async () => { n++; return { data: [{ name: 'x' }], next_offset: 1 }; }, {}, { tool: 't' });
    ok(n === 2, `最多 2 次（实际 ${n}）`);
  }

  console.log('\n[7] 渲染层采集处走分页版本');
  {
    const appSrc = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
    ok(/idaMcpCallPaged\('list_functions'/.test(appSrc), 'app.js 的 list_functions 采集走分页');
    ok(/idaMcpCallPaged\('list_globals'/.test(appSrc), 'app.js 的 list_globals 采集走分页');
    ok(!/idaMcpCall\('list_functions'/.test(appSrc), '无单页 list_functions 调用残留');
    ok(!/idaMcpCall\('list_globals'/.test(appSrc), '无单页 list_globals 调用残留');
    // native intel 的 list_funcs（SO 常上千函数）
    ok(/\['list_funcs', \{ paged: true \}\]/.test(appSrc), 'native intel 的 list_funcs 走分页');
  }

  console.log('\n[8] main.js 静态断言：采集处走 idaMcpCallPaged');
  {
    const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
    ok(/case 'ida_list_functions':\s*\r?\n\s*return await idaMcpCallPaged\('list_functions'/.test(mainSrc),
      'ida_list_functions 走 idaMcpCallPaged');
    ok(/case 'ida_list_globals':\s*\r?\n\s*return await idaMcpCallPaged\('list_globals'/.test(mainSrc),
      'ida_list_globals 走 idaMcpCallPaged');
    ok(/async function idaMcpCallPaged\(/.test(mainSrc), 'main.js 定义了 idaMcpCallPaged');
    ok(!/case 'ida_list_functions':\s*\r?\n\s*return await callIdaMcp\('list_functions'/.test(mainSrc),
      'ida_list_functions 不再直接走单页 idaMcpCall');
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
