// 批量解题的持久化语义：只有**已解出**的题才写入 skipChallenges。
//
// 历史缺陷：旧实现无条件把每道尝试过的题（含失败）写入 config.platform.skipChallenges，
// 导致批量跑失败的题（CrackMe 系列 8 道等）永久进入清单、后续再也不会重试，
// 且与"人工已解出"的语义混在一起，无法区分"解过"与"没解成"。
//
// 本测试锁住三条：
//   1. 源码里持久化分支必须带 r.ok 条件
//   2. 未解出分支必须明确不写入，并输出可重试提示
//   3. 定向模式（noPersistSkip）仍然不写
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, n, d) => {
  if (c) { pass++; console.log('  OK   ' + n); }
  else { fail++; console.log('  FAIL ' + n + (d ? '  → ' + d : '')); }
};

const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

console.log('\n[1] 持久化分支必须带"已解出"条件');
ok(/else if \(r\.ok && name && name !== '\(unknown\)'\)/.test(src),
  "写入分支为 r.ok && name", '未找到 r.ok 条件');

console.log('\n[2] 未解出时不写入，提示可重试');
ok(/else if \(!r\.ok && name && name !== '\(unknown\)'\)/.test(src),
  '存在未解出分支');
ok(/未解出（.*），不写入清单，下次可重试/.test(src),
  '未解出时输出"不写入清单，下次可重试"');

console.log('\n[3] 定向模式仍不写');
ok(/if \(opts\.noPersistSkip\)/.test(src), '保留 noPersistSkip 分支');

console.log('\n[4] 配置加载提示语义已更正');
ok(/已处理清单（/.test(src), '加载日志改为「已处理清单」');
ok(!/'\[平台\] 跳过清单: '/.test(src), '不再输出旧的「跳过清单」措辞');

console.log('\n[5] 默认配置为空');
const mainJs = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
ok(/skipChallenges:\s*\[\]/.test(mainJs), 'DEFAULT_CONFIG 的 skipChallenges 为空数组');

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
