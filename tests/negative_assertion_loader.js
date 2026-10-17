// 从 src/js/app.js 抽取"负面断言反证"逻辑，在 Node 里独立运行（不依赖 renderer/Electron）。
// 与 tests/scanner_loader.js 同思路：改 app.js 后测试自动跟随，避免测试与实现漂移。
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const start = src.indexOf('function buildNegativeAssertionRules()');
const end = src.indexOf('// 执行反证：把证据落盘');
if (start < 0 || end < 0) throw new Error('未能在 app.js 中定位负面断言反证代码块');
const body = src.slice(start, end);
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports = { buildNegativeAssertionRules, checkNegativeAssertions };')(mod, mod.exports);
module.exports = mod.exports;
