// 从 app.js 抽取失败归因逻辑（Phase 3），Node 内独立测试
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
// attributeFailure 依赖前面定义的 looksLikeMachineCode / findDecodedLayer，
// 抽取时必须一并带上，否则 new Function 作用域里它们是未定义标识符。
const start = src.indexOf('function looksLikeMachineCode(');
const end = src.indexOf('// Phase 3.3：把"已排除的路"');
if (start < 0 || end < 0) throw new Error('未能在 app.js 中定位归因代码块');
const body = src.slice(start, end);
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports = { attributeFailure, looksLikeMachineCode, findDecodedLayer };')(mod, mod.exports);
module.exports = mod.exports;
