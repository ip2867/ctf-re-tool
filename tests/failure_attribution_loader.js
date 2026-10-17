// 从 app.js 抽取失败归因逻辑（Phase 3），Node 内独立测试
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const start = src.indexOf('function attributeFailure(');
const end = src.indexOf('// Phase 3.3：把"已排除的路"');
if (start < 0 || end < 0) throw new Error('未能在 app.js 中定位 attributeFailure 代码块');
const body = src.slice(start, end);
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports = { attributeFailure };')(mod, mod.exports);
module.exports = mod.exports;
