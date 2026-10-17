// 从 app.js 抽取 buildPayloadExtractPython（载荷自动提取脚本生成，Phase 4），独立测试
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const start = src.indexOf('function buildPayloadExtractPython(');
const end = src.indexOf('// 尝试自动提取载荷');
if (start < 0 || end < 0) throw new Error('未能在 app.js 中定位 buildPayloadExtractPython');
const body = src.slice(start, end);
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports = { buildPayloadExtractPython };')(mod, mod.exports);
module.exports = mod.exports;
