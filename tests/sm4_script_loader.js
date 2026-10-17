// 从 electron/main.js 抽取 SM4 变体脚本生成相关函数，供 Node 测试使用
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const start = src.indexOf('function buildSM4VariantDecryptScript(');
const end = src.indexOf("ipcMain.handle('scan-crypto-fingerprints'");
if (start < 0 || end < 0) throw new Error('未能定位 SM4 脚本生成代码块');
// 只取 buildSM4VariantDecryptScript（不含后面依赖 buf 的函数）
const fnEnd = src.indexOf('\n// 在分析结果里附加"可直接跑的解密脚本"', start);
if (fnEnd < 0) throw new Error('未能定位 buildSM4VariantDecryptScript 结束位置');
const body = src.slice(start, fnEnd);
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports = { buildSM4VariantDecryptScript };')(mod, mod.exports);
module.exports = mod.exports;
