// 测试辅助：从 electron/main.js 里抽出算法指纹扫描器（CRYPTO_FP + scanCryptoFingerprints），
// 在 Node 里独立运行。这样单测不依赖 Electron 运行时，也不需要在源码里重复一份实现
// （改 main.js 后测试自动跟随，避免"测试与实现漂移"）。
//
// 注意：扫描器代码现在 require('./crypto-tables')，而抽取体用 new Function 执行，
// 必须把 require 传进去（指向 electron/ 目录，使相对路径 './crypto-tables' 正确解析）。
const fs = require('fs'), p = require('path'), path = require('path');
const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const start = mainSrc.indexOf('const CRYPTO_FP');
const end = mainSrc.indexOf("ipcMain.handle('scan-crypto-fingerprints'");
if (start < 0 || end < 0) throw new Error('未能在 electron/main.js 中定位扫描器代码块');
const body = mainSrc.slice(start, end);
const electronDir = p.join(__dirname, '..', 'electron');
// 模拟 CommonJS require：把相对模块解析到 electron/ 目录
const localRequire = (name) => {
  if (name === './crypto-tables') return require(p.join(electronDir, 'crypto-tables.js'));
  if (name === './crypto-detect') return require(p.join(electronDir, 'crypto-detect.js'));
  throw new Error('scanner_loader 未支持的 require: ' + name);
};
const mod = { exports: {} };
const cryptoDetect = require(p.join(electronDir, 'crypto-detect.js'));
const hashHint = require(p.join(electronDir, 'hash-hint.js'));
// eslint-disable-next-line no-new-func
new Function('fs', 'path', 'module', 'exports', 'require',
  'detectMd5RoundConstants', 'detectLaneBijectionTables',
  'assessHashTarget', 'buildMd5Note', 'parseImageMap',
  body + '\nmodule.exports = { scanCryptoFingerprints, CRYPTO_FP, classifySbox, gf2AffineFit, analyzeCustomBlockConstants, inferCipherStructure, findCiphertextCandidate };'
)(fs, p, mod, mod.exports, localRequire,
  cryptoDetect.detectMd5RoundConstants, cryptoDetect.detectLaneBijectionTables,
  hashHint.assessHashTarget, hashHint.buildMd5Note,
  require(p.join(electronDir, 'binary-map.js')).parseImageMap);
module.exports = mod.exports;
