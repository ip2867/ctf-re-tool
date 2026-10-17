// 测试辅助：从 electron/main.js 里抽出算法指纹扫描器（CRYPTO_FP + scanCryptoFingerprints），
// 在 Node 里独立运行。这样单测不依赖 Electron 运行时，也不需要在源码里重复一份实现
// （改 main.js 后测试自动跟随，避免"测试与实现漂移"）。
const fs = require('fs'), p = require('path');
const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const start = mainSrc.indexOf('const CRYPTO_FP');
const end = mainSrc.indexOf("ipcMain.handle('scan-crypto-fingerprints'");
if (start < 0 || end < 0) throw new Error('未能在 electron/main.js 中定位扫描器代码块');
const body = mainSrc.slice(start, end);
const mod = { exports: {} };
// eslint-disable-next-line no-new-func
new Function('fs', 'path', 'module', 'exports', body + '\nmodule.exports = { scanCryptoFingerprints, CRYPTO_FP };')(fs, p, mod, mod.exports);
module.exports = mod.exports;
