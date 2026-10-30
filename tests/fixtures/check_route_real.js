const fs = require('fs');
const path = require('path');
const { detectCapabilities, decideRoute } = require('../../electron/file-capability.js');

const p = 'E:\\ctf\\pratice\\ai\\[_CTF2019]yy\\attachment_x\\homebrewEventLoop\\server.py';
if (!fs.existsSync(p)) { console.log('SKIP: 文件不存在'); process.exit(0); }
const buf = fs.readFileSync(p);
const ext = path.extname(p).toLowerCase();
const cap = detectCapabilities(buf, ext);
const route = decideRoute({ fileType: 'SOURCE', ext, capabilities: cap });
const routeNoHint = decideRoute({ ext, capabilities: cap });

console.log('size      =', buf.length);
console.log('ext       =', ext);
console.log('textual   =', cap.textual);
console.log('firmware  =', cap.firmware);
console.log('route (有提示) =', route);
console.log('route (无提示) =', routeNoHint);
console.log('BEFORE_FIX route(无提示) 会是 =', cap.textual ? 'local-probe（旧行为：不看 textual）' : 'N/A');
console.log('RESULT    =', (route === 'source' && routeNoHint === 'source') ? 'PASS' : 'FAIL');
