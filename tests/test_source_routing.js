// 源码题路由回归
//
// 实测缺陷（homebrewEventLoop 的 server.py，2026-10-30）：
//   2322 字节的 Python2 源码被 detect-file-type 判成 UNKNOWN
//   → 分诊给出 local-probe
//   → 走 analyzeBIN（Kali 固件预检：22 端口超时 → magic/熵块采集）
//   → 白等 2 分钟，且方向完全错（协议交互题被当固件题）
//
// 三个根因，本测试逐个锁住：
//   ① detect-file-type 没有源码扩展名分支（.py/.sh/.c/... → UNKNOWN）
//   ② decideRoute 不看 textual 能力（纯文本落到 local-probe）
//   ③ 渲染层没有 source 路由（只能进 analyzeBIN）
//
// 外加一条纪律：
//   ④ 契约没有密文时，不能报"契约无命中"（那是"本地无密文"，不是解法错）
const fs = require('fs');
const os = require('os');
const path = require('path');

const { detectCapabilities, decideRoute } = require('../electron/file-capability.js');

const ROOT = path.join(__dirname, '..');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const PY_SRC = Buffer.from(
  '#!/usr/bin/python\n# -*- coding: utf-8 -*-\n' +
  'import socket, hashlib\n' +
  'def flag():\n    return "flag{[0-9a-zA-Z_]+}"\n' +
  'session = {}\n' +
  'def main():\n    print("hello")\n' +
  'if __name__ == "__main__":\n    main()\n', 'utf8');

console.log('[1] detect-file-type：源码扩展名必须被识别（不是 UNKNOWN）');
{
  // 主进程 SOURCE_LANG / SOURCE_EXTS 存在
  ok(/const SOURCE_LANG = \{/.test(mainSrc), '定义了 SOURCE_LANG 表');
  ok(/const SOURCE_EXTS = Object\.keys\(SOURCE_LANG\)/.test(mainSrc), 'SOURCE_EXTS 由 SOURCE_LANG 派生');

  const mustHave = ['.py', '.sh', '.c', '.cpp', '.go', '.rs', '.rb', '.php', '.java', '.lua'];
  const missing = mustHave.filter(e => !new RegExp(`'\\${e}':`).test(mainSrc));
  ok(missing.length === 0, '常见源码扩展名都在表里', missing.join(','));

  // 分支存在且产出 SOURCE
  ok(/SOURCE_EXTS\.includes\(ext\)/.test(mainSrc), 'detect-file-type 有 SOURCE_EXTS 分支');
  ok(/fileType = 'SOURCE'/.test(mainSrc), '产出 fileType=SOURCE');
  // 源码分支必须在 detect-file-type 的 else-if 链内（在 handler 的 return 之前）
  const iHandler = mainSrc.indexOf("ipcMain.handle('detect-file-type'");
  const iSource = mainSrc.indexOf("fileType = 'SOURCE'");
  const iHandleEnd = mainSrc.indexOf('// ============ 加密算法指纹扫描器', iHandler);
  ok(iHandler > 0 && iSource > iHandler && iSource < iHandleEnd,
    'SOURCE 分支位于 detect-file-type handler 内（在 handler 结束之前）',
    `handler=${iHandler} source=${iSource} end=${iHandleEnd}`);
}

console.log('\n[2] decideRoute：纯文本绝不落进 local-probe');
{
  const capText = detectCapabilities(PY_SRC, '.txt');
  ok(capText.textual === true, 'Python 源码被判为 textual');
  ok(decideRoute({ capabilities: capText, ext: '.txt' }) === 'source', '无扩展名提示的纯文本 → source',
    decideRoute({ capabilities: capText, ext: '.txt' }));

  const capPy = detectCapabilities(PY_SRC, '.py');
  ok(capPy.textual === true, '.py 被判为 textual');
  ok(decideRoute({ fileType: 'SOURCE', ext: '.py', capabilities: capPy }) === 'source', 'fileType=SOURCE → source');

  // 回归：真二进制不能被 textual 抢走
  const pe = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(200, 0x41)]);
  ok(detectCapabilities(pe, '.exe').executable === true, 'PE 仍是 executable');
  ok(decideRoute({ capabilities: detectCapabilities(pe, '.exe'), ext: '.exe' }) === 'static',
    'PE 路由仍为 static（executable 优先于 textual）');

  const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(200, 0x41)]);
  ok(decideRoute({ capabilities: detectCapabilities(elf, '.elf'), ext: '.elf' }) === 'static',
    'ELF 路由仍为 static');

  // 容器/流量不受影响
  const zipBuf = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  ok(decideRoute({ capabilities: detectCapabilities(zipBuf, '.zip'), ext: '.zip' }) === 'extract',
    'ZIP 仍走 extract');
  const pcap = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]);
  ok(decideRoute({ capabilities: detectCapabilities(pcap, '.pcap'), ext: '.pcap' }) === 'traffic',
    'pcap 仍走 traffic');

  // 真·未知二进制（不可打印）仍应走 local-probe
  const bin = Buffer.from(Array.from({ length: 512 }, (_, i) => (i * 37 + 200) & 0xff));
  const capBin = detectCapabilities(bin, '');
  ok(capBin.textual === false, '高熵二进制不是 textual');
  ok(decideRoute({ capabilities: capBin, ext: '' }) === 'local-probe', '未知二进制仍走 local-probe');
}

console.log('\n[3] 渲染层：source 路由存在且不进固件流程');
{
  ok(/capRoute === 'source'/.test(appSrc), '分诊消费 source 路由');
  ok(/analyzeSourceText/.test(appSrc), '有 analyzeSourceText 实现');
  ok(/case 'SOURCE':/.test(appSrc), 'switch 里有 SOURCE case');
  ok(/SOURCE_LANG_HINT/.test(appSrc), '渲染层有语言名表');

  // 源码提示词必须点明"不适用二进制/固件套路"
  const iFn = appSrc.indexOf('async function analyzeSourceText');
  ok(iFn > 0, '函数已定义');
  const body = appSrc.slice(iFn, iFn + 14000);
  ok(/不是二进制、不是固件/.test(body), '提示词明确"不是二进制/固件"');
  ok(/binwalk/.test(body), '提示词示例排除 binwalk（说明不适用）');
  ok(/Unicorn/.test(body), '提示词示例排除 Unicorn 仿真');
  ok(/文件里根本不存在答案|本地无密文|远端/.test(body), '提示词说明 flag 可能在远端、本地不存在');
}

console.log('\n[4] 纪律：契约无密文时不得报"契约无命中"');
{
  ok(/function contractsAllEmpty/.test(appSrc), '有 contractsAllEmpty 判定');
  ok(/本地无密文/.test(appSrc), '存在"本地无密文"文案');
  // 判定逻辑本体：把实现抽出来真跑一遍（避免只靠字符串匹配）
  const iFn = appSrc.indexOf('function contractsAllEmpty');
  ok(iFn > 0, '函数体可定位');
  // 从函数头切到下一个顶层函数声明（含注释行）之前，取到完整闭合的 }
  const tail = appSrc.slice(iFn);
  const endMark = tail.indexOf('\n// 验证闭环：解析 [VERIFY]');
  const impl = endMark > 0 ? tail.slice(0, endMark) : tail.slice(0, 1200);
  ok(/\}\s*$/.test(impl.trim()), '抽出的实现以 } 闭合', JSON.stringify(impl.slice(-40)));
  const f = new Function(impl + '\nreturn contractsAllEmpty;')();
  ok(f([]) === false, '空列表不算"全空"（无契约时不触发该文案）');
  ok(f([{ ciphertext: '' }]) === true, '单个空 ciphertext → true');
  ok(f([{ ciphertext: '' }, { ciphertext: '  ' }]) === true, '多个空白 ciphertext → true');
  ok(f([{ ciphertext: 'ab12' }]) === false, '有密文 → false');
  ok(f([{ ciphertext: '' }, { ciphertext: 'ab12' }]) === false, '部分有密文 → false');
}

console.log('\n[5] 回归：既有路由语义未被破坏');
{
  const js = Buffer.from('function x(){console.log(1)}', 'utf8');
  ok(decideRoute({ fileType: 'JS', ext: '.js', capabilities: detectCapabilities(js, '.js') }) === 'web',
    'JS 仍走 web');
  const html = Buffer.from('<html><body>hi</body></html>', 'utf8');
  ok(decideRoute({ fileType: 'HTML', ext: '.html', capabilities: detectCapabilities(html, '.html') }) === 'web',
    'HTML 仍走 web');
  const http = Buffer.from('GET /a HTTP/1.1\r\nHost: x\r\n\r\n', 'utf8');
  ok(decideRoute({ capabilities: detectCapabilities(http, '.txt'), ext: '.txt' }) === 'source',
    '含 HTTP 的纯文本 → source（不是 burp；burp 只对 pcap 生效）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
