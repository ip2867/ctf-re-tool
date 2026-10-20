// Kali 远程预检单测：不可达时必须在发任何远程命令之前就跳过。
//
// 实测：Kali 不可达时 file/binwalk/strings 各 60s → 白等 3 分钟。
// 缓存 120s；只测"远程预检阶段"，localFirmwareProbe（spawn Python）不计入。
const fs = require('fs');
const path = require('path');
const {
  decideKaliPreflight, decideKaliRemotePlan, DEFAULT_TTL_MS,
} = require('../electron/kali-preflight.js');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8').replace(/\r\n/g, '\n');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] 不可达 → skip + 固定日志');
{
  const r = decideKaliPreflight({ reachable: false, host: '192.168.230.129', port: 22 });
  ok(r.action === 'skip', `action=skip（${r.action}）`);
  ok(r.log === '[Kali] 22/TIMEOUT → 跳过远程命令，使用本地兜底', `固定日志（${r.log}）`);
}

console.log('\n[2] 可达 → remote');
{
  const r = decideKaliPreflight({ reachable: true, host: '10.0.0.5', port: 22 });
  ok(r.action === 'remote', `action=remote（${r.action}）`);
}

console.log('\n[3] 缓存 TTL');
{
  const ttl = DEFAULT_TTL_MS;
  ok(ttl === 120000, '默认 TTL 120s');
  const fresh = decideKaliPreflight({ reachable: true, cacheAgeMs: 1000, ttlMs: 120000 });
  ok(fresh.action === 'remote' && fresh.probe === false, '缓存新鲜（1s）→ 不探活');
  const stale = decideKaliPreflight({ reachable: true, cacheAgeMs: 130000, ttlMs: 120000 });
  ok(stale.action === 'remote' && stale.probe === true, '缓存过期（130s）→ 重新探活');
  const staleDown = decideKaliPreflight({ reachable: false, cacheAgeMs: 130000, ttlMs: 120000 });
  ok(staleDown.action === 'skip' && staleDown.probe === true, '过期且不可达 → skip 且探活');
}

console.log('\n[4] decideKaliRemotePlan');
{
  const down = decideKaliRemotePlan({ reachable: false });
  ok(down.commands.length === 0, '不可达时一条远程命令都不发');
  ok(/不能解包/.test(down.note), '能力边界写明"不能解包"');
  const up = decideKaliRemotePlan({ reachable: true });
  ok(JSON.stringify(up.commands) === JSON.stringify(['file', 'binwalk', 'strings']), `可达时 file→binwalk→strings（${up.commands.join('→')}）`);
  const zip = decideKaliRemotePlan({ reachable: true, capabilities: { archive: true } });
  ok(!zip.commands.includes('binwalk'), '已知容器不必 binwalk');
}

console.log('\n[5] 源码：analyzeBIN 在第一次 execKaliCommand 之前预检');
{
  const fn = appSrc.slice(appSrc.indexOf('async function analyzeBIN()'));
  const body = fn.slice(0, fn.indexOf('\n}\n\n') + 3);
  const preIdx = body.indexOf('kaliPreflight()');
  const firstExec = body.indexOf('execKaliCommand(');
  ok(preIdx >= 0, '调用 kaliPreflight');
  ok(firstExec > preIdx, `预检在第一次 execKaliCommand 之前（${preIdx} < ${firstExec}）`);
  ok(/pre\.action === 'remote'/.test(body), '只有 remote 才发远程命令');
  // localFirmwareProbe 在预检之后（不属预检计时区间）
  const probeIdx = body.indexOf('localFirmwareProbe(');
  ok(probeIdx > preIdx, 'localFirmwareProbe 在预检之后');
  ok(/const pre = await kaliPreflight\(\)/.test(body), '预检结果保存在 pre');
  ok(/\[Kali\] \$\{port\}\/TIMEOUT → 跳过远程命令，使用本地兜底/.test(appSrc) || /\[Kali\] \$\{port\}\/TIMEOUT → 跳过远程命令，使用本地兜底/.test(appSrc),
    '渲染层也有固定日志文案（无配置分支）');
  ok(/kaliPreflightDecide/.test(preloadSrc), 'preload 暴露 kaliPreflightDecide');
  ok(/ipcMain\.handle\('kali-preflight-decide'/.test(mainSrc), '主进程有 kali-preflight-decide');
  ok(/decideKaliPreflight\(/.test(mainSrc), 'main.js 调用纯模块决策');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
