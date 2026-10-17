// AI 对话 UI 的静态一致性检查（不启动 Electron）
// 覆盖本次修复的两个真机问题：
//   1) 流式输出时每个 token 强制滚到底 → 用户无法上滑（改为 stick-to-bottom）
//   2) 长任务期间看不到工具执行进度 → 加 tool-steps 步骤条
const fs = require('fs'), p = require('path');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

const appJs = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const html = fs.readFileSync(p.join(__dirname, '..', 'src', 'index.html'), 'utf8');
const css = fs.readFileSync(p.join(__dirname, '..', 'src', 'css', 'style.css'), 'utf8');
const mainJs = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const preloadJs = fs.readFileSync(p.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');

console.log('A) 滚动跳动修复：不得再逐 token 强制滚到底');
{
  // 流式回调里不允许直接写 scrollTop = scrollHeight
  const streamFn = appJs.slice(appJs.indexOf('window.electronAPI.onClaudeStreamChunk'), appJs.indexOf('window.electronAPI.onClaudeStreamChunk') + 900);
  ok(!/scrollTop\s*=\s*\w+\.scrollHeight/.test(streamFn), '流式回调内无强制滚动');
  ok(/followScroll|ScrollFollow\.follow/.test(streamFn), '流式回调改走 followScroll（贴底才跟随）');
  ok(/requestAnimationFrame/.test(streamFn), '流式渲染合并到每帧一次（防卡顿）');
  ok(/setupScrollFab/.test(appJs) && /btn-scroll-bottom/.test(appJs), '绑定了"回到底部"按钮');
  // 日志面板也必须绑定，否则 addLog 高频追加会拽回
  ok(/attachStickScroll\(logPanel\)/.test(appJs), '日志面板也绑定了贴底跟随');
}

console.log('\nB) stick-to-bottom 模块');
{
  const sf = p.join(__dirname, '..', 'src', 'js', 'scroll-follow.js');
  ok(fs.existsSync(sf), 'scroll-follow.js 存在');
  const src = fs.readFileSync(sf, 'utf8');
  ok(/STICK_PX\s*=\s*48/.test(src), '贴底阈值 48px');
  ok(/wheel/.test(src) && /setStick\(el, false\)/.test(src), '上滑（wheel）即脱离跟随');
  ok(/PageUp/.test(src), 'PageUp/Home 也脱离');
  ok(/isNearBottom/.test(src), '提供 isNearBottom 判据');
  ok(/toBottom/.test(src), '提供强制回底 API');
}

console.log('\nC) HTML/CSS 接线');
{
  ok(/<script src="js\/scroll-follow\.js"[^>]*defer/.test(html), 'scroll-follow.js 已引入且 defer');
  ok(/<script src="js\/app\.js"[^>]*defer/.test(html), 'app.js 使用 defer（不阻塞解析）');
  ok(/btn-scroll-bottom/.test(html), '回到底部按钮存在于 HTML');
  ok(/\.scroll-to-bottom\.visible/.test(css), '按钮显示态样式存在');
  ok(/\.tool-steps/.test(css) && /\.tool-step-running/.test(css)
     && /\.tool-step-done/.test(css) && /\.tool-step-error/.test(css), '工具步骤条四类样式齐全');
}

console.log('\nD) 工具进度事件链路');
{
  ok(/claude-tool-event/.test(mainJs), '主进程发送 claude-tool-event');
  ok(/onClaudeToolEvent/.test(preloadJs), 'preload 暴露 onClaudeToolEvent');
  ok(/setupToolEventListener/.test(appJs), '渲染层注册工具事件监听');
  ok(/function toolLabel/.test(mainJs), '主进程有 toolLabel（人话标签）');
  ok(/phase === 'start'/.test(appJs) && /phase === 'done'/.test(appJs) && /phase === 'error'/.test(appJs),
     '三种 phase 都处理');
  // 工具名覆盖度抽查
  for (const t of ['scan_crypto', 'run_python', 'ida_decompile', 'extract_payload', 'gen_block_cipher_solver']) {
    ok(new RegExp(`case '${t}'`).test(mainJs), `toolLabel 覆盖 ${t}`);
  }
}

console.log('\nE) 字体本地化（离线/内网不得卡启动）');
{
  ok(!/cdnjs\.cloudflare\.com/.test(html), 'HTML 不再引用 cdnjs');
  ok(/vendor\/fontawesome\/css\/all\.min\.css/.test(html), '改为本地 vendor 字体库');
  const fa = p.join(__dirname, '..', 'src', 'vendor', 'fontawesome', 'css', 'all.min.css');
  ok(fs.existsSync(fa), '本地字体 CSS 存在');
  ok(!/font-src https:/.test(html), 'CSP 不再放行外部字体域');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
