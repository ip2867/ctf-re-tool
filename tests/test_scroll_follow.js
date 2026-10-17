// 滚动跟随单测：直接对 scroll-follow.js 用假 DOM 元素验证行为。
// 核心回归：用户上滑后，后续"流式追加"不得把视口拽回底部（这是真机 bug 的根因）。
const SF = require('../src/js/scroll-follow.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

// 极简假元素：模拟滚动容器
function makeEl(height, viewport) {
  const listeners = {};
  const el = {
    scrollTop: 0,
    scrollHeight: height,
    clientHeight: viewport,
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    emit(type, evt) { (listeners[type] || []).forEach(f => f(evt || {})); },
    grow(px) { this.scrollHeight += px; },
  };
  return el;
}

console.log('A) 贴底时自动跟随');
{
  const el = makeEl(1000, 400);           // 内容 1000，视口 400 → 底部 = 600
  el.scrollTop = 600;
  ok(SF.isNearBottom(el), '在底部时 isNearBottom=true');
  el.grow(300);
  SF.follow(el);
  ok(el.scrollTop === 1300, `跟随到底部（scrollTop=${el.scrollTop}）`);
}

console.log('\nB) 上滑后不再被拽回底部（真机 bug 回归）');
{
  const el = makeEl(1000, 400);
  el.scrollTop = 600;
  SF.attach(el);
  el.emit('wheel', { deltaY: -120 });      // 用户向上滚
  el.scrollTop = 300;                      // 视口停在历史位置
  for (let i = 0; i < 20; i++) {           // 模拟 20 个流式 token 持续追加
    el.grow(50);
    SF.follow(el);
  }
  ok(el.scrollTop === 300, `20 次追加后 scrollTop 仍为 300（实际 ${el.scrollTop}）`);
  ok(!SF.isNearBottom(el), '确实处于"阅读历史"状态');
}

console.log('\nC) 滚回底部后恢复跟随');
{
  const el = makeEl(1000, 400);
  el.scrollTop = 600;
  SF.attach(el);
  el.emit('wheel', { deltaY: -120 });
  el.scrollTop = 200;
  el.emit('scroll');                       // 仍在历史 → 保持脱离
  ok(!SF.isNearBottom(el), '滚到 200 仍脱离');
  el.scrollTop = 600;                      // 用户自己滚回底部
  el.emit('scroll');
  ok(SF.isNearBottom(el), '滚回底部');
  el.grow(100);
  SF.follow(el);
  ok(el.scrollTop === 1100, `恢复跟随（scrollTop=${el.scrollTop}）`);
}

console.log('\nD) PageUp / Home 脱离；toBottom 强制恢复');
{
  const el = makeEl(1000, 400);
  el.scrollTop = 600;
  SF.attach(el);
  el.emit('keydown', { key: 'PageUp' });
  el.grow(100);
  SF.follow(el);
  ok(el.scrollTop === 600, 'PageUp 后追加不跟随');
  SF.toBottom(el);
  ok(el.scrollTop === 1100, `toBottom 强制到底（${el.scrollTop}）`);
  el.grow(100);
  SF.follow(el);
  ok(el.scrollTop === 1200, 'toBottom 后恢复跟随');
}

console.log('\nE) 边界与幂等');
{
  const el = makeEl(1000, 400);
  SF.attach(el);
  SF.attach(el);                            // 重复绑定不应出错/重复触发
  el.scrollTop = 600;
  el.emit('wheel', { deltaY: -1 });
  el.emit('wheel', { deltaY: -1 });
  el.grow(100); SF.follow(el);
  ok(el.scrollTop === 600, '重复 attach 后行为正常');
  ok(SF.STICK_PX === 48, '贴底阈值 48px');

  // 空元素不崩
  SF.follow(null);
  SF.toBottom(null);
  SF.attach(null);
  ok(true, 'null 输入不崩');

  // 内容不足一屏（scrollHeight < clientHeight）→ 视为贴底
  const short = makeEl(100, 400);
  ok(SF.isNearBottom(short), '内容不足一屏时视为贴底');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
