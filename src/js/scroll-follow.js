// 滚动跟随（stick-to-bottom）——聊天/日志面板共用。
//
// 背景（真实 bug）：旧实现每个流式 token 都执行 `el.scrollTop = el.scrollHeight`，
// 用户向上滚一次，下一个 token 立刻把视口拽回底部 → "一直跳、根本不能向上滑"。
//
// 正确语义：
//   · 用户仍在底部附近（≤48px）→ 自动跟随新内容；
//   · 用户主动上滑（wheel 向上 / touchmove 离开底部 / PageUp·Home）→ 脱离跟随，
//     停在原处读历史；新内容不再改变视口；
//   · 用户滚回底部，或点"回到底部"按钮 → 恢复跟随。
//
// 独立成模块的原因：这段逻辑与 DOM 强耦合、又是高频路径，放在 6000 行的 app.js 里
// 无法单测。抽出来后可用假元素直接验证"上滑后不被拽回"。
(function (global) {
  'use strict';

  const STICK_PX = 48;              // 距底部多少像素内视为"贴底"
  const stateMap = new WeakMap();   // el -> { stick, raf, listeners }

  function getState(el) {
    let s = stateMap.get(el);
    if (!s) {
      s = { stick: true, raf: 0, onStateChange: null };
      stateMap.set(el, s);
    }
    return s;
  }

  function isNearBottom(el) {
    return el.scrollHeight - el.scrollTop - el.clientHeight <= STICK_PX;
  }

  function setStick(el, stick) {
    const s = getState(el);
    if (s.stick === stick) return;
    s.stick = stick;
    if (s.onStateChange) s.onStateChange(el, stick);
  }

  // 追加新内容后调用：仅在"贴底"时跟随。
  // 用 rAF 合并同一帧内的多次请求——流式 token 很密，逐 token 设置 scrollTop
  // 会强制同步重排，长回答会明显掉帧。
  function follow(el) {
    if (!el) return;
    const s = getState(el);
    if (!s.stick) return;
    if (typeof requestAnimationFrame !== 'function') {
      // 无 rAF 环境（单测/旧环境）直接同步执行
      el.scrollTop = el.scrollHeight;
      return;
    }
    if (s.raf) return;
    s.raf = requestAnimationFrame(function () {
      s.raf = 0;
      if (s.stick) el.scrollTop = el.scrollHeight;
    });
  }

  // 用户主动发消息 / 点击"回到底部"：强制跟随。
  function toBottom(el) {
    if (!el) return;
    setStick(el, true);
    el.scrollTop = el.scrollHeight;
  }

  // 绑定事件（幂等：同一元素重复调用不会重复绑定）
  function attach(el, onStateChange) {
    if (!el || el.__scrollFollowAttached) return;
    el.__scrollFollowAttached = true;
    const s = getState(el);
    if (typeof onStateChange === 'function') s.onStateChange = onStateChange;

    // 主动上滑 = 立刻脱离，不等 scroll 事件（否则下一帧又会把视口拽回底部）
    if (el.addEventListener) {
      el.addEventListener('wheel', function (e) {
        if (e && e.deltaY < 0) setStick(el, false);
      }, { passive: true });

      el.addEventListener('touchmove', function () {
        if (!isNearBottom(el)) setStick(el, false);
      }, { passive: true });

      el.addEventListener('keydown', function (e) {
        if (e && (e.key === 'PageUp' || e.key === 'ArrowUp' || e.key === 'Home')) {
          setStick(el, false);
        }
      });

      // 滚回底部 → 恢复跟随；滚动过程中同步 UI 状态
      el.addEventListener('scroll', function () {
        if (isNearBottom(el)) setStick(el, true);
        else setStick(el, false);
      }, { passive: true });
    }
  }

  const api = { attach: attach, follow: follow, toBottom: toBottom, isNearBottom: isNearBottom, STICK_PX: STICK_PX };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  global.ScrollFollow = api;
})(typeof window !== 'undefined' ? window : globalThis);
