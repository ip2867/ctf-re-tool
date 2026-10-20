'use strict';
// IDA MCP 列表工具的分页契约（纯函数，零 Electron 依赖）。
//
// 背景：ida-pro-mcp 的 list_funcs / list_globals 默认 count=100
// （api_core.py 里 `query.get("count", 100)`），返回信封是
//   [{ data: [...], next_offset: <offset+count 或 null> }]
// 只调一次等于只拿到前 100 条——实测函数表被截断后，函数选择/按地址读表/缺口计算
// 全部建立在残缺表上（CrackMe2 的 0x403a87-0x40b2b7 伪缺口即由此而来）。
//
// 因此：解信封时必须**先取出 next_offset**，再合并 data；不能用"拍平成数组"的
// unwrapIdaDataEnvelope（它保留数据、丢掉翻页游标）。

// 单条返回 → [{data, next_offset}]
// 支持：{data:[...], next_offset}、[{data,next_offset}, ...]、裸数组（视为末页）。
function normalizePages(resp) {
  const asPage = (v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const hasEnvelope = Array.isArray(v.data) || Object.prototype.hasOwnProperty.call(v, 'next_offset');
      if (hasEnvelope) {
        return {
          data: Array.isArray(v.data) ? v.data : [],
          next_offset: v.next_offset === undefined ? null : v.next_offset,
        };
      }
      return { data: [], next_offset: null };
    }
    if (Array.isArray(v)) return { data: v, next_offset: null };
    return { data: [], next_offset: null };
  };

  if (resp == null) return [];
  if (!Array.isArray(resp)) return [asPage(resp)];

  // 数组本身可能是"一页的数据"，也可能是"多页信封"。只有每个元素都是信封才算分页形态。
  const allEnvelopes = resp.length > 0 && resp.every(v =>
    v && typeof v === 'object' && !Array.isArray(v) &&
    (Array.isArray(v.data) || Object.prototype.hasOwnProperty.call(v, 'next_offset')));
  if (allEnvelopes) return resp.map(asPage);
  return [asPage(resp)];
}

function mergePages(pages) {
  const out = [];
  for (const p of (pages || [])) {
    const data = p && Array.isArray(p.data) ? p.data : [];
    for (const item of data) out.push(item);
  }
  return out;
}

// next_offset 为 null/undefined/''/'null' 或 0 时停止。
// 0 视为"没有下一页"：插件算法是 next_offset = offset + count（count>=1），
// 首轮 offset=0 → 首轮 next_offset>=1，因此 0 只在"实现方用 0 表示结束"时出现。
function shouldContinue(nextOffset) {
  if (nextOffset == null) return false;
  if (typeof nextOffset === 'string') {
    const s = nextOffset.trim();
    if (!s || s === 'null' || s === 'undefined' || s === 'None') return false;
    const n = Number(s);
    return Number.isFinite(n) && n > 0;
  }
  if (typeof nextOffset === 'number') return Number.isFinite(nextOffset) && nextOffset > 0;
  return false;
}

// 翻页循环。callOnce(queries) 必须返回**未解包**的信封（否则 next_offset 已丢失）。
// 返回 {pages, items, log}；log 字段与主进程日志同文，便于测试断言。
async function callPaged(callOnce, baseQuery, opts) {
  const o = opts || {};
  const count = Number(o.count) || 500;
  const maxPages = Number(o.maxPages) || 200;
  const maxItems = Number(o.maxItems) || 100000;
  const tool = String(o.tool || 'list');
  const log = typeof o.log === 'function' ? o.log : () => {};

  const pages = [];
  let offset = 0;
  let exhausted = false;
  for (let i = 0; i < maxPages; i++) {
    const queries = Object.assign({}, baseQuery || {}, { offset, count });
    const resp = await callOnce(queries);
    const batch = normalizePages(resp);
    if (!batch.length) { exhausted = true; break; }
    pages.push(...batch);
    if (mergePages(pages).length >= maxItems) break;
    const next = batch[batch.length - 1].next_offset;
    if (!shouldContinue(next)) { exhausted = true; break; }
    const n = Number(next);
    // 游标不前进就停：宁可少翻一页，也不能在服务端返回同一个 next_offset 时无限循环。
    if (!Number.isFinite(n) || n <= offset) { exhausted = true; break; }
    offset = n;
  }

  const items = mergePages(pages);
  const tail = exhausted ? '末页 next_offset=null' : '已达分页上限';
  const text = `[IDA] ${tool} 分页 ${pages.length} 页/${items.length} 条（${tail}）`;
  log(text);
  return { pages: pages.length, items, log: text };
}

module.exports = { normalizePages, mergePages, shouldContinue, callPaged };
