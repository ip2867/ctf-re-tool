'use strict';
// IDA MCP 的扩展组 URL 构造（纯模块，Node 可直接 require）。
//
// 背景：ida-pro-mcp 的 dbg_* 工具都标了 @ext("dbg")；zeromcp 的 tools/list 会跳过
// 未启用的扩展组，tools/call 则直接返回 requires extension。启用方式是在 MCP 端点
// 的 query 上带 ext=dbg（rpc.py 登记 MCP_EXTENSIONS，mcp.py 读 query）。
// 仓库配置的 URL 没有 query，因此所有调试工具对 AI 都不可见。
//
// 该处理必须在主进程完成（initialize 与 tools/list 都要带同一 query），
// 否则会话建立后发现的工具表与后续 tools/call 的 URL 不一致。

function idaMcpEffectiveUrl(baseUrl, extensions) {
  const raw = String(baseUrl == null ? '' : baseUrl).trim();
  if (!raw) return raw;
  const exts = (Array.isArray(extensions) ? extensions : [extensions])
    .map(e => String(e == null ? '' : e).trim())
    .filter(Boolean);

  let url;
  try { url = new URL(raw); } catch (e) {
    // 非法 URL 原样返回：调用方会在请求时报出更具体的连接错误。
    return raw;
  }

  // 合并已有 ext（逗号分隔），去重且保持"已有在前、新增在后"的顺序。
  const existing = String(url.searchParams.get('ext') || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  const merged = [...new Set(existing.concat(exts))];
  if (merged.length) url.searchParams.set('ext', merged.join(','));

  // 末尾无斜杠：会话缓存按字符串比较 URL，斜杠差异会造成无谓的会话重建。
  // 注意 path 的尾斜杠也要归一，否则 ".../mcp/" 与 ".../mcp" 被当成两个端点。
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, '');
  return url.toString();
}

function needsSessionReset(prevUrl, nextUrl) {
  return String(prevUrl == null ? '' : prevUrl) !== String(nextUrl == null ? '' : nextUrl);
}

module.exports = { idaMcpEffectiveUrl, needsSessionReset };
