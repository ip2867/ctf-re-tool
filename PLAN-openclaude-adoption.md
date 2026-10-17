# PLAN：借鉴 openclaude 优化 CTF-RE-TOOL 的 agent 运行时

> 生成时间：2026-10-17
> 上游参考：`Twigpine/openclaude` v0.33.0（本地 `C:\Users\Administrator\Desktop\工具\openclaude`）
> 定位：**AI 是解题主体，工具是它手里的能力**。本计划只改"AI 怎么用工具"，不改扫描器的算法判定逻辑。

---

## 0. 现状体检（为什么需要这份计划）

读 `electron/main.js` 的实际实现后，当前 agent 循环的真实能力：

| 机制 | 现状 | 缺口 |
|---|---|---|
| 工具循环 | `MAX_TOOL_ITERATIONS=60`（`main.js:5534`） | 到点静默停止，无"强制总结" |
| 工具输出 | `truncateOutput()` 一刀切 8000 字符（`main.js:2984`） | 头截断，尾部（错误信息）丢失；无落盘 |
| 上下文压缩 | **完全没有** | 长任务 60 轮×多次工具输出必然爆窗口 |
| 重复脚本检测 | `scriptSimilarity>0.88` 且 count≥3（`main.js:5691`） | 只查脚本内容，不查"工具+参数"重复；不按错误类别计数 |
| 失败恢复 | 仅 `stop_reason=max_tokens` 续写 + actionNudge | 无 API 重试/退避；无 context overflow 处理 |
| 经验沉淀 | `experience.md` 自由文本，**手动点"保存"才入库** | 无自动提取、无按题型检索、无"上次同题型该走哪条路" |
| 提示词 | 静态拼接 | 无按需技能加载、无 hook 注入纠错 |
| 会话持久化 | 无 | 中途崩溃/关窗即丢全部进度 |

openclaude 在同样问题上给出的答案，正好补齐这 7 项。

### 0.1 源码级参数对照（已逐文件核对，非估算）

| 参数 | openclaude 值 | 出处 |
|---|---|---|
| 单工具结果落盘阈值 | 50,000 字符（硬上限，工具只能声明更低） | `src/constants/toolLimits.ts: DEFAULT_MAX_RESULT_SIZE_CHARS` |
| 单条 user 消息聚合预算 | 200,000 字符（并行工具合计） | 同上 `MAX_TOOL_RESULTS_PER_MESSAGE_CHARS` |
| 预览大小 | 2,000 字节 | `src/utils/toolResultStorage.ts: PREVIEW_SIZE_BYTES` |
| 头尾比例 | head = ⌊可用空间 × 0.6⌋，尾部取余数；断行对齐（行字节 ≥ 目标 50% 时才吸附换行） | `getHeadTailTargets` / `chooseHeadEnd` / `chooseTailStart` |
| 省略标记 | `… N bytes omitted …` | `formatOmissionMarker` |
| 清理占位串 | `[Old tool result content cleared]` | `microCompact.ts: TIME_BASED_MC_CLEARED_MESSAGE` |
| doom loop 阈值 | 3 次；key = 工具名 + sha256(**完整** input)；阻断后保持阻断直到签名变化 | `src/utils/doomLoop.ts` |
| 失败环阈值 | 3 次；四类计数器：`persistentSignatureCounts / signatureCounts / categoryCounts / pathCounts`；第 threshold-1 次发 advisory；成功写操作重置 | `src/query/toolFailureLoopGuard.ts` |
| 自动压缩阈值 | 有效窗口 − 30,000 token；手动压缩预留 3,000 | `autoCompact.ts: AUTOCOMPACT_BUFFER_TOKENS / MANUAL_COMPACT_BUFFER_TOKENS` |
| 压缩失败熔断 | 连续 3 次失败 → 冷却 5 分钟 | `MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES / AUTOCOMPACT_FAILURE_COOLDOWN_MS` |
| 消息条数触发 | 200 条 | `utils/config.ts: maxMessagesCompactionThreshold` |
| 压缩后恢复现场 | 最近 5 个文件（每个 ≤5k token，总 ≤50k）+ 已用技能（总 ≤25k） | `compact.ts: POST_COMPACT_*` |
| 压缩超长重试 | 从最旧按 API 轮次丢弃，最多 3 次 | `MAX_PTL_RETRIES` |
| 技能清单预算 | 上下文窗口 1%（默认 8,000 字符），单条描述硬上限 250 字符 | `SkillTool/prompt.ts` |
| 会话日志 | 追加式 JSONL，单文件读取上限 50MB | `sessionStorage.ts: getTranscriptPath / MAX_TRANSCRIPT_READ_BYTES` |
| 压缩摘要模板 | 9 段（Primary Request / Concepts / Files / Errors / Problem Solving / User Messages / Pending / Current Work / Next Step） | `services/compact/prompt.ts` |

**移植时的换算**：DeepSeek 窗口 128k、`max_tokens` 当前 32768。按 openclaude 的比例
（摘要预留 = min(maxOutputTokens, 20k)）→ 建议本工具：

- 单工具结果落盘：**24,000 字符**（≈6k token），约为 openclaude 的一半（窗口更小）。
- 单条消息聚合：**80,000 字符**。
- 自动压缩触发：**90,000 token**（窗口 70%）。
- 压缩后保留：最近 3 个扫描结论 + 当前文件路径 + 已生成脚本路径 + 最多 2 条匹配经验。


---

## Phase A：上下文不爆（最高优先，直接决定长任务能不能跑完）

### A1. 大工具输出落盘 + 头尾预览

**参考**：`src/utils/toolResultStorage.ts`（`generatePreview` / `generateHeadTailPreview` / `getHeadTailTargets` / `chooseHeadEnd` / `chooseTailStart`）、`src/constants/toolLimits.ts`

**改法**（`electron/main.js`，替换 `truncateOutput`）：
```js
const TOOL_RESULT_MAX_CHARS = 24000;   // ≈6k token（DeepSeek 窗口较紧，取 openclaude 50k 的一半）
const PREVIEW_HEAD_RATIO = 0.6;        // 与 openclaude 一致：60% 头 + 40% 尾
const OMIT_MARK = (n) => `\n… ${n} bytes omitted …\n`;

function headTailPreview(text, maxChars) {
  if (text.length <= maxChars) return text;
  const marker = OMIT_MARK(text.length);
  const avail = Math.max(0, maxChars - marker.length);
  let headEnd = Math.floor(avail * PREVIEW_HEAD_RATIO);
  // 断行对齐：优先切成整行，但行字节不能少于目标的 50%（否则退回硬切）
  const nl = text.lastIndexOf('\n', headEnd);
  if (nl > 0 && (nl + 1) >= headEnd * 0.5) headEnd = nl + 1;
  let tailStart = text.length - (avail - headEnd);
  const nl2 = text.indexOf('\n', tailStart);
  if (nl2 !== -1 && (text.length - nl2) >= (avail - headEnd) * 0.5) tailStart = nl2 + 1;
  return text.slice(0, headEnd) + marker + text.slice(tailStart);
}

function persistToolResult(toolName, toolUseId, text) {
  if (text.length <= TOOL_RESULT_MAX_CHARS) return text;
  const dir = path.join(app.getPath('userData'), 'tool-results');
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, `${toolUseId}.txt`);
  fs.writeFileSync(f, text, 'utf8');
  return `<persisted-output tool="${toolName}" chars="${text.length}" file="${f}">\n` +
    headTailPreview(text, TOOL_RESULT_MAX_CHARS) +
    `\n</persisted-output>\n需要完整内容时用 read_file 读取上面路径（可按行 offset/limit 分段读）。`;
}
```
要点：
- **60% 头 + 40% 尾**（openclaude 实测比例）：错误堆栈/flag 常在尾部，只截头会丢掉关键信息。
- 预览里显式给文件路径 + "怎么读回来"，否则模型不知道该二次读取。
- 单条消息聚合预算 80,000 字符：并行多个工具时，从最大者开始落盘直到达标。
- 按工具分配额度：`ida_decompile/strings/read_file` 大额度，`bash` 小额度（2,000）。

**验收**：200KB 反编译输出 → 模型收到 ≤24k 字符 + 路径；上下文不爆；模型能主动 `read_file` 取回细节。

### A2. 旧工具结果微压缩（零模型调用）

**参考**：`src/services/compact/microCompact.ts`（`TIME_BASED_MC_CLEARED_MESSAGE = '[Old tool result content cleared]'`）

**改法**：`claudeChatWithTools` 的每轮开始前执行
```js
const KEEP_RECENT_TOOL_RESULTS = 6;
function microcompact(history) {
  const slots = [];   // 所有 tool_result 的位置（按时间序）
  history.forEach((m, i) => {
    if (m.role !== 'user' || !Array.isArray(m.content)) return;
    m.content.forEach((b, j) => { if (b.type === 'tool_result') slots.push([i, j]); });
  });
  const drop = slots.slice(0, Math.max(0, slots.length - KEEP_RECENT_TOOL_RESULTS));
  for (const [i, j] of drop) {
    const b = history[i].content[j];
    if (String(b.content).includes('[Old tool result content cleared]')) continue;
    if (b.is_error) continue;   // 错误信息是模型纠错的依据，不清
    history[i].content[j] = { ...b, content: '[Old tool result content cleared]' };
  }
}
```
要点：
- **只改内容、不改结构**：`tool_use_id` 必须原样保留，否则 API 直接 400。
- 最近 6 条不动：模型当前推理依赖的现场。
- `is_error` 不清：否则模型会重复犯错。
- openclaude 还有"时间触发"变体（距上次 60 分钟且只保留 5 条）——本工具单题时长通常 <30 分钟，**不需要**。

### A3. 摘要式压缩（阈值触发）

**参考**：`src/services/compact/compact.ts`、`src/services/compact/prompt.ts`、`src/services/compact/autoCompact.ts`

**改法**：
- 触发条件（两者取先到）：
  - 估算 token > **90,000**（窗口 128k × 70%）；
  - 消息条数 > **120**。
- 摘要 prompt 直接沿用 openclaude 的 9 段骨架，改成 CTF 语境：
  1. 题目与目标（文件路径、平台题名、已知 flag 形态）
  2. 已确认事实（扫描结论：骨架/S 盒关系/CK 差分/密文偏移/key 提示）
  3. 已排除路线（试过但失败的算法×参数组合，附失败原因）
  4. 当前进展（解到第几层、stage 文件路径、已生成脚本路径）
  5. 待验证假设（按信息增益排序）
  6. 关键偏移与常量（不能丢的硬数据）
  7. 错误与修复（哪些工具调用报了什么错、怎么绕过的）
  8. 下一步（具体到"调用哪个工具、传什么参数"）
  9. 禁止重复的事（明确列出不要再试的组合）
- 压缩后**重建现场**：最近 3 次 `scan_crypto` 摘要 + 当前目标文件 + 已生成脚本路径 + top-2 匹配经验（各 ≤500 字符）。
- 熔断：连续 3 次压缩失败 → 冷却 5 分钟（openclaude 原值）。
- 超长重试：从最旧的消息按轮次丢弃，最多 3 次（对应 `MAX_PTL_RETRIES`）。

**验收**：150 轮压力测试不崩；压缩后模型仍能正确回答"当前在解哪个文件、已知哪些常量、下一步做什么"。

---

## Phase B：别让模型在同一个坑里反复摔（投入产出比最高）

### B1. 工具级 doom loop（按 工具+参数哈希）

**参考**：`src/utils/doomLoop.ts`（源码已核对：阈值 3；`sha256` 哈希**完整**入参，不做前缀截断——前缀截断会把"同文件不同尾部内容的两次 Write"误判为相同）

**改法**：现有 `scriptSigs` 只覆盖"脚本内容相似"，扩展为通用：
```js
const callSigs = new Map();   // key = `${toolName}::${sha256(JSON.stringify(input))}`
let lastSig = null, consecutive = 0, blocked = false;

function checkDoomLoop(toolName, input, threshold = 3) {
  const sig = `${toolName}::${crypto.createHash('sha256').update(JSON.stringify(input) ?? '').digest('hex')}`;
  if (sig === lastSig) consecutive++;
  else { lastSig = sig; consecutive = 1; blocked = false; }
  if (consecutive >= threshold && !blocked) { blocked = true; return { blocked: true, count: consecutive }; }
  return { blocked, count: consecutive };
}
```
关键细节（都来自源码）：
- **哈希完整入参**，不用前缀（否则误伤合法的相似调用）。
- **连续**计数，不是累计：中间插入任意不同调用就重置。
- 阻断后**保持阻断**直到签名变化（`state.blocked`），避免"第 4 次又放行"的抖动。
- 阻断文案要给出改法：`"同样的调用已连续 3 次。请改参数、换工具或换假设——如果可观测状态确实变了，再重复一次是允许的。"`
- 成功且状态有变化的调用（`write_file` 成功、`bash` 产出新结果）重置计数。

### B2. 跨轮失败环检测（按错误类别）

**参考**：`src/query/toolFailureLoopGuard.ts`（源码已核对：四个独立计数表；同一轮内的并行失败**每个 key 只计一次**，避免批量失败直接触发）

**改法**：
```js
state = {
  persistentSignatureCounts: new Map(),  // `${tool}\0${category}`
  signatureCounts: new Map(),            // `${tool}\0${category}\0${sigHash}`
  categoryCounts: new Map(),             // category
  pathCounts: new Map(),                 // 归一化路径
}
// 错误类别归一化（CTF 语境扩展）：
//   InputValidation | NotFound | Permission | Timeout | ToolCrash
//   | NoSymbol | WrongArch | ScriptError
// 第 threshold-1 次（=2）：advisory —— 注入"同类失败 2/3，请换方法"
// 第 threshold 次（=3）：trip —— 终止该轮，强制换路线
// 成功的写操作重置该路径的计数
```
CTF 特化建议（写进 advisory 文案）：
- `NoSymbol` × 3 → "IDA 连续找不到函数。改用候选名序列 `main/_main/WinMain/_WinMainCRTStartup/start`，或先 `strings`/`xrefs` 定位"。
- `ScriptError` × 3 → "脚本连续报错。检查是否缺 `import idaapi/idc`、是否用了 Py2 语法；或改用 `ida_get_bytes` 读字节自己算"。
- `WrongArch` × 3 → "架构不符。先确认是 x86/x64/ARM，再换对应 IDA 实例"。

### B3. 工具预检 + 纠正性错误

**参考**：`src/utils/toolErrors.ts:formatZodValidationError`（missing / unexpected / type-mismatch 三句式）、`src/tools/GrepTool/GrepTool.ts:suggestPathUnderCwd`（`Did you mean …?`）

**改法**：每个工具在真正执行前做确定性预检，错误信息**必须包含"怎么改"**：
- `ida_decompile(function=xxx)`：先查函数是否存在；不存在则返回"未找到；相近候选：`["main","_main","WinMain"]`——请用其中之一重试"。
- `bash` 命令：检测 `python` 脚本常见错误（缺 import、用了 Py2 print）→ 直接给出修正后的命令模板。
- 路径不存在：给出同目录最相近的 3 个文件名（Levenshtein 距离）。
- Schema 错误统一三句式：`缺少必填参数 \`x\`` / `多出未知参数 \`y\`` / `参数 \`z\` 应为 number，实际是 string`。

---

## Phase C：把"经验"从自由文本变成可检索资产

### C1. 经验条目结构化

**参考**：`src/memdir/`（MEMORY.md 索引 + frontmatter `type` + `Rule/Why/How to apply` 三段式）

**改法**：把 `experience.md` 从自由文本升级为：
```md
# 索引（≤200 行）
- [SM4 变体·自定义 S 盒](exp/sm4-custom-sbox.md) — CK 差分定位 + 32 轮逆序 + 块内 dword 反序
- [VM switch 分发](exp/vm-switch.md) — 逐 opcode 翻译 + 常量区当程序读
```
单条文件：
```md
---
type: technique      # technique | pitfall | layout | tool-usage
applies_to: ["SM4", "自定义S盒", "dword数组"]
---
**规则**：S 盒按 dword 数组存放时，必须按 4 字节步长取低字节。
**Why**：C 里声明为 `unsigned int sbox[256]`，连续读会把 0x00 当表项。
**How to apply**：scan_crypto 报 stride=4 时，生成的脚本已自动处理；手写实现时同理。
```
- **写入时机**：解题成功（已验证 flag）后自动提取，而不是手动点保存。
- **检索时机**：`scan_crypto` 命中后，用题型特征（骨架/S 盒关系/存放形态）反查，只注入 top-3 相关条目（不是全部 200 条）。

**验收**：解过 A 题后，遇到同题型的 B 题，提示词里出现 A 的经验（且 ≤500 字符）。

### C2. 技能懒加载（省上下文）

**参考**：`src/skills/loadSkillsDir.ts`（frontmatter `paths` 条件激活）、`src/tools/SkillTool/prompt.ts`（清单预算 = 窗口 1%、单条描述硬上限 250 字符）

**改法**：现有 `skills/ctf-crypto-identify/SKILL.md` 已经在做这件事。补齐三点：
- frontmatter 加 `paths: ["**/*.apk", "**/*.so", "**/*.dex"]`，只在触碰匹配文件后才进上下文。
- 技能清单注入只保留 `name + 一句话描述`（≤250 字符），正文由 AI 主动 `read_file` 展开。
- 清单总预算不超过 8,000 字符（窗口 1%）；超了就先砍非内置技能的描述。

---

## Phase D：会话可靠性（崩溃可续跑）

### D1. 追加式 JSONL 会话日志

**参考**：`src/utils/sessionStorage.ts`（`getTranscriptPath` / `recordTranscript` / `insertMessageChain`）、`src/utils/conversationRecovery.ts`（`deserializeMessagesWithInterruptDetection`）

**改法**：
- 路径：`<userData>/sessions/<caseId>.jsonl`，**追加式**写入（`fs.appendFileSync`）。
- 每条消息：`{uuid, parentUuid, role, content, toolUseId?, ts}`。
- 恢复流程（严格按 openclaude 的过滤顺序）：
  1. **剥离未完成的 tool_use**（有 tool_use 但没有对应 tool_result）——否则 API 400；
  2. 剥离孤立的 thinking-only assistant 消息；
  3. 剥离纯空白的 assistant 消息；
  4. 若末尾是 user，注入 `"Continue from where you left off."` 作为续跑指令。
- 读取上限：单文件 50MB（超出只读尾部）。
- 附带 `fileHistory` 快照（每轮一次，最多 20 个）供回滚。

**验收**：解题中途 kill 进程，重开后能接着跑且不重复已完成的阶段。

### D2. API 重试与退避

**参考**：`src/services/api/withRetry.ts`

**改法**：`claudeTransport` 外层加：
- 最多 5 次；延迟 `min(500ms × 2^(n-1), 32s)` + 0–25% 抖动；优先用响应头 `retry-after`。
- 429 单独计数（上限 3 次，之后报错给模型而不是继续重试）。
- 区分"可重试"（网络/5xx/429）与"不可重试"（400 参数错，直接把错误文本回给模型让它改参数）。

---

## Phase E：可选增强（收益明确但非必需）

### E1. 子 agent 隔离重活
**参考**：`src/tools/AgentTool/`（隔离上下文，只回最后一条 assistant 文本）
- 场景：`ida_decompile` 一个 3000 行函数后，"总结这个函数在做什么"这类任务开子 agent，只回 500 字摘要，主上下文不接触原始输出。
- 实现成本中等（需要独立消息栈 + 只回传摘要）。

### E2. Prompt cache 友好结构
**参考**：`src/services/api/claude.ts:addCacheBreakpoints`
- 若 provider 支持 `cache_control`：只打一个缓存断点（system + tools 前缀）。
- 若不支持（如当前 DeepSeek 代理）：**保持前缀稳定**——system prompt 与 tools 定义固定不变，动态内容（扫描结果/经验）一律放最后一条 user 消息，避免每轮前缀变化导致缓存全失效。

### E3. 目标闭环（goal evaluator）
**参考**：`src/commands/goal/` + `src/services/goal/evaluator.ts`
- 每 N 轮用一次小模型判定 `{complete, confidence, reason, next_instruction}`，未完成则注入下一步指令；避免模型在第 40 轮开始"复述已有结论"耗到 60 轮上限。

---

## 执行顺序与验收

| 阶段 | 内容 | 预估改动量 | 验收 |
|---|---|---|---|
| **A1** | 工具输出落盘 + 头尾预览 | ~60 行 | 200KB 输出不爆窗口，模型可回查 |
| **B1** | 工具级 doom loop | ~50 行 | 同调用重复 3 次被拦并给出改法 |
| **B3** | 预检 + 纠正性错误 | ~120 行 | IDA 函数名错误时返回候选；路径错误返回相似名 |
| **A2** | 旧结果微压缩 | ~40 行 | 60 轮后上下文仍稳定 |
| **C1** | 结构化经验 + 题型检索 | ~200 行（含迁移脚本） | 同题型二次解题命中经验 |
| **D1** | JSONL 会话 + 续跑 | ~150 行 | kill 后能续跑 |
| **D2** | API 重试退避 | ~40 行 | 429/5xx 自动恢复 |
| **A3** | 摘要压缩 | ~180 行 | 150 轮压力测试通过 |
| **E1–E3** | 子 agent / cache / goal | ~400 行 | 按需 |

**先做 A1 + B1 + B3**（约 1 天，改动小、收益立刻可见），再做 A2/C1/D1，最后 A3/E。

---

## 明确不做的事

- **不引入 openclaude 的多 provider/bridge/websocket 架构**——本工具只需单一 Anthropic 协议端点，照搬会显著增加维护成本。
- **不引入其 hooks 的 `prompt`/`agent` 类型 hook**——用确定性规则（正则/类别映射）即可，不需要再烧模型调用。
- **不照搬 `buddy/`（像素宠物）等 UI 装饰**——与解题能力无关。
- **不把 `maxIterations` 提到很高**——真正的解法是压缩与纠错，不是给更多轮次烧预算。
