# CTF-RE-TOOL 优化计划 V3（第二轮修订）

> 依据：6 道未解出题（CrackMe2 / CrackMe3 / CrackMe5 / cnbragon / not-baby-parallelism / QuiZow）的根因复核材料，以及本次对代码、样本、会话日志的实测（命令与输出见 §三）。
> 本版针对第二轮评审的 27 条问题与 14 条缺失逐条修订，修订对照见 §零。原则不变：**只做通用机制，不写题目特判**。
> 标注「新增」的测试文件当前**不存在**（本次 `fs.existsSync` 实测 MISSING），是交付物；标注「修改」的是既有文件。

---

## 零、本轮修订对照（评审问题 → 本版位置）

| 评审问题 | 本版处理 |
|---|---|
| `executeToolCall` 的 catch（7502）吞掉 throw，6559 收不到 | §rank2 改法 2：**双通道**——① 类型化 `ToolCallError` 在 catch 内重新抛出，由主循环 6559 置 `is_error:true`；② 非类型化路径返回的字符串由 `toToolResult` 在 6544 处识别为失败。两条路径都有单测，见验收 T1/T6 |
| `py_exec_file` 返回对象，`String(r).match` 读不到 BYTES | §rank2 改法 1 `parsePyExecReply`，验收 T3 |
| 7241 的 `state` 未定义 | §rank2 改法 2 明确删除该引用（改 `currentWorkDir`），验收 T7 静态断言 |
| 验收无法在 Node 下执行（main.js 不可 require） | §rank2 改法 1/3：case 体抽成 `electron/tool-result.js` 的纯函数，注入 `callMcp/fs/exec/app`；验收 T4/T6 直接 require |
| `formatBytesResult` 只测字符串 | §rank2 改法 1 `parseBytesReply` 以**数组**为主形态，覆盖多 region/空 data；验收 T2 |
| `scan_crypto` 样本不触发目标分支 | §rank2 改法 4 + 验收 T5 明确用 CUSTOM-BLOCK 样本，并先断言 `constantAnalysis` 存在 |
| bash 未覆盖 `cd /d ... &&` 前缀 | §rank2 改法 5 + 验收 T8 用真实命令，并断言 cwd 输出 |
| `test_tool_contract` 没有请求构造器 | §rank2 改法 1 导出 `buildGetBytesAttempts`/`pyExecArgs`，验收 T9 |
| microcompact 白名单自相矛盾 | §rank1 改法 5：把 `ida_list_functions` 从 `COMPACTABLE_TOOLS` 移除，验收 T10 断言 `has(...) === false` |
| A/B 层计数冲突、`sameTemplateDifferentAddr` 不存在 | §rank1 改法 3/4 + 验收 T11（明确 API 名 `isSameIdea`，A 层只在逐字节相同时优先，B 层用文本不同的脚本验证） |
| `targetsOverlap` 分母未定义 | §rank1 改法 2：**只用地址集合 + min 分母（containment）**；实测 cm5 115/31=0.000、nb 47/49=0.200、nb 47/51=0.333、cm5 115/119=1.000 |
| msg#36 证据不精确 | §rank1「为什么」改为「覆盖该区间」，并给出实测（243 条指令，区间内 17 条，含 `1400015b7: movsx ecx, byte ptr [r8]`） |
| dedup 测试 harness 不够 | §rank1 改法 6：状态机抽成 `electron/script-dedup.js` 的 `checkDedup(...)` |
| rank3 无 PE 映像解析能力 | §rank3 改法 1 新增 `electron/binary-map.js` + IPC，验收 T12 |
| 渲染层无 `path.resolve` | §rank3 改法 3：路径规范化全部在主进程完成（实测 app.js `path.resolve` 0 次） |
| QuiZow / 跨题哈希计数 | §3.3 更正为 100 项函数、不含 `0x42F038`、越界 62（VirtualSize）/56（SizeOfRawData）、9 个 case |
| 8399-8405 是死分支 | §rank4 根因与 §rank6 改法 4：改点放到 `main.js:2620-2627` 的 note 与 `app.js:8360-8361` 的注入；另发现并纳入 `app.js:7982-7983` 的同类误导句 |
| `vr.hits` 判据对 CrackMe3 不成立 | §rank5 改法 2：verified = 「AI 用 `[FLAG]` 声明该值」∧「含该 key 的契约本地复现命中」；验收用真实 hits（shellcode hex） |
| `attributeFailure` 不在 finalizeSolve 作用域 | §rank5 改法 5：改用 `findDecodedLayer(vr.rawOutput)`，在 10146 分支内、10159 之前判定；不再提 `attributeFailure` |
| `findings.answers` 未初始化 | §rank5 改法 1：`newFindings`（app.js:38-52）增加 `answers: []` |
| MD5「连续 ≥8」无效 | §rank6 改法 1：散落 K 常量，`hits>=48 && ivHits<=1`（实测校准） |
| cnbragon 表布局读错 | §rank6 改法 2：真实布局 `00 v v v`，值在字节 1（lane 1），lane 0 恒 0；验收用真实布局构造 |
| 零指纹验收自相矛盾、D 段不覆盖 medium | §rank6 改法 4 + 验收：不再要求日志缺少 `(未发现算法指纹)` 标签，只断言误导句消失；D 段覆盖所有置信度 |
| §3.3 引用了已删除脚本 / 39 个测试 | §三 全部改为可复跑的内联命令，测试基线实测 **42/42 + 回归 13/13** |
| not-baby get_bytes 计数 | §rank2 更正为 **2 次** |
| 「7/7 日志无描述」是空检查 | §rank4 改为解析 **22 份 2026-10-19 会话第 0 条 prompt**（实测 22/22 均无该标题） |
| `applyWrap` / `newFindings` / `_platformChallenge` | §rank4 改法 2/3 写明 `applyWrap`、保留 `_platformChallenge`；§rank5 改法 1 写 `answers: []` |
| 重试只有一次、`写盘接力` 不存在 | §rank5 改法 4 改成循环（硬上限 2 轮）；验收不再要求 `写盘接力`，改用源码中实有的 `写盘为新文件`、`不要换算法、不要换 key` |

---

## 一、结论摘要

6 道题的失败是三类工具侧断链叠加：

1. **去重闸把「新的观测目标」判成「重复劳动」**：归一化抹掉地址/常量（只改地址的两个 disasm 脚本相似度实测 1.0000），命中计数只增不减且新脚本不入池；同时 microcompact 清空旧结果，却不给"重取已清空结果"豁免 —— 形成死锁。
2. **工具失败以成功形态回传**：`executeToolCall` 外层 catch 把异常改写成字符串；`callIdaMcp` 把传输异常也改写成字符串；`ida_get_bytes` 用 `String(obj)` 判错误（恒为 `[object Object]`）；`py_exec_file` 兜底拿对象却用 `String(r).match` 解析；`scan_crypto` case 引用未定义的 `buf/size`；bash 空 stdout 报"成功"；IDA 复用只看端口。
3. **已达成的答案在末公里被丢弃**：CrackMe3 的 `771535` 通过 `[FLAG]` 进入 `extractFlags` → 写进 solve note，却在 `recordFlag` 处被 `looksLikeFlag` 静默丢弃；平台"请包上 flag{}"从未被转成动作。

| rank | 机制 | 直接受影响题 | 成本 |
|---|---|---|---|
| 1 | 去重闸改为「地址目标指纹」+ 载荷变化重置 + 已清空结果豁免重取 | CrackMe2、CrackMe5、not-baby-parallelism（3/6） | 中低 |
| 2 | 工具结果可信性（错误传播双通道、真实参数名与返回形态、case 作用域、bash 执行方式） | CrackMe2、cnbragon、not-baby-parallelism、CrackMe5（4/6） | 低 |
| 3 | IDA 会话身份绑定 + 主进程映像解析 + 落界校验 | cnbragon、not-baby-parallelism、QuiZow、CrackMe5（4/6） | 中高 |
| 4 | 平台题目契约贯穿流程 + 零指纹误导句的真实改点 | not-baby-parallelism、CrackMe3（2 道确定受害） | 低 |
| 5 | 末公里候选闭环：契约驱动的 verified、重试提示被消费、机器码优先 | CrackMe3（1 道确定；通用通路） | 低 |
| 6 | 指纹扫描：散落 MD5 K 常量 + 真实 lane 布局变表 + 零指纹措辞 | CrackMe2、cnbragon（2/6） | 中低 |

---

## 二、逐项计划

### rank 1 — 去重闸改为「地址目标指纹」：比观测地址，不比文本骨架

**为什么排这里**

- CrackMe2（会话 `2026-10-19T03-39-30-617Z.jsonl`）：64 条 tool_result 中 8 条是「同一思路、仅换写法」（索引 18/28/30/34/44/82/110/118）；被拦脚本分别读 `0x42fcd9`、`0x401000`、`0x42f1aa`、`0x401420` 等不同观测点。AI 随后停止静态分析。
- CrackMe5（会话 `2026-10-19T03-54-16-554Z.jsonl`）：7 条拦截（索引 30/38/52/80/112/116/120）。用 `main.js` 的 `normalizeScript/scriptSimilarity` 对真实脚本复算：**tool_use 索引 115 vs 31 = 0.8808，119 vs 31 = 0.8910，115 vs 119 = 0.8627**。日志不打印具体相似度（只打印 `>88%`），这三个值是我本地复算（命令见 §3.3）。
  关于"已取到的证据被清空"：会话**索引 36** 的反汇编输出覆盖 `0x140001400–0x1400017ee`（243 条指令，区间内 17 条，首条 `1400015a0`、末条 `1400015d5`，含 `1400015b7: movsx ecx, byte ptr [r8]`）——它**覆盖** AI 后来要重取的 `0x14000159a-0x1400015d8`，但不是逐字节同区间；重取本身（索引 115/119）才是被拦对象。
- not-baby-parallelism（会话 `2026-10-19T04-02-16-457Z.jsonl`）：tool_use 在**索引 47/49/51**，复算 `sim(47,49)=1.0000`、`sim(47,51)=0.9709`、`sim(49,51)=0.9709`；去重 tool_result 在索引 52，AI「我不再继续反汇编」在索引 53。

**根因（已复核）**

- `electron/main.js:6653-6655`：字符串→`S`、`0x...`→`N`、数字→`N`；实测只改地址的 disasm 脚本相似度 = **1**，归一化输出不含原地址。
- `electron/main.js:6484` 阈值 0.88；`6486-6494` 命中后只 `similarHit.count++`，**新脚本不入池**，`count>=3` 起该模板永久失效。
- `electron/main.js:6472`：脚本类工具完整参数签名第 2 次即拦。
- `electron/agent-runtime.js:69-74` 的白名单**包含 `ida_list_functions`**（本次 `R.COMPACTABLE_TOOLS.has('ida_list_functions') === true`、`has('ida_find_strings') === false`）；`microcompact`（`87-99`）完全未使用白名单：函数体内 `COMPACTABLE` 出现 0 次，12 条含 `ida_find_strings` 的结果被清掉 8 条。

**改什么**

1. 新增纯函数 `scriptTargets(input)`（放在 `normalizeScript` 旁，或新模块 `electron/script-dedup.js`）：
   - 只抽**地址类**常量：`0x[0-9a-fA-F]+` 且数值 ≥ `0x1000`，以及长度 ≥8 的纯 hex 字符串字面量（按数值处理）；
   - 返回 `{addrs:Set<string>, path:string}`，地址用 `BigInt` 规范化成不带前导零的小写十六进制（如 `14000159a`）；`path` 取脚本里出现的第一个文件路径（用于"同文件"前置判断）。
   - **不把十进制小整数、长度、`len/size` 计入目标集合**（实测这些小数字在任意两个脚本间几乎全等，会把不同实验判成相同）。
2. 新增 `targetsOverlap(a, b)`：**分母取较小集合（containment）**，且只比较 `addrs`：
   ```
   targetsOverlap = |A.addrs ∩ B.addrs| / min(|A.addrs|, |B.addrs|)
   ```
   - 任一侧 `addrs` 为空 → 返回 0，并记日志 `[去重] 无地址目标指纹，B 层不判定（仅 A 层生效）`；
   - 若两侧 `path` 都存在且归一化后不同 → 直接返回 0（不同文件不可能是同一实验）。
   - 实测校准（本次，真实脚本）：CrackMe5 115 vs 31 = **0.000**、119 vs 31 = **0.000**、115 vs 119 = **1.000**；not-baby 47 vs 49 = **0.200**、47 vs 51 = **0.333**。阈值 0.5 可把前四对全部放行、把"同区间重取"判为重复。
3. 去重判定（B 层）改为：`similarity > 0.88 && targetsOverlap >= 0.5` 才算同一思路；否则视为新实验，**新脚本入池**。命中时按目标指纹计数，目标集合变化即 `count=1` 重建条目；同一目标第 3 次起才拦。拦截文案打印双方地址集合与重叠度。
4. A/B 两层合并规则（明确顺序）：
   1. **CLEARED 豁免最先判定**：若历史中同签名（`toolCall.name + JSON.stringify(input)` 的 sha1）的 tool_result 内容等于 `[Old tool result content cleared]`，放行一次，`dupCounter` 与 B 层计数清零，日志 `[去重] 上一轮结果已被清空，允许重取一次`。
   2. **A 层**（`6472`，脚本类阈值 2）：仅在"参数逐字节相同"时生效；命中即拦，文案前缀 `A/逐字节相同`。
   3. **B 层**（`6484`）：只有相似度与地址重叠同时达标才拦，文案前缀 `B/同目标`。
   4. A 层命中时不进入 B 层；B 层命中时不改 A 层计数。验收 B 层必须用**文本不同、地址相同**的三份脚本（避免被 A 层第 2 次提前拦）。
5. 新增 `isSameIdea(prev, next)` 作为两层合并后的唯一入口（供主循环调用、供测试直接调用）：返回 `{blocked:boolean, layer:'cleared'|'A'|'B'|null, count:number, reason:string}`。
6. 状态机抽到 `electron/script-dedup.js`（纯函数，无 Electron 依赖）：
   `createDedupState()` 返回 `{dup:Map, sigs:Map}`；`checkDedup(state, {name, input, sig, norm, targets, clearedSigs})` 返回 4 的结果。主循环只保留一行调用。
7. microcompact：`microcompact(history, keepRecent, toolNameById)` 真正按 `COMPACTABLE_TOOLS` 过滤；**从白名单移除 `ida_list_functions`**（它是跨题串台的高风险证据，见 rank 3，重新获取代价低）；`ida_find_strings`/`list_globals` 本就不在白名单，保持"永不清"。`main.js:6119` 调用前由相邻 `tool_use` 建 `id→name` 映射传入。

**验收（可观察）**

- `node tests/test_script_dedup.js`（修改既有）新增并通过：
  - `scriptTargets('disasm 0x42fcd9')` 的 `addrs` 为 `{'42fcd9'}`（大小写/前导零归一）；
  - `targetsOverlap(scriptTargets('0x42fcd9'), scriptTargets('0x42f1aa')) === 0`；
  - 用真实脚本快照（`tests/fixtures/dedup-cm5-115.js`、`dedup-cm5-31.js`，从会话索引 115/31 原样落盘）断言 `targetsOverlap === 0` 且 `isSameIdea(...).blocked === false`；
  - 同一份脚本连续 3 次（参数逐字节相同）→ 第 2 次就被 A 层拦（`layer==='A'`）；
  - 三份**文本不同、地址相同**（均读 `0x42fcd9`，变量名不同）的脚本 → 前 2 次 `blocked:false`，第 3 次 `blocked:true` 且 `layer==='B'`；
  - 三份**地址不同**、相似度 1.0 的脚本 → 全部 `blocked:false`，日志含 `目标集合不同，按新实验放行`；
  - `clearedSigs` 含该签名 → `layer==='cleared'` 且计数归零；
  - 既有「共享 boilerplate 任务不同 <0.88」「同思路换写法 >0.88」用例保持通过。
- `node tests/test_agent_runtime.js`（修改既有）新增并通过：`R.COMPACTABLE_TOOLS.has('ida_list_functions') === false`；`keepRecent=4` 时 12 条 `ida_find_strings` 结果内容全部不变；`bash/run_python` 的旧结果仍被清；`clearedSigs` 判定函数对 `CLEARED` 返回 true。
- 实跑 CrackMe5 定向复验：日志出现 `[去重] 目标集合与历史不同，按新实验放行`；索引 115/119 类重取不再返回 `is_error`。
- `node tests/run_all.js` 退出码 0。

**通用性**：判据是脚本的**观测地址集合**（同一文件内）+ 结构相似度，适用于任何"模板固定、只换地址/偏移/长度"的检索；无地址指纹时宁可不判（放宽），避免把新实验锁死。

---

### rank 2 — 工具结果可信性：失败必须是失败，参数与返回必须按对方真实形态处理（下一轮实施）

> 改动集中在 `electron/main.js` 与新增 `electron/tool-result.js`（纯 JS，零 electron 依赖，可被 Node 测试直接 require）。

**为什么排这里**

- `ida_get_bytes` 在 CrackMe2（4 次）、cnbragon（11 次）、not-baby-parallelism（**2 次**，会话索引 6/10）、CrackMe5（1 次）全部返回 `[{addr:"",data:null,error:"Failed to parse address (missing 0x prefix): "}]`，但都被判成功并直接 return。
- cnbragon 首次 `scan_crypto` 即 `工具调用失败: buf is not defined`，AI 从未拿到结构推理。
- 4 份会话共出现 5 次「命令执行成功（无输出）」，其中 CrackMe2 索引 7/37 的多行 `cd /d ... && python -c "..."` 是确定受害者（其后的 `type dis401000.txt` 报文件不存在）。

**根因（已复核）**

| # | 事实 | 证据 |
|---|---|---|
| a | `executeToolCall` 外包 try/catch，**所有 throw 被改写成普通字符串**；`callIdaMcp` 也把 MCP 异常改写成字符串 | `main.js:7502-7503`、`7508-7513`；主循环 `6542-6555` 只拿字符串且 `is_error:false` |
| b | `py_exec_file` 返回 `{result,stdout,stderr}`；兜底用 `String(r).match(/BYTES.../)`，`String(obj)==="[object Object]"` | `api_python.py:243-247`；`main.js:7228`；实测输出 `[object Object]` |
| c | `7241` 引用主进程不存在的 `state`（全仓 `let/const/var state` 0 处） | 实测 `state&&state.currentFile` → `ReferenceError: state is not defined` |
| d | `main.js` 在纯 Node 下不能 require | 实测 `TypeError Cannot read properties of undefined (reading 'getPath')` |
| e | `get_bytes` 成功返回是**数组** `[{addr,data:'0x55 0x8b'}]`，多 region 为多元素 | `api_memory.py:72-90`；`main.js:3765-3843` |
| f | `ca` 只来自 `fingerprints[].constantAnalysis`；标准 SM4 的 `sk=null` 不挂该字段 | `main.js:7333`、`2483-2497`、`2633-2665`（`if (sk)`） |
| g | 现有契约测试只静态解析 schema/precheck，请求对象在 case 内联构造 | `tests/test_tool_contract.js:13-37,62-67`；`main.js:7203-7208` |
| h | 多行 `python -c`（含 `cd /d X &&` 前缀）经 cmd.exe 得到 `err=null/stdout=""/stderr=""` | 实测两条命令（§3.3） |
| i | `execCommandAsync` 用 `currentWorkDir` 作 cwd，命令里常自带 `cd /d ...` | `main.js:7642/7649/8427` |

**改什么**

1. **新增 `electron/tool-result.js`**，导出：
   - `toolFailureReason(result)`：
     - 字符串：先 `JSON.parse` 尝试（失败忽略）；再匹配 `^(工具调用失败|IDA MCP调用失败|JEB 调用失败|Python执行失败|命令执行失败|读取文件失败|写入文件失败|扫描失败)` → 返回匹配到的消息；否则 `null`；
     - 数组：逐元素判 `typeof el.error === 'string' && el.error`、`hasOwn(el,'data') && el.data === null`、`el.success === false`；空数组返回 `null`；返回第一条错误文本；
     - 对象：`success === false`、`error` 非空字符串（`null`/`""` 不算失败）、`stderr` 非空且 `stdout` 与 `result` 均为空（仅当 `opts.pythonExec === true`，由调用方显式传）。
   - `buildGetBytesAttempts(addr, size)`：**四种**形态，顺序为 `[{regions:[{addr,size}]}, {regions:[{addr}]}, {address,size}, {address,count:size}]`，旧兼容形态保留在后两位。
   - `pyExecArgs(tmpPath)` → `{file_path: tmpPath}`。
   - `parseBytesReply(result)`：接受数组（主形态）、单对象、或字符串；逐元素取所有 `0x..` token（允许 `,`/空格分隔），按**数组顺序拼接**成 Buffer；`data` 为 `null` 或空字符串的项跳过；无数据返回 `null`。输出 16 字节/行 hex dump。
   - `parsePyExecReply(result)`：接受 `{stdout,stderr,result}`、字符串、数组；从 `stdout`（其次 `result`）取 `BYTES\s+([0-9a-f]+)`；返回 Buffer 或 `null`；若 `stderr` 非空且无 BYTES，返回 `null`（调用方据此判失败）。
   - `toToolResult(result)`：`{__toolError:true}` → `{content:String(result.message), isError:true}`；字符串/对象经 `toolFailureReason` 判定，命中 → `isError:true`；否则 `isError:false`。**主循环用它决定 `is_error`**，这是"失败必须是失败"的可单测接缝（覆盖 a 的字符串通道）。
   - `rewriteMultilinePython(command)`：识别 `python|python3 -c "..."` 且引号内含换行；拆出前导 `cd ... && `（可多段）与后缀参数，把 `-c` 内容写入给定 `tmpPath`，返回 `{command:'<prefix>python "<tmp>"', mode:'file', cwdPrefix}`；识别失败返回 `null`。
2. **错误传播双通道**（两条都要，缺一不可）：
   - `callIdaMcp`（`7508-7513`）改为 `throw new ToolCallError(msg)`，`ToolCallError` 带 `__toolError = true`；
   - `executeToolCall` 的 catch（`7502`）改为 `if (err && err.__toolError) throw err;`，其余异常仍返回字符串（保持既有工具语义）；
   - 主循环 6543-6555：`const out = toToolResult(await executeToolCall(...));`，`is_error: out.isError`；`6559` 的 catch 保持 `is_error:true`，用于类型化异常。这样即使某个工具仍返回 "工具调用失败: ..." 字符串，也会被 `toToolResult` 标记为失败；
   - `7241` 删除 `state.currentFile`，改为 `currentWorkDir || '(当前工作目录)'`。
3. **case 体抽成可注入纯函数**（解决"main.js 不能 require"）：
   - `idaGetBytes({ callMcp, writeTemp, topLevelDir }, input)`：实现完整的四形态 + 兜底 + `ToolCallError`；
   - `scanCryptoCase({ fs, scanCrypto, inferCipherStructure }, input)`：实现 `buf/size` 修复与文本输出；
   - `runBash({ exec, tempDir, cwd }, command, opts)`：实现多行 python 改写与空输出语义；
   - `main.js` 内对应 case 变成 3~5 行适配器（只负责注入 `callIdaMcp`/`fs`/`app`/`exec`）。
4. **`ida_get_bytes` 具体逻辑**：四形态依序调用；每次结果先 `toolFailureReason`，失败记 `lastResp` 继续；成功 `parseBytesReply`；兜底 `callMcp('py_exec_file', pyExecArgs(tmp))` + `parsePyExecReply`；全失败 `throw new ToolCallError('ida_get_bytes 全部形态失败（最后错误: ...）；替代方案：用 run_python 直接解析本地文件（工作目录 ' + topLevelDir + '）')`。
5. **`scan_crypto` case**：`const raw = fs.readFileSync(f); const size = raw.length;`，`7345` 改 `inferCipherStructure(raw, size, ca[0])`。
6. **`execCommandAsync`**：
   - 先 `rewriteMultilinePython`；命中则写 `.py` 到 `app.getPath('temp')`，执行 `<prefix>python "<tmp>"`，`cwd` 仍为 `currentWorkDir`，**保留 `cd /d ... &&` 前缀**；
   - 成功且 `stdout` 为空 → 返回 `命令执行结束（exit=0，无输出；stderr=<非空则附>；mode=file|shell）`；
   - `error !== null` → 附 `error.code` 与 stderr；
   - 原 `truncateOutput` 保留。

**验收（可观察，全部可在纯 Node 内执行）**

- 新增 `node tests/test_tool_result_truth.js`：
  - T1 `toolFailureReason([{addr:'',data:null,error:'Failed to parse address...'}])` 非空；`toolFailureReason([{addr:'0x401000',data:'0x55 0x8b ec'}]) === null`；`toolFailureReason([]) === null`；
  - T2 `parseBytesReply([{addr:'0x401000',data:'0x55 0x8b'},{addr:'0x401002',data:'0xec'}])` 输出含 `0000  55 8b ec`；`parseBytesReply([{addr:'x',data:null}]) === null`；
  - T3 `parsePyExecReply({stdout:'BYTES 558bec',stderr:'',result:''})` 返回 3 字节；`parsePyExecReply({stdout:'',stderr:'File not found',result:''}) === null`；
  - T4 `idaGetBytes` 注入伪 `callMcp`：只认 `regions[0].addr` → 返回 hex；只认 `{address,count}` → 返回 hex；只认 `py_exec_file`（要求 `file_path`）→ 返回 hex；全拒绝 → 抛 `__toolError === true`；
  - T5 `scanCryptoCase` 注入真实 `scanner_loader` 与一个 CUSTOM-BLOCK 样本（256 项伪随机双射、stride=4、高字节恒 0；测试先断言 `scanCrypto(sample).fingerprints.some(f=>f.constantAnalysis)` 为真）→ 输出含 `## 结构推理`，不抛 `buf is not defined`；
  - T6 `toToolResult('工具调用失败: buf is not defined')` → `isError:true`；`toToolResult({__toolError:true,message:'x'})` → `isError:true`；`toToolResult('正常输出')` → `isError:false`；
  - T7 静态断言：`main.js` 中不再出现 `state.currentFile`（正则 `state\.currentFile` 计数 0），且 `writeTemp`/`path` 参数不再出现在 `py_exec_file` 调用处（`{ path:` 0 次）。
- `node tests/test_tool_contract.js`（修改既有）新增并通过：`buildGetBytesAttempts('0x401000',8)` 四形态依次含 `regions[0].addr`、`regions[0].addr`、`address`、`address+count`；`pyExecArgs('X')` 深等于 `{file_path:'X'}`（两者从 `tool-result.js` require，不再解析内联源码）。
- 新增 `node tests/test_bash_result.js`：
  - T8a `rewriteMultilinePython('cd /d C:\\Windows\\Temp && python -c "\nimport os\nprint(os.getcwd())\nprint(111)\n"', 'C:\\t\\x.py')` 返回 `mode:'file'`、`cwdPrefix==='cd /d C:\\Windows\\Temp && '`、命令含 `python "C:\\t\\x.py"`；
  - T8b 真实执行该命令 → 输出同时含 `C:\\Windows\\Temp` 与 `111`；
  - T8c 真实执行裸多行 `python -c "\nprint(111)\n"` → 输出为 `111`，不等于任何"无输出"文案；
  - T8d 单行 `python -c "print(222)"` → `222`；
  - T8e 空输出场景文案含 `exit=0` 且不含 `成功`。
- `node tests/run_all.js` 退出码 0（本次基线：**42/42 个测试文件 + 回归题集 13/13**）。

**通用性**：判据是"返回值结构 / 对方 schema 字段名 / 真实返回形态"，对所有 MCP 外部工具生效；三个 case 体与错误映射都是纯函数，可注入、可单测，不依赖 Electron。

---

### rank 3 — IDA 会话身份绑定 + 主进程映像解析 + 落界校验

**为什么排这里**

- cnbragon：`ida_decompile(DialogFunc)` 返回 `GetDlgItemTextA(hDlg,1000,...,512)`，而目标 `0x401420` 真实字节是 `8b 1c ad 98 11 42 00`。
- not-baby-parallelism：日志「检测到 IDA MCP 已在运行（13337），跳过再次启动 IDA」后给出 `_WinMain@16`；本题是 ELF64（magic `7f454c46`），文件内不含 `WinMain`。
- QuiZow：证据文件 `mveqp9r2_函数列表.txt` 解析后 **100 项**，**不含 `0x42F038`**（`0x42F038` 只出现在 `mveqp9rk_关键函数反编译.c` 的 `sub_42F038()` 调用里）。目标 `ImageBase=0x400000`、`SizeOfImage=0x7000`、4 节；按 `VirtualSize` 越界 **62/100**，按 `SizeOfRawData` 越界 **56/100**，按映像上限越界 0。两种口径都说明数据不属于该文件。
- 跨题复用（本次实测）：`423468a1…` = **18 个文件 / 9 个 case**；`48b3020d…` = **19 个文件 / 9 个 case**（均含 plutochat、pppp 两个 ELF 题）。
- CrackMe5：复用到的库是 32 位（`_WinMain@16`），目标 Machine=0x8664。

**根因（已复核）**

- `app.js:1839-1845` 只做 `checkPort(13337)`；`3999-4000` 先打印「IDA打开文件」再启动。
- 全仓 `server_health` / `list_instances` / `open_file` **零调用**。
- **没有现成的映像范围来源**：`analyze_structure` 只做分组密码骨架推断（`main.js:7458-7481`）；`app.js` 中 `SizeOfImage`/`readUInt32LE` 均 0 次；主进程 `read-file` 以 utf8 读取（`main.js:3180`）；渲染层 `path.resolve` 0 次且无 `require('path')`。

**改什么**

1. 新增 `electron/binary-map.js`（纯函数）：`parseImageMap(buf)` → `{format:'pe'|'elf', imageBase, sizeOfImage, sections:[{name, va, vsize, fileOff}]}`；PE 读 `e_lfanew → OptionalHeader.ImageBase/SizeOfImage` 与节表；ELF64 读 `PT_LOAD`（`p_vaddr/p_memsz`）。
2. 新增 IPC：
   - `ida-identity` → 调 `server_health`，返回 `{success:true,input_path,idb_path,module,imagebase}` 或 `{success:false,error}`；
   - `file-image-map` → 二进制读取并 `parseImageMap`。
   - **路径规范化只在主进程做**（`path.resolve` + 小写 + 反斜杠归一），渲染层只传原始路径。
3. `app.js` 的复用改为 `ensureIdaForFile(fileToOpen)`：端口未监听 → `launch`；端口监听 → `ida-identity`：
   - `success:false` → **强制重载**（"不知道是谁"是最危险状态），日志 `[IDA] 身份未知，按安全策略重载`，优先 `open_file {file_path,switch:true,autonomous:true}`；`open_file` 不可用时按 PID 结束实例后重启；
   - `success:true` 且路径一致 → 复用并记 `[IDA] 身份校验通过: <basename>`；不一致 → `open_file` 重载，日志含双方路径。
4. 结束实例**按 PID**：不用 `taskkill /IM ida.exe`。`spawnArgv` 的 GUI 分支当前不回传 PID，改为启动前后对 `ida.exe` 做 PID 差集（`wmic process where "name='ida.exe'" get ProcessId,CreationDate`），只结束差集内的进程；日志打印被结束的 PID。**`open_file` 会新起实例**：重载后需等待新实例注册完成，并把旧 PID 记入 `retiredPids`，落界校验重试时不得回连旧实例。
5. 落界校验：`filterFunctionsInImage(funcs, map)` 返回 `{kept, dropped}`（判定用 `imageBase+va <= addr < imageBase+va+vsize`）；`app.js:7769-7791`、`7925-7934` 与函数列表落盘前都过一遍；`dropped` 非空 → `is_error` + 一次重载重试，日志 `[IDA] 越界地址 0x... 不在映像 [...]，判定为串台`。

**验收（可观察）**

- 新增 `node tests/test_binary_map.js`：QuiZow 样本解析出 `ImageBase=0x400000`、`SizeOfImage=0x7000`、4 节；`filterFunctionsInImage` 返回 `kept=38/dropped=62`（VirtualSize 口径）；pppp 返回 `format:'elf'` 且 `sizeOfImage = max(p_vaddr+p_memsz) - min(p_vaddr)`；非法/截断输入返回 `null` 不抛。
- 新增 `node tests/test_ida_identity.js`：`decideIdaAction({listening, identity, samePath})` 四态——`listening:false → launch`、`identity.success:false → reload(reason:'unknown')`、`samePath:false → reload`、`true → reuse`；日志文案含 `身份未知`/`目标不一致`/`身份校验通过`；`planPidClose(before, after)` 返回差集且不包含 `before` 中已存在的 PID。
- 实跑 cnbragon / not-baby-parallelism / QuiZow：不再出现"跳过再次启动 IDA"而无后续身份结论；`cases/*/evidence/*函数列表*.txt` 的 md5 与其它题不同（当前 9 个 case 共用同一份）。
- `node tests/run_all.js` 退出码 0。

**通用性**：判据是"分析器自述的加载对象 vs 当前目标文件"与"返回地址 vs 当前映像范围"，与题目内容无关；主进程 PE/ELF 解析可复用于任何需要映像范围的功能。

---

### rank 4 — 平台题目契约贯穿流程 + 零指纹误导句的真实改点

**为什么排这里**

- 解析 **22 份 2026-10-19 会话第 0 条 prompt**（长度 ≥5000 字符那批）实测：`## 题目描述（平台官方` 与 `## 同包伴生文件` **22/22 均为 false**；not-baby-parallelism 的 prompt 里没有 `Run with`。应用日志不含 prompt 正文，因此不能作为证据，本版全部改用 session JSONL。
- CrackMe3 题面「请包上 flag{} 提交」存进了 `state._platformChallengeDesc`，但 `app.js:8320-8329` 的 8 条 `shapeRules` 对它命中为空。

**根因（已复核，修正上一版的错误定位）**

- `app.js:1009` 写 `_platformChallengeDesc` → `1082` 调 `analyzeFile` → **`678-680` 同时清空 `_platformChallenge`、`_platformChallengeDesc`、`_platformFiles`**。
- zip 手包：`1460` 写 `_platformFiles` → `1468` 再调 `analyzeFile(main)` → 再次清空。
- **零指纹误导句有两处**：① `main.js:2620-2627` 在 `summary` 里 push `(未发现算法指纹)` + note「本层极可能是**壳/加载器/decoy**」，经 `app.js:8360-8361` 拼进 `algHint`（实测 CrackMe2 首条 prompt 开头即含该句）；② `app.js:7982-7983`（`autoSolveBinaryFlag` 的提示词）还有一份独立硬编码的同义句。`app.js:8399-8405` 因 `summary` 永不为空而是**死分支**，改它无效。

**改什么**

1. `analyzeFile`（`678-680`）清理段加守卫：`if (!opts.keepPlatformContext) { _platformChallenge=null; _platformChallengeDesc=''; _platformFiles=null; }`；平台流程 `1082` 与 zip 手包 `1468` 都传 `{keepPlatformContext:true}`；用户拖入新文件仍清空。
2. 平台流程在 `analyzeFile` 之后用局部变量恢复**三项**：`_platformChallenge`（题名，`failureHintSection` 用）、`_platformChallengeDesc`、`_platformFiles`；抽成纯函数 `restorePlatformContext(state, saved)` 以便单测。
3. 新增 `parseWrapDirective(desc)` → `{template:'flag{%s}', evidence}` 或 `null`；新增 `applyWrap(value, tpl)` → 包装后的字符串（`tpl` 为 `flag{%s}` 时返回 `flag{value}`）；写入 `state._platformWrapTemplate`，在两处提示词（`8360` 所在与 `7982` 所在）都追加 `按题面要求包外壳：<template>`。
4. 零指纹措辞（两处一起改）：
   - `main.js:2620-2627` 的 note 改为中性：「未识别到已知算法常量；可能是自实现算法、使用轮常量、或算法在其它层」；
   - `app.js:7982-7983` 与 `app.js:8360` 的注入按 `payloads.length` 分支：`payloads.length===0` → 「本层无内嵌载荷，优先在本层找逐字节比较/位运算循环」；`>0` → 保留原有的 loader/下一层提示。
   - 标签 `(未发现算法指纹)` **保留**（下游测试与日志依赖），只是不再附会"壳/decoy"。
5. 伴生文件：`_platformFiles` 在 Tool-Use 提示词中始终列出；小文本内联（既有 `8300-8309`）不变。

**验收（可观察）**

- 新增 `node tests/test_platform_context.js`：
  - `parseWrapDirective('注意：得到的 flag 请包上 flag{} 提交')` → `template==='flag{%s}'`；`applyWrap('771535', t) === 'flag{771535}'`；`parseWrapDirective('Run with pppp -n ...') === null`；
  - 状态机夹具（`new Function` 抽出 `restorePlatformContext` 与清理守卫）：`keepPlatformContext:true` 路径保留 desc/files/challenge 三项；缺省路径三项全清空；zip 顺序（写 files → analyzeFile(keep) → 恢复）后 `_platformFiles` 仍含 `flag.out`；
  - 静态断言 `app.js:1082`、`app.js:1468` 两处调用都带 `keepPlatformContext:true`；
  - 零指纹夹具：`payloads=[]` 时生成的提示词含「本层无内嵌载荷」，不含「极可能是**壳」；`payloads` 非空时含 loader 提示。
- 下一次平台实跑：会话第 0 条 prompt 出现 `## 题目描述（平台官方` 与 `## 同包伴生文件`；not-baby-parallelism 出现 `Run with`；CrackMe3 类题面日志出现 `[平台] 检测到包装指令 → flag{...}`。
- `node tests/run_all.js` 退出码 0。

**通用性**：题面是所有平台题的最高价值检索目标；状态生命周期与题目内容无关；包装指令与零指纹措辞都按模式/载荷存在性判定，不引用题名。

---

### rank 5 — 末公里候选闭环：契约驱动 verified、重试提示必须被消费

**为什么排这里**

- CrackMe3：`findings.json` 的 `notes[8]`（`求解结果(修正重试)`）原文含 `[FLAG]771535[/FLAG] [VERIFY]{...}`；`extractFlags` 走 `contractRe` 抽出 `771535` 并写进 `Flag` note（`9966`），而 `recordFlag`（`9006-9009`）用 `looksLikeFlag` 丢弃 → `flags: []`。实测 `looksLikeFlag('771535')===false`、`looksLikeFlag('flag{771535}')===true`。
- **`vr.hits` 的真实内容是 shellcode hex**：`p1-CrackMe3-1792382026960.log:125` 为 `命中中间值/密钥（非 flag）：83ec18b065...`；`771535` 是契约的 `key`（本次解码 `solve_enum_mvepz7z1.py` 内嵌 base64 得到 `{algo:'custom',key:'771535',expected:'83ec18b065b16388442404'}`）。
- 重试链：`app.js:8568` 的第二次 `finalizeSolve` 返回值未接收，`8571` 直接 return；日志第 134 行生成定向提示却无第三轮。
- 归因：`attributeFailure` 只在 `runHypotheses`（`11012`）内调用，`verifyAndRecord` 忽略其返回值（`9965`），`finalizeSolve` 拿不到；但 `finalizeSolve:10237` 已用 `findDecodedLayer(vr.rawOutput)` 并在 `10244-10247` 给出「写盘为新文件 / 不要换算法、不要换 key」（源码实有，实测命中；`写盘接力` 不存在）。

**改什么**

1. `newFindings`（`app.js:38-52`）增加 `answers: []`；`recordAnswer(value,{source,verified,evidence})` 做懒初始化（`if (!Array.isArray(findings.answers)) findings.answers = []`），不经 `looksLikeFlag`。
2. **verified 判定（严格、契约驱动）**：值 `V` 记为 `verified:true` 当且仅当同时满足：
   - `V ∈ extractFlags(aiText)`（AI 用 `[FLAG]` 或 flag 形态明确把它当答案提出）；且
   - 存在契约 `c` 使 `String(c.key).trim() === V`，且该契约在本地复现中产生至少一个命中（`vr.hits.length > 0`）。
   - 其余候选一律 `verified:false`。这样 CrackMe3 的 `771535` 会被标 verified（AI 写了 `[FLAG]771535`，含该 key 的契约复现出 shellcode），而任意"顺手给的 key"不会被误标。
3. 提交路径（`app.js:1086-1099`）：收集 verified 的 flag 形态 + verified 的 answers；后者按 `state._platformWrapTemplate` 包装，无模板时只尝试一次 `flag{%s}`，失败即降级 `verified:false` 并记日志 `[平台] 裸答案包装后提交未通过，已降级`。
4. 重试改为循环（`app.js:8550-8574`）：`let fin2; for (let round = 1; round <= 2; round++) { ... if (!fin2.retryPrompt) break; }`，每轮日志 `[重试] 第 N 轮定向提示已消费`，达到上限记 `[重试] 已达上限（2 轮）`；`reason` 区分 `验证失败（首轮）`/`验证失败（第 N 轮）`。
5. 机器码优先级：在 `10146` 分支内、`10159` 之前算 `const dlEarly = findDecodedLayer(vr.rawOutput || '')`；`dlEarly.count > 0` 时**跳过** `classifyIntermediateValues`，改用既有 `10238-10249` 的 `decodedNote` 文案构造 `retryPrompt`（即使 `vr.failureFeedback` 为空也返回），日志 `[验证闭环] 机器码结论优先于通用 hex 分类`。不再引用 `attributeFailure`。

**验收（可观察）**

- 新增 `node tests/test_answer_shape.js`：
  - **真实形态夹具**：`vr={hits:['83ec18b065b16388442404'],contracts:[{algo:'custom',key:'771535',expected:'83ec18b065b16388442404'}]}`，`aiText` 含 `[FLAG]771535[/FLAG]` → `findings.answers` 含 `{value:'771535',verified:true,source:'verify-contract-key'}`；mock 提交收到 `flag{771535}`；日志含 `[验证闭环] 裸答案经平台外壳规则包装`；
  - 反例 A：同一夹具但 `vr.hits=[]` → `771535` 仅 `verified:false`，不进入提交；
  - 反例 B：`aiText` 不含 `[FLAG]771535`（仅 contract.key）→ 不标 verified；
  - 反例 C：`contracts` 里没有 key 等于该值 → 不标 verified；
  - `newFindings()` 返回值含 `answers: []`（静态断言）。
- 重试：伪 `claudeChat` 第 2 次返回带 `retryPrompt` 的结果 → 调用 3 次且日志含「第 1 轮」「第 2 轮定向提示已消费」；第 3 次不再追加；`reason` 文本随轮次变化。
- 机器码优先级：`vr.rawOutput` 含 `[MISS] attempt=0 algo=x keyenc=ascii stage=verify result=no-flag preview=55 89 e5 ... c3` 且 `vr.hits=['deadbeef']` → 返回的 `retryPrompt` 含 `写盘为新文件` 与 `不要换算法、不要换 key`，不含 `作为下一层的 ciphertext`，日志含「机器码结论优先于通用 hex 分类」。
- `node tests/run_all.js` 退出码 0（含既有 `test_printable_wrap.js`、`test_intermediate_advance.js`）。

**通用性**：所有"答案是口令/序列号/裸字符串"或"平台要求自行包壳"的题共用同一通路；判据是"AI 明确提出的候选 + 含该 key 的契约在本地复现成功"，与题名和具体值无关，不会把未验证猜测标成已验证。

---

### rank 6 — 指纹扫描：散落 MD5 K 常量 + 真实 lane 布局变表 + 零指纹措辞

**为什么排这里**

- CrackMe2：真实算法是 MD5（`sub_4016B0`），扫描器实测输出 `(未发现算法指纹)`、`payloads=0`。
- cnbragon：真实 S 盒在文件偏移 **0x1fb98**，dword 为 `00 70 70 70` / `00 82 82 82`（字节 0 恒 0，字节 1-3 承载值且三者相等），256 项双射。

**根因（已复核）**

- `main.js:580` 只有连续 IV `01 23 45 67 89 ab cd ef`；CrackMe2 中该串不存在。64 个 K 常量**散落**（首个 `0xd76aa478` 小端在 0xB2F；偏移 2863,2871,2899,2927,...），按 K 顺序的最长有序 run 仅 27（远非"连续 8 个表"），用 `Buffer.concat(8 个 K)` 匹配 run=0。**因此"连续 ≥8"必然 0 命中。**
- 校准（同一检测器，本次实测）：
  - CrackMe2：`K 命中 64/64`，`IV 命中 0/4`；
  - ntoskrnl / ntdll：`K 命中 64/64`，`IV 命中 4/4`；
  - KanxueCTF2016Keygenme、CrackMe5、notepad、calc、kernel32、msvcrt、crypt32、bcrypt、wininet、ole32、combase、ucrtbase：`K 命中 0`。
  → 判据 `hits>=48 && ivHits<=1`。
- S 盒：`main.js:2436-2438/2457` 的 `highBytesZero` 与真实布局冲突；`2470` 的"值在低字节"也错（真实值在 lane 1）。
- 零指纹结论：`main.js:2620-2627` + `app.js:7982/8360`；D 段误报测试只覆盖 high 与"疑似非 low"，新增 medium 会漏检。

**改什么**

1. `detectMd5RoundConstants(buf)`（纯函数）：计算 64 个标准 K 的小端字节，统计 `hits`；再统计 MD5 IV 四值（LE 与 BE 都试）命中数 `ivHits`；返回 `{hit: hits>=48 && ivHits<=1, hits, ivHits}`。命中时 summary 写 `MD5`（high），evidence 写 `K 常量命中 N/64，IV M/4`。
2. `detectLaneBijectionTables(buf, maxHits=6)`（纯函数）：
   - 以 4 字节对齐的 dword 为单位，对每个 lane 用滑动 XOR/SUM 预筛 256 项置换；
   - 通过后要求：**恰好一个 lane 是 256 双射**；其余 lane 在窗口内恒定**或**与该 lane 逐项相等（同时覆盖 `00 v v v` 与 `v 0 0 0`）；
   - 排除恒等表与 `a*i+b mod 256` 仿射表；
   - 返回 `{off, valueLane, constLanes}`；`item.stride=4`，`head` 从**值 lane** 取。
   - 校准（本次实测）：cnbragon 命中 `0x1fb98`（lane 1/2/3）、`0x1ff98`、`0x20398`、`0x20798`；ntdll/kernel32/msvcrt/notepad/electron(前 8MB) **0 命中**；8MB 约 10~25ms。
3. `main.js:2457` 替换为 lane 检测（保留 `isTrivialTable`）；`2470` 的 strideNote 改为「值在 lane N」。
4. 零指纹措辞：`main.js:2620-2627` 的 note 改中性；`app.js:7982-7983` 与 `app.js:8360` 按 `payloads.length` 分支（与 rank 4 同一改点，**两处都要改**）。标签 `(未发现算法指纹)` 保留。
5. `tests/test_scan_fingerprints.js` 的 D 段改为：对每个真实二进制断言 `summary` 中任何置信度的 `CUSTOM-BLOCK` 命中数为 0（显式覆盖 medium）。

**验收（可观察）**

- `node tests/test_scan_fingerprints.js`（修改既有）新增并通过：
  - **MD5（散落布局）**：把 64 个 K 小端按真实间隔（每个之间插入 5~30 字节的 `0x05/0xC1` 等单字节）写入临时文件、不含 IV → `summary` 含 `MD5`；
  - **反例**：同样的 K 再补齐 4 个 IV（LE 连续）→ `summary` 不含 `MD5`（模拟 ntoskrnl/ntdll）；
  - **变表（真实布局）**：`for i: writeUInt32LE(0x00000000 | perm[i]<<8 | perm[i]<<16 | perm[i]<<24)`（字节 `00 v v v`）→ `summary` 含 `CUSTOM-BLOCK`，该条 `stride=4` 且 `valueLane===1`；
  - **变表（反向布局）**：`perm[i] | 0` 写为 dword（字节 `v 00 00 00`）→ 同样命中；
  - **误报**：ntdll/kernel32/msvcrt/notepad/electron 上 `CUSTOM-BLOCK`（含 medium）命中数为 0；
  - **零指纹**：既有 C 段改为断言 `algo === '(未发现算法指纹)'` 且 `note` 含「未识别到已知算法常量」、**不含**「极可能是**壳」。
- 用 `tests/scanner_loader.js` 扫 CrackMe2 样本：`summary` 含 `MD5`、`note` 不含「极可能是**壳」；扫 cnbragon 样本：`summary` 含 `CUSTOM-BLOCK`，`fingerprints` 中 `0x1fb98` 条目 `stride=4`。
- CrackMe2 重跑：prompt 不含「本层极可能是**壳」；日志 `[算法扫描]` 行可以仍含标签 `(未发现算法指纹)`（已不再是 MISMATCH 判据），但 note 文本为中性。
- `node tests/run_all.js` 退出码 0。

**通用性**：内联轮常量与"多 lane 存放的双射表"是哈希/自定义分组密码的常见编译产物；阈值（K≥48、IV≤1、排除仿射）由 15 份系统二进制与 2 个真实样本校准，不引用题名或路径。

**实施记录（2026-10-19，全部已落地并验证）**

| 计划项 | 落地位置 | 与计划的差异 / 原因 |
|---|---|---|
| 1 `detectMd5RoundConstants` | 新增 `electron/crypto-detect.js` | 额外返回 `firstOffset`（summary 里要写首个 K 的偏移，否则 AI 无法定位） |
| 2 `detectLaneBijectionTables` | 同上 | **判据由"恰好一个 lane 双射"改为"双射 lane 逐项相同 + 其余 lane 恒定"**。`00 v v v` 的 lane 1/2/3 三个都是双射且互为镜像，按原判据会全部拒绝（cnbragon 实测 0 命中） |
| 2' 相位 | 同上 | 小文件（≤16MB）额外扫 1/2/3 相位；>64MB 直接跳过（通用程序量级）。50MB 实测 325ms |
| 3 接入扫描器 | `main.js:2447` 连续字节分支保留 stride 1/2；新增 `2.5)` lane 分支 | 把 stride=4 从"高字节全 0"分支里摘出来，改走 lane 检测；`valueLane=0` 的 dword 数组（Disguise 形态）仍由 lane 检测覆盖 |
| 3' 读表起点 | `analyzeCustomBlockConstants(..., valueLane)` | 新增参数：`sboxOff` 传的是**值读取起点**（窗口+lane），CK/FK 搜索用 `windowOff` 按 4 字节对齐，否则会扫出 unaligned 假候选 |
| 4 摘要 | `main.js:2617` 起 | `MD5-K` 命中写 `MD5`/high，证据 `K 常量命中 N/64，IV M/4，首个 K @off`；纯 `MD5-IV` 仍为 medium，两者不重复出条 |
| 4' 零指纹 bug | `main.js:2631` | **顺带修掉一个真 bug**：原代码 `out.payloads` / `out.embeddedPE` 从未被赋值（载荷在局部变量 `payloads`），`hasPayload` 恒 false → 零指纹永远走"本层无载荷"分支 |
| 4'' 措辞 | `main.js` 零指纹 note + `app.js:8249` / `app.js:8699` | 三处统一为中性措辞，并删掉"扫描器目前只认连续 IV"这句已经过时的自述 |
| 5 测试 | `tests/test_scan_fingerprints.js` | C 段改中性断言；新增 D（散落 MD5）、E（lane 布局）、G（真实样本）三段；F 段对 ≤16MB 的真实二进制**零容忍** CUSTOM-BLOCK，>16MB 仍只断言无 high（electron.exe 自带密码库，其置换表是真实存在的） |

**验收实测**

- `node tests/test_scan_fingerprints.js` → **32 通过 / 0 失败**（含 CrackMe2 真实样本：MD5/high、K 64/64、IV 0/4；cnbragon 真实样本：`0x1fb98` stride=4 valueLane=1）。
- `node tests/_rank6_verify.js` → **15 通过 / 0 失败**：阈值边界 32/47/48/64+IV、lane 2/3 形态、噪声 lane 拒绝、连续字节 S 盒未回归、50MB 性能、15 份系统二进制 0 误报。
- `node tests/run_all.js` → 退出码 **0**，单元测试 **49/49**，回归题集通过。
- 校准数据（本机实测）：`ntdll` K 64/IV 4、`ntoskrnl` 64/4、`shell32` 64/4、`electron.exe` 64/4（均为库实现，不判内联）；其余 12 份 K 0/IV 0；`combase`/`advapi32` 各 1 个 IV 但无 K（不误判）。lane 检测在这 16 份上全为 0。

---

## 三、已验证事实

### 3.1 P1 定向复验（`p1-verify-summary.json`，`kind=p1-directed`）

| 指标 | 结果 | 出处 |
|---|---|---|
| 复验题数 | 7 | `total: 7` |
| 解出 | 1 道：PlutoChat `sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}`，平台 `accepted:true`、`earned_points:100` | `solved:1`；`autotest-logs/p1-PlutoChat-1792383206876.log:117` |
| augmentSynth | 触发 1 次（CrackMe3），`工具追加 30 组补充维度` | `augmentFired:1` |
| 中间值自动推进 | 触发 0 次 | `intermediateFired:0` |
| 其余 6 道 | `no-verified-flag`，未提交 | 各题 `flagLines` |

### 3.2 已修复的 4 个通用缺陷（逐条核对代码）

1. `synthesizeHypotheses` 不再硬性要求 ciphertext：`src/js/app.js:10675`。
2. 自动推进不把猜测标为已验证：`src/js/app.js:10172-10193`。
3. 定向驱动每题用新端口并清残留进程：`tests/_p1_verify.js:24-26`、`55-58`。
4. 点名优先不再被去重过滤：`src/js/app.js:973-980`。

### 3.3 本次修订阶段实测（全部在本机执行，均为可直接复跑的内联命令）

| 复核项 | 命令 | 实测输出 |
|---|---|---|
| 去重误判（地址） | `node -e "const fs=require('fs');const s=fs.readFileSync('electron/main.js','utf8');eval(s.slice(s.indexOf('// 脚本归一化'),s.indexOf('// 工具调用落盘日志')));const a='disasm 0x1200:0x1400 @0x401200',b='disasm 0x1f00:0x2100 @0x401f00';console.log(scriptSimilarity(normalizeScript(a),normalizeScript(b)),/401200/.test(normalizeScript(a)))"` | `1 false` |
| CrackMe5 真实相似度 | 读上述会话索引 115/119/31 的 `script` 后同法计算 | `115vs31=0.8808`、`119vs31=0.8910`、`115vs119=0.8627`（日志只打印 `>88%`，数值为本地复算） |
| not-baby 索引与相似度 | 同法读会话 04-02 索引 47/49/51 | `47vs49=1.0000`、`47vs51=0.9709`、`49vs51=0.9709`；去重结果索引 52，AI 文本索引 53 |
| 地址 containment | 抽 `0x[0-9a-f]+` 且 ≥0x1000，按 min 分母 | `cm5 115/31=0.000`、`119/31=0.000`、`115/119=1.000`；`nb 47/49=0.200`、`47/51=0.333` |
| CrackMe5 索引 36 覆盖 | 取 `content` 中 243 条指令地址 | `0x140001400–0x1400017ee`；区间 `0x14000159a-0x1400015d8` 内 17 条（`1400015a0`…`1400015d5`），含 `1400015b7: movsx ecx, byte ptr [r8]` |
| `isBad` 失效 | `node -e "const r=[{addr:'',data:null,error:'x'}];const f=x=>!x||/missing|invalid|error|失败/i.test(String(x).slice(0,300));console.log(f(r),f(JSON.stringify(r)))"` | `false true` |
| `String(obj)` 失效 | `node -e "console.log(String({result:'',stdout:'BYTES 558b',stderr:''}))"` | `[object Object]` |
| 主进程无 `state` | 正则统计 `let/const/var state` + `node -e "try{state&&state.currentFile}catch(e){console.log(e.constructor.name,e.message)}"` | 0 处；`ReferenceError state is not defined` |
| main.js 不可 require | `node -e "try{require('./electron/main.js')}catch(e){console.log(e.constructor.name,e.message)}"` | `TypeError Cannot read properties of undefined (reading 'getPath')` |
| `looksLikeFlag` 丢弃裸答案 | `node -e "const s=require('fs').readFileSync('src/js/app.js','utf8');eval(s.slice(s.indexOf('const DECOY_FLAG_RE'),s.indexOf('function recordFlag')));console.log(looksLikeFlag('771535'),looksLikeFlag('flag{771535}'))"` | `false true` |
| CrackMe3 契约 | 解码 `cases/CrackMe.exe_ee7ba0e8/scripts/solve_enum_mvepz7z1.py` 内嵌 base64 | `[{algo:'custom',key:'771535',expected:'83ec18b065b16388442404',ctLen:256}]`；日志 `p1-CrackMe3:125` 的 hits 为 shellcode hex |
| `scan_crypto` 作用域 | 抽取 `case 'scan_crypto'` 段正则统计 | `defines buf:false / uses buf:true / defines size:false / uses size:true` |
| `constantAnalysis` 条件 | 读 `main.js:2483-2497`、`2633-2665` | 仅 CUSTOM-BLOCK（分析成功）或 AES/SM4 且 `sk` 非空；标准 SM4 的 `sk=null` |
| microcompact | `node -e "const R=require('./electron/agent-runtime.js');console.log(R.COMPACTABLE_TOOLS.has('ida_list_functions'),R.COMPACTABLE_TOOLS.has('ida_find_strings'));...12 条 ida_find_strings,keepRecent=4"` | `true false`；`{"cleared":8,"total":12,"kept":4}`；函数体内 `COMPACTABLE` 出现 0 次 |
| bash 多行（裸） | `node -e "const{exec}=require('child_process');exec('python -c \"\nprint(111)\n\"',{shell:'cmd.exe'},(e,o,s)=>console.log(e===null,JSON.stringify(o),JSON.stringify(s)))"` | `true "" ""` |
| bash 多行（cd 前缀） | 同上，命令 `cd /d "C:\\Windows\\Temp" && python -c "\nimport os;print(os.getcwd())\nprint(111)\n"` | `true "" ""` |
| MD5 K 分布 | 64 个 K 小端逐值 `indexOf` + IV 命中 + 最长有序 run | CrackMe2 `64/0/27`；ntoskrnl、ntdll `64/4/18`；其余 12 份系统库 `0/0/-` |
| cnbragon 表布局 | 读 `0x1fb98` 起 16 字节并逐 lane 统计 distinct | `00707070 00828282 002c2c2c 00ececec`；lane0 distinct=1，lane1/2/3 distinct=256 且逐项相等 |
| lane 检测校准 | 提案算法跑 cnbragon + ntdll/kernel32/msvcrt/notepad/electron(8MB) | cnbragon `0x1fb98/0x1ff98/0x20398/0x20798`；系统二进制 0 命中；8MB 10~25ms |
| QuiZow 越界 | 解析 `mveqp9r2` 函数列表 + PE 节表 | 100 项、`has42f038=false`；VirtualSize 越界 **62**，SizeOfRawData 越界 **56**，映像上限越界 0；ImageBase 0x400000 / SizeOfImage 0x7000 |
| 跨题证据 | 遍历 `cases/*/evidence/*` 求 md5 统计 | `423468a1…` 18 文件/9 case；`48b3020d…` 19 文件/9 case |
| 平台描述未进 prompt | 解析 22 份 2026-10-19 会话第 0 条（长度 ≥5000） | 22/22 `## 题目描述（平台官方` 为 false；22/22 `## 同包伴生文件` 为 false；not-baby `Run with` 为 false |
| 无现成映像解析 | 统计 `analyze_structure` 实现 + `app.js` 的 `SizeOfImage`/`readUInt32LE`/`path.resolve` | 只做骨架推断；三者各 0 次 |
| 测试文件存在性 | `fs.existsSync` 逐个检查 | `test_tool_result_truth.js`、`test_bash_result.js`、`test_ida_identity.js`、`test_platform_context.js`、`test_answer_shape.js`、`test_binary_map.js` 均 **MISSING** |
| 全量测试基线 | `node tests/run_all.js` | **42/42 个测试文件通过，回归题集 13/13**，退出码 0 |
| 插件真实字段 | 读 `ida_mcp/utils.py:50-55`、`api_memory.py:72-90`、`api_python.py:205-247`、`api_core.py:351-367`、`api_discovery.py:281/351` | `regions[].addr`；`{result,stdout,stderr}`；`file_path`；`idb_path/input_path/module/imagebase`；`list_instances/open_file` |

---

## 四、不再重复的项

| 项 | 状态 | 依据 |
|---|---|---|
| P0.1 分层收尾 | 已完成 `15d3d7e` | `OPTIMIZATION-PLAN.md:10` |
| P0.2 骨架先行 | 已完成 `199dd80` | 同上 `:11` |
| P0.3 零新数据拦截 | 已完成 `199dd80` | 同上 `:12` |
| P0.4 中间值形态识别 | 已完成 `196b96d` | 同上 `:14` |
| P0.4b 明文自动加外壳 | 已完成 `af0011b` | 同上 `:15` |
| P1 契约枚举 + augmentSynth | 已完成 `8d74a87`/`4a09987`，本轮触发 1 次 | git log；`p1-verify-summary.json` |
| P2 中间值自动推进 | 已完成（`app.js:10161-10228`），本轮 0 次触发 | 代码；`p1-verify-summary.json` |
| Burp 链路 | 已完成 `20c2c2c`/`97df62b`/`8322b11`/`971ef5c` | git log |
| hex 不误包外壳 | 已完成 `7964b72` | git log |

---

## 五、实施顺序与交付物

```
rank 2（工具结果可信性）  ← 下一轮实施；是 rank 1/3 的取证前提
rank 1（去重地址目标指纹）
rank 3（IDA 身份 + 映像解析）
rank 4（平台契约贯穿 + 零指纹措辞）
rank 5（末公里候选闭环）
rank 6（指纹扫描）
```

交付物清单（新增文件）：

| 文件 | 用途 | 对应 rank |
|---|---|---|
| `electron/tool-result.js` | 失败判定/请求构造/返回解析/case 体（可注入） | 2 |
| `electron/script-dedup.js` | `scriptTargets`/`targetsOverlap`/`checkDedup` 状态机 | 1 |
| `electron/binary-map.js` | PE/ELF 映像解析与落界过滤 | 3 |
| `tests/test_tool_result_truth.js` | T1–T7 | 2 |
| `tests/test_bash_result.js` | T8a–T8e | 2 |
| `tests/test_parse_fixtures/*` | 真实返回形态夹具 | 2 |
| `tests/test_ida_identity.js` | `decideIdaAction`/`planPidClose` | 3 |
| `tests/test_binary_map.js` | PE/ELF 解析与越界 | 3 |
| `tests/test_platform_context.js` | 包装指令 + 状态生命周期 | 4 |
| `tests/test_answer_shape.js` | 契约驱动 verified + 重试循环 | 5 |
| `tests/fixtures/dedup-cm5-115.js`、`dedup-cm5-31.js` | 真实去重脚本快照 | 1 |

修改的既有文件：`electron/main.js`、`electron/agent-runtime.js`、`src/js/app.js`、`tests/test_script_dedup.js`、`tests/test_agent_runtime.js`、`tests/test_scan_fingerprints.js`、`tests/test_tool_contract.js`。

---

## 六、底线

- 所有判据基于"输入结构 / 返回结构 / 目标地址集合 / 映像范围 / 常量分布"，不写题名、样本路径、具体 flag 或地址特判。
- 每项都有纯函数接缝 + 单测断言 + 日志可观察字符串；无法在 Node 内直接跑的（真实平台 prompt）用"下一次定向复跑的会话第 0 条"验收。
- 每项改完必须跑 `node tests/run_all.js`（当前基线 42/42 + 回归 13/13）并通过，再对 6 道题定向复跑，逐题记录 `[去重]`、`[工具失败]`、`[IDA]`、`[平台]`、`[验证闭环]` 日志行与提交结果。

---

## 七、独立复核 7 个问题的修复记录（2026-10-19）

复核结论为 `matchesPlan=true` 但 `risky=true`、7 个问题。逐条修复如下，全部有回归用例。

| # | 问题 | 修法 | 回归用例 |
|---|---|---|---|
| 1 | 多行 Python 改写在"成功"路径静默丢弃命令尾部（`&&` / 重定向 / 位置参数） | 改用"与开头配对"的引号定位，尾部原样拼回改写命令（`tail`），不再丢弃 | `test_bash_result.js` T8f/T8g（真实执行：重定向写出文件、`sys.argv` 收到参数） |
| 2 | hexdump 的地址列被当成数据字节 | `bytesFromData` 先按 hexdump 行解析（地址 + 字节 + 可选 ASCII 列），只取字节列；`0x` 后 5+ 位视为地址 | `test_tool_result_truth.js` T9 |
| 3 | 失败前缀表不完整，真实失败仍 `isError:false` | 补齐 `搜索失败`/`浏览器MCP搜索失败`/`ADB命令失败`/`读取失败` 等，并加行首 16 字符内"失败:"兜底 | T10 |
| 4 | `error:0`/`error:false` 被误判失败 | 新增 `hasErrorValue`：0/false/null/'0'/'false' 都不算错误 | T11 |
| 5 | 多段返回中部分段 `data:null` 导致整体拒绝 | `idaGetBytes` 改为**先解析字节、再判失败**，避免提前 `continue` 丢掉已拿到的段 | T12 |
| 6 | 兜底 `.py` 从不删除；参数形态与工单措辞不一致 | `finally` 里删除；`buildGetBytesAttempts` 补齐"无 size 的对象形态"并保留裸串形态 | T13/T14、`test_tool_contract.js` H 段 |
| 7 | 主循环 `isError` 分支不消费 advisory，建议滞留到无关错误 | 在失败分支内 `takeAdvisories()` 并追加到本条 tool_result | 静态行为修复（`main.js` 失败分支） |

**修复后基线**：`node tests/run_all.js` → 单元测试 **44/44**、回归题集 **13/13**，exit 0。
`test_tool_result_truth.js` 65 项、`test_bash_result.js` 19 项、`test_tool_contract.js` 64 项全部通过。

**仍未验证**：这 7 项修复都是机制级验证，尚未在真实平台重跑六道题确认解出率变化。

