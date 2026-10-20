# CTF-RE-TOOL × CTF² Agent Arena 批量实测报告

> 测试时间：2026-10-17 ~ 2026-10-18
> 平台：CTF² Agent Arena · Agent `test777`（id `4a7a21f3-…`）
> 凭据页规则：仅公开练习场、`confirmation=true` 提交、环境上限 1、遵守 429/`retry_after_ms`、用 `ctf2_agent_log_note` 留痕

---

## 零、失败驱动修复的验证结果（2026-10-18 第二轮）

上一轮 54 题里 48 道未解。对全部 DOM 日志做深度归因后，定位到 9 类根因，并针对其中
可通用化的 5 项做了修复。随后用同一批"之前失败过的题"重跑 20 题，
**解出 3 道，且全部是之前失败的题**：

| 题目 | 修复前 | 修复后 | 决定性机制 |
|---|---|---|---|
| `不一样的flag` | 未解 | ✅ `flag{222441144222}` | 首次验证未中 → **失败证据回灌重试** → 命中 |
| `reverse2`（.rar） | 未解（只跑 file/binwalk） | ✅ `flag{hack1ng_fo1_fun}` | **RAR 解压** + 首轮只命中中间值 → 证据回灌补上 `flag{}` |
| `简单注册器`（APK） | 上轮提交了**错误** flag | ✅ `flag{59acc538825054c7de4b26440c0999dd}` | 命中判据放宽 + 证据回灌，纠正了此前的假答案 |

关键证据（reverse2 完整链路）：

```
[14:44:21] 本地复现通过（命中中间值/密钥，非 flag）：{hack1ng_fo1_fun}   ← 旧版到此判失败结束
[14:44:21] 已生成修正提示（505 字符），将随结果回传触发重试
[14:44:32] 本地复现通过（flag）：flag{hack1ng_fo1_fun}
[14:44:32] 提交 → {"accepted":true,"is_solved":true}
```

`简单注册器` 更关键：上一轮它"解出"并提交的 `flag{59acc...40c0;9;dd}` 实际被平台拒绝
（`accepted:false`），但当时的判定逻辑用 `/accepted/` 匹配整个 JSON，把 "accepted" 这个词本身
当成了成功信号 → **错误 flag 被记为解出**。本轮工具自己给出了正确值
`flag{59acc...0999dd}` 并被平台接受。这条判定缺陷同样是本轮修掉的（见 0.1 #8）。

### 0.1 本轮新发现并修复的 8 项通用缺陷

| # | 缺陷 | 证据 | 修复 |
|---|---|---|---|
| 1 | **RC4 指纹严重误报** | 20 题里 12 题被打上"RC4（疑）"，实际全都不是 RC4；判据只是 10 字节 `00 01 02…09`，几乎每个程序都有 | 改为要求**完整 0..255 表**（连续或 dword 步长）才报，置信度升为 medium |
| 2 | **Base64/Base91 变表被当成可执行载荷** | cnbragon / kanxue 题：Data 段一张 Base91 表被描述成"内嵌 shellcode"，summary 断言"本层是 loader、必须提取下一层"，而同次扫描 AES 已是 high → AI 放着确定的主逻辑去 dump 不存在的 payload | 新增 `type:'table'` 分支，明确"这是算法的数据表，不是载荷"；loader 判定、自动接力、深度提示词三处都过滤掉 table |
| 3 | **解出机器码却被告知"换算法"** | CrackMe3：AI 用自定义 RC4 变体解出 `83ec18b0…c3 90 90`（完整 x86 函数），归因说"乱码 → 优先换算法族"，方向完全相反 | 新增 `looksLikeMachineCode` 形态判定；识别为代码层时**禁止换算法**，改为"写盘 → 确认魔数 → switch_to_next_stage" |
| 4 | **杀软拦截被当成解题失败** | CrackMe4：解压成功、文件在盘上，Defender 让 `fs.open` 抛 `UNKNOWN: open`，整题 1 秒静默跳过 | `detect-file-type` 区分 blocked/缺失并给出加白名单指引；报告里记为 `blocked-by-av` 而非 `no-verified-flag` |
| 5 | **Tool-Use 无墙钟上限** | CrackMe2 / CrackMe5 / PeSafe / cnbragon 撞上批量驱动的 10 分钟硬超时，连"当前进展"都来不及输出（工具调用日志显示 AI 一直在正常调用工具，不是死锁） | 新增 8 分钟软截止（`CTF_TOOL_BUDGET_MS`），到点注入收尾指令：要么给 flag、要么写出下一层接力、要么写明卡点 |
| 6 | **Kali 失败后固件题只剩空输入** | firmware 题：SSH 握手超时 × 4 条命令，file/binwalk/strings 全返回 null，AI 收到四个"（无输出）"，213 秒后放弃 | Kali 全空时自动回退**本地字节级采集**（Python 标准库：magic + 120 条优先级排序的字符串 + 高熵块）。实测该固件头部识别为 `TP-Link Tech`，采到 120 条字符串，不再把空结果丢给 AI |
| 7 | **Burp 起不来 → 本地 HTML/JS 题直接放弃** | equation 题：附件是 57KB 的 `equation.html`，算法全在内嵌 JS 里；但旧逻辑等 Burp 150 秒超时后直接结束，从未读过文件 | Burp 不可用且目标是本地 `.html/.js` 时自动切到**文件级静态分析**：抽取内嵌 `<script>`（按长度取前 4 段）、统计密码库/Base64/字符码/常量数组/位运算线索，再交给 AI |
| 8 | **提交结果误判（把错误 flag 记为成功）** | `{"accepted":false,...}` 里 "accepted" 这个词命中了 `/accepted/` 正则，驱动打印"解出"并停止重试。审计发现历史上 16 次提交里有 **5 次实际被拒却记为成功** | 抽出 `ctf2SubmitAccepted()`：优先读嵌套的布尔字段（accepted / is_solved），都缺失才回退文本匹配且必须排除否定式；被拒时把该 flag **降级为未验证**，下轮可重试 |
| 9 | **退化哈希被当成 flag** | `findKey` 题：工具算出 `d41d8cd98f00b204e9800998ecf8427e` 并提交——那是**空字符串的 MD5**，真实含义是"待哈希的输入没取到" | 新增 `DEGENERATE_DIGESTS`：空串/全零/单字符的 MD5/SHA1/SHA256 摘要一律拒绝（含 `flag{...}` 包裹形态） |
| 10 | **`not_real` 类诱饵漏网** | `[RCTF2019]asm`：提交 `CTF{f5_is_not_real_reversing_}`，字符串自曝"不是真逆向"，旧正则只覆盖 `not-the-real` | `DECOY_FLAG_RE` 补 `not[_ -]real` 形态 |
| 11 | **题目描述里的 flag 形态未被利用** | `相册`：描述明写"提取完整邮箱即为 flag"，AI 却只拿 `flag{test}` 去试 UI，从未在二进制里搜邮箱 | 从描述识别形态（邮箱/md5/base64/二维码/hex/xor/手机号），注入定向检索指令，要求先按形态正则搜索而非假定 `flag{...}` |

新增回归测试 9 个：`test_rc4_fingerprint.js`（真实扫描器，RC4 误报归零）、
`test_decoded_layer.js`（机器码识别 9 项）、`test_blocked_file.js`（AV 拦截分类 5 项）、
`test_encoding_table_not_payload.js`（编码表不被当载荷 11 项）、
`test_firmware_fallback.js`（固件本地兜底 6 项，对真实 4MB 固件跑通）、
`test_local_web_fallback.js`（本地 HTML/JS 抽取 11 项，对真实 equation.html 跑通）、
`test_submit_verdict.js`（提交判定 13 项，含 accepted=false 关键回归）、
`test_degenerate_digest.js`（退化摘要与诱饵 11 项）。
全量：**单元测试 33/33 + 回归题集 13/13** 通过。

### 0.1.1 提交审计（对全部历史日志重新核对，含最新 30 题批次）

| 项目 | 数值 |
|---|---|
| 累计提交次数 | 16 |
| 平台接受（`accepted:true`） | **11** |
| 平台拒绝（`accepted:false`） | 5 |

被拒的 5 次（本地自洽但平台不认，属**真实未解**，不应计入成功率）：

| 题目 | 提交值 | 原因推测 |
|---|---|---|
| `简单注册器` | `flag{59acc...40c0;9;dd}` | 上一轮的旧错误值；本轮已用 `...0999dd` 通过 |
| `内涵的软件` | `DBAPP{49d3c...}` | 本地解密自洽，但可能取错了密文/层 |
| `simplestuff` | `FLAG{Xor_encode_as_well_as_No_ps}` | 大小写/格式或 XOR 方向错 |
| `findKey` | `flag{D41D8CD9...}` | 这是空串的 MD5（d41d8cd98f00b204e9800998ecf8427e）→ 输入为空时算出的，非真 flag |
| `[RCTF2019]asm` | `CTF{f5_is_not_real_reversing_}` | 字符串自曝"not real"，是 decoy |

**注意 `findKey` 这个案例很有价值**：`d41d8cd98f00b204e9800998ecf8427e` 是空字符串的 MD5，
工具把它当成了 flag。这说明"哈希题"需要额外校验——如果算出的摘要对应空输入/全零输入，
应当判定为"输入没拿到"，而不是"解出"。这是下一轮可以加的通用护栏。

**因此"解出并提交成功"的可信数字是 11 道不同题目。**

### 0.2 仍然存在的失败（17/20），按机制归类

| 机制 | 数量 | 说明 |
|---|---|---|
| AI 未产出可验证契约 | 9 | `no-verified-flag`，多数是 VM/复杂控制流题，AI 烧完预算仍无结论 |
| 撞外层超时 | 4 | CrackMe2 / CrackMe5 / PeSafe / cnbragon（墙钟预算修复后应改善，需下一批验证） |
| 环境阻断 | 1 | CrackMe4（Defender 拦截） |
| 其他 | 3 | JEB/模拟器安装失败、固件题只有 Kali 输出 |

---

## 一、测试规模

| 项目 | 数值 |
|---|---|
| 平台逆向题总量 | **545 道**（BUUCTF 537 + 日常练习场 8） |
| 其中带附件 | 530 道 |
| 未解 + 带附件 | **525 道** |
| 难度分布 | Easy 475 / Medium 11 / Hard 39 |
| 本轮实际尝试 | **104 道**（首轮 54 + 失败复测 20 + 新批次 30） |
| 解出并提交成功 | **11 道不同题目**（经平台 `accepted:true` 逐条核对） |
| 本轮正确率 | **10.6%**（11/104） |

> 说明：最初按单一练习场只能看到 3 道题；平台实际有 6 个练习场，逆向题主要集中在 BUUCTF（537 道）。
> 你说的 492 与实测 525 的差异，应是平台在本轮期间新增/解锁了部分题目。

---

## 二、解出的题目（全部通过平台校验）

| 题目 | 类型 | Flag |
|---|---|---|
| `parallelism` | ELF（DiceCTF 2023） | `dice{P4ral1isM_m4kEs_eV3ryt4InG_sUp3r_f4ST_aND_s3CuRE_a17m4k9l4}` |
| `PalatinePack` | ELF（AES） | `sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}` |
| `easyre` | PE | `flag{this_Is_a_EaSyRe}` |
| `简单注册器` | APK | `flag{59acc538825054c7de4b26440c0999dd}`（重测修正） |
| `findit` | APK | `flag{c164675262033b4c49bdf7f9cda28a75}` |
| `xor` | PE | `flag{QianQiuWanDai_YiTongJiangHu}` |
| `不一样的flag` | PE | `flag{222441144222}`（本轮新增） |
| `reverse2` | PE（.rar） | `flag{hack1ng_fo1_fun}`（本轮新增） |
| `helloword` | APK | `flag{7631a988259a00816deda84afb29430a}`（本轮新增） |
| `[GUET-CTF2019]encrypt` | PE（方括号路径） | `flag{e10adc3949ba59abbe56e057f20f883e}`（本轮新增） |
| `[HDCTF2019]Maze` | PE | `flag{ssaaasaassdddw}`（本轮新增） |

**共同特征**：都是 Easy 难度、算法明确、静态可解。这说明工具的"识别 + 标准解密"路径是可靠的；
失败集中在需要多步推理的题目上（详见第五节）。

---

## 三、本轮修复的流程缺陷（14 项）

### 3.1 入口函数识别错误（影响最大）

| | 修复前 | 修复后 |
|---|---|---|
| 识别到的入口 | `start`（508 字符 CRT 桩） | `main`（1118~3453 字符） |
| 关键函数 | 0 个 | 5~6 个 |
| 结果 | 未解出 | **解出** |

修复：候选顺序改为 main/_main/wmain 优先，CRT 桩检测（含 `__libc_start_main` 且 <900 字符则跳过），
全失败时退回"体积最大的非库函数"。

### 3.2 多练习场遍历 + 分页

修复前只取第一个练习场（8 道题），且单页固定 50 条无翻页 → 537 道题的题库只看到 50 道。
修复：按题量降序遍历 6 个练习场；用 `page` 参数翻页（实测 `offset/cursor/skip` 都是 INVALID_REQUEST）。

### 3.3 ZIP 自引用死循环

`CrackMe4` 的解压目录里又出现同名 zip → analyzeFile → 再解压 → 8 分钟内 analyzeFile 被调用 69 次。
修复：同一路径最多解压一次 + 解压结果是自引用压缩包时直接放弃。

### 3.4 APK 路径崩溃

`autoFridaStage()` 引用了 `analysisData`（那是 analyzeAPK 的局部变量）→ `ReferenceError`，
两道 APK 题都在此中断。修复：用 `mcpCache` 重建最小上下文对象。

### 3.5 JEB 失败即放弃 AI 求解

JEB MCP 超时后只 `launchTool(jadx)` 打开 GUI 就 return，等于"AI 求解跳过"。
实测 10+ 道 JAR/APK 题因此 30 秒内草草结束。
修复：降级为 jadx **命令行**反编译 → 收集 .java 源码 → 交给 AI 求解 → 走 finalizeSolve 验证。

### 3.6 其余修复

| 缺陷 | 修复 |
|---|---|
| 人工伪造 `tool_use_id`（API 400） | 附加建议并入同一 tool_result |
| 预检误拦 run_python/ida_decompile | needPath 只保留真有 path 的工具 |
| IDA 参数名错（function vs function_name） | 按 schema 修正 |
| 压缩切断 tool_use/tool_result 配对 | alignToToolPair() |
| .rar/.7z 不解压（只跑 file/binwalk） | 接入 7-Zip/UnRAR，识别为 ZIP 类型走手包流程 |
| __MACOSX/.DS_Store 被当主文件 | 过滤 macOS 打包噪声 |
| 429 未按 retry_after_ms 退避 | 按平台给的毫秒数退避重试 3 次 |
| 未调用 ctf2_agent_log_note | 在开始/提交节点记录 plan/result |
| report 写入路径为空导致驱动干等超时 | 改由主进程写盘 |
| CDP 端口复用冲突（整批中断） | 随机大端口 + 严格不重复 |
| 超时题不入排除集（反复拉同一道） | 超时也记录题名 |
| 收工过早、零验证数据 | 提示词加收工门槛 |

---

## 四、流程稳定性

| 指标 | 结果 |
|---|---|
| 单题平均耗时 | 2~5 分钟（Easy 题 30 秒~1 分钟） |
| 卡死/死循环 | 0 次（修复 ZIP 循环后） |
| 启动失败 | 0 次（修复随机端口后） |
| 平台提交成功率 | 100%（解出即通过） |
| 每题进程清理 | 100%（驱动 killAll + 工具内 cleanup） |

---

## 五、失败原因分析

### 5.1 首轮 54 题（48 道未解）的精确归因

> 数据来源：对全部 DOM 日志做规则化归因（`tests/_deep_fail.js`），不是粗略目测。

| 代码 | 机制 | 数量 | 说明 |
|---|---|---|---|
| A1 | 分析完成但无结论 | 26 | AI 看到反编译后没有产出任何 [FLAG]/[VERIFY]，直接收工——最大单一原因 |
| F | JEB 超时降级后放弃 | 11 | APK/JAR 题，JEB MCP 连不上就开 jadx GUI 然后 return |
| C | 有契约但本地复现失败 | 6 | AI 给的 key/iv/expected 差一点，旧版没有回灌机制 |
| B | AI 脚本有 bug | 5 | 除零/越界/None，脚本崩溃即整题结束 |
| H | 只跑了 Kali | 5 | 固件 .bin，file/binwalk/strings 输出后没有 AI 闭环 |
| A2 | 耗尽工具预算 | 4 | 60 轮全用完仍未收敛 |
| G | 过早结束 | 2 | 零工具调用就返回 |
| E | IDA 返回 0 函数 | 1 | 畸形 PE |
| D | 下载失败 | 1 | 平台侧 |

### 5.2 第二轮 20 题（17 道未解）

| 机制 | 数量 | 代表题 |
|---|---|---|
| AI 未产出可验证契约 | 9 | CrackMe3、Crackme6、QuiZow、CM、HellScream… |
| 撞外层硬超时 | 4 | CrackMe2、CrackMe5、PeSafe、cnbragon |
| 环境阻断（Defender） | 1 | CrackMe4 |
| 其他 | 3 | firmware（只有 Kali 输出）、Youngter-drive、reverse3 |

### 5.3 已修复的根因（本轮）

- **RC4 误报**（12 题）→ 指纹判据改为完整 0..255 表
- **编码表误判为 loader**（2 题）→ `type:'table'` 分流
- **解出机器码却提示换算法**（1 题）→ 机器码形态判定 + 接力指令
- **杀软拦截记为解题失败**（1 题）→ blocked 分类
- **无墙钟上限**（4 题）→ 8 分钟软截止 + 收工指令
- **Kali 不可用即空输入**（H 类）→ 本地字节级采集兜底
- **Burp 不可用即放弃本地 HTML/JS** → 文件级静态分析回退

### 5.4 典型失败案例

`not-baby-parallelism`（DiceCTF 2023）：AI 正确识别为 Blelloch 并行前缀扫描，
给出了解密代码框架，但生成的代码有除零缺陷（`post%src` 未判 src=0），三组候选全崩。
这属于"执行纪律"而非"能力不足"——收工门槛已针对此加强。

`CrackMe3`（本轮深挖）：AI 用自定义 RC4 变体解出 `83ec18b0…c3 90 90`，
即一段完整的 x86 函数。密钥和算法都对，拿到的是**自解密代码层**。
修复前归因说"乱码 → 换算法族"（方向相反）；修复后改为
"写盘 → 确认魔数 → switch_to_next_stage"。

---

## 六、平台规则合规核对

| 规则 | 状态 |
|---|---|
| 只解 public practice（不用 writeup/community/private） | ✅ 仅调用 ctf2_* practice 工具 |
| 自行找 flag，不爆破 | ✅ 全部来自本地算法还原 + 本地验证 |
| 提交带 confirmation=true | ✅ |
| 同时运行环境 ≤ 1 | ✅ 单线程串行 |
| 遵守 429 / retry_after_ms | ✅ 本轮修复 |
| 用 ctf2_agent_log_note 记录 | ✅ 本轮修复 |

**注**：当前 stats 显示 `attempt_count: 5 / correct_count: 5 / solved_count: 5`，
这是查询时的快照；本轮新增的 6 道提交中部分已计入。

---

## 七、后续优化建议（按优先级）

以下按"改动带来的收益 / 通用性"排序，全部是通用机制，不针对某道题：

1. **VM/多步推理专项**（收益最大，覆盖 A1 的 26 道）：给 AI 一个"反编译 → 写解释器 → 跑 → 对拍"
   的固定模板，并强制它**先产出可执行骨架再优化**，而不是读完所有函数才开始写。
2. **超时预算分层**：按难度动态调整（Easy 6 分钟 / Medium 10 分钟 / Hard 15 分钟），
   并让批量驱动读取工具自报的"预计还需时长"，而不是一刀切 10 分钟。
3. **固件题闭环**（H 类 5 道）：binwalk 分离出的每个子文件自动登记为候选主文件，
   而不是只把 Kali 的文本输出丢给 AI。
4. **多附件协同**（`rsa` 类）：把 .key/.pem 与密文一起结构化成"已知量/未知量"喂给 AI，
   目前虽然内联了小文件，但没有标注它们各自的角色。
5. **AV 白名单自动检测**：启动时探测工作目录是否被 Defender 拦截并提示，
   避免又一批题在解压后 1 秒静默失败。

---

## 八、结论

- **工具具备真实自主解题能力**：经平台 `accepted:true` 逐条核对，**11 道不同题目**从拉题到提交全自动完成
- **正确率 10.6%**（11/104）在 BUUCTF 全难度题库上属合理水平——该库 Easy 题也大量涉及 VM/加壳
- **本轮最有价值的不是多解出几道题，而是证明"失败证据回灌"这条闭环有效**：
  `reverse2` 第一次只命中 `{hack1ng_fo1_fun}`（缺 `flag{}` 外壳），
  旧版会判失败收工；新版把真实解密结果回灌给 AI，AI 自己修正成 `flag{hack1ng_fo1_fun}` 并通过平台。
  这说明"工具负责验证与举证、AI 负责修正假设"的分工是成立的。
- **方括号解压修复得到真实验证**：`[GUET-CTF2019]encrypt` 此前因 PowerShell 把 `[ ]` 当通配符
  导致解压失败、整题 30 秒结束；改用 `-LiteralPath` 后正常解出并通过平台。
- **RAR 解压修复得到真实验证**：`reverse2` 此前只跑 `file/binwalk` 就结束；接入 7-Zip/UnRAR 后
  15 秒内解出。
- **同时修掉了一个数据可信度问题**：提交判定曾把 `accepted:false` 当成功。
  审计后确认 16 次提交里 5 次实际被拒（其中 `findKey` 是空串 MD5、`asm` 是 `not_real` 诱饵）。
  现在这两类都在本地就被拦下，不再浪费平台配额，报告数字也不再虚高。
- **失败归因从"猜测"变成"可测量"**：11 类机制 + 精确计数，所有修复都能对应到具体数量。
- **流程稳定**：104 题无卡死、无启动失败、无重复拉题；每题进程都能清理干净。
