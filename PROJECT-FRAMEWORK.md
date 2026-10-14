# CTF-RE-TOOL 项目框架总览（SSOT）

> **用途**：本文件是项目的**单一事实来源（SSOT）**。新开对话时**先读本文件**即可掌握项目全貌，再按需深入具体文件。
> **版本**：v1.3.14 ｜ **形态**：Electron 桌面应用（Windows）｜ **定位**：CTF 逆向 AI 解题工作台
> **一句话**：把「静态分析 → 动态 Hook → 算法还原 → 本地验证」串成 AI 可自主驱动的流水线；通过 MCP 接入 IDA/JEB/Burp，内置 11 个方法论技能 + 54 页结构化知识库。

---

## 0. 新对话快速上手（30 秒版）

```text
这是什么   → Electron 桌面工具：拖入 CTF 题目文件，AI 自动逆向并求出 flag
技术栈     → Electron 35 + 原生 JS（无框架、无打包器）；主进程 Node，渲染层浏览器
代码中心   → electron/main.js（主进程/全部外部能力） + src/js/app.js（渲染层/解题编排）
两个仓库   → ctf-tool-v2（源码，本地无远程） → ctf-re-tool-publish（镜像） → GitHub ip2867/ctf-re-tool
当前版本   → v1.3.14（已发 GitHub Release，exe 73.3MB normal 压缩）
```

**新对话要做的第一件事**：确认改动落在哪个仓库。**源码仓 `ctf-tool-v2` 是唯一编辑点**；`ctf-re-tool-publish` 只是复制品，改完源码后同步过去再 push。

**改代码后必须做的三件事**：
1. `node --check` 三个 JS（`electron/main.js`、`src/js/app.js`、`electron/preload.js`）
2. 若改了求解器（`buildSolvePython`）→ 跑 `_revhelp` 里的回归脚本（见 §9）
3. 版本号 4 处同步 + 两仓同步 + push（见 §8）

**绝对不要做**：`taskkill /F /IM node.exe`（会杀掉 electron 包装进程导致"闪退"）；把 `E:\...` 本机路径 / 私有端点 / flag 提交进仓库。

---

## 1. 目录结构与规模（v1.3.8 实测）

```
ctf-tool-v2/                          # 源码仓（本地，无远程）
├── electron/
│   ├── main.js        (4690 行)    # 主进程：全部业务逻辑 + 55 个 IPC handler
│   ├── preload.js     (108 行)     # contextBridge 暴露 55 invoke + 2 事件监听 = 57 API
│   └── pyc_decompile.py (7.5KB)    # ★新增：PYC 多后端反汇编助手（asarUnpack 解包）
├── src/
│   ├── index.html     (566 行)     # 主页面（CSP + SRI）
│   ├── css/style.css  (1299 行)
│   └── js/app.js      (8594 行)    # 渲染层：UI + AI 编排 + 解题流程 + 验证闭环
├── skills/                         # 11 个方法论技能（SKILL.md，AI 用 read_skill 加载）
├── wiki/                           # 54 页可检索知识库（AI 用 wiki_search/wiki_read）
│   ├── AI-SEARCH-INDEX.md          # 全局检索索引（优先读）
│   ├── PAYLOAD-CHEATSHEET.md       # 套路/Payload/脚本速查
│   ├── reverse/ (44 文件=43 题+_INDEX)  # 历年逆向题条目库（YAML meta）
│   ├── frida/ (6 页)               # 动态 Hook 手法页
│   ├── firmware/ (1 页)
│   └── README.md
├── assets/icons/                   # 图标
├── package.json                    # electron-builder 打包配置（portable + asarUnpack）
├── _build.cmd                      # 本地打包脚本（gitignore，不入库）
└── 启动.bat                        # npm start 包装（GBK 编码）
```

**发布流程（两仓）**：`ctf-tool-v2`（源）→ **复制** `electron/ src/ skills/ wiki/ package.json README.md PROJECT-FRAMEWORK.md 启动.bat` → `ctf-re-tool-publish` → commit → `git push origin main`。

---

## 2. 进程架构与数据流

```
┌─────────────────────────────────────────────────────────────┐
│ 渲染进程 (src/js/app.js)                                      │
│   UI / 事件 / 解题流程编排 / AI 对话 / 知识库检索              │
│   ↕ window.electronAPI.xxx()   （注意：大写 API！）            │
├─────────────────────────────────────────────────────────────┤
│ preload.js  (contextBridge, sandbox:true, contextIsolation)   │
│   ↕ ipcRenderer.invoke('xxx', ...)                            │
├─────────────────────────────────────────────────────────────┤
│ 主进程 (electron/main.js)                                     │
│   IPC handlers / 外部工具调用 / MCP 客户端 / AI 传输 / 落盘     │
│   ↕ spawn(argv[], shell:false)                                │
├─────────────────────────────────────────────────────────────┤
│ 外部：IDA MCP(13337) / JEB MCP(16161) / Burp MCP(9876)        │
│       nox_adb(62025) / frida-server(27042) / Claude API       │
└─────────────────────────────────────────────────────────────┘
```

**关键约定**
- 渲染层**禁止**拼 shell 命令；一律走 `runToolArgs(argv[])`（argv 数组、`shell:false`）。
- 渲染层调主进程**必须**用 `window.electronAPI`（曾误写 `electronApi` 致 IDA 采集全空 → 0 反编译）。
- 落盘根目录：开发态=应用目录；打包态=`%APPDATA%/ctf-reverse-tool/`（`writableBase()`）。
- 打包态 asar=true：**外部进程（python）读不到 asar 内文件** → 需 `asarUnpack` 或运行时物化到 temp。

---

## 3. 主进程 main.js 关键模块

| 模块 | 说明 |
|---|---|
| `DEFAULT_CONFIG` | 所有工具路径默认**空字符串**（用户设置页填）；`config.json` 存 userData |
| `spawnArgv()` | 统一进程启动；GUI 工具走 `cmd /c start`（否则窗口不可见）；`.bat` 走 `cmd /s /c`+`windowsVerbatimArguments` |
| `run-tool-args` IPC | **参数化执行原语**（argv 数组，无 shell 解析）——命令注入收口 |
| `resolveAdbPath()` | **优先 nox_adb**（Nox 自带 v36，避免与系统 adb v41 互杀） |
| `adb-command` IPC | 版本不匹配时 kill-server/start-server 重建；瞬断重试 |
| IDA MCP 客户端 | `idaMcpEnsureSession`/`idaMcpResolveTool`/`normalizeIdaArgs`；**逻辑名 → 真实工具名候选映射** |
| JEB MCP 客户端 | **直通透传** method 给插件（无名字映射，故无漂移风险） |
| Burp MCP 客户端 | 双传输自适应（Streamable HTTP ↔ 经典 SSE） |
| Claude 传输层 | `postClaudeJSON` / `postClaudeStream`（SSE）；**baseUrl 空则明确报错** |
| Frida 执行 | `execFridaHook` / `runFridaOnce`（滚动窗口）/ `resolveFridaProcessName` / `resolvePidByName` / `adbForegroundPackage` |
| 知识库 | `listWikiDirs` / `wikiSearch`（解析 YAML meta 加权）/ `wikiRead` |
| **PYC 反汇编** | `pyc-decompile` IPC + `materializePycHelper()`：**多后端回退**（见 §3.2） |
| AI 工具层 | `getToolDefinitions()`(27 工具) / `executeToolCall(toolName,input)` |

### 3.1 IDA MCP 工具名映射（易漂移，重点）
`idaMcpEnsureSession` 从 `tools/list` 解析真实工具名；`candidates` 表把逻辑名映射到候选名：
```
list_functions → ['list_functions','list_funcs','...']   # 实测真实名 = list_funcs
find_strings   → ['find_regex','search_text','...']      # 用 find_regex（快，不阻塞 IDA）
decompile      → [...,'decompile']                        # 参数归一化为 {addr}
xrefs_to       → [...,'xrefs_to']                         # 参数 {addrs:[..]}（数组！）
trace_data_flow→ [...,'trace_data_flow']                  # 参数 {addr}
```
`normalizeIdaArgs(logicalName,args,realName)` 负责参数名转换。**新增 IDA 工具必须同步改 candidates + normalize**。

### 3.2 PYC 多后端反汇编（v1.3.8 新增）
用户配置的单个 pycdc 对高版本 pyc 会报 `Bad MAGIC!` 直接失败 → 后端链自动回退：
```
配置的 pycdc
  → 内置 electron/pyc_decompile.py：
       xdis/pydisasm（跨版本反汇编 + 常量表）
       → 原生 marshal.loads + dis（版本一致时最完整，递归常量）
       → 纯字节串扫描（ASCII/GBK中文/长hex/base64/大整数）★永不空手而归
```
输出按 `### META/DISASM/CONSTS/STRINGS ###` 分区，主进程解析后交给 AI。

---

## 4. 渲染层 app.js 解题流水线（核心）

### 4.1 入口分流
```
analyzeFile()  → detectFileType → 按类型分派（autoAnalyze 的 switch）:
  APK           → analyzeAPK()      (JEB MCP + IDA MCP + Frida)
  PE/ELF        → analyzePE()/analyzeELF()   (IDA MCP)
  DEX           → analyzeDEX()      → analyzeJavaLike() (JEB MCP 采集 → AI → finalizeSolve) ★v1.3.13
  JAR/CLASS     → analyzeJava()     → analyzeJavaLike() (JEB 优先，降级 jadx) ★v1.3.13
  PYC           → analyzePYC()      (多后端反汇编 → AI → 验证闭环)
  JS/HTML       → analyzeWebJS()    (Burp MCP + 代理浏览器)
  MACHO         → analyzeMachO()    (IDA MCP → autoSolveBinaryFlag) ★v1.3.13
  LUAC          → analyzeLua()      (Python 抽取字节/常量 → AI → 验证闭环) ★v1.3.13
  BIN/UNKNOWN   → analyzeBIN()      (Kali)
  ZIP           → 仅提示（非题目文件，先解包）
```
> ★v1.3.13：DEX/JAR/CLASS/MACHO/LUAC 此前是"只启动工具/只打印指引"的空壳 handler（15~24 行），
> 现全部改造为真正的 AI 求解路径（采集 → 求解 → 验证 → 经验），分流表 12/12 均路由到真实求解器。

### 4.2 APK 全自动 7 阶段（analyzeAPK）
```
[1/7] DIE 查壳
[2/7] JEB 分析 Java 层（自动拉起 JEB + MCP 插件）
[3/7] 提取 native SO → IDA 分析 → collectIdaNativeIntel()
[4/7] 检查/启动模拟器
[5/7] 安装 APK（installApkToEmulator）
[6/7] 启动 frida-server
[7/7] 生成 Hook 脚本
→ autoSolveFlag()  →  toolUseDeepSolve()  →  autoFridaStage()  →  autoSolveBinaryFlag()
```

### 4.3 求解阶段
| 阶段 | 函数 | 说明 |
|---|---|---|
| 阶段1 | 直接调 MCP 采集 | Manifest / Activity / 类列表 / 关键类反编译 |
| 阶段2 | `autoSolveFlag()` | AI 初步分析（固定清单） |
| 阶段2.5 | `toolUseDeepSolve()` | **Tool-Use 深度求解**：AI 自主调 JEB/IDA/脚本，4 阶段提示词 |
| 阶段3 | `autoFridaStage()` | 动态 Hook：AI 生成脚本 → `driveAppIteratively` 驱动界面 → `runFridaHook` |
| 阶段3.5 | `autoSolveBinaryFlag()` | PE/ELF 版 Tool-Use 求解 |

### 4.4 采集：collectIdaNativeIntel()（关键，最易踩坑）
枚举函数 → 挑目标（JNI 导出 / 语义名 / sub_XXXX）→ 逐个 `decompile` → 按**行为特征**筛选保留（≤28 个）→ 采集被引用的全局数据表 + 数据段兜底。
- **必须用 `window.electronAPI`**；失败要打日志（曾有拼写错被空 catch 吞掉 → 0 反编译）。
- 函数枚举用 `list_funcs {queries:{}}`（**`{}` 才返回全量**，加 `count:0` 反而只回 4 个）。

### 4.5 验证闭环 & 本地枚举
```
AI 输出 [VERIFY]{json}[/VERIFY]  → parseVerifyContracts()
  → buildSolvePython(attempts)   → Python 本地复现（真实 subprocess 跑）
  → [HIT] attempt=N ... flag=... → recordFlag(verified=true)
AI 输出 [HYPOTHESES][...][/HYPOTHESES] → runHypotheses() 并行枚举组合
  ▲ 若 AI 未给 [HYPOTHESES] → synthesizeHypotheses() 自合成候选矩阵（≤24 组）
```
- **统一入口 `finalizeSolve(aiText, {source, noteSection})`**（v1.3.13）：把「验证闭环(`verifyAndRecord`) → 失败自动枚举 → 登记 flag → **解题成功则经验自动入库**(`harvestExperience`)」封成**一处**，返回 `{vr, flags, verifiedFlags}`。9 个求解流程全部改调它 —— 此前"验证"与"收割经验"是两步、散落 9 处，反复漏接（v1.3.11/v1.3.12 补了两轮）。**新增流程只调此一处**。
  此前这 7 行在 7 个流程里各写一遍且**语义已漂移**（有的 `if(!vr)` 门控登记、有的无条件）——**新增流程务必调用它，不要再复制粘贴**。
- `VERIFY_ALGOS` / `VERIFY_CONTRACT`：**契约模板唯一权威常量**（不要再各处写死 algo 清单）。
- 支持算法：`rc4/tea/xtea/xxtea/xor/aes_ecb/aes_cbc/des_*/des3_ecb/sm4_ecb/chacha20/salsa20/base64/base64_custom/node_js/custom`。
- 求解器健壮性（v1.3.7/1.3.8 加固）：
  - `dec_cbc_multi()`：AES/DES-CBC **缺 IV/给错 IV** 时枚举（全零 / 密文首块 / 前置IV）+ 回退 ECB。
  - `key_candidates()`：key 非 16/24/32 字节（口令）→ 试 MD5/SHA-256 派生/零填充；**单字节整数 key**（`xor_key=199`）识别为 1 字节。
  - `_to_bytes_out()`：`custom` 返回 `str`/`list[int]` 先归一化为 bytes。
  - `_unpad`/`_pt_score`：剥 PKCS#5 后按**可打印比例**打分（CBC 错 IV 只有第 1 块乱，flag 常在第 2 块）。
  - `_hit_seen`：`[HIT]` 全局去重。
  - **ChaCha20 坑**：counter 初值常非 0；`dec_chacha20_try` 枚举 counter 大小端候选。

### 4.6 多候选密文交叉校验 + 自动裁决（防"变种题"陷阱）
```
runVerification() 复现通过后:
  crossCheckCandidates()   → extractNativeCandidates() 从 nativeIntel 抽全部 hex 常量
                           → rankCandidatesByXref()   用 IDA xrefs_to 判"哪条被校验函数引用"
     ├─ authoritative 命中且与 AI 不同 → 自动以权威为准（AI 原答案标 superseded）
     ├─ 一致 → 确认
     └─ 判不出 → 回落为告警（列全部候选交人工）
打分：引用函数可反编译(+3) + 含比较语义 memcmp/strcmp/Arrays.equals(+3) + trace_data_flow 强判据
阈值：top≥3 且有真实引用 且 领先第二名≥2 才标权威（避免同分误判）
```

### 4.7 经验库（自进化）
- `harvestExperience(aiText, {autoSave})` 收割 AI 输出的 `[EXPERIENCE]...[/EXPERIENCE]`（支持 `→` 多步攻击链）。
- **解题成功（本地验证出已验证 flag）→ 自动入库**（`autoSave:true`）；未确认成功才暂存，等用户发「保存」（`flushPendingExperience()`）。**自动入库由 `finalizeSolve()` 统一触发**（`harvestExperience(autoSave:verifiedFlags>0)`）。
- **去重是内容级、与日期无关**：`experienceKey()` 剥离 `[日期]` 前缀与标点后精确比对 + `experienceSimilar()` 二元组 Jaccard≥0.78 / 子串判定（吃掉"措辞微调/补半句"，不误合并"不同题"）。
- 入库写入器统一为 `writeExperienceEntries()`（首建表头 → 追加 → 修剪），自动/手动两条路径共用；**手动 `经验 <内容>` 命令也走 `experienceKey`/`experienceSimilar` 去重**（v1.3.12，此前直接追加绕过去重）。
- 下次解题 `selectRelevantExperience()` 按关键词注入；**注入模板统一走 `experienceSection()`**（所有求解路径都调它，含写死 system prompt 的 APK/PE/Frida）。

### 4.8 系统提示 buildSystemPrompt()
注入：真实 MCP 连接状态 + 技能索引 + wiki 索引 + 经验速查（`experienceSection()`）+ 已收集结论（防重复劳动）。**只注入索引，不注入全文**（省 token）。
- **主路径自动预取**：`autoSolveFlag`/`autoSolveBinaryFlag` 是"固定清单 + 禁止调工具"提示词，AI 无权检索 → `prefetchKnowledge()` 从已采集代码/字符串探测算法·工具·混淆特征词，**调用前主动 wiki_search 并把攻略摘要内联进提示词**（否则 43 篇题库形同虚设）。

---

## 5. 知识库（wiki/）与技能（skills/）

### 5.1 wikiSearch 结构化加权（v1.3.5 修复 / v1.3.11 修复解析 bug）
- 兼容两种 meta 写法：`---` front matter **和** ` ```yaml ` 围栏块（reverse/ 用的是后者）。
- **字段解析 `pickMetaValue()`（v1.3.11 修复）**：兼容 ① 行内 `key: value` ② 列表 `key:` 换行 + `- 步骤` ③ 块标量 `|`/`>`。
  旧正则带 `m` 标志使 `$` 匹配行尾 → **列表写法的 attack_chain/failed_attempts 全解析为空**（43 篇里仅 13 篇解法链可用）。修复后 → 38/43。
- 加权字段：`tags(6)` / `key_observations|key_payload|failed_attempts|lesson(5)` / `keywords(5, 手法页)` / `one_liner(5)` / `attack_chain(4)` / `reasoning_chain(4)` / `failed_attempts(4)` / `vuln_type|contest|difficulty(3)`。
- 命中片段展示 **要点 + 解法链 + 避坑（失败教训）**，**保留原文大小写**（防 flag 被小写化）。

### 5.2 11 个技能
`ctf-dispatch`（分流调度）｜`ctf-reverse-binary`（PE/ELF）｜`ctf-reverse-android`（APK）｜`ctf-reverse-langs`（pyc/Go/Rust/Lua）｜`ctf-reverse-tooling`（Z3/angr/Unicorn）｜`ctf-frida-dynamic`｜`ctf-antidebug`｜`ctf-jsreverse`｜`ctf-iot-firmware`｜`ctf-crypto-identify`｜`ctf-writeup`

### 5.3 AI 可用工具（27 个，`getToolDefinitions()`）
`read_file / write_file / bash / glob / grep / run_command / run_python / adb_command / frida_hook / read_skill / wiki_search / wiki_read` ＋
`jeb_get_manifest / jeb_get_class_decompiled / jeb_get_method_decompiled / jeb_get_exported_activities / jeb_get_all_classes / jeb_get_class_methods` ＋
`ida_decompile / ida_list_functions / ida_find_strings / ida_get_xrefs` ＋ `browser_search / browser_open` ＋ `burp_get_history / burp_get_message / burp_call`

---

## 6. 已知坑与修复记录（血泪清单，勿重蹈）

| 坑 | 根因 | 修复 |
|---|---|---|
| IDA 采集 0 反编译 | `window.electronApi`（小写 pi）→ TypeError 被空 catch 吞 | 改 `electronAPI`；失败打日志 |
| IDA 函数枚举空 | 用 `export_funcs{}`/`list_functions`（不存在） | 改 `list_funcs {queries:{}}` |
| `unknown algo chacha20` | 提示词承诺但求解器无该分支；且 5 处模板漂移 | 补 `dec_chacha20`；契约统一为常量 |
| APK 装失败（冷启动） | `Failed to install <path>:`（空原因）不在重试正则内 | 纳入瞬时重试，4 次递增等待 |
| Frida "不找到进程" | 包名 ≠ 进程名；App 未启动 | `-a` 解析 + App 未运行自动拉起 |
| **Frida 枚举全崩** | `frida-ps`/`-f`/`-n`/`-F` 走 `queryIntentActivities`（Nox9 quirk，**与版本无关**） | 改 **`adb pidof` → `frida -p <PID>`**（该路径正常） |
| `xrefs_to` 报缺 addrs | 返回 `{address:..}`（单数） | 改 `{addrs:[..]}`（数组） |
| IDA `search_text` 卡死 | 原生 regex 对每个 EA 反复 find_text | 路由到 `find_regex`（缓存正则） |
| 工具"闪退" | `taskkill /IM node.exe` 杀了 electron.cmd 的 node 包装 | **禁止全杀 node**；只用 PID 精确杀 |
| GUI 窗口不可见 | `windowsHide:true` / `spawn(detached)` | GUI 走 `cmd /c start` |
| 打包卡死 | 旧 exe 被运行占用输出文件 | `_build.cmd` 检测并自动关闭旧实例 |
| 打包压缩停滞 | `-mx=9` 在本机卡死 | `_build.cmd store` 跳过压缩 |
| Hook 有输出却报"共 0 条关键数据" | 滚动窗口只在 `[DATA]`/flag 时续期，纯 `[HIT]` 噪音不续期 | 改为**任何新输出都续期**；收尾报告 3 个计数 |
| 单契约复现失败即卡死 | AI 未给 `[HYPOTHESES]` → 只打警告不枚举 | `synthesizeHypotheses()` 自合成候选矩阵（≤24 组） |
| AES-CBC 缺 IV 必然无命中 | 求解器缺 IV 直接抛 `Incorrect IV length` | `dec_cbc_multi()` 枚举 IV + 回退 ECB |
| 进程内解密段刷 25 行同错 | IV 不合法即 `return`，3s tick 无限重刷 | 枚举 IV/key/模式 + 最多重试 4 次 |
| 枚举 NPE 时仍试 `-f` spawn | `-f` 与 `-n`/`-F` 同走 NPE 路径，注定失败 | `autoFridaStage` 直接 adb 拉起 + PID attach |
| 手动 Hook 只抓启动噪音 | `runHook` 只 attach 不驱动 UI，App 停首页 | 与自动阶段一致：并行 `driveAppIteratively` |
| **PYC 直接失败退出** | 单个 pycdc 对高版本 pyc 报 `Bad MAGIC!` 且**失败即结束**（不交 AI） | 多后端回退 + `analyzePYC` 接入 AI/验证闭环 |
| PYC `xor_key` 解不出 | 整数 `199` 被当 `b"199"` 三字节密钥 | 求解器识别单字节整数 key |
| PYC custom 解密崩 | AI 的 decrypt 返回 `str` 被按 bytes 处理 | `_to_bytes_out()` 先归一化 |
| 验证闭环 7 处复制粘贴 | 各流程各写一遍，语义漂移（`if(!vr)` 门控不一致） | v1.3.9 统一为 `verifyAndRecord()` |
| **`flags is not defined` 崩溃** | v1.3.9 重构后 `autoSolveBinaryFlag`/`autoSolveFlag` 只解构 `verifiedFlags` 却仍引用裸 `flags`（旧声明已删） | v1.3.10 补 `const { verifiedFlags, flags } = ...`；**改 verifyAndRecord 调用点必须同时解构两个变量** |
| **经验"存了没用"** | ① 只暂存不自动入库 → 库里长期为空；② 注入只在 `buildSystemPrompt()`，而 APK/PE 主路径用**写死 prompt**（禁止调工具、无经验段）；③ 去重按"整行含日期"→ 换日必重复 | v1.3.11：解题成功自动入库 + 内容级去重（`experienceKey`/`experienceSimilar`）；`experienceSection()` 注入**所有求解路径** |
| **题库攻略 70% 丢失** | `wikiSearch` 解析 meta 的正则带 `m`，`$` 匹配行尾 → **列表写法** `attack_chain:`+`- 步骤` 被解析为空（43 篇仅 13 篇可用） | v1.3.11 `pickMetaValue()` 逐行解析（行内/列表/块标量）→ 38/43；摘要加"避坑" |
| 主路径拿不到题库 | APK/PE 固定清单提示词"禁止调工具"，AI 无法 `wiki_search` | v1.3.11 `prefetchKnowledge()` 调用前主动检索并把攻略摘要**内联进提示词**；v1.3.12 扩展到 PYC/WebJS |
| **经验沉淀有死角** | 有的求解路径只做 `verifyAndRecord` 不 `harvestExperience`（JS/详细分析），有的连验证都没有；手动 `经验` 命令绕过去重 | v1.3.12 补齐 9/9 求解路径；手动回写同一去重器 |
| **结构性漏接根治** | "验证"与"收割经验"是两步、散落 9 处 → 每轮都在补漏 | v1.3.13 收口为 `finalizeSolve()` 单一入口（一步内含四件）；**新增流程只调它**（§9） |
| **5 类入口是空壳** | `.dex`/`.jar`/`.class`/Mach-O/`.luac` 的 handler 只有 15~24 行，只启动工具/打指引，AI 不参与 | v1.3.13 全部改造为真求解（JEB/IDA/字节抽取 → AI → finalizeSolve）；分流 12/12 均接真实求解器 |
| **跨文件 MCP 缓存泄漏** | 新求解器往 `mcpCache.otherClasses` 塞结果不清空；`state._keyClassesByContent` 从不重置 → 连解多题时上一题数据串进本题提示词/类选择 | v1.3.14：`analyzeJavaLike` 入口 `clearMcpCache()`；`_keyClassesByContent` 并入 `clearMcpCache()` 重置 |

---

## 7. 安全约束（必须保持）

1. **不发布私有信息**：`E:\...` 路径、IP、用户名、私有端点不得进仓库（当前 0 泄露）。
2. `HANDOFF.md`（含真实 flag/路径）**不得**入库（已 gitignore）。
3. 经验入库：**解题成功（已验证 flag）时自动入库**（内容级去重）；未确认成功的才需用户发「保存」。
4. **禁止** `taskkill /F /IM node.exe`。
5. **不 clone 含恶意样本的仓库**（只读文本）。
6. 访问仓库前先确认凭据来源；不要往源码/README 写真实 Token。

---

## 8. 构建与发布

```cmd
:: 打包（store=不压缩快 / normal=默认，发布用 / maximum=最慢）
_build.cmd normal
:: 产物：dist-build2\CTF-RE-TOOL.exe（会先自动关闭正在运行的旧 exe）
```
- exe 体积：store≈287MB / normal≈73MB（发布用 normal）
- **发布仓同步**：复制 `electron/ src/ skills/ wiki/ package.json README.md PROJECT-FRAMEWORK.md 启动.bat .gitignore` → `ctf-re-tool-publish` → commit → `git push origin main`
- **版本号需同步 4 处**：`package.json`、`src/index.html`（`version-badge`）、`启动.bat`（GBK，需字节级替换）、`README.md` 头部
- 发 Release：GitHub 网页**无法上传 73MB** 文件 → 走 API（`POST /releases` → `POST uploads.github.com/.../assets`），token 取自 Windows 凭据管理器 `git:https://github.com`
- 发布后**必须验证**：实际下载 exe 并比对 SHA256 == 本地构建产物

---

## 9. 速查：常见任务从哪下手

| 要做什么 | 改哪里 |
|---|---|
| 新增/修复 AI 工具 | `main.js` `getToolDefinitions()` + `executeToolCall()` + preload 暴露 |
| 新增 IDA 工具 | `main.js` candidates + `normalizeIdaArgs`；`app.js` 调用点 |
| 新增验证算法 | `app.js` `VERIFY_ALGOS` 常量 + `buildSolvePython` 求解器分支（**两处同改**） |
| **新增求解流程** | **只调一处**：`const { verifiedFlags, flags } = await finalizeSolve(text, { source })` —— 它内含「验证闭环 + 失败自动枚举 + 登记 flag + 解题成功则经验自动入库」四件。经验注入用 `buildSystemPrompt()` 或 `experienceSection()`；禁止调工具的路径必须 `prefetchKnowledge()`。**别再手写 verifyAndRecord+harvestExperience 两步**（v1.3.13 已把 9 处收口为 finalizeSolve） |
| 改解题提示词 | `app.js` `toolUseDeepSolve` / `autoSolveFlag` / `analyzePYC` 的 prompt |
| 改 PYC 反汇编 | `electron/pyc_decompile.py`（后端链）+ `main.js` `pyc-decompile` 分区解析 |
| 改知识库 | `wiki/` 页面 + 更新 `AI-SEARCH-INDEX.md` / `README.md` 登记 |
| 改技能 | `skills/<name>/SKILL.md` |
| 改 UI | `src/index.html` + `src/css/style.css` + `app.js` 事件 |
| 排查环境问题 | `wiki/frida/environment-troubleshooting.md` |
| 求解器回归测试 | 见下方"测试基线" |

### 测试基线（每次改求解器/验证闭环后跑）
在 `C:\Users\Administrator\_revhelp\` 放临时脚本（**勿入库**）：
- **求解器回归 11 项**：AES/DES-CBC（有/无/错 IV）、口令派生 key、ChaCha20、RC4、XOR（多字节+单字节整数）、custom 返回 str、负例不误报
- **PYC 实战 4 项**：`py_obf_04.pyc`（Python 3.12，base64+XOR 199）各种契约写法
- 做法：用 `new Function` 抽出 `buildSolvePython` → 写 template → 用 python 替换 `ATTEMPTS` 跑
