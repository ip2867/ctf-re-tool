# CTF-RE-TOOL 项目框架总览

> **用途**：本文件是项目的**单一事实来源（SSOT）速查文档**。上下文压缩后，先读本文件即可恢复对项目全貌的理解，再按需深入具体文件。
> **版本**：v1.3.7 ｜ **形态**：Electron 桌面应用（Windows）｜ **定位**：CTF 逆向 AI 解题工作台
> **一句话**：把「静态分析 → 动态 Hook → 算法还原 → 本地验证」串成 AI 可自主驱动的流水线，通过 MCP 接入 IDA/JEB/Burp，内置 11 个方法论技能 + 54 页结构化知识库。

---

## 1. 目录结构与规模

```
ctf-tool-v2/                         # 源码仓（本地，无远程）
├── electron/
│   ├── main.js        (~4600 行)    # 主进程：全部业务逻辑 + 54 个 IPC handler
│   └── preload.js     (107 行)      # contextBridge 暴露 57 个 API（sandbox:true）
├── src/
│   ├── index.html     (567 行)      # 主页面（CSP + SRI）
│   ├── css/style.css  (1300 行)
│   └── js/app.js      (~8180 行)    # 渲染层：UI + AI 编排 + 解题流程 + 验证闭环
├── skills/                          # 11 个方法论技能（SKILL.md，AI 用 read_skill 加载）
├── wiki/                            # 54 页可检索知识库（AI 用 wiki_search/wiki_read）
│   ├── AI-SEARCH-INDEX.md           # 全局检索索引（优先读）
│   ├── PAYLOAD-CHEATSHEET.md        # 套路/Payload/脚本速查
│   ├── reverse/ (43 页 + _INDEX)    # 历年逆向题条目库（YAML meta）
│   ├── frida/ (6 页)                # 动态 Hook 手法页
│   └── firmware/ (1 页)
├── assets/icons/                    # 图标
├── package.json                     # electron-builder 打包配置（portable）
├── _build.cmd                       # 本地打包脚本（gitignore，不入库）
└── 启动.bat                         # npm start 包装
```

**发布流程（两仓）**：`ctf-tool-v2`（源）→ 复制到 `ctf-re-tool-publish` → 推送 GitHub `ip2867/ctf-re-tool`。

---

## 2. 进程架构与数据流

```
┌─────────────────────────────────────────────────────────────┐
│ 渲染进程 (src/js/app.js)                                      │
│   UI / 事件 / 解题流程编排 / AI 对话 / 知识库检索              │
│   ↕ window.electronAPI.xxx()   （注意：大写 API）             │
├─────────────────────────────────────────────────────────────┤
│ preload.js  (contextBridge, sandbox)                          │
│   ↕ ipcRenderer.invoke('xxx', ...)                            │
├─────────────────────────────────────────────────────────────┤
│ 主进程 (electron/main.js)                                     │
│   IPC handlers / 外部工具调用 / MCP 客户端 / AI 传输 / 落盘     │
│   ↕ spawn(参数数组, shell:false)                              │
├─────────────────────────────────────────────────────────────┤
│ 外部：IDA MCP(13337) / JEB MCP(16161) / Burp MCP(9876)        │
│       nox_adb(62025) / frida-server(27042) / Claude API       │
└─────────────────────────────────────────────────────────────┘
```

**关键约定**
- 渲染层**禁止**拼 shell 命令；一律走 `runToolArgs(argv[])`（argv 数组、`shell:false`）。
- 渲染层调主进程**必须**用 `window.electronAPI`（曾误写 `electronApi` 致 IDA 采集全空）。
- 落盘根目录：开发态=应用目录；打包态=`%APPDATA%/ctf-reverse-tool/`（`writableBase()`）。

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
| Frida 执行 | `execFridaHook` / `runFridaOnce`（滚动窗口抓取）/ `resolveFridaProcessName` / `resolvePidByName` |
| 知识库 | `listWikiDirs` / `wikiSearch`（解析 YAML meta 加权）/ `wikiRead` |

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

---

## 4. 渲染层 app.js 解题流水线（核心）

### 4.1 入口分流
```
analyzeFile()  → detectFileType → 按类型分派:
  APK/DEX  → analyzeAPK()      (JEB MCP + IDA MCP + Frida)
  PE/ELF   → analyzePE()/analyzeELF()   (IDA MCP)
  PYC      → analyzePYC()
  JS/HTML  → analyzeWebJS()    (Burp MCP + 代理浏览器)
  ...      → analyzeBIN/MachO/Lua
```

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

### 4.3 求解三阶段
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
  → buildSolvePython(attempts)   → Python 本地复现（真实跑）
  → [HIT] flag = ... → recordFlag(verified=true)
AI 输出 [HYPOTHESES][...][/HYPOTHESES] → runHypotheses() 并行枚举组合
```
- `VERIFY_ALGOS` / `VERIFY_CONTRACT`：**契约模板唯一权威常量**（不要再各处写死 algo 清单）。
- 支持算法：`rc4/tea/xtea/xxtea/xor/aes_ecb/aes_cbc/des_*/des3_ecb/sm4_ecb/chacha20/salsa20/base64/base64_custom/node_js/custom`。
- **ChaCha20 坑**：counter 初值常非 0（本题=1）；`dec_chacha20_try` 枚举 counter 大小端候选。

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
- `harvestExperience()` 收割 AI 输出的 `[EXPERIENCE]...[/EXPERIENCE]`（支持 `→` 多步攻击链）。
- **只在用户发送「保存」时**才写入 `experience.md`（`flushPendingExperience()`），否则只暂存。
- 下次解题 `selectRelevantExperience()` 按关键词注入系统提示。

### 4.8 系统提示 buildSystemPrompt()
注入：真实 MCP 连接状态 + 技能索引 + wiki 索引 + 经验速查 + 已收集结论（防重复劳动）。**只注入索引，不注入全文**（省 token）。

---

## 5. 知识库（wiki/）与技能（skills/）

### 5.1 wikiSearch 结构化加权（v1.3.5 修复）
- 兼容两种 meta 写法：`---` front matter **和** ` ```yaml ` 围栏块（reverse/ 用的是后者）。
- 加权字段：`tags(6)` / `key_observations|key_payload|failed_attempts(5)` / `one_liner(5)` / `attack_chain(4)` / `reasoning_chain(4)` / `vuln_type|contest|difficulty(3)`。
- 命中片段优先展示 `one_liner`+`attack_chain`，**保留原文大小写**（防 flag 被小写化）。

### 5.2 11 个技能
`ctf-dispatch`（分流调度）｜`ctf-reverse-binary`（PE/ELF）｜`ctf-reverse-android`（APK）｜`ctf-reverse-langs`（pyc/Go/Rust/Lua）｜`ctf-reverse-tooling`（Z3/angr/Unicorn）｜`ctf-frida-dynamic`｜`ctf-antidebug`｜`ctf-jsreverse`｜`ctf-iot-firmware`｜`ctf-crypto-identify`｜`ctf-writeup`

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
| Hook 有输出却报"共 0 条关键数据" | 滚动窗口只在 `[DATA]`/flag 时续期，纯 `[HIT]` 噪音不续期 | 改为**任何新输出都续期**；收尾报告给 3 个计数 |
| 单契约复现失败即卡死 | AI 未给 `[HYPOTHESES]` → 只打警告不枚举 | `synthesizeHypotheses()` 自合成候选矩阵（≤24 组） |
| AES-CBC 缺 IV 必然无命中 | 求解器缺 IV 直接抛 `Incorrect IV length` | `dec_cbc_multi()` 枚举 IV + 回退 ECB |
| 进程内解密段刷 25 行同错 | IV 不合法即 `return`，3s tick 无限重刷 | 枚举 IV/key/模式 + 最多重试 4 次 |
| 枚举 NPE 时仍试 `-f` spawn | `-f` 与 `-n`/`-F` 同走 NPE 路径，注定失败 | `autoFridaStage` 直接 adb 拉起 + PID attach |
| 手动 Hook 只抓启动噪音 | `runHook` 只 attach 不驱动 UI，App 停首页 | 与自动阶段一致：并行 `driveAppIteratively` |

---

## 7. 安全约束（必须保持）

1. **不发布私有信息**：`E:\...` 路径、IP、用户名、私有端点不得进仓库（当前 0 泄露）。
2. `HANDOFF.md`（含真实 flag/路径）**不得**入库（已 gitignore）。
3. 经验入库**只在用户发「保存」时**触发。
4. **禁止** `taskkill /F /IM node.exe`。
5. **不 clone 含恶意样本的仓库**（只读文本）。

---

## 8. 构建与发布

```cmd
:: 打包（store=不压缩快，normal=默认，maximum=最慢）
_build.cmd store
:: 产物：dist-build2\CTF-RE-TOOL.exe
```
- exe 约 300MB（store）/ 76MB（压缩）
- 发布仓同步：复制 `electron/` `src/` `skills/` `wiki/` `package.json` `README.md` `启动.bat` → `ctf-re-tool-publish` → 提交 → `git push`
- 版本号需同步 4 处：`package.json`、`src/index.html` 徽章、`启动.bat`、`README.md` 头部

---

## 9. 速查：常见任务从哪下手

| 要做什么 | 改哪里 |
|---|---|
| 新增/修复 AI 工具 | `main.js` getToolDefinitions + executeToolCall + preload 暴露 |
| 新增 IDA 工具 | `main.js` candidates + normalizeIdaArgs；`app.js` 调用点 |
| 新增验证算法 | `app.js` VERIFY_ALGOS 常量 + buildSolvePython 求解器分支（**两处同改**） |
| 改解题提示词 | `app.js` toolUseDeepSolve / autoSolveFlag 的 prompt 字符串 |
| 改知识库 | `wiki/` 页面 + 更新 `AI-SEARCH-INDEX.md` / `README.md` 登记 |
| 改技能 | `skills/<name>/SKILL.md` |
| 改 UI | `src/index.html` + `src/css/style.css` + `app.js` 事件 |
| 排查环境问题 | `wiki/frida/environment-troubleshooting.md` |
