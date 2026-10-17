# CTF-RE-TOOL v1.7.3

[![Release](https://img.shields.io/github/v/release/ip2867/ctf-re-tool?color=d97757)](https://github.com/ip2867/ctf-re-tool/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)]()
[![Electron](https://img.shields.io/badge/Electron-35-47848F?logo=electron&logoColor=white)]()

一个基于 Electron 的 **CTF 逆向 AI 解题工作台**（Windows 桌面应用）。把「静态分析 → 动态 Hook → 算法还原 → 本地验证」串成一条 AI 可自主驱动的流水线，并通过 MCP 实时接入 **IDA / JEB / Burp**，内置 **11 个逆向方法论技能**（Skills）与**可检索的结构化知识库**（Wiki）。

核心是**解题成功率**，不是功能堆砌：

- **AI 工具循环（Tool-Use）**：AI 自主调用 JEB/IDA/Frida/Python 等工具反复推进，而不是一次性问答；分阶段提示词（①收集 → ②定位算法 → ③写脚本本地验证 → ④结论）。
- **本地验证闭环**：AI 给出的每个 flag 都附 `[VERIFY]` 契约，工具自动生成 Python 复现脚本本地跑一遍，标注 ✅已验证 / ⚠️未验证——**不靠"AI 说解出来了"就当解出来了**。
- **结构化知识库**：54 页可检索手法/题解页（含 43 篇历年逆向题，带 `attack_chain` 解法链 / `reasoning_chain` 思维链 / `failed_attempts` 避坑），按关键词结构化加权检索，命中即注入 AI 上下文。
- **经验自进化**：每次解题沉淀的多步攻击链写入经验库，下次同类题自动速查复用。

**下载**：[v1.7.3 便携版 CTF-RE-TOOL.exe](https://github.com/ip2867/ctf-re-tool/releases/download/v1.7.3/CTF-RE-TOOL.exe)（73.9 MB，单文件双击即用，无需安装 / 无需 Node.js）

> 校验：`SHA256 = 04a7c37e53c1b663379ab8683fb1863facd1e551456fffcc50634670908262d1`
>
> 首次运行请在「设置」页填写 IDA / JEB / jadx 等外部工具路径（本工具是调度框架，不含这些工具）。

> 适用范围：CTF 竞赛、授权渗透测试、自有系统的安全研究。请勿用于未授权目标。

## 功能特性

![主界面](assets/screenshots/main-ui.png)

> 三栏布局：左侧文件分析与工具区，中间 AI 对话，右侧输出日志 / Frida Hook / 快速操作。

### 1. 文件拖入+自动识别
- 支持 APK、EXE/PE（含 .NET 识别）、ELF/SO、DEX、PYC（全版本魔数）、JAR/.class、Lua 字节码、WASM、Mach-O
- ZIP 按内容精确区分 APK / JAR / 普通 ZIP
- .NET 程序集自动提示 dnSpy/ilspycmd 流程；APK 自动检测 Unity IL2CPP（global-metadata.dat）
- 显示文件详细信息（MD5、SHA256、大小等）

### 2. 一键调用逆向工具
**静态分析工具：**
- IDA Pro - 静态分析
- DIE - 查壳工具
- JEB - Android 分析
- jadx - DEX→Java 反编译

**脱壳工具：**
- UPX - 脱壳工具
- apktool - APK 解包

**Python工具：**
- pycdc - Python 字节码反编译
- pycdas - Python 字节码反汇编

### 3. Frida 自动 Hook
- 自动生成**针对题目情报**的 Hook 脚本（从静态分析提取类名/native 方法/算法特征注入模板，而非固定模板）
- **Java 层**：Cipher、MessageDigest、String、SharedPreferences、Base64、`Arrays.equals` 等
- **Native 层**：主动扫描 Java 声明的 native 方法 + **RegisterNatives 拦截**（动态注册、无 `Java_` 导出时的唯一入口）+ 符号级 `findFunc`
- **JCE 通杀自吐**：Hook `Cipher.init`/`doFinal`，不追业务代码直接吐算法/密钥/明文
- **进程内解密出 flag**：把已求得的 key/iv/密文注入 Hook，在 App 进程内直接 decrypt 并 `send('[FLAG]...')`，绕过关卡
- **反检测**：Frida 文件/端口探测绕过、SSL pinning 绕过（Java 层 + native `SSL_read/write`）、反调试绕过
- 实时显示 Hook 日志；滚动窗口抓取（每来数据续 60s，绝对上限 10min）；spawn 失败自动回退 attach

### 4. 解密脚本生成
- 自动生成 Python 解密脚本
- 支持常见算法：AES、DES/3DES、TEA、XXTEA、RC4、XOR、Base64（含自定义码表）、CRC32、SM4（国密）
- RSA 攻击脚手架（小指数/factordb/Wiener/共模）、Z3 约束求解、angr 符号执行模板

### 5. 反调试绕过
**Android：**
- ptrace 检测绕过、Debuggable 标志清除
- Frida 文件/端口检测绕过、TracerPid 检测绕过
- System.exit / Process.killProcess / Debug.isDebuggerConnected 绕过

**Windows PE（新增）：**
- IsDebuggerPresent / CheckRemoteDebuggerPresent / PEB BeingDebugged
- NtGlobalFlag / NtQueryInformationProcess / OutputDebugString 绕过

**APK 重打包（新增）：**
- apktool 解包 → smali patch → 回编 → zipalign + jarsigner 签名 一键批处理

### 6. AI 分析引擎（流式输出）
- 兼容 CCSwitch / Claude Code 的 Anthropic `/v1/messages` 接口（Base URL 留空则由环境变量或设置页提供）
- SSE 流式逐字渲染，发送按钮可随时停止 AI 任务
- 429/5xx 自动退避重试；`max_tokens` 可配置；连接 60s / 空闲 120s 超时
- **Tool-Use 循环**（最多 25 轮，工具结果自动截断防止撑爆上下文）
- **分阶段解题提示词**：APK/PE/ELF 深度求解按「①收集代码+数据 → ②定位算法 → ③写脚本本地验证 → ④出结论」四阶段推进，强制"先证据后结论"，禁止跳步臆测
- **模型分级**（cascade）：先用快速模型初解，未出 flag 再升级思考模型，兼顾速度与成功率
- AI 系统提示注入真实 MCP 连接状态、已收集结论（避免重复劳动/推翻已验证项）、知识库索引与经验速查；flag 用 `[FLAG]...[/FLAG]` 契约标记便于程序提取
- **兜底模板针对性**：AI 生成的 Frida 脚本失败时，回退模板会注入题目情报（包名、类名、native 方法、算法特征）做**针对性 Hook**，而非固定模板

### 7. Agent Skills 知识库（v1.2 新增）
- `skills/` 目录 + SKILL.md 格式，兼容 Anthropic Agent Skills / ljagiello·ctf-skills（MIT）
- 内置 11 个中文方法论文档：`ctf-writeup`（提交级题解写作）、`ctf-reverse-android`、`ctf-reverse-binary`、`ctf-reverse-tooling`（Z3/angr/Unicorn 自动化求解 + 迷宫题）、`ctf-reverse-langs`（Python 字节码/Go/Rust/Lua 语言特定逆向）、`ctf-iot-firmware`（固件提取/解包/QEMU 仿真）、`ctf-crypto-identify`、`ctf-antidebug`、`ctf-frida-dynamic`、`ctf-jsreverse`（JS/Web 逆向五阶段）、`ctf-dispatch`（分流与卡题决策）
- AI 可通过 `read_skill` 工具按需加载（渐进披露，不占固定提示词）；系统提示只注入技能索引
- 用户可往 `%APPDATA%/ctf-reverse-tool/skills/` 或应用 `skills/` 目录放自己的 SKILL.md，重启即生效

### 8. CASE 证据体系 + 验证闭环（v1.2 新增）
- 拖入文件自动建案：`cases/<题名>_<md5前8>/`，含 `evidence/`（MCP 采集物落盘）、`scripts/`、`timeline.jsonl`（全量日志时间线）、`findings.json`（结构化发现）
- flag/解题记录双写：原 `solveNotes` 兼容保留，新增结构化 findings（含来源与时间戳）
- **验证闭环**：AI 按契约输出 `[VERIFY]{"algo","key","ciphertext","expected"}[/VERIFY]` → 工具自动生成 Python 本地复现 → flag 标 ✅已验证 / ⚠️未验证
- **本地枚举**：AI 给出 `[HYPOTHESES][...][/HYPOTHESES]` 候选组合（算法/密钥/字节序），工具并行枚举全部组合，命中即停；验证失败自动触发，也可聊天输入 `枚举假设` 手动触发

### 9. WP 双轨（v1.2 新增）
- 模板轨（`wp` 命令 / "生成WP"按钮）：升级为 findings 驱动——证据清单、flag 验证状态自动填充，无数据才留占位
- AI 轨（`aiwp` 命令）：按 ctf-writeup 技能生成"摘要-分步解法-单一完整求解脚本-Flag"提交级题解，AI 失败自动回退模板轨

### 10. Burp MCP + JS 逆向（v1.3 新增）
- **Burp MCP 客户端**：会话握手/工具发现与 IDA 同款（Streamable HTTP），AI 可搜索代理历史、取 HTTP 报文详情、调用插件暴露的任意工具
- Burp 路径可配置（在设置页指定自己的启动器路径），左侧工具区一键启动，MCP 栅格一键连接，`burp 启动`/`burp 历史` 聊天命令
- **ctf-jsreverse 技能**：五阶段流程（观察→捕获→复现→验证→记录）；路径A 算法追踪四板斧 vs 路径B 环境伪装；JSVMP/瑞数/obfuscator.io 判型速查；案例坑库（TikTok X-Bogus、抖音 a_bogus、瑞数 sdenv）
- **node_js 验证契约**：AI 还原的 JS 加密函数经 `[VERIFY]{"algo":"node_js","code":"function decrypt(input){...}","input":"参数原文","expected":"密文"}` 交给本地 node 复现，与抓包密文比对
- **全局经验库**（reverse-skill 进化层思路）：**解题成功自动入库（内容级去重，不重复）**，下次解题自动注入 AI 提示词速查；也可用 `经验 <一句话>` 手动回写、`查经验` 查看

### 11. 结构化知识库 + 检索体系（v1.3.5 重构）
- **三层结构**：`AI-SEARCH-INDEX.md`（全局检索索引，按技术标签定位资源）→ `PAYLOAD-CHEATSHEET.md`（逆向套路/Payload/脚本速查）→ 各专题页
- **历年逆向题条目库（`wiki/reverse/`，43 篇）**：从公开题库筛选的纯逆向题，每题一个页面，带结构化 meta：
  - `attack_chain` —— 完整解法链（特征 → 关键步骤 → 坑 → 出 flag）
  - `reasoning_chain` —— 思维链（怎么想到这条路的）
  - `failed_attempts` —— 走不通的路与原因（**往往比成功更有价值**）
  - `key_observations` / `key_payload` / `one_liner` / `tags` / `difficulty`
- **结构化加权检索**：`wiki_search` 解析 YAML meta，命中 `tags`/`attack_chain`/`reasoning_chain`/`key_observations`/`one_liner` 的条目**大幅加权**（远高于正文散命中），带 meta 的条目优先返回 `one_liner`+`attack_chain` 摘要，让 AI 一步拿到"这道题该怎么解"
- **手法专题**：`wiki/frida/`（多阶段 Hook、进程内解密出 flag、Native 密钥反演、参数/IV 编码坑、环境排障、native 定位+RegisterNatives+反检测+脱壳）、`wiki/firmware/`（固件解包/QEMU 仿真踩坑）
- **两处可放页**：应用内置 `wiki/`（随 exe 分发）+ `%APPDATA%/ctf-reverse-tool/wiki/`（用户自加，重启即生效）；系统提示只注入页面索引，不占固定上下文
- 设计参考 Des-CTF-Knowledge 知识库的「结构化 meta + attack_chain + 分段索引」范式（**仅借鉴设计思路，纯文本条目，零样本落地**）

### 12. 分组密码识别与变体求解（v1.7 新增）
- **S 盒知识库**（`electron/crypto-tables.js`）：AES / AES 逆 / SM4 完整 S 盒、AES Rcon、SM4 FK/CK/旋转常量全部固化，扫描器不再散落硬编码
- **S 盒三级关系判定**：`classifySbox()` 逐个比对标准表，报出 `exact`（完全相同）/ 逐项 `XOR·ADD` / **GF(2) 仿射**（高斯消元求 8×8 可逆矩阵 + 回代验证 256 项），并给出能否精确还原
- **非线性度指标**：Walsh 谱计算（标定值 AES/SM4 = 112，随机置换 90~96）。**只描述设计强度，不据此劝退**——CTF 大量题目用随机置换当 S 盒，照样能解
- **结构推理** `inferCipherStructure()`：SM4 CK 固定差分 → SM4 骨架；AES S 盒关系 + Rcon → AES 骨架；未知结构明确说"未知"而不是硬猜
- **多骨架解密器**：
  - SM4：枚举 密文 × FK × key × 16 种字节序/状态组合 × 3 种块内排列
  - AES：pycryptodome 主路径，枚举 key 长度 16/24/32（轮数 10/12/14）× 字节序 × 状态排列
  - DES/Blowfish：**明确不支持**，不假装能解
- **诚实边界**：轮数被改 / MixColumns 矩阵被替换的变体不支持，未命中时明确提示"不代表算法认错"

### 13. AI Agent 运行时（v1.7.3 新增）
借鉴开源项目 openclaude 的上下文管理与可靠性设计（`electron/agent-runtime.js`，参数逐项对照其源码标定）：

| 能力 | 机制 |
|---|---|
| **大输出落盘** | 超过 24k 字符的工具输出写盘，回传 **60% 头 + 40% 尾**预览（错误堆栈/flag 常在尾部）。旧实现只截头会丢关键信息 |
| **旧结果微压缩** | 每轮把旧 `tool_result` 替换为占位串，只保留最近 6 条；**绝不清 `is_error`**（错误是模型纠错的依据） |
| **确定性上下文压缩** | 超 90k token 触发，保留首条任务 + 最近 10 条 + 抽取的硬事实（偏移/常量/骨架/已排除路线）；熔断 3 次 / 冷却 5 分钟；**不额外调模型** |
| **连续调用拦截** | `sha256(工具 + 完整入参)` 连续 3 次即拦（不做前缀截断，否则"同文件不同尾部的两次写"会被误判） |
| **跨轮失败环** | 按 (工具,错误类别) / 类别 / 路径 三键累计；第 2 次提醒、第 3 次判死；NoSymbol 时给出候选函数名 |
| **工具预检** | 执行前做确定性检查，错误必带"怎么改"：路径不存在给相近文件、IDA 缺参给补救工具建议 |
| **结构化经验检索** | 按当前题特征词给经验条目打分，只注入命中的 top 6（≤600 字符），**零命中不注入** |
| **会话续跑** | 追加式 JSONL；恢复时剥离未完成的 `tool_use` / 孤立 `tool_result`（不清洗会直接 400），末尾注入续跑指令 |
| **API 重试** | 5 次指数退避 + 抖动、优先 `retry-after`、429 上限 3、4xx 不重试 |

**界面**：AI 调用工具时显示实时步骤条（`⏳ 正在反编译 main` → `✅ 1.2s · 3400 字符`），长任务不再"看起来卡死"。

### 14. 对话滚动与离线可用性（v1.7.3 修复）
- **修复"流式输出时无法向上滚动"**：旧实现每收到一个 token 就 `scrollTop = scrollHeight`，用户上滑一次立刻被拽回底部。改为 stick-to-bottom（距底 ≤48px 才跟随；滚轮上滑/PageUp/Home 立即脱离），并加"回到底部"悬浮按钮；日志面板同样受保护
- **图标库本地化**：Font Awesome 全量内置到 `src/vendor/`（约 1MB），CSP 收紧为 `font-src 'self'`。原来依赖 cdnjs，实测超时 16 秒会让 `<link>` 阻塞解析、页面停在 loading（内网/离线环境表现为启动卡死）

## 环境要求

- Windows 10/11
- Node.js 18+
- Python 3.10+（用于解密脚本）
- 安卓9模拟器（ADB端口：62025，Frida端口：27042）

## 打包成单文件 exe

```bash
npm install            # 首次：装依赖（含 electron-builder）
npm run build:exe      # 产物：dist/CTF-RE-TOOL.exe（便携版，双击即用）
```

- 产物为便携单文件 exe（无需安装），图标取自 `assets/icons/icon.ico`
- 打包后取证目录 `cases/`、脚本目录 `scripts/` 会自动落到 `%APPDATA%/ctf-reverse-tool/` 下
  （打包态 `app.getAppPath()` 是只读 asar，不能写入，见 `main.js` 的 `writableBase()`）
- 首次构建需下载 Electron 运行时与打包工具二进制；国内网络建议走镜像：
  ```bash
  set ELECTRON_BUILDER_BINARIES_MIRROR=https://registry.npmmirror.com/-/binary/electron-builder-binaries
  ```

## 工具路径配置

本工具是一个**框架**——它调用外部逆向工具干活，本身不含这些工具。首次运行请在应用内「**设置**」页把工具路径填成你机器上的实际路径，配置保存到 `%APPDATA%\ctf-reverse-tool\config.json`。

需要的工具（JEB/jadx/apktool/UPX/DIE/pycdc/Frida/Nox 模拟器等）请从各自官网获取；IDA Pro、JEB、Burp Suite 为商业软件，需自行购买授权。

`electron/main.js` 的 `DEFAULT_CONFIG` 中所有工具路径默认为**空字符串**（占位），由用户在设置页填入，例如：

```javascript
tools: {
  ida:    'C:\\Tools\\IDA\\ida.exe',
  jadx:   'C:\\Tools\\jadx\\bin\\jadx-gui.bat',
  apktool:'C:\\Tools\\apktool\\apktool.jar',
  upx:    'C:\\Tools\\upx\\upx.exe',
  nox_adb:'C:\\Program Files\\Nox\\bin\\nox_adb.exe'
}
```

## 安装与运行

```bash
# 克隆项目
git clone <repository-url>
cd ctf-tool-v2

# 安装依赖
npm install

# 启动应用
npm start

# 或者双击 启动.bat
```

## 项目结构

```
ctf-tool-v2/
├── package.json          # 项目配置 + electron-builder 打包配置
├── electron/
│   ├── main.js           # Electron 主进程（IPC、工具调用、MCP 客户端、AI 传输、知识库检索、打包路径处理）
│   └── preload.js        # 预加载脚本（contextBridge 暴露 API，sandbox 开启）
├── src/
│   ├── index.html        # 主页面（CSP + SRI 加固）
│   ├── css/style.css     # 样式（暖白简约主题）
│   └── js/app.js         # 渲染层逻辑（AI 编排、Tool-Use 循环、Hook 生成、验证闭环、WP 生成）
├── skills/               # 11 个逆向方法论技能（SKILL.md，AI 经 read_skill 按需加载）
│   ├── ctf-dispatch/     #   总调度：分类 → 选方法 → 卡题换路
│   ├── ctf-reverse-binary/ ctf-reverse-android/ ctf-reverse-langs/
│   ├── ctf-reverse-tooling/   #   Z3/angr/Unicorn 自动化求解 + 迷宫题
│   ├── ctf-frida-dynamic/ ctf-antidebug/ ctf-jsreverse/
│   ├── ctf-iot-firmware/ ctf-crypto-identify/ ctf-writeup/
├── wiki/                 # 可检索结构化知识库（54 页，AI 经 wiki_search/wiki_read 检索）
│   ├── AI-SEARCH-INDEX.md      # 全局检索索引（优先读）
│   ├── PAYLOAD-CHEATSHEET.md   # 逆向套路/Payload/脚本速查
│   ├── reverse/                # 43 篇历年逆向题（YAML meta：attack_chain/reasoning_chain/failed_attempts）+ _INDEX.md
│   ├── frida/                  # 6 篇动态 Hook 手法页
│   └── firmware/               # 固件解包与仿真
├── assets/icons/         # 应用图标
├── LICENSE               # MIT
├── 启动.bat              # Windows 快速启动
└── README.md
```

> `dist*/`（打包产物）、`cases/`（取证目录）、`scripts/`（生成脚本）为运行期产物，不入库。

## 使用说明

### 基本操作

1. **拖入文件**：将 APK/EXE/ELF 等文件拖入左侧区域
2. **查看信息**：自动显示文件类型、MD5、SHA256 等信息
3. **启动工具**：点击工具按钮直接启动对应逆向工具
4. **生成脚本**：点击快速操作按钮生成 Frida/解密脚本

### 分析流程（基于ctf-agent）

**APK分析：**
1. DIE查壳 → 有壳则脱壳
2. jadx/JEB静态分析
3. 定位关键函数
4. Frida Hook动态分析
5. 算法还原 → Python解密脚本

**PE分析：**
1. DIE查壳 → 有壳则脱壳
2. IDA静态分析
3. 反调试检测与绕过
4. 算法识别
5. 解密脚本生成

**ELF分析：**
1. IDA静态分析
2. 反调试检测与绕过
3. 算法识别
4. Frida动态分析

### 快捷键

- `Enter` - 发送消息
- `Shift+Enter` - 换行

## Claude API 配置（兼容 CCSwitch）

本应用会读取 CCSwitch/Claude Code 使用的环境变量，并直接调用 Anthropic-compatible `/v1/messages` 接口：

- `ANTHROPIC_BASE_URL`：你的 AI 接口地址（如 `https://api.anthropic.com`，或自建/中转地址）
- `ANTHROPIC_AUTH_TOKEN`：你的 API Token / 鉴权 Token
- `ANTHROPIC_MODEL`：模型名，例如 `claude-sonnet-4-5`、`glm-5.3`

也支持 `CTF_CLAUDE_BASE_URL`、`CTF_CLAUDE_API_KEY`、`CTF_CLAUDE_MODEL` 覆盖上述值。也可以在应用「设置 → AI 接口」里直接填写 Base URL / API Key（保存到用户目录 config.json，不进源码）。启动前可在 PowerShell 中设置（不要把真实 Token 写入源码或 README）：

```powershell
$env:ANTHROPIC_BASE_URL = "https://your-api-endpoint.example.com"
$env:ANTHROPIC_AUTH_TOKEN = "<你的 Token>"
$env:ANTHROPIC_MODEL = "claude-sonnet-4-5"
npm start
```

未配置 Base URL 时，应用会在调用 AI 时明确报错并提示去哪里配置。

应用会自动请求 `${ANTHROPIC_BASE_URL}/v1/messages`。如果你的服务提供的是完整 `/v1/messages` URL，请去掉该后缀。若从 CCSwitch 启动本应用，请确认 Electron 子进程继承了这些环境变量；否则将变量设置为 Windows 用户环境变量或使用同一 PowerShell 启动。


本项目默认使用 **夜神模拟器 Nox（Android 9）**，不是雷电（LDPlayer）。默认配置为：

- ADB：`127.0.0.1:62025`
- Frida 转发端口：`127.0.0.1:27042`
- ADB 程序：`<Nox安装目录>\bin\nox_adb.exe`（在设置页配置实际路径）

因此**不需要另外下载雷电 App**。如果你使用 LDPlayer，需要在配置中改成 LDPlayer 的 ADB 路径和实际端口，并确认设备架构与 `frida-server` 一致。

### 首次部署 Frida

1. 在模拟器中开启 Root，并确认设备在线：

```bat
<nox_adb路径> connect 127.0.0.1:62025
<nox_adb路径> -s 127.0.0.1:62025 shell getprop ro.product.cpu.abi
<nox_adb路径> -s 127.0.0.1:62025 devices
```

2. 从 Frida Releases 下载与电脑端 `frida` 版本相同、架构匹配的 `frida-server`，然后部署：

```bat
<nox_adb路径> -s 127.0.0.1:62025 push frida-server /data/local/tmp/frida-server
<nox_adb路径> -s 127.0.0.1:62025 shell su -c "chmod 755 /data/local/tmp/frida-server"
<nox_adb路径> -s 127.0.0.1:62025 shell su -c "/data/local/tmp/frida-server -D"
<nox_adb路径> -s 127.0.0.1:62025 forward tcp:27042 tcp:27042
frida-ps -H 127.0.0.1:27042
```

3. 软件中点击“Frida进程”确认能列出进程，再点击“运行Hook”。运行前先安装并启动 APK；软件会抓取约 20 秒 Hook 输出。也可以在终端持续运行：

```bat
frida -H 127.0.0.1:27042 -n "包名或进程名" -l hook.js
```

若提示 `unable to connect`，依次检查：模拟器在线、`frida-server` 正在运行、PC 端 `frida` 与 server 版本一致、端口转发存在、目标进程已经启动。

## IDA MCP（ELF/PE）要求

“ELF 一键 AI 分析”需要 **IDA 已打开当前 ELF/PE 文件，并且 IDA MCP 插件正在监听 `http://127.0.0.1:13337/mcp`**。应用现在会完成 MCP 会话握手、读取 `tools/list`、兼容 JSON/SSE 响应并按实际工具名调用。若端口未监听，先在 IDA 中启用 MCP 插件，再重试；日志中应看到“IDA MCP 已连接”和工具发现结果。

Android/APK 流程使用 JEB MCP（默认 `127.0.0.1:16161`），与 IDA MCP 是两套独立服务，所以 APK 正常不代表 IDA 已启动。


## 更新日志

### v1.7.3 (2026-10-18) — AI Agent 运行时 + 对话滚动修复 + 分组密码能力补齐

**一、AI Agent 运行时（借鉴 openclaude）**

新增 `electron/agent-runtime.js`，解决长任务三个核心痛点：上下文爆掉、原地打转、崩溃丢进度。

| 能力 | 机制 | 参数来源 |
|---|---|---|
| 大输出落盘 | 60% 头 + 40% 尾预览，超阈值写盘可回读 | openclaude 50k → 本工具 24k（窗口更小） |
| 旧结果微压缩 | 保留最近 6 条；**不清 is_error** | `microCompact.ts` |
| 确定性压缩 | 90k token 触发，抽硬事实；熔断 3 次/冷却 5 分钟 | `autoCompact.ts` |
| 连续调用拦截 | `sha256(工具+完整入参)` × 3 | `doomLoop.ts` |
| 跨轮失败环 | 三键计数，第 2 次提醒、第 3 次判死 | `toolFailureLoopGuard.ts` |
| 工具预检 | 错误必带"怎么改" | `toolErrors.ts` |
| 经验检索 | 按题型特征词打分，零命中不注入 | `memdir/` |
| 会话续跑 | JSONL + 结构清洗 | `sessionStorage.ts` |
| API 重试 | 5 次指数退避 | `withRetry.ts` |

> 与计划的偏差：A3 原计划"调模型生成摘要"，改为**确定性抽取硬事实**——压缩本身要再发大请求且可能失败，而 CTF 里必须保住的是偏移/常量/骨架/已排除路线，规则抽取即可。

**二、复查抓到的 4 个致命缺陷（都会让真实求解中断）**

| 缺陷 | 后果 |
|---|---|
| 预检/失败环伪造 `tool_use_id`（`id+'-adv'`） | API 400，整轮求解中断 |
| `needPath` 错列 `run_python`/`ida_decompile` | 所有 Python 脚本与 IDA 反编译被判"缺 path"而拒绝 |
| IDA 参数名写错（`function` vs 真实 `function_name`） | IDA 工具永远无法通过预检 |
| 压缩切点落在 `tool_result` 上 | 对应 `tool_use` 被丢弃 → API 400 |

**三、对话滚动修复**

流式输出时每收到一个 token 就 `scrollTop = scrollHeight`，用户上滑一次立刻被拽回底部。改为 stick-to-bottom（距底 ≤48px 才跟随；滚轮上滑/PageUp/Home 立即脱离），新增"回到底部"按钮；日志面板同样受保护。

**四、离线可用性**

Font Awesome 全量本地化（约 1MB），CSP 收紧。原来依赖 cdnjs，实测超时 16 秒导致 `<link>` 阻塞解析、页面卡在 loading——内网/离线环境会表现为启动卡死。

**五、分组密码能力（v1.7.0–1.7.2）**

- `crypto-tables.js`：AES/SM4 全表知识库
- `classifySbox()`：exact / XOR·ADD / GF(2) 仿射三级判定
- S 盒非线性度（Walsh 谱）：**修正了两处公式错误**——旧实现把 AES/SM4 标准表也算成 -128，会让 AI 放弃真实 S 盒
- `inferCipherStructure()`：SM4 / AES 骨架推理
- 多骨架解密器：SM4 全组合枚举 + AES pycryptodome 主路径；DES/Blowfish 明确不支持

**六、测试**

25 个测试文件 / 13 道真实回归题 / 全绿。新增专项：
- `test_tool_contract.js`（57 项）：工具 schema 与预检/UI 标签的参数名一致性
- `test_precheck.js`（26 项）：合法调用必须放行、非法调用必须拦截
- `test_message_contract.js`（17 项）：`tool_use`/`tool_result` 一对一契约
- `test_agent_runtime.js`（60 项）：运行时九大能力
- `test_scroll_follow.js`（14 项）/ `test_ui_integrity.js`（36 项）：滚动与 UI 接线

### v1.6.0 (2026-10-17) — 自主解题：确定性感知 + 负面断言反证 + 全组合枚举

**核心转变**：从"给 AI 喂结论"升级为"**用数据验证假设**"。四个阶段（详见 `PLAN-autonomous-solving.md`）：

**一、载荷检测流水线（可插拔）**

新增 `PAYLOAD_DETECTORS` 注册表，把"找下一层载体"从单一公式升级为按序尝试多种形态：
单字节 XOR/ADD×stride 1/2/4、周期 XOR（2/3/4/8 字节）、滚动 XOR/ADD、Base64/Hex 文本存储、
ELF/DEX、裸 shellcode 序言。新增形态只需注册一个函数，主流程/提示词/测试都不用改。

> 回归题集当场抓到一个会让情况变糟的误报：首版把 **11 道正常 ELF 全报成"内嵌 ELF @0x0"**。
> 根因是 `key=0`（明文）未排除。没有回归题集，这个缺陷会让 AI 对每道正常 ELF 题都先去"提取下一层"。

**二、负面断言自动反证（本项目最重要的机制）**

AI 说"没有第二载体 / 没有加密 / 真 flag 不在此文件"时，工具**不再被动采信**，而是用扫描数据反驳：
- 规则表：`no-second-carrier` / `no-crypto` / `no-decoding` / `no-vm` / `delegates-to-user`
- 只看确定性证据（偏移、长度、魔数），不用猜测反驳猜测
- 反证成立且本轮无 flag → **自动追加一轮 AI**，把反驳当新一轮输入

> `delegates-to-user` 专门拦"请用户提供 stage2"这类**把可自动完成的活推给人**的结论——
> 实测中 AI 的正确诊断配上了错误的行动，工具本可以自己提取。

**三、假设—实验—反馈闭环**

- Python 模板输出 `[FAIL]`/`[MISS]` 结构化行 → 归因分类为"算法错 / key 错 / 参数形态错 / 密文取错"，给出可执行建议
- `rankAttempts()` 按信息增益排序（工具识别的算法优先、已排除组合降权）
- 失败组合落盘 `excluded_paths.json`，下一轮提示词注入"已排除的路"

**四、跨阶段自主接力**

- 扫描到高置信度 PE/ELF/DEX 载荷且本层无算法指纹时，工具**自动**解码→写盘→校验魔数→接力，不再等 AI 喊
- 判据区分「载荷定位结论」与「算法指纹结论」（修复了"内嵌 PE/high"被误判导致自动接力全线失效的 bug）
- 四段式交接包；层数上限 3→6，防循环交给 md5 去重

**五、常量差分分析 + SM4 变体全组合解密**

针对"AI 认出了算法却仍解不出"的问题（实测 345 秒 / 59 次工具调用未果）：
- `analyzeCustomBlockConstants()`：比对 S 盒与标准表、定位轮常量表并算出**精确差分**
  （如"该表 = 标准 SM4 CK 的每一字节都 +0x1"）、给出 FK 候选与字节序线索
- `buildSM4VariantDecryptScript()`：生成可执行脚本，枚举 密文候选 × FK 候选 × key 候选
  × 8 种字节序 × 3 种块内排列，命中即退出
- 阶段 1.9：工具直接跑该脚本，**1.1 秒解出**，不再消耗 AI 预算

**能力边界（明确声明）**：脚本只覆盖 **SM4 骨架**。无 SM4 形态轮常量表时**拒绝生成**；
未命中时明确标注"不代表算法认错"，避免 AI 误推翻正确结论。

**六、修复真机暴露的 3 个通用缺陷**

| 缺陷 | 后果 |
|---|---|
| `analysisData` 跨作用域引用（3 处） | `ReferenceError` 吞掉整轮 AI 结果 |
| "内嵌 PE/high" 被当作算法指纹 | 自动接力在**每道 loader 题**上失效 |
| `_inStageHandoff` 阻断多层接力 | 多层题只能剥一层 |

另修复两个解码 bug：ADD 编码方向写反（应 `-key` 而非 `+key`）；JS 模板里的 `"\n"` 劈开 Python 字符串。

**七、测试**

16 个测试文件 / 13 道真实回归题 / 能力边界 14 项断言。
新增 `tests/run_regression.js`（多题实测）与 `tests/test_scope_safety.js`（静态扫描跨作用域引用）。

### v1.5.3 (2026-10-16) — 算法识别优先：文件级指纹扫描 + 步长 S 盒 + 同思路脚本拦截

**背景（Disguise 血泪）**：工具的"算法识别"此前只有**软提示、没有确定性识别**——`detect-file-type`
只管容器类型；`app.js` 里硬编码的 `0x9E3779B9`/S 盒/SM4 只用于聊天回复；真正决定 AI 看到什么的是
IDA 采集器，而 PE/ELF 主路径只读"被反编译函数引用"的地址。后果：AI 每次都往 AES 猜、
反编译 13 个 VM handler、烧掉 500+ 秒仍卡在"怎么写模拟器"。

**一、文件级算法指纹扫描器（核心新增）**

`scanCryptoFingerprints()` **直接读文件字节**（不走 IDA、不受引用关系限制、不需 IDA 在线）：
- 命中 SM4 FK 系统参数（铁证）、SM4/AES/AES 逆 S 盒、SM3 IV、MD5/SHA256 IV、TEA delta、CRC32 多项式、RC4、Base64
- **256 项双射表同时扫 stride=1/2/4**——C 的 `unsigned int sbox[256]` 占 4 字节/项（`8e 00 00 00 …`），
  只扫连续字节会**完全漏掉**；Disguise stage2 的自定义 S 盒 @0xd630 即此形态，**这正是此前把 SM4
  变体误判成 AES 变体的根因**
- 滑动窗口预筛（置换的 XOR/和 为定值的必要条件）保证 180MB 级文件不卡；平凡表过滤
  （相邻差种类 <100 → 剔除偏移表/位重排表/GF(2⁸) 反对数表）；>16MB 通用程序（浏览器/DLL）降为 low 置信度
- **零指纹 = 有效信息**：明确提示"本层是壳/加载器/decoy，算法在下一层，去 dump 后重扫"

**二、识别结果强注入 + 硬顺序约束**

采集阶段与深度求解两处把扫描结论注入提示词**顶部**；出现 high 判定或确认双射 S 盒时追加
**硬性顺序约束**："必须先用对应算法的标准解密框架（SM4：32 轮 + 轮密钥逆序 `rk[31-i]` + 块内字节反序
`[3][2][1][0]`，常量换题目表）完成验证；只有在标准路线确实全部失败（并说明报错）之后，才允许进入
逐条 opcode 手撕 VM 的路线。禁止无视本判定直接啃 VM 字节码。"

**三、防"换写法重跑"：脚本归一化相似度**

在"完全相同签名"拦截之外，新增 `normalizeScript`/`scriptSimilarity`：把变量改名/注释/空白折叠后比较
（二元组 Jaccard），相似度 >88% 视为"同思路换写法"，第 3 次拦截并提示换路。脚本类工具**逐字节相同**
则第 2 次即拦。实测"同一读常量表脚本换写法跑 30 次"的卡死场景可被截住。

**四、知识库/技能联动**

`skills/ctf-crypto-identify`：补"魔改变体识别三问"（常量标准？S 盒双射？轮结构？）与步长 S 盒坑。
`wiki/reverse/method_pe_loader_vm_obfuscation.md`：补"如何用工具扫描结果确认魔改算法"决策表。

**五、测试**：新增 `tests/`（扫描器 11 项 + 解密枚举回归 6 项 + 脚本去重 10 项）+ `run_all.js` 运行器。


### v1.5.2 (2026-10-16) — 修复"模型文本形态工具调用未执行"（AI 空转绕圈根因）+ 多阶段接力 + 长任务超时

**一、文本形态工具调用未被解析（严重：AI 全程空转）**

部分模型/代理不返回标准 `tool_use` 块，而是把工具调用当**纯文本**吐出，形如
`<｜｜tool▁calls▁begin｜｜>ida_find_strings(regex="flag")`（全角竖线 + U+2581 分隔符，训练期特殊 token）。
原解析器只认 `content[].type==="tool_use"` → **工具一个都没执行**，AI 拿不到任何真实数据，只能凭上下文空想，
表现为"3 秒完成、结论全是幻觉、反复绕圈子"（实测 Disguise 题 60 轮预算全废）。

**修复**：`parseClaudeResult` 加兜底解析 `parseTextToolCalls`——识别该标记格式并转成真正的工具调用
（支持 `func(args)`/裸名/`name` 与参数分行/单双竖线变体），同时清洗文本。流式推流处同步过滤，标记不再显示到聊天区。

**二、多阶段接力（壳/packer 题自动续解）**

新增 AI 工具 `switch_to_next_stage`：AI 解出内嵌新文件后自动接力——关闭当前 IDA/JEB 进程、
保留本阶段结论（摘要注入下一阶段）、以新文件重建分析上下文继续求解。层数上限 3，同一 md5 不重复接力。

**三、长任务超时放宽**

`run_python` 60s → **300s**（Z3 求解 AES 变体、大规模枚举需数分钟；旧值会把"正在收敛的正确解法"误杀成超时，
AI 误判方向后换路重试，烧光预算）；`bash` 30s → 120s。超时提示改为可行动指引（"算得久≠方法错"，建议缩小搜索空间/拆分脚本）。

**四、提示词新增分组密码题分诊**

识别为"16 字节分组 + S 盒查表 + 多轮"（AES 变体/微指令 VM 加密）时，**不硬逆**——写出正向模拟器用
`enc(候选)==目标` 验证（块密码双射，正演验证等价且简单得多）；符号求解一次只解 1 个块、S 盒用常量数组。


### v1.5.1 (2026-10-16) — 修复消息路由误拦 + 全局中文输出

实战反馈两个问题，均修复。

**一、消息路由宽泛关键词误拦（严重：用户消息根本到不了 AI）**

旧路由用 `lowerMessage.includes('工具')` 做子串匹配——只要消息里出现「工具」二字（如"不要调用工具"、"用什么工具解这题"），
就直接返回一段固定的「ctf-agent 工具链」清单并 `return`，**AI 完全收不到消息**。同类宽泛拦截共 13 处（`输出`/`规范`/`脚本`/`流程`/`反调试`/`签名`/`重打包`，以及 `tea`/`aes`/`sm4`/`rc4`/`md5`/`crc`/`apk`/`pe`/`elf` 等算法与类型名），都会把正常提问误判为"查询知识卡片"。

**修复**：全部改为**精确匹配**（`^工具链$` 这类整句命令，或"生成…脚本"这类明确意图短语），普通自然语言提问一律放行给 AI。

**二、AI 输出中英混杂（用户要求全中文）**

AI 的推理叙述常输出英文（"I'll start by analyzing this PE file…"），可读性差。

**修复**：在主进程请求构造处（`sendClaudeRequest` / `sendClaudeRequestWithTools`）**单点注入**语言约束——所有 AI 调用路径（聊天、Tool-Use、分级快慢模型、复盘、题解、动态 Hook 决策）100% 覆盖。约束只针对自然语言叙述；代码、变量名、flag、路径、命令行、寄存器名保持原样不翻译。


### v1.5.0 (2026-10-15) — CTF² 平台 8 题实战打磨：验证闭环三修 + 新题型分流 + 题目隔离

接入 CTF² Agent Arena 真实解题 8 道（全解出）：ELF×5 / XLSX / TXT / zip 手包，全程观察工具表现就地修复 9 个缺陷。

**验证闭环（[VERIFY] 契约本地复现）三修 —— custom 契约命中率 0/3 → 3/3**
1. **调用形态自适应**：AI 常写单参 `decrypt(target)`（置换/数据变换类），旧脚本只按双参调用 → TypeError 全灭。现按 `inspect.signature` 自动尝试 单参/双参原文/双参bytes/关键字参 五种形态，函数名兼容 `decrypt/custom_decrypt/solve/decrypt_flag`。
2. **expected 双向包含**：AI 给的 expected 常被截断成 flag 前缀（如 `dice{P4ra...`），与完整明文全等必败。改双向包含判定，命中值优先取 FLAG_RE 完整匹配。
3. **printable() 剥协议头**：RC4 等明文常带控制字符封装头（`\x03\x11+len`），整段被判不可打印回退成 hex，flag 被埋掉。现剥首尾控制符后再判，主体可读即返回文本。

**新题型分流（直读文本，不再误入固件流程）**
- `detect-file-type` 新增 **XML**（xml/rels/json/plist/yml）与 **TXT**（txt/enc/log/md/csv）两类。
- 新增 `analyzeXMLText()`：全文直读（≤256KB）→ Tool-Use AI 求解（可 read_file 伴生文件、bash 跑 Python 反推）——Excel 公式题、短密文题不再被丢给 Kali 白等 60 秒。
- **OOXML 感知**：xlsx/docx/pptx 按 ZIP 容器解压；主文件按「公式数」主导打分（ExceLLM 实测 244 公式的 VERIFY sheet 正确胜出，元数据 docProps 沉底）。

**平台/下载器加固**
- 下载器目录碰撞防御：附件与同名目录冲突时自动改名重试（EISDIR 整轮中止 → 消除）。
- 每题附件独立子目录 `<下载目录>/<题名>/` + 多附件主文件按类型权重挑选（ELF/PE/pyc/zip 优先）——杜绝 AI 跨题读到历史残留文件（实战真实发生过：AI 把上一题的解压产物当成当前题的逻辑）。
- CTF² 自动解题流水线（MCP 客户端/下载/解压/清理）保留在代码内，**平台拉题按钮从 UI 移除**（内部测试功能不随版本发布）。

**求解器增强**
- AI Tool-Use 提示词加预算纪律（60 轮上限 + 冲刺指令）与「伴生文本必须 read_file 读全文」纪律。
- max_tokens 截断自动续写；IDA `-o` 参数坑规避（同目录建库）。


### v1.4.0 (2026-10-14) — 修复 Frida Hook 证据被噪音淹没 / 降噪失效 / 经验跨阶段丢失

审查两次真实运行日志（一次 APK 自动解题、一次 Frida Hook）发现三个真实缺陷，全部修复。

**一、Frida 输出"真证据被噪音挤出 AI 结论窗口"（高危，可能漏 flag）**

Hook 输出回灌 AI 前，旧逻辑把 `[DATA]`/`[FLAG]` 真证据与 `[HIT]` 噪音**混在一个池子**里再 `slice(-120)`。而噪音（可达上百条）通常出现在真证据**之后** → 尾部 120 条几乎全是噪音，**真证据被整段丢弃**。
本次实测复现：131 条关键行里 2 条真证据 + 129 条噪音，`slice(-120)` 后**真证据 0 条保留**。
（这次 flag 没丢，是因为另有一条独立逻辑直接收割 `[FLAG]` 行兜底；但若 flag 只以 `[DATA]`/普通解密输出形式出现，就会彻底漏掉。）

**修复**：改为**分级保留** —— 高价值行（`[DATA]`/`[FLAG]`/flag 形态/加解密实参/SP 读写）**全部保留、不参与截断**；仅对 `[HIT]` 噪音限量（保留末尾 40 条作线索）。实测：真证据 ✅必留。

**二、Frida `String.equals` 降噪形同虚设（129 条 `[HIT]` 全是误报）**

两条根因：
- 关键词正则 `/flag|ctf|key|secret|token|pass|stage/i` **命中了应用包名本身** —— 本题包名 `com.nctf.hookmysecret` 同时含 `ctf` 与 `secret`，导致每条涉及包名的比较都被判"有意义"而刷屏；
- 兜底规则"两串 ≥6 字且长度差 ≤2"太松，把 `include==ViewStub`、`pathInterpolator==linearInterpolator`、`res/*.xml` 等框架/资源串全部放行。

**修复**：改为"**高熵优先 + 噪音形态黑名单**"——① 高熵串（flag 形态/长 hex/base64）**先**保留（`flag==flag` 这种最终校验不能被误杀）；② 双方均为噪音形态（包名/资源/绝对路径/算法名/框架词）排除；③ 语义词命中且非噪音形态才打印。修复前后对比：**129 条噪音 → 0 条**（降噪 100%），5 个正例（flag、hex key、password 对）全部保留。

**三、经验"跨阶段丢失"（前序暂存的经验永远进不了库）**

一次 APK 解题里，阶段2（初步分析）AI 产出的经验被"暂存"，阶段2.5（Tool-Use）解出 flag 后**只入库了它自己那条** —— 阶段2 那条滞留在内存 `pendingExperience`，既不入库、也不持久化（关应用即丢）。且该暂存区从不随换题清空，会跨题残留。

**修复**：① 换题（加载新文件）时清空 `pendingExperience`；② 解题成功时把**本题前序暂存的全部经验**一并入库（含防御性去重）。实测：阶段2 暂存 1 条 + 阶段2.5 成功 1 条 → 库内 2 条、暂存清空、重复幂等。

> 回归：修复项 #1 真证据必留 ✅ ｜ #2 降噪 128/128 且正例 5/5 ✅ ｜ #3 经验接管与幂等 ✅ ｜ 原有回归（经验流 6/6、相似度 5/5、finalizeSolve 契约 2/2、求解路径审计 10/10）无回退 ｜ `node --check` 全过。

### v1.3.14 (2026-10-14) — 当日汇总

> 本条目汇总 **2026-10-14 当天**的全部更新（原按里程碑分为 v1.3.6 ~ v1.3.14 多次提交，现合并为一个版本）。

**解题结构根治**
- **"三件套"收口**：把"验证闭环 + 经验沉淀"从散落 9 处的两步复制粘贴，收口为单一入口 `finalizeSolve(text, {source})` —— 内含「验证闭环 → 失败自动枚举 → 登记 flag → 解题成功则经验自动入库」，从结构上杜绝"修一处漏一处"。
- **5 类"只指路"入口改为真正解题**：`.dex` / `.jar` / `.class` / Mach-O / `.luac` 此前只启动外部工具或打印指引（AI 不参与），现全部接入 AI 求解闭环 —— DEX/JAR 走 **JEB 优先**（不可用降级 jadx）、Mach-O 走 IDA、`.luac` 走字节/常量抽取。分流表 12/12 均路由到真实求解器。
- **修复跨文件 MCP 缓存泄漏**：`analyzeJavaLike` 未清缓存、`state._keyClassesByContent` 从不重置 → 连解多题时上一题数据会串进本题提示词/类选择；现随 `clearMcpCache()` 一并清理。

**经验与知识库"真正帮到解题"**
- **经验自动入库 + 真去重**：解题成功即写入（无需手动「保存」）；去重从"按整行含日期比对（换日必重复）"改为**与日期无关的内容级去重**（精确 + 二元组相似度≥0.78 + 子串判定）。经验注入补全到所有求解路径。
- **修复题库 meta 解析 bug**：`wiki_search` 解析 YAML 的 `m` 标志令 `$` 匹配行尾，导致**列表写法**的 `attack_chain`/`failed_attempts` 被解析为空 —— 43 篇题库仅 13 篇解法链可用。修复后 **13 → 38 篇**，检索摘要升级为 **要点 + 解法链 + 避坑**。
- **主路径自动预取**：新增 `prefetchKnowledge()`，调用 AI 前按题面特征词检索题库并把攻略内联进提示词（已覆盖 APK/PE/ELF、PYC、Web/JS、DEX/JAR、Lua）。

**PYC 逆向从"无解"到可用**
- 多后端自动回退：**pycdc → xdis/pydisasm → 原生 marshal+dis → 纯字节串扫描**（永不空手）；内置零依赖助手 `electron/pyc_decompile.py`。
- 求解器兼容 `xor` **单字节整数密钥**（`xor_key=199`）、`custom` 返回 `str`/`list[int]` 归一化。

**验证闭环与动态 Hook 通用性**
- **修复 IDA 采集 0 反编译（最严重）**：`window.electronApi` 拼写错被空 catch 吞掉，实测反编译 **0 → 19 个**。
- 验证闭环不再"没契约就放弃"：`synthesizeHypotheses()` 自合成候选矩阵（≤24 组）。
- AES/DES-CBC **缺 IV/错 IV** 不再必然失败（枚举全零/首块/前置 IV + 回退 ECB）；口令 key 自动派生（MD5/SHA-256/零填充）。
- 多候选密文**交叉校验 + 自动裁决**（IDA `xrefs_to` 判"哪条被校验函数引用"），防"变种题"陷阱。
- 动态 Hook：修复"抓到输出却报 0 条关键数据"、手动 Hook 自动驱动界面、枚举失败改按 PID attach、`String.equals` 降噪。

**重构引入问题的修复**
- v1.3.9：验证闭环 7 处复制粘贴收敛为 `verifyAndRecord()`（纯重构）。
- v1.3.10：修复该重构遗漏 —— `autoSolveFlag`/`autoSolveBinaryFlag` 只解构 `verifiedFlags` 却引用裸 `flags`，导致 `ReferenceError: flags is not defined`。


### v1.3.5 (2026-10-13) — 结构化知识库 + 解题成功率优化
- **知识库重构为「结构化 + RAG 友好」**：新增全局检索索引 `AI-SEARCH-INDEX.md` 与速查表 `PAYLOAD-CHEATSHEET.md`
- **历年逆向题条目库**：新增 `wiki/reverse/`，**43 篇**纯逆向题（从 132 候选筛选、剔除 PWN/杂项），每题带 `attack_chain`（解法链）/`reasoning_chain`（思维链）/`failed_attempts`（避坑）等 YAML meta
- **修复结构化检索失效**：`wiki_search` 此前只解析 `---` front matter，而条目库把 meta 放在 ` ```yaml ` 围栏里，导致 tags/attack_chain 加权**完全失效**；现兼容两种写法，并新增 `vuln_type`/`contest`/`difficulty` 加权；命中片段优先展示 `one_liner`+`attack_chain` 且保留原文大小写（防止把大小写敏感的 flag 小写化）
- **系统提示瘦身**：不再逐条列出 43 篇逆向条目路径（交给 `wiki_search` 检索），每次请求省约 1.5k tokens
- **Frida 能力增强**：吸收两大开源 Frida Hook 项目精华——RegisterNatives 拦截、JCE 通杀自吐、SSL pinning 绕过（Java+native）、脱壳、反检测；兜底模板注入题目情报做针对性 Hook（不再是固定模板）
- **AI 解题流程优化**：APK/PE/ELF 深度求解改为四阶段流水线提示词；AI 脚本语法错自动重新生成 2 轮
- **环境自愈**：frida client/server 版本一致性自检、双 adb 互杀重连、装 APK 前 package 服务就绪轮询、GUI 窗口可见性修复（IDA/JEB/Nox）
- **Frida 枚举失败自动降级为按 PID 附加**：某些模拟器（如 Nox Android9）上 `frida-ps`/`-f`/`-n`/`-F` 会抛 `queryIntentActivities NullPointerException`（**即使 client=server 版本完全一致**，是枚举路径本身的 quirk）——旧逻辑据此判"Frida 不可用"并跳过整个动态阶段。现改为 `adb pidof/ps` 取 PID → `frida -p <PID>` 附加（实测该路径正常），动态阶段继续
- **隐私与安全**：移除源码/文档中硬编码的私有 AI 中转地址（Base URL 默认留空，未配置时明确报错）；`git-filter-repo` 抹除历史中的私有域名与本机路径；清理构建残留与一次性调试脚本
- **发现并修复**：`wikiSearch` 结构化 meta 解析失效（见上）；`baseUrl` 为空时由 `Invalid URL` 改为明确的中文配置提示

### v1.3.4 (2026-10-09) — 知识库扩充 + 固件逆向 + 开源发布
- **知识库技能 8→11**：新增 `ctf-reverse-tooling`（Z3/angr/Unicorn 自动化求解 + 迷宫题）、`ctf-reverse-langs`（Python 字节码/Go/Rust/Lua 语言特定逆向）、`ctf-iot-firmware`（固件提取/解包/QEMU 仿真）
- **知识库 Wiki**：`wiki/` 可检索手法页（`wiki_list`/`wiki_search`/`wiki_read`），系统提示只注入页面索引；内置 Frida 专题 + 固件解包/仿真专题
- **Hook 进程内解密直接出 flag**：把已求解的 key/iv/密文注入 Hook 脚本，运行时捕获明文，绕过关卡直接解出；滚动窗口抓取（每来数据续 60s，绝对上限 10min）
- **命令注入收口**：新增参数化执行原语 `run-tool-args`（argv 数组，无 shell 解析）、纯 Node `zip-list`/`grep-in-dir`，渲染层不再拼接 PowerShell/cmd 命令字符串
- **文件 IPC 边界**：`write-file`/`read-file`/`ensure-dir`/`append-file` 加写入根约束（userData/应用目录/临时目录/CASE 目录），并屏蔽读取工具自身凭据配置
- **Electron 加固**：`webPreferences` 启用 `sandbox`，拦截 `will-navigate` 与 `setWindowOpenHandler`（外部链接一律交系统浏览器）
- **界面**：暖白简约主题；键盘焦点环（`:focus-visible`）+ 减少动效支持；移除说明书弹窗
- **打包**：electron-builder 输出便携单文件 `CTF-RE-TOOL.exe`（含应用图标）
- **仓库卫生**：`node_modules`/`HANDOFF.md`/`.zcode` 计划/一次性调试脚本取消入库，重写 `.gitignore`

### v1.3.3 (2026-09-12) — 第四轮复审（自动化流程专项）
- P0：processUserMessage 的 hasWord 在声明前使用（TDZ），英文消息含 "script" 一词即静默崩溃 → 提升至函数顶部
- P1：analyzeWebJS 全程占锁（轮询阶段此前不加锁，可并发双流程造成流错乱）；两个轮询循环可通过再点发送键中止（flowAbortRequested）
- P1：Burp 传输探测双重 initialize（严格 Streamable 服务器会拒绝导致误判回落 SSE）→ 复用 burpHttpEnsureSession
- P2：tools/call 超时不再重试（防非幂等重复执行）；SSE 连接失败路径补 waiter 清理；JS 文件读证失败不再中断流程；AI 空结果单列提示；experience.md 表头判断修正（read-file 返回 {success:false} 而非抛异常）
- 知识库：ctf-dispatch 分流表补 Web/JS/加密参数 → ctf-jsreverse 路由 + 下一步菜单模式 + 经验库优先原则

### v1.3.2 (2026-09-12) — Web/JS 逆向全自动工作流
- **像 IDA/JEB 一样自动拉起工具链**：说"分析这个站的加密参数"即触发——自动探测 Burp（9876）→ 未运行自动启动 MCP_Burp.bat 并轮询就绪（150s）→ 自动连 MCP → 无流量自动拉起**走 Burp 代理的隔离浏览器**（Chrome/Edge 自动探测 + 独立 user-data-dir 保证代理生效 + 忽略证书告警）→ 后台轮询等流量（90s）→ AI 接手按 ctf-jsreverse 五阶段分析
- 新增 IPC：burp-probe（TCP 快探）/ open-proxy-browser（代理浏览器）；新增 web 配置组（浏览器路径/Burp 代理端口，设置页可视化）
- .js/.mjs/.html 拖入即走 Web 流程（JS 原文自动存 evidence）；`burp 启动` 现在启动后自动连接 MCP
- 逻辑单测：路由正则触发/不触发用例、历史空判断（结构化 JSON 检测，10 用例）、浏览器候选探测

### v1.3.1 (2026-09-12) — Burp MCP 实装完成
- 本地 Burp 2025.11.2 全链路实装官方 MCP Server 扩展（burp-suite v1.1.2）：jar 下载 → mcp_user_options.json 免 GUI 自动加载（MCP_Burp.bat 追加 --config-file）→ GUI 勾选 Loaded/Enabled/历史免审批
- 客户端重写为双传输自适应（auto：先 Streamable HTTP 社区扩展，失败转经典 SSE 官方扩展）；SSE 端点路径多候选（/sse 与 /）；notification 不占 pending 超时；URL 变更自动重置传输探测
- 实测：9876 监听 ✓、initialize/tools/list 握手 ✓、27 个工具全部发现（get_proxy_http_history / send_http2_request / get_scanner_issues / Repeater / Collaborator / 编解码）
- 参数适配单测 6 场景全过；tools.burp 默认启动器改为 MCP_Burp.bat

### v1.3.0 (2026-09-12)
Burp MCP 集成 + JS 逆向能力（工作思路参考 reverse-skill 与 hello_js_reverse_skill，择优吸收）：
- Burp MCP 客户端（逻辑名映射：history/message + 任意工具透传），MCP 栅格/工具区/聊天命令三处入口；.bat/.vbs 启动器支持
- 新增 ctf-jsreverse 技能：五阶段流程、路径A算法追踪四板斧、路径B环境伪装、JSVMP/瑞数/obfuscator 判型、案例坑库
- 验证闭环支持 node_js 契约：AI 还原的 JS 函数本地 node 复现（修复 argv 取参 bug 并端到端实测）
- 全局经验库：解题成功**自动入库**（内容级去重）/ `经验 <内容>` 手动回写 / `查经验` 查看 / 自动注入 AI 系统提示（近15条）
- 参考来源：[reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT）

### v1.2.2 (2026-09-12)
第三轮复审（CSS/UI 层 + 知识库技术细节）：
- P1：Frida 输出面板换行丢失+长 hex 行被裁剪（补 pre-wrap/break-all）；日志长 token 同样裁剪；聊天气泡长 base64/哈希撑破面板 + 行内 code 无样式
- P2：流式光标闪烁动画；"分析结果"tab 标题/段落/flag 候选排版（此前被全局 margin 归零挤压）；说明书 help-note 提示框样式；移除分析 tab 双层嵌套 padding；MainActivity 识别支持 activity-alias；自动求解中止提示优化；findings.json 串行化写队列防并发交错
- 知识库：SM4 描述修正（非平衡 Feistel）；7 个 SKILL.md 机器校验（frontmatter/代码围栏闭合/交叉引用/乱码）全部通过；密码学常量与反调试偏移逐项人工复核

### v1.2.1 (2026-09-12)
系统性架构+知识库复审（独立代理交叉审查）修复：
- P0：PE/ELF"详细分析"传入空对象导致 `otherFunctions.length` TypeError，Tool-Use 深度分析必挂
- P1：CSP 使内联 onclick 失效（清空日志按钮同时会折叠面板）；解密模板中 xxtea 实现错误（TEA 风格轮函数，解出乱码）改为正确 MX 算法；`[VERIFY]`/`[HYPOTHESES]` 契约解析遇 custom 代码中的 `}`/`]` 截断（改匹配闭合标签）；Python 求解器契约改 base64 内嵌（三引号守护本就无效）
- P2：验证命中只标命中 flag；AI 中止显示为提示而非错误；聊天路由 pe/tea/md5/crc 等改词边界（"open/steal"不再误触发）；移除 data-collapse 死代码；grep 默认根目录对齐工作目录；browser_search/open 从占位接为真实调用；流式重试不再造成文本重复；PYC 魔数收紧（校验第 2 字节 0x0D）；移除无效 defaultFilter；kali 启动失败如实报错；Frida 17 API 兼容 shim 内置到全部模板；设置页新增"测试AI连接"；安装 APK 前设备就绪轮询
- 知识库：ctf-crypto-identify 契约算法清单与求解器实现对齐；ctf-frida-dynamic 补充 Frida 17+ API 变更说明

### v1.2.0 (2026-09-11)
- Agent Skills 引擎：7 个内置中文方法论 skill（写题解/Android/二进制/算法识别/反调试/Frida/调度），AI 经 `read_skill` 按需加载，用户可自装
- CASE 证据体系：每题独立目录（evidence/scripts/timeline.jsonl/findings.json），MCP 采集物自动落盘
- 验证闭环：`[VERIFY]` 契约 → 自动生成 Python 本地复现 → flag 标注 ✅已验证/⚠️未验证
- 本地枚举：`[HYPOTHESES]` 契约 → 组合枚举一键跑完（TEA/XTEA/XXTEA/RSA字节序/密钥编码歧义等），验证失败自动触发
- WP 双轨：模板轨升级为 findings 驱动（证据清单+验证状态自动填充）；AI 轨（`aiwp`）按 ctf-writeup 技能产出提交级题解，失败自动回退
- 参考 [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)（MIT）与 [anthropics/skills](https://github.com/anthropics/skills) 的 SKILL.md 组织方式

### v1.1.0 (2026-09-11)
**缺陷修复**
- 修复 JEB MCP 一键启动读取错误配置键（`mcp.jeb` → `mcp.jebMcpScript`）的问题
- 修复聊天/日志/Frida 输出的 HTML 注入（XSS）漏洞
- 修复 MainActivity 误识别：现在精确解析 Manifest 中的 LAUNCHER activity
- 修复 APK 自动分析结果虚假成功提示：每步真实汇报 ✅/❌
- 修复 PYC 魔数只认旧版本、`.zip` 一律当 APK、kali-stop-vm 空 vmx 等问题
- 修复设置保存丢失 nox_path/mcp/kali 配置段、WP 保存后脚本类型错乱等问题

**健壮性与体验**
- AI 回复 SSE 流式输出 + 发送按钮一键停止
- JEB/IDA MCP 连接改为就绪轮询；模拟器等待不再固定 60 秒
- 429/5xx 指数退避重试；`max_tokens` 可在设置中调整（默认 8192）
- `saveScript` 实现系统保存对话框；聊天工具栏按钮接线；新增"分析结果"标签页
- 设置页新增 AI 接口 / MCP 地址 / Kali SSH / 输出目录 配置
- 硬编码路径与端口（frida 27042、ADB 62025、scripts 目录、VS Code、JEB MCP 脚本）全部进配置

**解题能力扩展**
- 文件分流新增：JAR/.class（jadx）、.NET（dnSpy/ilspycmd 指引）、Unity IL2CPP（Il2CppDumper 指引）、Lua 字节码（unluac）、Mach-O 指引
- 解密模板新增：SM4、3DES、自定义码表 Base64、RSA（小指数/factordb/Wiener/共模）、Z3、angr
- 新增 Windows PE 反调试绕过 Frida 脚本、smali 重打包签名批处理脚本
- RC4 动态脚本参数化（模块名/RVA 弹窗输入，不再硬编码 2.exe）
- WP 报告增强：多格式 flag 提取（flag/ctf/NSSCTF/SCTF…）、关键结论区块、真实连接状态
- flag 统一提取函数，支持 `[FLAG]...[/FLAG]` 输出契约

**安全加固**
- adb/frida/launch-tool/vmrun 全部改为 spawn 参数数组，消除命令注入面
- Kali SSH 改用 ssh2 库（原 sshpass 方案在 Windows 不可用）；密码不再写死在源码
- `shell.openExternal` 仅允许 http/https；新增 CSP；FontAwesome 加 SRI
- 工具输出统一 8000 字符截断（IPC 与 AI 上下文双重保护）

### v1.0.0 (2026-07-23)
- 初始版本发布
- 支持文件拖入和自动识别
- 集成 IDA、DIE、JEB、jadx、UPX、apktool、pycdc 等工具
- Frida Hook 脚本生成（基于ctf-agent模板）
- Python 解密脚本生成（支持多种算法）
- 反调试绕过脚本生成（支持多种绕过技术）
- 响应式窗口布局

## 许可证

MIT License
