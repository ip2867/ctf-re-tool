# CTF-RE-TOOL v1.9.1

[![Release](https://img.shields.io/github/v/release/ip2867/ctf-re-tool?color=d97757)](https://github.com/ip2867/ctf-re-tool/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)]()
[![Electron](https://img.shields.io/badge/Electron-35-47848F?logo=electron&logoColor=white)]()

一个基于 Electron 的 **CTF 逆向 AI 解题工作台**（Windows 桌面应用）。把「静态分析 → 动态 Hook → 算法还原 → 本地验证」串成一条 AI 可自主驱动的流水线，并通过 MCP 实时接入 **IDA / JEB / Burp**，内置 **11 个逆向方法论技能**（Skills）与**可检索的结构化知识库**（Wiki）。

设计原则：**AI 是解题主体，工具提供能力**。不是把功能堆在一起，而是让 AI 在解题过程中真正调用工具、识别算法、验证结论。

- **AI 工具循环（Tool-Use）**：AI 自主调用 JEB/IDA/Frida/Python 等工具反复推进，而不是一次性问答；分阶段提示词（①收集 → ②定位算法 → ③写脚本本地验证 → ④结论）。
- **动态调试闭环**：IDA 调试器可直接下断点、单步、读写内存，覆盖本地 PE 与 Kali 远程 ELF；先静态取数锁定函数，再定向取证。
- **花指令自动修复**：11 类花指令特征识别 + 只 nop 跳转本身的等长修补（字节偏移与语义都不变），修复后自动让 IDA 重新分析并等到就绪；实测把非对齐跳转降 78%、边界冲突点降 98%，让原本反编译失败的关键函数变得可读。
- **本地验证闭环**：AI 给出的每个 flag 都附 `[VERIFY]` 契约，工具自动生成 Python 复现脚本本地跑一遍，标注 ✅已验证 / ⚠️未验证——**不靠"AI 说解出来了"就当解出来了**。
- **结构化知识库**：50 条可检索条目（43 篇历年题 + 7 篇方法论），每条带 `attack_chain` 解法链 / `failed_attempts` 避坑；按题目特征自动预取，命中即注入 AI 上下文。
- **经验自进化**：每次解题沉淀的多步攻击链写入经验库，下次同类题自动速查复用。

**下载**：[v1.9.1 便携版 CTF-RE-TOOL.exe](https://github.com/ip2867/ctf-re-tool/releases/download/v1.9.1/CTF-RE-TOOL.exe)（74.11 MB，单文件双击即用，无需安装 / 无需 Node.js）

> 校验：`SHA256 = 0b81078183312a1e8acb31ab1c4f784ad430284c7423ed64b8d3d29ed32ee167`
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
IDA Pro、JEB、jadx（静态分析）、DIE（查壳）、UPX、apktool（脱壳）、pycdc / pycdas（Python 字节码）。路径在设置页配置，本工具负责调度。

### 3. Frida 自动 Hook
自动生成**针对本题情报**的 Hook 脚本（类名 / native 方法 / 算法特征从静态分析提取，不是固定模板）。

- **Java 层**：Cipher、MessageDigest、String、SharedPreferences、Base64、Arrays.equals
- **Native 层**：扫描 native 方法 + RegisterNatives 拦截（无 `Java_` 导出时的唯一入口）+ 符号级查找
- **JCE 通杀**：Hook `Cipher.init`/`doFinal` 直接吐出算法/密钥/明文，不追业务代码
- **进程内解密**：把求得的 key/iv/密文注入 Hook，在目标进程内 decrypt 后直接取 flag
- **反检测**：文件/端口探测、SSL pinning、反调试三类绕过
- spawn 失败自动回退 attach

### 4. 解密脚本生成
- 自动生成 Python 解密脚本
- 支持常见算法：AES、DES/3DES、TEA、XXTEA、RC4、XOR、Base64（含自定义码表）、CRC32、SM4（国密）
- RSA 攻击脚手架（小指数/factordb/Wiener/共模）、Z3 约束求解、angr 符号执行模板

### 5. 反调试绕过

| 平台 | 覆盖 |
|---|---|
| Android | ptrace / TracerPid / Debuggable 标志 / Frida 文件与端口探测 / System.exit 与 killProcess |
| Windows PE | IsDebuggerPresent / CheckRemoteDebuggerPresent / PEB / NtGlobalFlag / NtQueryInformationProcess |
| APK 重打包 | apktool 解包 → smali patch → 回编 → zipalign + jarsigner 签名，一键批处理 |

### 6. AI 分析引擎
兼容 CCSwitch / Claude Code 的 Anthropic `/v1/messages` 接口，SSE 流式输出，可随时中断。

- **Tool-Use 循环**：AI 自主调用工具反复推进，而不是一次性问答
- **四阶段推进**：①收集代码与数据 → ②定位算法 → ③写脚本本地验证 → ④出结论；先证据后结论，禁止跳步臆测
- **模型分级**：快速模型初解，未出 flag 再升级思考模型
- **上下文纪律**：大输出落盘、旧结果压缩、确定性压缩、连续调用拦截、跨轮失败环（详见开发文档）

### 7. Agent Skills 方法论库
`skills/` 目录 + SKILL.md 格式，兼容 Anthropic Agent Skills。

内置 11 个中文方法论：题解写作、Android、二进制、自动化求解（Z3/angr/Unicorn）、语言特定（Python 字节码/Go/Rust/Lua）、IoT 固件、密码识别、反调试、Frida 动态、JS 逆向、总调度。

AI 通过 `read_skill` 按需加载，系统提示只注入索引。也可往 `%APPDATA%/ctf-reverse-tool/skills/` 放自己的技能，重启生效。

### 8. CASE 证据体系 + 验证闭环
拖入文件自动建案（`cases/<题名>_<md5前8>/`），采集物、脚本、时间线、结构化发现各自落盘。

- **验证闭环**：AI 输出 `[VERIFY]` 契约 → 工具生成 Python 本地复现 → 标注 ✅已验证 / ⚠️未验证
- **本地枚举**：AI 给出 `[HYPOTHESES]` 候选组合，工具并行枚举，命中即停

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

### 12. 分组密码识别与变体求解

S 盒知识库内置 AES / SM4 完整表（含逆 S 盒、Rcon、FK/CK），扫描器不再散落硬编码。

- **S 盒关系判定**：exact（完全相同）/ 逐项 XOR·ADD / GF(2) 仿射（高斯消元 + 回代验证）
- **结构推理**：SM4 的 CK 固定差分、AES 的 S 盒关系 + Rcon → 直接给骨架，未知就说未知
- **多骨架解密**：SM4 枚举密文 × FK × key × 字节序 × 块内排列；AES 走 pycryptodome 覆盖 16/24/32 字节密钥
- **诚实边界**：DES/Blowfish 明确不支持；轮数或 MixColumns 被改的变体不支持，未命中时说明"不代表算法认错"

### 13. 长任务可靠性

借鉴 openclaude 的上下文管理设计，解决长任务三个核心痛点：上下文爆掉、原地打转、崩溃丢进度。

| 能力 | 说明 |
|---|---|
| 大输出落盘 | 超阈值写盘，回传头 60% + 尾 40%（错误堆栈与 flag 常在尾部） |
| 旧结果微压缩 | 只保留最近几条，**绝不清除错误标记**（错误是模型纠错的依据） |
| 确定性压缩 | 超阈值触发，保留任务首条 + 最近若干条 + 抽取的硬事实；不额外调模型 |
| 连续调用拦截 | 相同工具 + 相同入参连续多次即拦，防止原地打转 |
| 跨轮失败环 | 按工具/错误类别/路径三键累计，第 2 次提醒、第 3 次判死 |
| 工具预检 | 执行前检查，错误必带"怎么改" |
| 会话续跑 | JSONL 追加；恢复时清洗未完成的 tool_use / 孤立 tool_result |

界面在 AI 调用工具时显示实时步骤条，长任务不再"看起来卡死"。

### 14. 定向动态调试

**核心原则：动态调试是取证手段，不是探索手段。** 它只回答"这个值运行时是多少"，
不回答"这段代码在干什么"——后者反编译更便宜、更可复现。

四条入场条件全满足才启动调试器：

1. 有函数清单
2. 候选函数说得清职责（读输入 / 做变换 / 比对 / 解壳）
3. **写得出调试假设**：断点地址 + 命中后读哪个表达式 + 期望值 + 判定方式
4. 有办法把流程逼到那里（入口断点 / 输入触发 / 定时触发 / 改 IP）

写不出第 3 条 = 静态还没读够，回反编译。

| 能力 | 说明 |
|---|---|
| 本地 PE | start 后停在入口，可直接单步；32 位 WOW64 优先改内存 |
| 远程 ELF | Kali 上跑 IDA 自带 linux_server，自动 suspend + 重定位符号 |
| 断点 | 变换函数入口/出口 ＞ memcmp/strcmp 调用点 ＞ 解密循环内部 |
| 状态机 | -1 暂停（可单步）/ 0 无进程 / 1 运行中 / 2 已退出 |
| 取数 | 一次命中批量读寄存器 + 关键内存 + 调用栈，不在同一点反复单步 |
| SMC | 在解密循环结束后下断，dump 后对新字节重新静态分析 |

实测：本地 PE 10/10、远程 ELF 11/11。

### 15. 离线加解密与变换链

- **crypto**：AES / SM4 / DES / 3DES / RC4 / TEA 系 / 哈希 / HMAC，数据不出本机（标准向量 35/35）
- **recipe**：CyberChef 式变换链，一次调用跑完 base64→xor→反转→解压，每层给 printable/entropy/hex

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
├── wiki/                 # 可检索结构化知识库（50 条，AI 经 wiki_search/wiki_read 检索）
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

## 开发文档

架构设计、实测报告与优化计划放在 [docs/](docs/)：

| 文档 | 内容 |
|---|---|
| [PROJECT-FRAMEWORK.md](docs/PROJECT-FRAMEWORK.md) | 项目框架总览（SSOT） |
| [AUTOTEST-REPORT.md](docs/AUTOTEST-REPORT.md) | 批量实测报告：104 道题的失败归因与修复 |
| [FINAL-REPORT.md](docs/FINAL-REPORT.md) | 第三轮实测：rank 1–6 机制落地效果 |
| [CHALLENGE-LOG.md](docs/CHALLENGE-LOG.md) | 逐题过程记录 |
| [CTF2-ARENA-8题实战记录.md](docs/CTF2-ARENA-8题实战记录.md) | 8 道题完整 Writeup |
| [OPTIMIZATION-PLAN.md](docs/OPTIMIZATION-PLAN.md) | 优化与完善计划（含每轮实测数据） |
| [OPTIMIZATION-PLAN-V3.md](docs/OPTIMIZATION-PLAN-V3.md) | 优化计划 V3 |
| [PLAN-autonomous-solving.md](docs/PLAN-autonomous-solving.md) | 从辅助解题到自主解题的路线图 |
| [PLAN-cipher-identification.md](docs/PLAN-cipher-identification.md) | 分组密码识别能力规划 |
| [PLAN-openclaude-adoption.md](docs/PLAN-openclaude-adoption.md) | agent 运行时优化计划 |
| [CHANGELOG-ARCHIVE.md](docs/CHANGELOG-ARCHIVE.md) | v1.4.0 及更早的更新日志 |

## 更新日志

### v1.9.1 (2026-10-26) — 花指令（junk code）识别与修复闭环 + 安全性审查

新增一整条**花指令自动修复**能力，并修掉代码审查发现的 7 类会静默改坏正常程序的缺陷。

**花指令能力（新）**

- `junk_scan` / `junk_patch` / `junk_repair` 三个 AI 工具，覆盖 11 类特征
  （假跳转、永真永假 jcc、call/ret 地址操纵、跳转链、伪造函数、异常 XREF、垃圾序列、
  栈指针混淆、跳转到数据）。
- 核心判据：**跳转目标必须落在指令边界上**。"目标不在边界"是纠错依据而不是病症本身。
- 修复策略只把**跳转指令本身**换成等长 NOP，字节偏移与可执行语义都不变。
- 写出修补文件后**自动**让 IDA 重新分析并等到就绪（`ida_open_file` + `idaReloadAndWait`），
  解决"AI 在旧 IDB 上反编译 → 误判修补无效 → 退回自己写脚本 nop"的死循环。
- 多实例兜底：`open_file` 拿不到新实例端口时，用 `list_instances` 按路径匹配 + `select_instance` 精确切换。
- 实测 Matr1x（ELF32）：非对齐跳转 301 → 63（-78.6%），边界图冲突点 403 → 6（-98.5%），
  不可解码 647 → 259，IDA 识别函数 54 → 90，可反编译函数 35 → 50。

**安全性修复（代码审查发现，均已补回归测试）**

| 问题 | 后果 |
|---|---|
| `decodeInsn` 的 `0F 8x` 分支丢弃 `rel` | jcc32 目标恒为 null → 边界图崩溃；线性扫描把 xor + 整条 jnz 一起 nop |
| `isFlagSetter` 把 `test/cmp/and r,imm` 当"条件恒定" | 把编译器最常见的空指针检查 `test eax,eax; jz` 改成无条件 jmp，跳过真实代码 |
| F02 不看条件方向 | "永不跳"被改成"永远跳"；反向跳被改成 `EB FE` 死循环 |
| F05 nop 短 jmp | 执行落进被跳过的字节，垃圾变代码 |
| `scanJunkFeatures` 不校验 `end <= buf.length` | ELF 的 `p_memsz > filesz` 时扫到文件外，主进程 OOM |
| `idaReloadAndWait` 忽略 `new_database`、180s 撞传输层 60s、失败伪装成功 | 丢失旧库；大程序假失败；失败被记成成功 |
| `features` 参数名与 schema 不一致 | 按文档传参 = 静默关闭全部检测 |
| 解码器缺口（`0x40` 当 REX、`0F 77` 多吃一字节、`25/2D/35/3D` 返回 null） | 指令边界整体错位——正是花指令要解决的问题本身 |

新增 `tests/test_junk_safety.js`（58 条断言）专门锁死上述每一类，回归 **88/88**。

### v1.9.0 (2026-10-20) — 动态调试打通 + 知识库可达性修复

这一版只有一件事：**让工具真的能参与解题**，而不是只把能力写进文档。

**动态调试从"看起来能用"变成"实测能用"**

三个被误判了很久的实现缺陷：

1. 进程状态语义判反 —— `get_process_state()` 的 `-1` 是**已暂停**、`1` 是**运行中**。
   之前把 1 当暂停去等、把 -1 当无状态，于是所有单步都"失败"。
2. `continue`/`run_to` 是**异步投递** —— 插件返回的 IP 是投递前的旧值，
   必须轮询到进程真正停下。GUI 程序进消息循环后 STATE 恒为 1，这是正常状态而非错误。
3. `start_process("")` 在路径为空时返回 **0（启动被取消）**。
   以前"能用"是因为进程选项里残留着上次的目标路径；做过一次远程调试后残留变成
   Linux 路径，本地启动就稳定失败——这才是"本地调试时好时坏"的真正原因。

远程调试另有三处与本地不同：`start` 后不会停在入口（需主动 suspend）、
PIE 断点必须用重定位后的地址、`dbg_add_bp` 对远程段恒返回 False（改用 `idaapi.add_bpt`）。

实测：本地 PE 10/10、远程 ELF 11/11。

**知识库从"写了"变成"用得上"**

审计发现方法论页写完后，自动预取**根本拉不到**（5 个真实题面特征全部落榜）：
特征词表没有动态调试信号、检索词退化成 `native`、提示词清单只列非 `reverse/` 页、
技能描述里也没提。修复后 5 类特征均排到第 1 位，普通算法题不误命中。

**新增能力**

- `ida_dbg` 增加 `status` / `suspend`，`start` 幂等
- 运行态下 `step`/`run_to`/`write` 被前置拦截并给出可执行下一步
- `crypto` 离线加解密（AES/SM4/DES/RC4/TEA/哈希/HMAC，标准向量 35/35）
- `recipe` 变换链（CyberChef 式，一次跑完多层）
- `gui_input` 标准控件喂输入 + 回读校验
- `remote_exec` Kali SSH 透传退出码，错误分类为 TIMEOUT/AUTH/REFUSED/UNCONFIGURED

**回归**：单元测试 78/78；新增两个手工验收脚本
（`manual_dbg_local.js` 10/10、`manual_dbg_remote.js` 11/11）。

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

> v1.4.0 及更早版本见 [CHANGELOG-ARCHIVE.md](docs/CHANGELOG-ARCHIVE.md)。

## 许可证

MIT License
