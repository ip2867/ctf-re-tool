# CTF-RE-TOOL 优化与完善计划（第三轮）

> 依据：[FINAL-REPORT.md](./FINAL-REPORT.md)（本轮题库中段 6 道 + rank 6 复测 2 道）+ [CHALLENGE-LOG.md](./CHALLENGE-LOG.md)（逐题）+ [OPTIMIZATION-PLAN-V3.md](./OPTIMIZATION-PLAN-V3.md)（rank 1–6 工单与验收细节）。
> 原则不变：AI 是解题主体，工具提供确定性证据与可执行操作；所有改动必须是通用机制，不针对任何题名。

## 一、已完成（本轮，不需要再做）

| rank | 机制 | 文件 | 测试 | 实战验证 |
|---|---|---|---|---|
| 1 | 去重闸改为地址目标指纹 | `electron/script-dedup.js` | 24 + 68 | ✅ 6 题中多次出现"无地址指纹 → B 层不判定"的正确退让 |
| 2 | 工具结果可信性（失败必须失败） | `electron/tool-result.js` | 65 + 19 + 64 | ✅ 全量回归绿 |
| 3 | IDA 会话身份 + 映像落界 | `electron/binary-map.js` | 40 + 46 | ✅ 6 题 6 次正确重载，无跨题串台 |
| 4 | 平台题目契约贯穿 | `src/js/app.js` | 35 | ✅ level1 正确识别 `flag{}` 包装指令 |
| 5 | 末公里候选闭环（契约驱动 verified） | `src/js/app.js` | 45 | ✅ xxor 首次把验证失败转成成功 |
| 6 | 指纹扫描（MD5 K / lane 变表 / 中性措辞） | `electron/crypto-detect.js` | 32 + 15 | ✅ CrackMe2 报 `MD5(high)`、cnbragon 报 `自定义分组密码(high)`；两题仍未解出（模型侧） |

全量：`node tests/run_all.js` → 单元测试 **49/49**、回归题集通过、exit 0。

## 一之二、2026-10-20 修复与真实联调（已完成）

在 rank 1–6 之上，针对工作流复核暴露的契约级缺口与工具链可用性做了 6 项修复，并完成 4 条真实联调。

### 修复项

| # | 缺陷 | 修法 | 回归用例 |
|---|---|---|---|
| 1 | Burp `get_proxy_http_history` 的 `count`/`offset` 都是必填，`adaptBurpArgs` 只改名 `max→count`，缺 `offset` → 整条 history 报错 | `adaptBurpArgs` 按 schema 的 `required` 补中性初值（数字 0 / 字符串空 / 数组空 / 布尔 false），只补缺不覆盖 | `test_protocol_contracts.js` [1] |
| 2 | MCP `result.isError` 未透传：`requires extension`、`Field 'offset' is required` 这类失败被当成功文本交给 AI | 新增 `mcpResultIsError`/`mcpErrorText`，接入 IDA 与 Burp 两个客户端 | 同上 [2] |
| 3 | `sshExec` 忽略退出码：命令失败仍返回 `success:true` + 空 stdout | `stream.on('close', (code, signal))` 透传真实退出码；`remote_exec` 消费它 | 同上 [3] |
| 4 | `file-capability.js` 用 4 字节 `head` 全等比较 2 字节的 `'1F8B'`，gzip 头永远判不出 | 改用 `startsWith` | 同上 [4] |
| 5 | `detect-file-type` 产出 `WASM`，但 `autoAnalyze` 的 switch 没有对应 case → 落进未知类型提示 | 新增 `case 'WASM'` 走本地探测 | 同上 [5] |
| 6 | Burp 返回的错误串被 `burpHistoryLooksEmpty` 判成"有流量" → 跳过拉起浏览器 + 把报错喂给 AI | 新增错误前缀识别（`Error:` / `BURP_DOWN` / `requires extension` / `Field '...' is required` 等）+ 结构化 `isError` 识别 | 同上 [6] |
| 7 | IDA 9 异步调试器：`idaapi.step_over()` 投递成功却返回 False，插件报 `Failed to step over`，而 IP 实际已前进 | 新增 `rescueStepFailure`：单步失败后读 IP，确实变化即判成功 | `test_ida_dynamic.js` [4] |
| 8 | 调试能力白名单必须与 `buildDbgCall` 产出严格一致，否则又变成"宣称了 AI 调不到的能力" | 白名单收敛为 15 个已包装工具 | `test_ida_dbg_wiring.js` [7] |

### 真实联调结果（全部 PASS）

| 链路 | 证据 |
|---|---|
| **Burp offset** | 同一活服务上三态对比：`{max:5}` → 服务器拒绝未知键；旧适配 `{count:5}` → `Field 'offset' is required`；新适配 `{count:5,offset:0}` → 返回真实 `GET / HTTP/1.1` 历史 |
| **IDA 动态调试** | 不带 `?ext=dbg` 时 62 个工具、dbg_* = **0**；带上后 82 个工具、dbg_* = **20**。`dbg_start` 返回 `{started:true, ip:"0x77d2a6b0"}`；`dbg_regs` 返回真实寄存器；单步后 IP `0x77d284cc → 0x4012d1`；`dbg_read@0x4012d3` 读出 `6aff68c0504000689c1f400064a10000`；`dbg_add_bp(0x4012d0)` → `dbg_bps` 可见 → `dbg_run_to` 命中；`dbg_exit` 正常 |
| **Kali SSH** | 修正凭据后 `uname -a` 返回 Kali 6.12.38；`binwalk 2.4.3` / `file` / `strings` / `python3` 均可用；失败命令返回退出码 2 并被 `classifyRemoteError` 判为 `REMOTE_REFUSED` |
| **Kali 端到端** | 按能力分诊：ELF→static、gzip→extract、squashfs→extract、裸 .bin→local-probe、pcap→traffic。把样本传到 Kali 后 `file`/`binwalk`/`strings` 全部 code=0 并返回真实输出 |

全量：`node tests/run_all.js` → 单元测试 **71/71**、回归题集通过、exit 0。

**凭据修正**：`config.json` 的 `kali.sshUser/sshPass` 由占位值 `kali/kali` 改为本机实际账号（连接验证通过后写入，密码不回显）。

## 一之三、2026-10-20 续：变换链工具 + 调试模式分离（已完成）

### 1. `recipe`：CyberChef 式的有界变换链

**动机**：实测里 AI 反复手写同一类脚本（base64 → xor → 反转 → 解压），每次都要生成代码、
处理异常、自己判断哪层解出了明文，几十轮预算烧在重复劳动上。这些变换是**有界且确定**的。

新增 `electron/recipe.js`（28 个操作）与 AI 工具 `recipe`：

| 类别 | 操作 |
|---|---|
| 编码 | `from_hex`/`to_hex`、`from_base64`/`to_base64`、`from_base32`/`to_base32`、`custom_base64(alphabet)`、`url_decode`/`url_encode` |
| 压缩 | `gunzip`、`zlib_inflate`、`zlib_deflate_raw`（`bzip2` 明确报"未内置"，不假装成功） |
| 字节 | `reverse`、`reverse_each_4`、`xor(key,key_encoding)`、`add`/`sub`、`rot`、`bit_shift`、`slice` |
| 文本 | `utf16le_decode`/`utf16le_encode`、`to_upper`/`to_lower`/`trim` |
| 哈希 | `hash(algo)` 单向计算；`crack(algo,dictionary)` 有界字典反查（未命中**原样返回**，不静默变成别的值） |

设计边界：
- 每一步都返回 `len / printable / entropy / hex / preview`，让 AI 自己判断哪层是有效明文。
- 链长上限 20 步；任一步失败**指到具体步号**，绝不静默跳过。
- `auto:true` 自动试常见解码链并只返回可打印结果（有界，不猜 XOR key）。

**注意**：MD5 仍然不可逆。`crack` 只做弱口令/数字 0..9999 的有界尝试；
真正的突破口应来自题目里的明文线索，而不是穷举。

### 2. IDA 调试模式：local / remote 显式分离（修 `dbg_start` 恒失败）

**根因（实测确证）**：IDA 的进程选项是**全局持久**的。一次 `set_remote_debugger(host, pass, port)`
之后，`get_process_options()` 会一直带着这组值：

```
('...\\CrackMe.exe', '', '...', '192.168.230.129 ', '200512', 23946)
```

此后即使 `load_debugger("win32")` 成功，`start_process` 也返回 **-1** ——
这就是"本地 Windows 调试明明可用，却一直 Failed to start debugger"的真因。

**修法**：

- `start` 不再走无参 `dbg_start`，统一走 `py_eval`，先决定模式再起进程：
  - `local`（PE）：`set_remote_debugger("", "", -1)` 清残留 → `load_debugger("win32", False)` → `start_process`
  - `remote`（ELF）：`load_debugger("gdb", True)` → `set_remote_debugger(host, pass, port)` → `start_process`
- 模式自动推断：PE → local；ELF 且配置了 Kali → remote。可用 `mode` / `target_kind` 显式覆盖。
- 新增 `action="clear_remote"`：只复位远程配置，不启动进程（本地启动莫名失败时先跑它）。
- `py_eval` 输出 `START_RC`，主进程解析：`-1` 判为**失败**并提示原因（含检测到的残留 host）。
- 启动成功后等 IP 可读再返回（`readDbgIp` 重试 4 次），避免 AI 紧接着调 `dbg_regs`
  拿到 `Debugger not running`。
- 目标类型经 `set-workdir` 从渲染层同步到主进程（`currentTargetFile` / `currentTargetKind`）。

**实测结果**：

| 步骤 | 结果 |
|---|---|
| 启动前读进程选项 | 确认残留 `192.168.230.129 / 200512 / 23946` |
| `clear_remote` | `REMOTE_CLEARED` + `LOCAL_LOADED` |
| `start`（local，PE） | **`START_RC 1`**，返回 `ip=0x77b8123c` |
| `regs` | `ip=0x77b8123c`，thread=24812，寄存器可读 |
| `bp_add` / `bp_list` | 断点被正确登记 |
| `exit` | `{"exited":true}` |

**未达成的部分（如实记录）**：GUI 程序（CrackMe 系列）启动后停在消息循环，
`continue` 不会自动进入校验代码——需要人工在界面上触发按钮，或改用
`dbg_run_to(校验地址)` 强制跑到目标。这一步是**题目的交互约束**，不是工具缺陷；
对无交互的 ELF/控制台程序（配 gdbserver）不受此限。

全量：`node tests/run_all.js` → 单元测试 **72/72**、回归题集通过、exit 0。

## 一之四、2026-10-20 三续：`gui_input` 自动喂输入（GUI 题动态调试闭环）

**动机**：上一节实测发现 GUI 程序启动后阻塞在消息循环，`continue` 8 轮 IP 全程停在系统 DLL，
`dbg_run_to(校验地址)` **永远等不到**（校验只在按钮点击 `WM_COMMAND` 时执行）。
因此 GUI 题的动态调试必须先把输入喂进去。

新增 `electron/gui-input.js` 与 AI 工具 `gui_input`：

| 参数 | 作用 |
|---|---|
| `list_only` | 只列窗口与控件（hwnd / class / ctrl id / text），先用它定位目标 |
| `pid` / `title_contains` | 定位目标窗口（pid 优先） |
| `text` + `control_id` | 填入文本；不指定控件则取第一个 `Edit` |
| `submit` | 点击按钮（默认 true；优先匹配 OK/确定/确认/提交/验证/注册/check/submit/login/confirm） |
| `send_message` | 改用 `SendMessageTimeout`（默认 false，即 `PostMessage`） |

**关键技术点**（都是实测踩出来的）：

1. **必须用 `PostMessage`，不能用 `SendMessage`**：进程被调试器挂起时 `SendMessage` 会阻塞到超时。
   `PostMessage` 只是排队，`continue` 后才处理——正好符合"先投递、再放行、然后断点命中"。
2. **`WM_SETTEXT` 的 `lParam` 用字符串重载**：这是系统消息（`< WM_USER`），跨进程由系统封送，
   不能传指针。
3. **`BM_CLICK` 而不是手拼 `WM_COMMAND`**：让按钮自己向父窗口发 `BN_CLICKED`，更接近真实点击。
4. **PowerShell 脚本必须是纯 ASCII**：Windows PowerShell 5.1 读无 BOM 的 `.ps1` 按系统 ANSI
   代码页解码（中文系统 GBK），UTF-8 中文注释会被拆成乱码 → `Add-Type` 编译失败
   （实测 stderr 全是 `???`）。中文说明只放 JS 侧 `description`，按钮匹配用 unicode 转义拼。
5. **输出用 `[Console]::Out.Write` 单行写完**：管道/`Out-String` 会按控制台宽度折行并截断。
6. **解析不能 `lastIndexOf('{')`**：会命中 JSON 内部最后一个嵌套对象，截出的片段必然解析失败
   （枚举多个窗口时必现）。改为按行从后往前找第一个能整体解析的 JSON。

**验证结果**：

| 用例 | 结果 |
|---|---|
| `list_only`（当前进程） | `ok=true`，Win32 链路可执行 |
| `list_only`（全窗口） | **枚举到 32 个真实窗口**（含任务栏/开始按钮/桌面），解析正确 |
| 不存在的 PID | `NO_WINDOW` 优雅失败，不崩溃 |
| 单元测试 | `test_gui_input.js` **41/41** |

**诚实边界（已写进工具描述，避免 AI 空转）**：
- 只对**标准控件**（Edit/Button）有效；自绘 UI、Qt 自绘窗口、游戏引擎不吃这套。
- 这是模拟用户操作，程序逻辑一步不少跑，不是跳过 UI 的捷径。
- 本机沙箱**没有可用桌面**（`spawn` GUI 程序报"无效类"），因此**注入动作未能在真实
  CTF 样本上端到端验证**——已验证的是 Win32 调用链、窗口/控件枚举、参数解析与错误处理。
  真实注入需要在有桌面会话的环境跑一次。

**提示词同步**：`smcBlock` 后追加「动态调试决策顺序」：
离线 Unicorn 优先 → GUI 题先 `gui_input` → 无交互程序（ELF/gdbserver）才直接 `run_to` →
本地启动失败先 `clear_remote`。

全量：`node tests/run_all.js` → 单元测试 **73/73**、回归题集通过、exit 0。

**上一轮遗留的两项也已验证**：
- P1 契约自动枚举 → 演进为 rank 5 的"契约驱动 verified + 重试循环"，本轮 xxor 实测转成功
- P2 中间值自动推进 → 已落地（`electron/intermediate-advance.js`，17 项单测 + 3 项 E2E）

## 二、本轮新发现的两个通用缺陷（优先级最高）

这两条不是从计划里推出来的，是真实运行暴露的，且都可复现、都是纯形态判据。

### P0-A — 包装去重壳（`[WUSTCTF2020]level1`）

**现象**：平台描述要求 `flag{}`，AI 给的值已经是 `ctf2020{d9-dE6-20c}`，工具套成 `flag{ctf2020{d9-dE6-20c}}` → `accepted:false`。

**根因**：`applyWrap(value, tpl)` 只做字符串填充，不检查值是否已有 `<word>{...}` 外层壳。

**改法**（通用）：
1. 套壳前判断值是否匹配 `^[A-Za-z0-9_!-]{1,24}\{([\s\S]*)\}$`；
2. 若匹配且外层词 **不等于** 目标前缀，且内层非空 → 先剥一层再套；
3. 若外层词等于目标前缀 → 视为已包装，不重复套；
4. 剥壳后仍不合法（内层含嵌套 `{`）→ 保留原值并记日志，交 AI 判断。

**验收**：
- 单测：`ctf2020{x}` + `flag{%s}` → `flag{x}`；`flag{x}` + `flag{%s}` → `flag{x}`；`{x}` + `flag{%s}` → `flag{x}`；`a{b{c}}` → 保持原值并给出日志
- 真实重跑 `[WUSTCTF2020]level1`，平台返回 `accepted:true`

### P0-B — flag 形态合理性校验（`[MRCTF2020]Xor`）

**现象**：AI 给 `CTF{UA^SSQ@VC_L\OB~[q}`，本地脚本确实输出该串 → 契约复现通过 → 标 verified → 提交被拒。

**根因**：rank 5 的契约驱动 verified 只证明"脚本输出 === 契约值"，不证明"这个值语义上是 flag"。前半段控制符说明异或没解完。

**改法**（通用，不依赖题面）：
1. verified 前统计 flag 体字符集：控制字符（<0x20）、`\ ^ ~ | \`` 及非可打印 Unicode 的占比；
2. 占比 > 0 **且** 题面未声明这些符号合法 → 降级为"中间值"，记 `[验证闭环] 形态不合理，降级为中间值`，不进提交候选；
3. 同时把"疑似未完成的编码"证据回灌给 AI（走现有 retryPrompt 通道）。

**边界（必须遵守）**：不能按"常见 flag 字符集"硬编码白名单——很多题允许 `!@#$%`。判据只针对**控制字符与转义类符号**，并且题面声明优先。

**验收**：
- 单测：`CTF{a\b}` → 降级；`flag{re_is_great!}` → 不降级；`flag{0046af1b...}` → 不降级
- 用 `[MRCTF2020]Xor` 重跑，日志出现降级且不再提交该值

## 三、下一轮优先级

### P1 — MD5 目标串自动定位（rank 6 的直接后续）

**数据**：CrackMe2 已能识别 `MD5(high)`（K 64/64），但 607 秒（总耗时；Tool-Use 阶段 579.4/323.2）内 AI 没把"用户名/序列号校验"的目标串找全。

**现状**：工具告诉 AI "这是 MD5"，但没告诉它"和什么比、比多少字节"。

**改法**（通用）：
1. 命中 `MD5-K`/`MD5-IV` 时，在文件里扫描**32 位 hex 字面量**与**16 字节高熵常量**，作为"疑似摘要目标"列出（带偏移与所在节）；
2. 若同时存在用户输入读取点（`scanf`/`fgets`/`GetWindowText`/`read` 等字符串常量）→ 生成"输入 → MD5 → 比较"的候选组合；
3. 把目标串列表写进 scan summary，明确告诉 AI "要爆破的是哪几个值"。

**验收**：CrackMe2 重跑时，scan summary 中出现疑似摘要目标串；AI 的脚本直接对这串爆破（而非自己再找一遍）。

### P2 — 单题预算按形态分层

**数据**：本轮 6 道平均 59s，但 CrackMe2 跑到 607 秒（总耗时；Tool-Use 阶段 579.4/323.2）、cnbragon 349 秒（总耗时；Tool-Use 阶段 579.4/323.2）仍无产出。

**现状**：一刀切的 60 轮 / 12 分钟。简单题浪费预算，难题预算不够。

**改法**（通用）：
1. 工具侧给出"题面复杂度信号"（文件大小、函数数量、是否含 VM 特征、是否有指纹）；
2. 信号 = 简单（有明确指纹 + 文件 < 1MB）→ 8 分钟；中等 → 15 分钟；复杂（无指纹 + 大文件/VM）→ 25 分钟；
3. 预算只做上限，不强制消耗——简单题解出即停。

**验收**：`tea`（有指纹）不被拖到 8 分钟以上；CrackMe2 拿到 25 分钟预算后能跑完爆破。

### P3 — 零指纹时的定向检索建议（rank 6 的措辞延伸）

**数据**：本轮 6 道里 4 道是零指纹，其中 3 道仍解出（usualCrypt/xxor/rc4）。说明零指纹很常见。

**现状**：中性措辞已经做到（不再说"是壳"），但只有"建议在本层找"，没有**具体检索方向**。

**改法**（通用）：按"文件里实际存在什么"给方向，而不是泛泛而谈：
- 有 32 位 hex 字面量 → 优先查哈希比较
- 有 Base64 字符表 → 查自定义 Base64（usualCrypt 就是这类）
- 有循环 + 逐字节比较 → 查编码/异或
- 有大常量数组 + 少指令 → 查 VM/查表

**验收**：rc4（零指纹但有 KSA 循环）重跑时，提示词里出现"循环 + 逐字节置换 → 优先查 RC4/自定义流密码"这类**由数据推导**的方向。

### P4 — 人工干预兜底（BLOCKER.md）

**数据**：本轮 2 道 rank 6 复测题（CrackMe2/cnbragon）消耗 956 秒仍无产出，人工无法快速接手。

**改法**：工具放弃时生成 `cases/<md5>/BLOCKER.md`：
```
## 已完成的步骤（带数据）
## 当前卡点（具体地址/函数/缺什么）
## 下一步建议（具体动作）
```
内容全部来自已有的 scan/IDA/验证记录，不新增探测。

**验收**：CrackMe2 失败后能产出含"MD5 K 表 @0xb2f、目标串候选、已试过的爆破范围"的 BLOCKER.md。

## 四、实施顺序

```
P0-A 包装去重壳        ← 直接吃一道现成的 accepted:false
P0-B flag 形态校验     ← 同上，防污染正确率
P1   MD5 目标串定位    ← rank 6 的直接后续
P2   预算分层          ← 让 P1/P3 有机会跑完
P3   零指纹定向建议    ← 纯提示词，成本最低
P4   BLOCKER.md        ← 最后一道
```

## 五、验收标准

| 项 | 验收 |
|---|---|
| P0-A | 单测 4 条；`[WUSTCTF2020]level1` 重跑 `accepted:true` |
| P0-B | 单测 3 条；`[MRCTF2020]Xor` 重跑出现降级日志且该值不被提交 |
| P1 | CrackMe2 scan summary 列出疑似摘要目标；AI 直接对其爆破 |
| P2 | 简单题 ≤ 8 分钟收口；复杂题有 ≥ 25 分钟预算 |
| P3 | rc4 这类零指纹题得到由数据推导的检索方向 |
| P4 | 任一道失败题产出可执行的 BLOCKER.md |

每项都要求：`node tests/run_all.js` exit 0 + 同一批题的前后对比。

## 六、底线

- 所有改动通用，不写题目特判、不写题名/路径/flag
- 形态判据优先"数据自身结构"，其次"题面声明"，最后才是经验默认值
- 解不出也必须留下可执行的卡点说明，保证人工可接手
- 未本地验证通过的 flag 不提交（避免污染正确率）——P0-B 正是为了加强这条
