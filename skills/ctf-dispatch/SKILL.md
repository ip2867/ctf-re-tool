---
name: ctf-dispatch
description: CTF 逆向题总调度：题目分类 → 选择专项方法 → 卡题换路（pivot）→ 汇总输出。开始分析一道新题、或卡住不知道下一步时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# CTF 逆向题调度与卡题决策

## 分流表

| 输入特征 | 类型 | 方法路径 |
|---|---|---|
| URL / 抓包流量 / 加密参数（sign/token/X-Bogus 类）| Web/JS | ctf-jsreverse（Burp 联动五阶段） |
| `.js/.mjs` 混淆代码 | JS | ctf-jsreverse 路径A（四板斧/AST） |
| `.apk` / `.dex` / `.jar` | Android | ctf-reverse-android |
| `.exe/.dll`（含 mscoree）| .NET | dnSpy/ilspycmd，de4dot 去混淆 |
| `.exe/.dll`（native）| PE | ctf-reverse-binary |
| `.so/.elf/.out` | ELF | ctf-reverse-binary（+ ptrace 反调试预案）|
| `.pyc/.pyo` / PyInstaller 打包 exe / PyArmor | Python | ctf-reverse-langs §1 |
| Go 二进制（`gopclntab`/`main.main`）| Go | ctf-reverse-langs §2（GoReSym 恢复符号）|
| Rust 二进制（`core::panicking`/mangled 符号）| Rust | ctf-reverse-langs §3（rustfilt demangle）|
| `.luac` / LuaJIT / 加密 Lua | Lua | ctf-reverse-langs §4；注意版本字节匹配 |
| `.wasm` | WASM | wasm2wat / wasm-decompile |
| 固件/无扩展名 bin / 路由器 dump / OTA 包 | IoT 固件 | ctf-iot-firmware（binwalk→解包→rootfs 找后门/口令→QEMU 仿真）|
| 迷宫/棋盘/状态机（输入是方向串 wasd/udlr）| 迷宫题 | ctf-reverse-tooling §迷宫 |
| 逻辑读懂但手算不完（逐字节校验/大循环/约束方程）| 自动化求解 | ctf-reverse-tooling（Z3/暴力）|
| 输入经大量分支，静态读不动 | 自动化求解 | ctf-reverse-tooling（angr 符号执行）|
| 自写 VM/自定义字节码，不想人肉复刻 | 自动化求解 | ctf-reverse-tooling（Unicorn 模拟）|

## 解题顺序原则

1. **先查经验库**：系统提示已注入历史经验（近15条），同类场景优先复用
2. **先白盒后黑盒**：能静态读出来的逻辑不要急着跑程序
3. **先便宜后昂贵**：strings(1秒) → 反编译(1分钟) → 动态Hook(5分钟) → 爆破(不确定)
4. **每一步产出一个证据**（函数地址/输出快照），写进当前 case 的记录
5. **每完成一个阶段，给用户 3-5 个编号的下一步选项**（下一步菜单模式），不要闷头跑偏
6. **数据不充分不臆测**（2026-09 验收教训）：逆向工具（IDA/JEB MCP）采集为空时，
   先排查工具链本身（MCP 端口是否就绪、返回信封是否解包、入口函数名是否猜对），
   修好采集再分析——**禁止**让 AI 在无数据/残缺数据下"脑补" flag
7. **代码与数据同等重要**：VM/查表题光有反编译代码不够，被引用的常量数据表
   （`.data` 的 `src_`/密文表）必须一并采集进上下文，否则不可解

## 解题学习闭环（每题强制，一次不可省）

本工具的知识库是活的：`experience.md`（经验速查，自动注入系统提示）+ skills（方法论）。
**每一道题都要走完"查→用→学"三步，缺一即违规**：

1. **查（解题前）**：先读系统提示的「历史经验速查」，命中同类题型特征时
   直接复用已验证的套路与避坑点，不重新摸索；需要完整方法论时 `read_skill`
   加载对应专项（binary/android/jsreverse…）
2. **用（解题中）**：严格按知识库流程执行。经验库已记录的坑
   （VM 题常量表必采、mingw `_main`、CRT 噪声降权、信封解包等）
   **不得重踩**；踩到新坑时在过程记录中标注"新坑"
3. **学（解题后，成败都算）**：回答最后输出经验块，工具自动写入经验库：
   ```
   [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"，最多5条[/EXPERIENCE]
   ```
   - 写"学到了什么"，不写"做了什么"（流水账不入库）
   - 失败题的经验往往比成功题更值钱：记录哪条路走不通、为什么、下次直接换哪条
   - 确无新收获写"无新增经验"，禁止为凑数硬编

## 卡题 Pivot 清单（按症状）

| 症状 | 换路方向 |
|---|---|
| 反编译看不懂/控制流爆炸 | 确认是否 OLLVM（平坦化→deflat）；或放弃静态直接动态，Hook 输入输出对 |
| 输入对但说 wrong | 有隐含变换：Hook 比较函数看"期望值"到底是什么 |
| 找不到比较点 | 搜"成功/失败字符串"的交叉引用；或动态对输入下内存写断点 |
| 算法认出但解不出 | 字节序/编码搞错 → 列假设组合交给工具 `[HYPOTHESES]` 枚举 |
| 有壳静态看不了 | upx -d / dump；VMP 类直接动态，Hook 加密 API 拿数据 |
| .so 太复杂 | 只还原 JNI 入口函数调用的关键子函数，其余当黑盒 |
| 多个 flag 候选 | 信"与预期流程/产物绑定"的那个：能被解密脚本复现的 > 字符串里裸躺的 > 假 flag（`flag{this_is_fake}` 类） |
| MCP 采集为空/连接失败 | IDA 冷启动慢于重试窗口是常事：等 MCP 就绪（端口监听）后重触发即可；接口返回 `[{data:...}]` 数组信封须先解包 |
| 反编译 Not found | 函数名不对，不是题目难：mingw 入口 `_main`、C++ mangled 名（`__Z9vm_operadPii`）按候选序列/子串重试 |
| 函数列表全是 CRT 噪声 | `__decode_pointer`/`_add_key_dtor`/`__matherr` 等是运行时噪声（名字恰好含 decode/key），降权后真函数才浮出 |
| 逻辑读懂但要手算上千字节 | 别手推 → ctf-reverse-tooling：逐位独立用暴力，有跨位依赖用 Z3 |
| 输入经过大量分支/跳转，静态跟不动 | ctf-reverse-tooling 的 angr：给 find/avoid 地址直接符号执行 |
| 自写 VM，人肉复刻解释器太慢 | ctf-reverse-tooling 的 Unicorn：只模拟执行，不翻译逻辑 |
| exe 解出来像 Python / 二进制有 go/rust 味 | 判型 → ctf-reverse-langs（PyInstaller/PyArmor、gopclntab、mangled 符号、luac 版本）|
| 输入是方向串/走到终点 | 迷宫题 → ctf-reverse-tooling §迷宫（提取地图+BFS，别手走）|
| 拿到固件/无扩展名大文件 | ctf-iot-firmware：先 file/strings 侦察，binwalk 提取后**常需二次解包**（.squashfs→unsquashfs）|
| 固件里某个二进制是 ARM/MIPS，想跑起来 | ctf-iot-firmware §QEMU：user-mode `qemu-arm/mipsel -L .` 最实用；别一上来全系统仿真 |
| 在固件里搜 password/key 类词搜不到 | 那是**符号名**不是字符串 → IDA 换 `Names` 视图（Shift+F4），别死磕 Strings |

## 输出契约（本工具约定）

- Flag：`[FLAG]flag{...}[/FLAG]`
- 验证数据：`[VERIFY]{"algo":"...","key":"...","ciphertext":"...","encoding":"hex|base64","expected":"..."}[/VERIFY]`（custom 算法附 `code`）
- 候选组合：`[HYPOTHESES][{...},{...}][/HYPOTHESES]`
- 证据：分析中发现的函数名/地址/关键字符串 → 报告给用户，由工具存入 case 证据目录

### 思考型模型（GLM 等）输出纪律

- 推理放 thinking 里进行，**正文直接给结论**：先 `[FLAG]...[/FLAG]`，再简短依据（函数名/地址/关键步骤）
- 不要在正文里长篇逐项验算——会耗尽 max_tokens 导致"token 用完自己停止"，结论反而丢失
- 若输出被截断，工具会自动续写（最多 2 轮），续写时直接给最终结论即可
