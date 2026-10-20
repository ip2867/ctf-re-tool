# CTF-RE-TOOL x CTF² Agent Arena 实战全记录：8 道逆向题完整 Writeup 与工具进化史

> 日期：2026-10-14 ~ 2026-10-15
> 工具：CTF-RE-TOOL v1.4.0（开发态）+ CTF² 平台自动解题流水线
> 战绩：**8/8 全部解出并提交通过**（missioncritical1 为全自动提交 +100 分；其余工具解出、人工复核提交）
> 所有反编译、验证脚本、AI 结论原文均可在 `cases/` 目录对应 CASE 中复查

---

## 题目总览

| # | 题目 | 难度 | 载体 | 核心考点 | AI 求解耗时* | 提交 |
|---|------|------|------|---------|---------|------|
| 1 | time-travel | Hard | ELF | 定点数 Laplace 行列式递归 | 457s | 人工提交 ✅ +1 |
| 2 | not-baby-parallelism | Hard | ELF | Blelloch 并行前缀扫描反演 | 4 轮（跨日） | 人工提交 ✅ |
| 3 | parallelism | Medium | ELF(MPI) | 三级置换网络静态反演 | 22s | 人工提交 ✅ |
| 4 | ExceLLM | Hard | XLSX | Excel 公式神经网络校验器 | 63s | 人工提交 ✅ |
| 5 | RomanRomance | Easy | TXT | Caesar +1 移位 | 48s | 人工提交 ✅ |
| 6 | PalatinePack | Medium | ELF+BIN | 三层 nibble 展开 + flipBits | 321s | 人工提交 ✅ |
| 7 | missioncritical1 | Easy | ELF | sprintf 拼接 + strcmp | **5.8s** | **全自动 ✅ +100** |
| 8 | PlutoChat | Medium | ELF+PCAP | LCG 密钥派生 + RC4 | 152s | 人工提交 ✅ |

\* 耗时为 CASE 目录 timeline 的 AI 分析阶段时长（不含下载/IDA 冷启动）。

---

## 1. time-travel — 定点数 Laplace 行列式

**附件**：`time_travel`（ELF x64）+ `input.bin`

### 1.1 静态侦察

main 的反编译只有 11 行，逻辑一目了然：

```c
input = read_input(argv[1]);
for (n63 = 0; n63 <= 63; ++n63) {              // 64 个矩阵
    v7 = sub_1423(*input);                      // 分配 N×N 指针数组
    for (i = 0; i < *input; ++i)
        memcpy(*(void **)(8LL*i + v7), &input[650*n63 + 1 + 36*i], 0x90u);  // 每行 0x90=144B
    v8 = sub_1638(v7, *input);                  // ← 核心函数
    putchar((char)(*(_QWORD *)&input[650*n63 + 649] - v8) + n63);           // target - det + n
}
```

三个关键观察：
1. **输入布局**：每矩阵 650 个 dword = 1（N）+ 36×18（矩阵数据）+ 1（目标值）；`0x90` 字节/行 = 18 个 qword → **N=18，元素按 qword（64 位定点数）处理**
2. **输出公式**：`putchar(target_qword - det(矩阵) + n63)` —— 明文字符 = 目标值减行列式再加索引
3. `sub_1638` 就是核心行列式函数

### 1.2 算法分析

`sub_1638` 是教科书级的 **Laplace 余子式递归**：

- 对每列：删去对应行列（`sub_1570` 构造子矩阵）→ 递归求 `det` → 符号交替 `v6 = -v6`
- 递归基：1×1 矩阵返回唯一元素
- 元素全部按 qword 定点数参与乘加

### 1.3 反演

flag 的第 n 个字符满足 `flag[n] = (target_n - det_n + n) & 0xff`。等价地：**从明文字符出发正向算 det**，找使等式成立的矩阵输入。AI 写 Python 按同样布局解析 64 个矩阵（每矩阵取前 18×18 个 qword + 末尾目标 qword），逐个求行列式后按公式拼出 64 字节明文，输出完整含结尾 `}`。

### 1.4 验证

正向复算：`target_qword == flag[n] + det_n - n`，64 个矩阵全部对上，无歧义。

**flag**：
```
dice{d3t4rm1n1NanT5_c4n_b3_F4sT_1a7sN2j1867327mA6jmapc817jgd6m0}
```

---

## 2. not-baby-parallelism — Blelloch 并行前缀扫描

**附件**：`pppp`（ELF x64，C++ 多线程）+ `flag.out`（51 个整数）

这道题跨了 4 轮，是成长闭环最完整的案例：前 3 轮失败的方向被逐条存档，第 4 轮 AI 带着完整的"已排除路"清单一次解出。

### 2.1 前几轮为什么失败（工具存档的真实记录）

| 轮次 | 误判 | 实际 |
|------|------|------|
| 1 | `flag.out` 首值 100 被当成"元素个数" | 100 是 ASCII `'d'`，是**数据本身** |
| 2 | worker 被当成朴素并行 `out[i] = op(data[i-1])` | 是 **Blelloch work-efficient scan**（up-sweep + down-sweep 两阶段树形扫描） |
| 3 | 预算烧在复现 glibc rand() 上 | 洗牌结果对任意种子恒为 `['xor','add','mul']`，**根本不用复现 rand** |

### 2.2 静态侦察（最终轮）

main 的骨架：

```c
while ((opt = getopt(argc, argv, "n:i:o:")) != -1) { /* -n 线程数, -i 输入, -o 输出 */ }
std::istream::operator>>(v16, &N);
srand(threads ^ N);
sub_3230(state, N, &shuffled);          // 洗牌 3 个算子
for (i = 0; i < N; ++i)  /* 读入 N 个整数 */
t0 = now();
sub_36C3(state, sub_330A, sub_3323, sub_333A);   // ← 核心：三算子扫描
t1 = now();  printf("%.17f\n", elapsed);
for (j = 0; j < N; ++j)  /* 写出结果数组 */
```

三个算子语义（反编译直接可读）：`sub_330A = a+b`、`sub_3323 = a*b`、`sub_333A = a^b`。

核心函数藏在 **C++ lambda 深链**里：`off_7D10`（vtable）→ 槽位 0x4a18（invoke）→ sub_4A18/4A44 → 4A64 → 4A80 → 4ADB → 4B18 → **sub_336C**。顺着 vtable 槽位一路追才找到真身——这也是前几轮放弃的原因之一。

### 2.3 核心算法（sub_336C）

```
每层 stride i（1,2,4,...）：算子 = table[round(log2(i)) % 3] = ['xor','add','mul'] 交替
up-sweep:   for k: u = 2*i*k - 1;  if (i+u < n) a[i+u] = op(a[u], a[i+u])
down-sweep: for k: u = 2*i*k - 1;  a[u] = op(a[u-i], a[u])
```

这正是 **Blelloch work-efficient prefix scan** 的标准结构：up-sweep 归约建树，down-sweep 下扫求前缀。

### 2.4 反演

`flag.out` 的 51 个值就是扫描输出（首值 100 = `'d'`，是数据不是元数据——这个误判浪费了一整轮）。反演 = **逆 down-sweep（按 up 层级顺序）→ 逆 up-sweep（按 down 层级顺序）**，每步用伙伴元素反解：

- `add` 逆 = 减、`xor` 逆 = 再异或、`mul` 逆 = 整除（需除数非零检查）
- 线程数 `dword_81D8` 未知 → 暴力 1..64，配合"结果全可打印 ASCII"约束，**锁定唯一明文**
- 正向回验：反演结果重跑 Blelloch 扫描，51 个输出逐一复现 `flag.out` ✓

### 2.5 验证契约

AI 交出的 [VERIFY] 契约用 Python 实现了精确逆过程（节选）：

```python
tbl = ['xor','add','mul']
lv  = lambda i: int(round(math.log2(i))) % 3
def decrypt(out):
    a = out[:]; n = len(a)
    for i in levels_up(n):        # 逆 down-sweep
        invf = inv[tbl[lv(i)]]; k = 1
        while 2*i*k-1 < n:
            u = 2*i*k-1
            if i+u < n: a[i+u] = invf(a[i+u], a[u])
            k += 1
    for i in reversed(levels_up(n)):   # 逆 up-sweep
        invf = inv[tbl[lv(i)]]; k = 1
        while 2*i*k-1 < n:
            u = 2*i*k-1; a[u] = invf(a[u], a[u-i]); k += 1
    return bytes(a)
```

**flag**：
```
dice{p4r411el_pref1x_sc4ns_w0rk_efficient_but_sl0w}
```

---

## 3. parallelism — MPI 三级置换网络

**附件**：`parallelism`（ELF x64，链接 libmpi）

### 3.1 题面即提示

> Run with `mpirun --oversubscribe -np 8 ./parallelism`

### 3.2 静态侦察

main（1118 字符）非常短：

```c
MPI_Init(&argc, &argv);
MPI_Comm_size(MPI_COMM_WORLD, &n8);
MPI_Comm_rank(MPI_COMM_WORLD, &rank);
if (n8 == 8) {
    if (sub_1369() && sub_1625() && sub_179C()) {
        if (!rank) puts("Correct!");
    } else puts("Invalid flag!");
} else puts("Must be run with 8 processes");
```

三个校验函数串联 = 三级变换流水线：

| 阶段 | 函数 | 逻辑 |
|------|------|------|
| Stage 1 | `sub_1369` | 输入 64 字符；用常量表 `v4[32]` 做 32 次 `s[n] ↔ s[v4[n]+31]` 交换（固定置换） |
| Stage 2 | `sub_1625` | 10000 轮环形搬运：每轮 rank R 从 `(R+n)%8` 号进程取 slot `n%8` 写入本地 slot `n%8` —— 全局确定性置换 P |
| Stage 3 | `sub_179C` | `MPI_Gather` 汇总后 `memcmp` 目标常量 `m_ERpmfrNkekU4_...` |

### 3.3 反演（不模拟真实 MPI）

关键洞察：Stage 2 虽然跑了 10000 轮跨进程通信，但**它是确定性置换**——用"单位标签"（0..63 依次编号）跑一遍同样的轮次逻辑即可得到 `perm_out`，无需真的起 8 个进程：

```python
def sim(data):                      # 用标签数组模拟 10000 轮
    rb = [list(data[i*8:(i+1)*8]) for i in range(8)]
    for n in range(10000):
        new = [None]*8
        for R in range(8): new[R] = rb[(R+n)%8][n%8]
        for R in range(8): rb[R][n%8] = new[R]
    return [c for r in rb for c in r]

perm_out = sim(list(range(64)))     # 置换表
def inv_stage2(out):                # 逆 Stage 2
    res = [None]*64
    for k in range(64): res[perm_out[k]] = out[k]
    return res

def inv_stage1(s):                  # 逆 Stage 1：反向重做同一交换
    for n in range(31, -1, -1):
        idx = v4[n]+31; s[n], s[idx] = s[idx], s[n]
    return s

flag = inv_stage1(inv_stage2(list(target)))
```

### 3.4 验证

正向：`encrypt(flag) == target` 逐字符（64/64）匹配；字节级复算 mismatch count = 0。

**工具问题**：AI 的正向复现已完全匹配，但 [VERIFY] 契约里 `decrypt(target)` 是单参函数、`expected` 只写了 flag 前 54 字符——工具按双参调用 + 全等比对判「无命中」拒绝自动提交。人工补交（对应 §修复 #2/#3）。

**flag**：
```
dice{P4ral1isM_m4kEs_eV3ryt4InG_sUp3r_f4ST_aND_s3CuRE_a17m4k9l4}
```

---

## 4. ExceLLM — Excel 公式搭的神经网络

**附件**：`ExceLLM.xlsx`（27.8 KB，4 个 sheet：LLM / BITS / WEIGHTS / VERIFY，后三个隐藏）

### 4.1 解压与定位

xlsx 本质是 OOXML zip。解压后：

| 文件 | 内容 | 判定 |
|------|------|------|
| `xl/workbook.xml` | sheet 清单：LLM(可见)、BITS/WEIGHTS/VERIFY(hidden) | 结构 |
| `xl/worksheets/sheet1.xml` | 2.5KB，只有 `IF(VERIFY!Z1=1,"Correct","Incorrect")` | **展示壳**（1 个公式） |
| `xl/worksheets/sheet2.xml` | 58KB，216 个公式 | **BITS**（位展开） |
| `xl/worksheets/sheet3.xml` | 164KB，纯常量 | **WEIGHTS** |
| `xl/worksheets/sheet4.xml` | 57KB，244 个公式 | **VERIFY**（校验器） |

工具按"公式数"选主文件正确命中 sheet4。

### 4.2 公式语义（把 Excel 当反汇编读）

BITS 表把每个输入字符按 ASCII 展开 8 位（MSB first）：

```
B2(k) = MOD(QUOTIENT(CODE(MID(LLM!B2, pos, 1)), 2^k), 2)     k=0..7
```

VERIFY 表是三层网络：

```
C{row} = MAX(0, (SUMPRODUCT(BITS!B{8位区间}, WEIGHTS!列k) + WEIGHTS!A{bias}) / 100)
H{row} = --( (SUMPRODUCT(C{8行组}, W2) + b2) / 100 > 0 )
Z1     = --( SUM(H10, H30, ..., H530) = 27 )
```

对照机器学习语义：`SUMPRODUCT` = 全连接层矩阵乘，`MAX(0,·)` = **ReLU**，`--(·>0)` = **阶跃激活**，`Z1` = 要求 27 组输出神经元全部为 1。

### 4.3 反演（逐字符独立枚举）

关键结构：每组校验**只依赖该位置字符的 8 位**，组间无耦合。因此对每个位置暴力枚举 32..126 的可打印 ASCII，H(该组)=1 的唯一字符即答案——27 次独立枚举，无需全局搜索。

AI 在此踩了一个关键坑并自我修正：**WEIGHTS 表是列主序 + 每组固定 stride=26 行**（W1 8 行 + bias 8 行 + W2 8 行 + H-bias 1 行）。最初误用 stride=20 时每个位置的候选集爆炸（0~95 个解）；改从 VERIFY 公式里的行号锚点（C10→A2:A9/A10，C30→A28:A35/A36，差 26）反推 stride 后，**每组恰好剩唯一解**——解集是否唯一本身就是 stride 正确性的判据。

### 4.4 验证

拼出 27 字符 flag 后前向复算：27 个 H 全为 1，`SUM=27`，与 `VERIFY!Z1=1` 一致。

**flag**：
```
sun{n0t_qu1t3_ch4t_GPT_l0l}
```

---

## 5. RomanRomance — Caesar 移位

**附件**：`enc.txt`（34 B）+ `romanromance`（ELF）

### 5.1 分析

题面：*"When in Rome..."*（暗示 Caesar）+ 注明非标准前缀 `sunshine{...}`。

密文（34 字符）：

```
tvotijof|lO1x`z1v5`s1nAo`iJ6u1sZ~
```

### 5.2 解法

单字节移位全扫（-31..+31），匹配 flag 前缀：

```python
for k in range(1, 32):
    d = ''.join(chr(ord(c) - k) for c in ct)
    if re.search(r'sunshine|flag|ctf', d): print(k, d)
```

**+1 移位**命中：`tvotijof` +1 = `sunshine`，整段可读，无歧义。

**flag**：
```
sunshine{kN0w_y0u4_r0m@n_hI5t0rY}
```

（本轮暴露了跨题文件串扰问题——AI 曾把上一题 ExceLLM 的结论带进本题，见 §修复 #7）

---

## 6. PalatinePack — 三层 nibble 展开 + flipBits

**附件**：`palatinepack.zip` → `palatinepack`（ELF）+ `flag.txt`（296 B 密文）

### 6.1 静态侦察

main 的变换链清晰：

```c
stream = fopen("palatinepackflag.txt", "r");   // ← 读"密码"（真 flag 是输入！）
n = ftell(stream) + 1;                          // = 37
fgets(s_, n, stream);
flipBits(s, n);                                 // 自逆变换
s_1  = expand(s,  n);                           // n  → 2n
s_2  = expand(s_1, 2*n);                        // 2n → 4n
ptr  = expand(s_2, 4*n);                        // 4n → 8n（37→74→148→296）
anti_debug();
fwrite(ptr, 1, 8*n, fopen("flag.txt", "wb"));   // 写出 296B 密文
```

**方向判定**：题目给的是程序**输出**（flag.txt 296 字节），真 flag 是程序**输入**——必须逆变换。

### 6.2 变换语义

- `flipBits`（0x1565）：交替「偶索引逐字节取反 / 奇索引异或流 `n105 += 32`（初值 105）」，**自逆**
- `expand`（0x16b9）：每字节拆 2 字节，nibble 按 `v4` 交替摆放（`v4=0` → `(a&0x0F)|(c&0xF0)`；`v4=1` → `(c&0x0F)|(a&0xF0)`），伴随状态 `n105 = n105*11 mod 256`，初值 105
- 干扰项：`doWeedStuff` / `rotate_block_left` / `SBOX`（AES S 盒）在 main 里**无 xrefs**，纯干扰，不浪费时间逆
- `teehee` 函数用 `mprotect` 试图把 expand 里的立即数 `0x69`（105）打补丁成 `0x01`——**但正向复现证明运行态仍是 105**（补丁未生效/打在别处）：反推结果用 {105, 1} 两值分别回验，只有 105 能 100% 复现 flag.txt 全部 296 字节

### 6.3 反演与验证

逆 `expand` 三次（读 nibble 重组）→ 逆 `flipBits`（自逆，再做一遍）→ 得 `sunshine{...}\0`。

正向回验：用还原的三层变换对 flag 正向展开，输出与 flag.txt **296 字节逐字节一致**（完全匹配，无歧义）。

**flag**：
```
sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}
```

---

## 7. missioncritical1 — 全自动闭环示范（15 秒从下载到提交）

**附件**：`chall`（ELF x64，14.1 KB）

### 7.1 分析

main 只有 15 行，校验逻辑直接写在 `sprintf` 里：

```c
sprintf(s_, "sun{%s_%s_%s}\n", "e4sy", "s4t3ll1t3", "3131");
printf("Enter satellite command: ");
fgets(s, 50, stdin);
if (!strcmp(s, s_)) puts("Access Granted!");
else                puts("Access Denied!");
```

三个片段直接来自字符串表（`a3131`、`aS4t3ll1t3`、`aE4sy`），AI 一轮分析即拼出完整 flag。

### 7.2 闭环时间线

```
17:38:33  平台拉题 → 下载 chall → 识别 ELF
17:38:34  IDA 启动 → 17:38:40 MCP 连接（6 秒冷启动）
17:38:41  阶段1 采集（函数列表/字符串/反编译/全局表）
17:38:47  AI 5.8 秒出结论 + [VERIFY] 契约
17:38:47  本地复现 [HIT] → flag 标记已验证 → 自动沉淀经验入库
17:38:47  自动提交平台 → {"accepted":true, "earned_points":100}
17:38:49  题后清理 IDA/java 进程
```

**从拉题到平台判对共 15 秒，全程零人工干预**——验证闭环（[VERIFY] 契约本地复现）在此题一次通过，flag 未验证不提交的防线也完整走通。

**flag**：
```
sun{e4sy_s4t3ll1t3_3131}
```

---

## 8. PlutoChat — LCG 密钥派生 + RC4 聊天记录

**附件**：`plutochat`（ELF）+ evidence.pcap（聊天流量）

### 8.1 静态侦察

main 是个 TCP 客户端：

```c
printf("Username: "); fgets(s, 256, stdin);
printf("Password: "); fgets(s_, 256, stdin);
fd = socket(2, 1, 0);
addr: inet_addr("127.0.0.1"), htons(0x7A69);   // 31337
sub_1CD7(fd); sub_189A(fd, s, s_);             // 登录与收发
```

真正的 flag 不在本地校验里——在**加密的聊天记录**里。AI 从二进制抽出了完整的密码学链路：

| 函数 | 语义 |
|------|------|
| `sub_1389` + `sub_1452` + `sub_12E5` + `sub_1285` | 标准 **RC4**（KSA / swap / PRGA） |
| `sub_1510` | 80 字节 RC4 key 派生：seed 经 `ROL32(x, x&0xf)` 递推填 20 个 int → `byte_4100` 置换表 → `byte_4120` 表 XOR 传播链 |
| 包格式 | `[4B seed][4B len][RC4 密文]` |

### 8.2 关键坑：未初始化的 v9

`sub_1510` 的 XOR 传播链用**未初始化的栈变量 `v9`** 作初值（`rbp-1`）——反编译默认值不可信。AI 用**已知明文攻击**锁定：登录成功消息首字节类型 = 1，爆破 v9 初值，`v9_0 = 0` 时 RC4 首字节恰好解出 `1`，唯一命中。

### 8.3 解密与取证

用 `gen_key(seed) + RC4` 解开 pcap 里全部消息，聊天记录完全可读：

> 用户 `topsecretengineer`（密码 `PlutoMars23!`）与 `givemethemoney`（密码 `Sellurdata12!`）对话，后者询问敏感 key，前者回复：

```
Of course! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}
```

**验证脚本小插曲**：解密明文带 `\x03\x11` 协议头（`[类型][len 用户名]` 封装），`printable()` 整段判"不可打印"回退成 hex，flag 被埋进 hex 里导致验证闭环无命中——修复"剥首尾控制字符"后重跑同一契约直接 `[HIT]`（见 §修复 #8）。

**flag**：
```
sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}
```

---

## 三、实战暴露的 9 个工具缺陷与修复

> 全部当日修复并回归验证；修复只改源码（开发态），未发版。

### #1 下载器目录碰撞（parallelism）
- **现象**：`所有附件均下载失败… EISDIR: illegal operation on a directory`
- **根因**：附件名 `parallelism` 无扩展名，与下载根目录下昨日建的 `parallelism/` 目录同名，`writeFileSync` 写目录直接抛异常，整轮中止。
- **修复**：`ctf2DownloadAttachment` 写入前 `statSync` 检查，同名目录自动改名 `parallelism_1` 重试。

### #2 验证契约调用形态（parallelism / PlutoChat 同根因）
- **现象**：`decrypt() takes 1 positional argument but 2 were given` → 契约 3 候选全 ERR。
- **根因**：验证脚本对 custom 算法只试 `decrypt(ct, key)` 双参形态；AI 处理置换/数据变换类题时习惯写单参 `decrypt(target)`。
- **修复**：`inspect.signature` 判形参数后按序尝试：单参原文 → 单参 bytes → 双参原文 → 双参 bytes → 关键字参；函数名同时兼容 `decrypt/custom_decrypt/solve/decrypt_flag`。

### #3 expected 截断全等比对（parallelism）
- **现象**：AI 只给 `expected:"dice{P4ra..."`（前 54 字符），与 64 字符完整明文做全等必败。
- **修复**：命中判定改**双向包含**（`exp in pt` 或 `pt in exp`），命中值优先取 FLAG_RE 完整匹配、其次解密全文。

### #4 xlsx 被拒解压（ExceLLM）
- **现象**：`解压失败: 仅支持 .zip` → 整轮 0 秒结束。
- **修复**：`ctf2-unzip` 白名单扩到 OOXML 全家（xlsx/xlsm/docx/pptx/apk/jar/aar/ipa/epub）+ PK 魔数兜底；非 .zip 扩展先复制为 .zip 再解（Expand-Archive 限制）。

### #5 OOXML 主文件挑选（ExceLLM 两连修）
- **现象一**：13 个解压文件里选中 241B 的 `docProps/custom.xml`（元数据）→ UNKNOWN → Kali。
- **修复一**：OOXML 感知打分——`docProps/` 记 1 分、`[Content_Types]/.rels` 记 2 分。
- **现象二**：sheet 同级时展示壳 sheet1（1 个公式）压过真校验器 sheet4（244 个公式）。
- **修复二**：公式数作为独立高位主导因子（≤900 分），ExceLLM 实测 sheet4 正确胜出。

### #6 XML/TXT 进 Kali 固件流程（ExceLLM / RomanRomance，各白烧 60s）
- **现象**：`UNKNOWN → 固件分析（Kali 模式）→ 3× Timed out while waiting for handshake`。
- **修复**：detect-file-type 新增 `XML`（xml/rels/json/plist/yml/yaml）与 `TXT`（txt/enc/log/md/csv）两类；新增 `analyzeXMLText()`：直读全文（≤256KB）存证 → AI 求解（Tool-Use 可 read_file 读伴生 sheet、bash 跑 Python），绕开 Kali/IDA。

### #7 跨题文件串扰（RomanRomance，最隐蔽）
- **现象**：AI 分析 RomanRomance 时把**上一题 ExceLLM 的 sheet 与 flag** 当成本题结论。
- **根因**：所有题附件混在共享根目录 `E:\ctf\pratice\ai`，AI 工具工作目录 = 根目录 → glob 翻到上题 `ExceLLM_x/` 残留；叠加刚入库的上题经验注入。
- **修复**：① 附件按题下载到独立子目录 `<dlDir>/<题名>/`；② 多附件按类型权重选主文件（ELF/PE/pyc/zip 优先，txt/enc 为伴生密文/提示）；③ 提示词加「题目边界」段：只分析本题文件，历史残留与相似经验仅作方法参考。

### #8 printable() 控制字符吞 flag（PlutoChat）
- **现象**：RC4 明文 `\x03\x11topsecret...sun{...}` 整段被判不可打印回退 hex，flag 埋进 hex，expected 包含判定同时失效 → 验证无命中。
- **修复**：`printable()` 先剥首尾控制字符（协议封装 `\x03\x11+len` 头常见），主体可读即返回文本。
- **回归**：修复后同一契约重跑直接 `[HIT]`。

### #9 （预防性）经验跨题注入
- ExceLLM 入库的「Excel 神经网络」经验出现在 RomanRomance 提示词里。由 #7 的边界提示词兜住：经验只作方法参考，本题结论必须来自本题文件。

---

## 四、数据与沉淀

- **平台分值**：time-travel +1；missioncritical1 +100（全自动）；其余 6 题工具解出、人工提交
- **AI 求解耗时**：最短 5.8s（missioncritical1），最长 321s（PalatinePack），中位数 ~60s
- **验证闭环回归**：parallelism 契约 ✅、PlutoChat 契约 ✅（修复后重跑命中）、missioncritical1 ✅ 一次通过——custom 契约命中率从 0/3 → 3/3
- **人工干预收敛**：第 1 题人工辅助反汇编 → 第 7 题零干预全自动

### 经验库沉淀（节选）

- MPI/多线程运行型题：**确定性置换用单位标签模拟求逆**，别模拟真实运行时
- Excel 公式题：`SUMPRODUCT`=矩阵乘、`MAX(0,.)`=ReLU、`--(...)`=布尔；先读 `workbook.xml.rels` 搞清 sheet 映射；权重表 stride 从公式行号锚点反推（解集唯一 = stride 正确的判据）
- 输入→变换→输出型（读 x 写 y）：**flag 往往是输入不是输出**，拿到密文先判方向
- `mprotect` 自改代码的立即数不可信：反推结果对候选常量（105/1）逐一正向回验择真
- 短密文（enc.txt 类）：先单字节 XOR/移位全扫 + flag 前缀匹配，30 秒内出结果再考虑复杂算法
- RC4 密钥流题：先找 LCG/置换/XOR 链常量表定 seed 关系；协议封装明文要剥控制字符头
- 无 xrefs 的花函数（AES S 盒等）= 干扰项，先查 xrefs 再决定要不要逆

## 五、工具当前状态

- 全部修复在源码（`electron/main.js` / `src/js/app.js`），开发态 `npm start` 验证通过，未发版（git 工作区含未提交改动）
- 平台 8 题全部 solved；skipChallenges 已登记 7 题名防重复拉取
- 新增能力：XLSX/OOXML 题型（Excel 公式逆向）、TXT 密文题、XML 结构化文本题的完整自动求解链路
