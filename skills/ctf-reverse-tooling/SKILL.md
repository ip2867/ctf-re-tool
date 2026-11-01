---
name: ctf-reverse-tooling
description: 自动化求解工具链：Z3 约束求解、angr 符号执行、Unicorn 模拟执行、迷宫/自定义规则题。遇到"逻辑能读懂但手算不完"（逐字节校验、大循环、约束方程组）、或程序无法直接运行/需要模拟执行时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# 自动化求解工具链（Z3 / angr / Unicorn）

## 何时用哪把锤子（按成本从低到高）

| 题目特征 | 工具 | 为什么 |
|---|---|---|
| 逐字节/逐位独立校验，每字符规则清晰 | **Z3** | 把校验逻辑翻译成约束，一次求解；比手写爆破稳 |
| 校验逻辑复杂但有明确方程（异或链、循环移位、AES 单字节） | **Z3** | 约束表达式直接编码 |
| 输入经过大量分支/间接跳转，静态读不动 | **angr** | 免翻译，直接符号执行到目标地址 |
| 程序是自写 VM / 自定义字节码 | **Unicorn** | 只模拟执行，不改写逻辑；比人肉复刻解释器可靠 |
| 程序依赖特定环境跑不起来（无源码、架构不对） | **Unicorn** | 只跑关心的那段代码 |
| 迷宫/棋盘/状态机类（走法即输入） | **BFS/DFS + 模拟器** | 见文末"迷宫题" |
| 逐字节校验且每个位置可独立（无跨位依赖） | **并行暴力** | 比 Z3 更省心，见文末 |

**判断口诀**：能独立爆破→先爆破（最省）；有跨位依赖/大循环→Z3；静态读不动→angr；自写 VM→Unicorn。

## 1. Z3 约束求解

### 基本范式
```python
from z3 import *

s = Solver()
flag = [BitVec(f'c{i}', 8) for i in range(N)]   # 每字节一个 8 位位向量
# 可打印字符约束（关键：不加约束会解出乱码）
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)
# 把题目校验逻辑逐行翻译成约束（异或/加/移位/查表）
for i in range(N):
    s.add( (flag[i] ^ KEY[i]) + SHIFT[i] == EXPECT[i] )
if s.check() == sat:
    m = s.model()
    print(bytes([m[c].as_long() for c in flag]))
```

**本工具环境优先用 `z3_solve` 工具**（不必自己写完整脚本）：只给约束代码，工具自动补
`from z3 import *` / `Solver` / `check` / 结果提取，并返回结构化 JSON：
```jsonc
{"status":"sat","model":{"f0":102,"f1":108},"summary":"f0=0x66(f), f1=0x6c(l)",
 "as_bytes_hex":"666c61...","as_text":"flag..."}
```
`as_text` 会按变量名数字后缀排序拼接字节 —— 直接看就是 flag 明文，省掉自己拼串。
`status` 四态：`sat` / `unsat`（约束无解，有效结果）/ `unknown`（超时）/ `error`（代码错）。

- **逐字节翻译**：把反编译代码里的校验循环，一条语句一条约束地抄过来，不要试图"化简"
- **跨字节依赖**（如 `flag[i]` 依赖 `flag[i-1]`）也直接写进约束即可，Z3 会处理
- 常见运算符映射：`+ → +`、`^ → ^`、`<< n → << n`、`>> n` 要用 `LShR`（逻辑右移）而非 `>>`（算术右移，会带符号位）

### 高频坑
- **符号位**：`BitVec(...,8)` 是**有符号**。涉及右移用 `LShR(x, n)`；比较常量时若原码用 `int8_t`，两边都要 `& 0xff`（`BitVecVal(x & 0xff, 8)`）
- **乘加混合**：`BitVec` 的加减乘都会自动模 2^8/2^32，与原 C 代码一致，无需手动 `&`
- **超时**：约束太多时 `s.set('timeout', 30000)`；仍超时说明该逐位拆解或换工具
- **无解**：先检查是不是漏了可打印约束方向、常量字节序反了、或运算用了有符号移位
- **`^` 只对 BitVec 成立**（D3CTF/强网杯实战踩过）：`Int('x') ^ Int('y')` 直接抛
  `unsupported operand type(s) for ^`。位运算一律用 `BitVec`；纯整数算术才用 `Int`。
- **别把"unsat"当工具失败**：unsat 说明约束组自相矛盾，是**有价值的负结果** ——
  回头验证推导（常见原因：把 `>>` 写成算术右移、常量字节序反了、漏了某条前置约束）。
  此时去改工具或换方法都是浪费。
- **乘除不互素导致无解**（强网杯实测）：`v * 0x1234 ≡ C (mod 2^32)` 当 `0x1234` 为偶数时
  左边的高位被清零，右边若奇数则必然无解。先验算 `gcd(乘数, 2^32)` 再决定能否用乘法约束。
- **`ZeroExt` 宽度要对**：8 位加到 32 位做异或前必须 `ZeroExt(24, b)`，直接 `b ^ INT32CONST`
  会变成 8 位截断，解出来看似"对"但校验不过。


## 2. angr 符号执行

### 基本范式
```python
import angr, claripy
p = angr.Project('./challenge', auto_load_libs=False)
flag = claripy.BVS('flag', 8 * LEN)          # LEN = 输入长度（从题面/scanf 宽度推）
st = p.factory.entry_state(stdin=flag)
for c in flag.chop(8):                        # 约束可打印
    st.solver.add(c >= 0x20, c <= 0x7e)
sm = p.factory.simulation_manager(st)
sm.explore(find=0x400123, avoid=0x400456)     # find=正确分支地址, avoid=错误分支
if sm.found:
    print(sm.found[0].posix.dumps(0))         # 0=stdin
```
- `find` / `avoid` 给**地址**（IDA 里"正确"分支与"错误"分支的地址）
- 入口若是库函数/自定义 `main`：`p.factory.call_state(addr, arg)` 直接调函数
- 慢是常态：先用 `find`/`avoid` 收窄，不要全程序探索

### 高频坑
- **输入长度未知**：从 `scanf("%20s")` / `read(0,buf,32)` / 题面提示推；用错长度会一直无解
- **`auto_load_libs=False`**：默认加载 libc 会拖慢十几倍，先关掉
- **hook 掉无关函数**：`p.hook(addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())` 跳过反调试/sleep
- **状态爆炸**：`sm.explore(step_func=...)` 限制；或改用 Z3（能翻译就别用 angr）
- **环境依赖**：需要 argv/env 时用 `entry_state(args=[...], env={...})`

## 3. Unicorn 模拟执行

### 基本范式（模拟自写 VM / 一段 native 代码）
```python
from unicorn import *
from unicorn.x86_const import *
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x1000, 0x100000)                 # 映射内存
mu.mem_write(0x1000, code_bytes)              # 写代码
mu.mem_write(0x2000, data_bytes)              # 写常量表
mu.reg_write(UC_X86_REG_RSP, 0x30000)         # 设栈
mu.hook_add(UC_HOOK_CODE, lambda uc,a,s,u: print(hex(a)))  # 可选：指令级 trace
mu.emu_start(0x1000, 0x1000+len(code_bytes))  # 起始地址, 结束地址
print(mu.mem_read(0x2000, 64))                # 读回结果
```
- **内存映射**要按题目地址对齐（页 0x1000），段权限缺一不可（缺写权限会崩）
- **API hook**：库函数（printf/strlen）用 `hook_add(UC_HOOK_CODE, fn, begin=addr, end=addr+1)` 拦截，自己实现返回
- **`mem_read` 越界**会抛 `UC_ERR_READ_UNMAPPED`：映射范围给足（多映射点不亏）

### 高频坑
- **架构/位数选错**：APK 里抽的 so 常见 arm64，用 `UC_ARCH_ARM64, UC_MODE_ARM`；位数错表现为一启动就异常
- **ARM 需设 PC 与 CPSR**：`mu.reg_write(UC_ARM64_REG_PC, addr)`；thumb 模式要设 CPSR 的 T 位
- **x86-64 调用约定**：参数 RCX/RDX/R8/R9；x86 是栈传参，进函数前把栈指针摆好
- **终止地址给错**：给"函数末尾 ret 之后"的地址，或 hook `ret` 指令停

## 迷宫 / 自定义规则题

**识别**：输入被当成"方向串"（wasd/udlr/0123），程序按字符在二维/三维网格上移动，撞墙或越界即失败，走到终点即成功。

**通用解法（写模拟器 + 搜路径，不要手推）**：
1. 从反编译提取**地图数据**（`.data`/`.rodata` 里的字符矩阵或位图）和**移动规则**（哪个字符对应 dx/dy，边界/墙的判定）
2. 写 BFS/DFS：状态 = 坐标（+ 已收集钥匙等），转移 = 四个方向，边权 = 1 或角色代价
3. 回溯路径 → 路径字符串即 flag 主体（可能再套一层编码）
```python
from collections import deque
def solve(maze, start, goal, moves):         # moves={'w':(-1,0),'s':(1,0),'a':(0,-1),'d':(0,1)}
    q, seen, prev = deque([start]), {start}, {}
    while q:
        cur = q.popleft()
        if cur == goal:
            path = []
            while cur != start: d, cur = prev[cur]; path.append(d)
            return ''.join(reversed(path))
        for ch, (dy, dx) in moves.items():
            ny, nx = cur[0]+dy, cur[1]+dx
            if maze[ny][nx] != '#' and (ny, nx) not in seen:
                seen.add((ny, nx)); prev[(ny, nx)] = (ch, cur); q.append((ny, nx))
    return None
```

**变体**：多目标（先拿钥匙再出门）→ 状态加"钥匙位掩码"；移动有代价/带转向限制 → Dijkstra/BFS 按代价；三维或带传送门 → 状态并入坐标。

## 逐位独立暴力（比 Z3 更省心的场景）

当每个位置的输出**只依赖该位置的输入**（`out[i] = f_i(in[i])`，位置间无耦合）：
```python
for i in range(len(expect)):
    for c in range(0x20, 0x7f):              # 可打印字符逐字节试
        if f_i(c) == expect[i]:
            ans.append(chr(c)); break
```
- 判据：反编译里校验是 `out[i] == const[i]` 的单层循环，没有 `flag[i]` 依赖 `flag[j≠i]`
- 复杂 `f_i`（含查表/加密）也只需枚举 95 个候选，比 Z3 建约束更快
- **与本工具配合**：把候选位置/规则写清楚交给 `[HYPOTHESES]` 或直接给完整脚本

## 输出契约

- 自动化求解脚本作为 `[VERIFY]` 的 `code` 字段（`algo:"custom"`），或直接落 CASE scripts/
- 多个候选（工具/字节序/映射）→ `[HYPOTHESES]`
- **必给可复现脚本**：Z3/angr/Unicorn 解出来的结果，要用 Python 脚本再跑一遍核对，不要只给一句"解出来了"
