---
title: 确定性取证与块链 VM——故障驱动虚拟机的逆向流程
category: reverse-method
vuln_type: fault-driven-vm
difficulty: hard
tags: [故障驱动VM, 块链VM, TF单步, SIGTRAP, 自修改代码, 确定性取证, /proc/pid/mem, 内存差分, 进程内dump, 重放器, splitmix64, 白盒AES, 强网杯]
keywords: [TF 单步 VM, pushf or 0x100 popf, si_code TRAP_TRACE, 白名单偏移, ctx 结构, mprotect RWX, 自修改代码, self-modifying, 块链, 槽位, 解释器, 重放, replay, 确定性, ASLR, ADDR_NO_RANDOMIZE, TracerPid, 内存差分, 轮询, /proc/pid/mem, shellcode 注入, 进程内 dump, 无竞态, 诱饵分支, 死路判定, 强网杯 license]
one_liner: 故障驱动 VM 把「反调试」和「主逻辑」编在一起，硬绕会走错分支。可靠流程是先把所有随机源钉死（ASLR/TracerPid/时间），再用无竞态的进程内 dump 取崩溃前最终状态，然后据真实 ctx 值回填重放器，用「解出的块与内存逐字节相同」作为重放正确性的硬判据。
attack_chain:
- 阶段 0 识别形态：看到 mprotect(RWX) + pushf/or 0x100/popf + jmp 到 RWX 区，就是 TF 单步 VM；再看 handler 是否按 si_code==2 分流、是否往 base+ctx[4] 拷 16 字节块——是则为块链 VM
- 阶段 1 找解释器：RWX 区里通常预置多份解释器副本（如 base+0x1000/0x1800/0x2000/0x2800 内容相同），它们才是真代码；base+0x3000 常只是跳板
- 阶段 2 钉死随机源：personality(ADDR_NO_RANDOMIZE) 关 ASLR；把 sec_env_probe 类函数首字节改 0xC3；把 /proc/self/status 的 open 路径重定向到假文件让 TracerPid 恒 0
- 阶段 3 无竞态取证：在废弃函数体里注入 shellcode，于「拒绝」瞬间把 VM 区 + ctx 整块写文件。绝不覆盖任何真实函数（曾把 fn_402bf5 覆盖成 shellcode，SIGILL 白查半天）
- 阶段 4 反推解释器：逐条抄出哈希输入字段（counter/各 ctx 字段/可能的 TracerPid）、乘法宽度（32 位 imul 与 64 位乘积结果不同）、splitmix64 常量
- 阶段 5 重放并硬验证：用 dump 的真实 ctx 回填重放器，算出 off 后用同一 splitmix 解开该处 16 字节，必须与内存内容逐字节相同；只在第一步对得上才继续往后推
- 阶段 6 区分控制流与数据流：若两组输入 RIP 轨迹完全一致而结果不同，说明分支由数据决定，停止追 RIP，改为比对内存/块内容
- 阶段 7 判死路：累计型状态（如 30M 次查表求和）的高位由表统计均值决定，与输入几乎无关；任何「该值 == 某魔数」的分支都是诱饵，直接判死，去找真正出口
failed_attempts:
- 用 ptrace 单步观测 TF 单步 VM → VM 自己要靠 SIGTRAP 驱动，ptrace 先截走信号，VM 直接崩
- 开着 ASLR 做两次运行 diff → 栈地址变化导致 hash 链整体移位，diff 结果全是噪声
- 把 TracerPid 当常量 0 → 它进 VM hash，ptrace 观测下非零，裸跑为零，两种环境轨迹不同却看不出原因
- 往 ctx+0x56 找 license 注入点 → 静态写完发现没有任何指令写它（解释器只清零），误以为 license 不进哈希，白绕很久
- 轮询 /proc/pid/mem 想拿完整写序列 → 4ms 间隔内的多次写被合并，只看到最终值
- 按「poll 到的第一个地址就是第一步」推理 → 早期几步在首次轮询前已完成，步号全错位
- 把 shellcode 放在 0x402bf1 这类看似空洞的地址 → 实际是 fn_402bf5 的入口，覆盖后触发 SIGILL
- 认为 unsat / Rejected 就是失败 → 实际实现可能先打印 Rejected 再走成功路径，必须看之后还做了什么
lesson: 这类题的瓶颈不是「绕不过反调试」，而是「观测不到确定的状态」。先把环境做成比特级可复现，再用进程内 dump 拿无竞态的最终快照，最后用「解密结果与内存逐字节一致」作为唯一可信的重放判据。控制流一致而结果不一致时，问题一定在数据侧。
---

# 确定性取证与块链 VM——故障驱动虚拟机的逆向流程

> 核心判断：**故障驱动 VM 的难点在观测，不在绕过。**
> 反调试是它的驱动机制本身，硬绕会改掉控制流；正确做法是把随机源钉死，然后安静地看。

## 一、识别形态

三个特征同时出现，基本可以确定是 TF 单步 + 块链 VM：

```
mprotect(base, size, PROT_READ|PROT_WRITE|PROT_EXEC)   ; 开 RWX
pushfq; or qword [rsp], 0x100; popfq; jmp base         ; 开 TF 单步跳进 RWX 区
handler: cmp qword [rsi+8], 2                          ; si_code == TRAP_TRACE 才处理
         cmp eax, <白名单偏移>; je ...                  ; 白名单：直接 RIP = base + ctx[4]，TF 保持
         否则: 把 ctx+0x10 的 16 字节拷到 base + ctx[4], RIP = base + (counter & 3)*0x800, TF 关
```

判定要点：
- **RWX 区里预置了多份解释器副本**（不同槽位内容完全相同）。找它们比找「哪个是 main」快。
- **槽位与写入目标分离**：解释器把解密结果写到 `base + off`（off 任意），但**执行**位置是
  `base + (counter & 3) * 0x800` 这类固定槽位。跟踪写地址 ≠ 跟踪执行地址。

## 二、钉死随机源（这一步不能省）

| 噪声源 | 症状 | 处理 |
|---|---|---|
| ASLR | 每次运行栈地址不同 → hash 链整体移位 | `personality(ADDR_NO_RANDOMIZE)`，子进程 `preexec_fn` 里调 |
| TracerPid | 自己进 VM hash；ptrace 观测下非零 | 把 `/proc/self/status` 的 open 重定向到假文件，值恒 0 |
| 环境探测函数 | `sec_env_probe` 类函数 fork/ptrace/rdtsc 自检 | 首字节改 `0xC3`（ret） |
| RDTSC 计时 | 单步/断点让计时暴增 | 把 `0F 31` patch 成 `31 C0`（xor eax,eax） |

做完这四项，同一个输入才会每次得到**完全相同的轨迹**。否则后面所有 diff 都是噪声。

## 三、无竞态取证：进程内 dump

轮询 `/proc/<pid>/mem` 的问题是粒度（约 4ms），间隔内的多次写被合并。可靠做法是
**让目标自己把状态写出来**：

1. 找一个**已经废弃**的代码区做 cave（例如被 patch 成 `ret` 的函数体，剩余字节全是死代码）
2. 注入 shellcode：`open("/tmp/dump", O_WRONLY|O_CREAT) → write(fd, base, VM_SIZE) →
   write(fd, ctx, 0x300) → write(fd, input_buf, 0x200) → re-exec 被覆盖的字节 → jmp 回原处`
3. 在「拒绝」处理入口挂一个 5 字节 `jmp cave` 跳板
4. 于是每次失败都会留下一份**崩溃前的完整快照**，完全没有竞态

**选址是唯一风险点**：必须先确认目标地址不属于任何真实函数。
踩过的坑：把 cave 放在 `0x402bf1`，结果它是 `fn_402bf5`（license 验证器）的入口，
覆盖后每次走到验证就 SIGILL，而 si_addr 指向 cave 内部，容易误判成 shellcode 写错。

## 四、反推解释器：容易抄错的四处

从 handler / 解释器的反汇编里逐条抄逻辑时，这四处几乎必错：

1. **乘法宽度**：`imul ecx, ecx, 0xb2f1` 是 **32 位**乘法（结果截到 32 位），
   写成 `(ecx * 0xb2f1) & 0xFFFF_FFFF_FFFF_FFFF` 就错了。要看操作数宽度。
2. **偏移公式的加法项**：常见形式 `off = (ctx[0] + (esi ^ (r9 & 0x3fff))) & 0x7ffff`。
   漏掉 `ctx[0]` 这一项，第一步就对不上；而 `ctx[0]` 初值往往不是 0，
   是**上一个 trap 的 handler 写入的 `disp`（可能为负，按无符号参与运算）**。
3. **RIP 相对寻址的目标计算**：`c7 05 disp32 imm32` 是 **10 字节**指令，
   `tgt = va + 10 + disp`；按 6 字节算会整体偏移 4，导致「谁初始化了这个字段」全错。
4. **先存后异或的顺序**：解密循环常是「先把原字节抄进 ctx 缓冲，再对内存异或」。
   顺序反了会得到「看似能跑但字节错位」的结果。

## 五、重放正确性的硬判据

不要用「off 序列看起来合理」判断重放对不对。唯一可信判据：

> 用重放算出的 `off` 和 splitmix 密钥解开该位置的 16 字节，
> 结果必须与 dump 里 `base + off` 处的内存**逐字节相同**。

只在这一步通过后，才继续往后推第二步、第三步。否则后面全是沙上建塔。

第一组输入验证通过后，换第二组输入：若 `off` 变了但**执行轨迹（RIP 序列）不变**，
说明分歧在数据侧（块内容），而不是控制流。

## 六、死路判定：累计型状态的魔数检查

典型诱饵：

```c
for (i = 0; i < 30000000; i++) { ...; acc += table[...]; }
if (acc == 0x51D2F3A4B6C7E809) { /* 成功路径 */ }
```

`acc` 是 3000 万次查表累加。其高位由表的统计均值决定，实测多组输入只在小范围内浮动
（例：高位恒为 `0x00e4e`），**与输入几乎无关**。所以这个魔数永远不可能成立，
该分支是诱饵。

判定方法：用多个差异极大的输入各跑一次，dump `acc`。若高位完全一致 → 死路，
立刻转去找真正的输出路径（通常是 VM 出口处 `puts(buf)`）。

## 七、观察结论

- 观测手段的选择比反调试绕过更重要：`/proc/<pid>/mem` 读不干扰运行，ptrace 会打断 TF 驱动。
- 「控制流相同、结果不同」直接指向数据流，不要再追 RIP。
- 「两次运行结果不同」先怀疑环境噪声（ASLR / TracerPid），不是逻辑差异。
- 诱饵设计（累计魔数、先打印 Rejected 再成功）很常见，判定死路比硬攻更省预算。
