---
title: OTA 包与跨架构校验器——固件升级包的快速定界与 flag 定位
category: reverse-method
vuln_type: firmware-ota
difficulty: medium
tags: [固件, OTA, 升级包, 跨架构, RISC-V, 校验器, 哈希, MAC, 强网杯, firmware, elf32]
keywords: [OTA 包, ota_package, 固件升级, QWBP, magic, 段表, 条目表, keymat, 哈希不匹配, 带 key 的 MAC, 跨架构, RISC-V, RV32, elf32, unicorn riscv, qemu-riscv32, 强网杯 firmware]
one_liner: 固件题给「校验器 + 目标镜像 + 小 OTA 包」三件套时，先在小包里把结构定死（magic/版本/key/条目表/magic 段），flag 通常在尾部的专用段里；校验器的 usage 直接跑出来比反汇编猜快，哈希对不上标准算法说明是带 key 的 MAC。
attack_chain:
- 阶段 0 三件套定架构：file 看清校验器与目标镜像架构常不同（x86-64 工具校验 RISC-V 镜像）
- 阶段 1 跑校验器看 usage：直接执行不带参数，它会打印参数格式（比反汇编快十倍）
- 阶段 2 先啃小包：几十到几百字节的 OTA 包 xxd 一遍就能读出 magic/版本/key/条目表/段数据
- 阶段 3 找 magic 段：搜 FLAG 类字样，紧跟 u32 长度 + 密文，这就是 flag 容器
- 阶段 4 哈希定性质：crc32/fnv/adler 都不匹配说明是带 key 的 MAC，别穷举标准算法，去校验器里找实现
- 阶段 5 补参数：缺的值若来自另一个固件的运行输出，先看它是不是只是打印一段常量（读 .rodata 即可，不必真跑）
- 阶段 6 用校验器当 oracle：它有成功/失败两个出口，构造候选喂进去看退出码，比盲试快
failed_attempts:
- 一上来 binwalk 1MB 大镜像 → 真正需要看的只是 176 字节的 OTA 包
- 以为校验器坏了（ldd 说「不是动态可执行文件」）→ 静态链接的 ELF 本来就这样
- 用 crc32/fnv/adler 逐个试条目哈希 → 全不匹配，其实是带 key 的 MAC
- 想跑 RISC-V 固件却没有 qemu-riscv32 → 该值可能只是常量，读 .rodata 就够
- Unicorn 映射 0x100000 失败 → 该版本对起始地址有对齐限制，改从 0x0 映射
- 找 UC_RISCV_INSN_ECALL → 部分版本不存在，改用 UC_HOOK_CODE 判断指令字 0x00000073
lesson: 固件题的性价比来自「先定界再看逻辑」。小文件里能读出的结构不要放到大镜像里找；校验器的 usage 是免费的说明书；哈希不匹配标准算法应立即改判为 MAC 而不是继续穷举。
---

# OTA 包与跨架构校验器——固件升级包的快速定界与 flag 定位

> 核心判断：**先在小文件里把格式定死，再决定要不要动大镜像。**

## 一、典型形态

| 文件 | 大小 | 身份 |
|---|---|---|
| `fw_a` | ~1MB | 校验/打包器，**x86-64** ELF |
| `fw_b.bin` | ~3KB | 目标固件，**RISC-V 32 位** ELF |
| `ota_package.bin` | ~200B | 升级包，flag 藏在这里 |

**架构不一致是常态**：x86 工具负责校验 ARM/MIPS/RISC-V 的镜像。
不要因为「跑不起来」就以为文件坏了。

## 二、先跑校验器

```bash
./fw_a
# usage: ./fw_a <ota_package.bin> <keymat_hex32> <vm_out8_hex16>
```

这一步给出：参数个数、每个参数的类型（哪些是 hex、多长）。比反汇编找 argv 使用点快得多。

`ldd ./fw_a` 显示「不是动态可执行文件」是**正常的**（静态链接），不是文件损坏。

## 三、小包定界（最高性价比）

176 字节 `xxd` 一遍，结构立刻清楚：

```
QWBP | ver(u32) | key16 | count(u32) | entry[] | 段数据
                                     └─ entry = { off(u32) len(u32) hash(u32) }
```

要点：
- `off` 是**包内偏移**，不是文件偏移。按 `len` 切出来就是密文段。
- 条目 `hash` 对不上 crc32/fnv/adler → 是**带 key 的 MAC**，去校验器里找那个 hash 函数。
- 尾部常见专用 magic 段（如 `QWBPFLAG` + u32 长度 + 密文），**那就是 flag 容器**。
  找到它比逆整个校验器划算。

## 四、缺参数怎么办

`vm_out8_hex16` 这类参数通常来自**另一个固件的运行输出**。两条路：

1. 该固件能跑（有 qemu 对应架构）→ `qemu-riscv32 ./fw_b.bin`，抓它的 write 输出。
2. 跑不起来 → 先看它是不是**只是打印一段常量**。静态文件里 3KB 的固件，
   输出几乎一定在 `.rodata` 或尾部字符串区，直接读就能拿到，不必真跑。

**Unicorn 仿真的两个坑**（RISC-V 32 位）：
- `mem_map(0x100000, ...)` 可能失败（该版本有对齐限制），**改从 `0x0` 映射**即可。
- `UC_RISCV_INSN_ECALL` 在部分版本不存在。改用 `UC_HOOK_CODE`，判断指令字是否为
  `0x00000073`（ecall），命中后读 `a7`（syscall 号）/`a0·a1·a2`（参数）自行处理。

## 五、用校验器当 oracle

校验器本身有「通过/不通过」两个出口。构造候选参数喂进去，看退出码：

```bash
./fw_a ota.bin "$KEY" "$VMOUT"; echo rc=$?
```

这比盲试快，也比赛猜算法可靠。若它打印明确错误（如 `wrong key` / `mac mismatch`），
那就是免费的诊断信息。

## 六、观察结论

- 小文件里能读出的结构，不要放到大镜像里找。
- 校验器的 usage 是免费说明书；先跑一次胜过先反汇编。
- 标准哈希全不匹配 → 立刻改判 MAC，不要继续穷举算法。
- 跨架构不等于跑不起来：先看目标是不是只输出常量。
