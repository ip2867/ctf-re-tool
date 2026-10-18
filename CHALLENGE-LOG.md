# CTF² Agent Arena · 逐题过程记录（第二轮：P0 修复后）

> 数据来源：2026-10-19 的全部运行日志（31 条记录，21 道唯一题目）。
> 本轮启用了 P0.1–P0.4b 五道改进（四道收工闸 + 中间值识别 + 明文外壳），用于验证修复效果。

## 总览

| # | 题目 | 难度 | 载体 | 工具识别 | 耗时 | 闸 | 结果 |
|---|------|------|------|----------|------|----|------|
| 1 | `CrackMe` | Easy | ZIP | (未发现算法指纹)(n/a) | 492.3s | 0 | 🔸 只命中中间值 |
| 2 | `brichfire` | Easy | ZIP | Base91变表(medium) | 132.8s | 1 | ⛔ 未产出契约 |
| 3 | `CrackMe2` | Easy | ZIP | (未发现算法指纹)(n/a) | 721.9s | 1 | ❌ 契约复现失败 |
| 4 | `CrackMe3` | Easy | ZIP | (未发现算法指纹)(n/a) | 161.2s | 0 | ❌ 契约复现失败 |
| 5 | `Crackme7` | Easy | ZIP | Base91变表(medium) | 158.3s | 0 | ⚠️ 平台拒绝 |
| 6 | `Crackme6` | Easy | ZIP | (未发现算法指纹)(n/a) | 391.3s | 0 | ⚠️ 平台拒绝 |
| 7 | `CrackMe4` | Easy | ZIP | — | — | 0 | 🛡 杀软拦截 |
| 8 | `CrackMe5` | Easy | ZIP | (未发现算法指纹)(n/a) | — | 0 | ❌ 契约复现失败 |
| 9 | `cnbragon` | Easy | ZIP | Base91变表(medium), AES(high) | 199.9s | 2 | ❌ 契约复现失败 |
| 10 | `kanxue-ctf-gxustudent` | Easy | ZIP | Base91变表(medium), Base64变表(mediu | 120.1s | 1 | ❌ 契约复现失败 |
| 11 | `QuiZow` | Easy | ZIP | (未发现算法指纹)(n/a) | 221.5s | 1 | ⛔ 未产出契约 |
| 12 | `(unknown)` | — | — | — | — | 0 | ⛔ 未产出契约 |
| 13 | `CM` | Easy | ZIP | Base91变表(medium) | 151.3s | 1 | ⛔ 未产出契约 |
| 14 | `PeSafe` | Easy | ZIP | Base91变表(medium) | 344.8s | 1 | ⛔ 未产出契约 |
| 15 | `HellScream` | Easy | ZIP | SHA256(medium) | 108.6s | 1 | ⛔ 未产出契约 |
| 16 | `Youngter-drive` | Easy | ZIP | (未发现算法指纹)(n/a) | 272.5s | 1 | ⛔ 未产出契约 |
| 17 | `reverse3` | Easy | ZIP | Base64(low) | 16.6s | 0 | 🔸 只命中中间值 |
| 18 | `firmware` | Easy | UNKNOWN | — | — | 1 | ⛔ 未产出契约 |
| 19 | `equation` | Easy | ZIP | — | — | 0 | ❌ 契约复现失败 |
| 20 | `新年快乐` | Easy | ZIP | (未发现算法指纹)(n/a) | 86.1s | 0 | 🔸 只命中中间值 |
| 21 | `内涵的软件` | Easy | PE | (未发现算法指纹)(n/a) | 33.3s | 0 | ❌ 契约复现失败 |

---

## 失败原因分布

| 分类 | 数量 | 占比 | 含义 |
|------|------|------|------|
| ⛔ 未产出契约 | 8 | 38.1% | AI 分析完但未产出 [VERIFY] 契约 |
| ❌ 契约复现失败 | 7 | 33.3% | 有契约但本地复现失败 |
| 🔸 只命中中间值 | 3 | 14.3% | 只解出中间值/明文，未进一步处理 |
| ⚠️ 平台拒绝 | 2 | 9.5% | 本地验证通过但平台拒绝 |
| 🛡 杀软拦截 | 1 | 4.8% | 杀软拦截文件读取 |

---

## 逐题详情

### ❌ CrackMe

**难度** Easy · **编号** PCHAL-2026-0014 · **载体** ZIP · **附件** `29894069-43cf-49fe-93f8-dc99eff72748.zip`（106.7 KB）

**解压内容**：CrackMe.exe

**执行路径**：多阶段接力 → IDA → 自动提取载荷

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：492.3s

**本地验证**：检测到 1 个 [VERIFY] 契约；🔸 只命中中间值 `55a54008ad1ba589aa210d2629c1df41`

**证据回灌重试**：1 次

**结果**：🔸 只命中中间值 — 只命中中间值 55a54008ad1ba589aa210d2629c1df41

<details><summary>关键过程日志</summary>

```
[00:41:57][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\stage_pe_34108.bin_d51111c0/scripts/solve_enum_mve1zci3.py
[00:41:57][验证闭环] 本地复现通过（命中中间值/密钥，非 flag）：55a54008ad1ba589aa210d2629c1df41
[00:41:57][验证闭环] 已提取失败证据（将回灌给 AI）: 93 字符
[00:41:57][验证闭环] 已生成修正提示（535 字符），将随结果回传触发重试
[00:41:57][重试] 追加一轮 AI（验证失败（附真实解密输出），强制基于证据修正）
[00:42:14][自动接力] 已切换并完成下一阶段分析（C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_827e520c/extracted/stage_pe_34108.bin）
[00:42:14][6/6] 检查是否产出已验证 flag 并提交平台...
[00:42:14][自动测试] 1/1 CrackMe: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792341740348-0.log`</sub>

---

### ❌ brichfire

**难度** Easy · **编号** PCHAL-2026-0015 · **载体** ZIP · **附件** `4af449ae-cf09-4cff-8ca8-b63bc8d5856e.zip`（34.4 KB）

**解压内容**：CrackMe.exe

**执行路径**：IDA

**工具识别**：Base91变表(medium)

**AI 深挖耗时**：132.8s

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[02:34:54][zip手包] 解压: E:\ctf\pratice\ai\brichfire\4af449ae-cf09-4cff-8ca8-b63bc8d5856e.zip
[02:34:55][zip手包] 共 1 个文件: CrackMe.exe
[02:34:55][zip手包] 选定主文件: CrackMe.exe
[02:35:00][算法扫描] Base91变表(medium)
[02:35:13][算法扫描] 注入深度求解提示：Base91变表
[02:36:37][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[02:37:25][6/6] 检查是否产出已验证 flag 并提交平台...
[02:37:25][自动测试] 1/1 brichfire: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792348649710-1.log`</sub>

---

### ❌ CrackMe2

**难度** Easy · **编号** PCHAL-2026-0608 · **载体** ZIP · **附件** `19248a41-b7fc-440d-ad52-d3fcf287cab9.zip`（95.5 KB）

**解压内容**：CrackMe.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：721.9s

**收工闸触发**：收敛×1

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[02:37:56][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_d2f7c502/scripts/solve_enum_mve64huz.py
[02:37:56][验证闭环] 本地复现失败（1 个契约无命中）
[02:37:56][验证闭环] 已提取失败证据（将回灌给 AI）: 389 字符
[02:37:56][验证闭环] 已生成修正提示（799 字符），将随结果回传触发重试
[02:37:56][算法扫描] 注入深度求解提示：(未发现算法指纹)
[02:39:54][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[02:49:58][6/6] 检查是否产出已验证 flag 并提交平台...
[02:49:58][自动测试] 1/1 CrackMe2: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792349399762-2.log`</sub>

---

### ❌ CrackMe3

**难度** Easy · **编号** PCHAL-2026-0609 · **载体** ZIP · **附件** `02da357b-0bce-4ff2-b2b3-d1c7e4e73fe8.zip`（11.7 KB）

**解压内容**：CrackMe.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：161.2s

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**证据回灌重试**：1 次

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[02:54:50][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[02:54:50][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_ee7ba0e8/scripts/solve_enum_mve6q80s.py
[02:54:50][验证闭环] 本地复现失败（1 个契约无命中）
[02:54:50][验证闭环] 已提取失败证据（将回灌给 AI）: 1099 字符
[02:54:50][本地求解] 3 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_ee7ba0e8/scripts/solve_enum_mve6q844.py
[02:54:50][验证闭环] 已生成修正提示（2019 字符），将随结果回传触发重试；检测到解出机器码 1 处 → 重试指令已改为"接力下一层"
[02:54:50][6/6] 检查是否产出已验证 flag 并提交平台...
[02:54:50][自动测试] 1/1 CrackMe3: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792349692941-3.log`</sub>

---

### ❌ Crackme7

**难度** Easy · **编号** PCHAL-2026-0610 · **载体** ZIP · **附件** `5ca3eeb0-dbfc-41d4-b1e8-057a24021496.zip`（45.4 KB）

**解压内容**：CrackMe.exe

**执行路径**：IDA

**工具识别**：Base91变表(medium)

**AI 深挖耗时**：158.3s

**本地验证**：检测到 1 个 [VERIFY] 契约；🔸 只命中中间值 `THISiSsERIALnUMBER`

**结果**：⚠️ 平台拒绝 — 平台拒绝 flag{THISiSsERIALnUMBER}

**提交被拒**：`flag{THISiSsERIALnUMBER}`

<details><summary>关键过程日志</summary>

```
[02:57:59][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[02:57:59][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_abe57dae/scripts/solve_enum_mve6uagv.py
[02:58:00][验证闭环] 本地复现通过（命中中间值/密钥，非 flag）：THISiSsERIALnUMBER
[02:58:00][验证闭环] 已提取失败证据（将回灌给 AI）: 190 字符
[02:58:00][本地求解] 3 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_abe57dae/scripts/solve_enum_mve6uakz.py
[02:58:00][验证闭环] 可打印明文加常见外壳后命中 flag：flag{THISiSsERIALnUMBER}
[02:58:00][6/6] 检查是否产出已验证 flag 并提交平台...
[02:58:00][自动测试] 1/1 Crackme7: 跳过（submit-rejected）
```

</details>

<sub>日志：`run-1792349884121-4.log`</sub>

---

### ❌ Crackme6

**难度** Easy · **编号** PCHAL-2026-0611 · **载体** ZIP · **附件** `0cfb1bc3-31b3-44f9-b08c-75740775da61.zip`（15.0 KB）

**解压内容**：Crackme.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：391.3s

**本地验证**：检测到 1 个 [VERIFY] 契约；🔸 只命中中间值 `pediy2016, ��.o�A���`

**结果**：⚠️ 平台拒绝 — 平台拒绝 flag{pediy2016}

**提交被拒**：`flag{pediy2016}`

<details><summary>关键过程日志</summary>

```
[03:05:07][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[03:05:07][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\Crackme.exe_3b821894/scripts/solve_enum_mve73gnt.py
[03:05:07][验证闭环] 本地复现通过（命中中间值/密钥，非 flag）：pediy2016, ��.o�A���
[03:05:07][验证闭环] 已提取失败证据（将回灌给 AI）: 245 字符
[03:05:08][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\Crackme.exe_3b821894/scripts/solve_enum_mve73grg.py
[03:05:08][验证闭环] 可打印明文加常见外壳后命中 flag：flag{pediy2016}
[03:05:08][6/6] 检查是否产出已验证 flag 并提交平台...
[03:05:08][自动测试] 1/1 Crackme6: 跳过（submit-rejected）
```

</details>

<sub>日志：`run-1792350309540-5.log`</sub>

---

### ❌ CrackMe4

**难度** Easy · **编号** PCHAL-2026-0612 · **载体** ZIP · **附件** `9eba9e66-f213-46ba-a82c-fd92b8a0dd69.zip`（388.5 KB）

**解压内容**：CrackMe.exe

**结果**：🛡 杀软拦截 — 杀软拦截文件读取

<details><summary>关键过程日志</summary>

```
[01:15:30][5/6] 交给本地逆向流程解题: E:\ctf\pratice\ai\CrackMe4\9eba9e66-f213-46ba-a82c-fd92b8a0dd69.zip
[01:15:30][zip手包] 解压: E:\ctf\pratice\ai\CrackMe4\9eba9e66-f213-46ba-a82c-fd92b8a0dd69.zip
[01:15:31][zip手包] 共 1 个文件: CrackMe.exe
[01:15:31][zip手包] 选定主文件: CrackMe.exe
[01:15:31][zip手包] 同一压缩包已处理过，跳过（防循环）: E:\ctf\pratice\ai\CrackMe4\9eba9e66-f213-46ba-a82c-fd92b8a0dd69.zip
[01:15:31][6/6] 检查是否产出已验证 flag 并提交平台...
[01:15:31][自动测试] 1/1 CrackMe4: 跳过（blocked-by-av）
```

</details>

<sub>日志：`run-1792343734961-6.log`</sub>

---

### ❌ CrackMe5

**难度** Easy · **编号** PCHAL-2026-0613 · **载体** ZIP · **附件** `0aca6176-2145-4217-9a36-b4e124192460.zip`（79.5 KB）

**解压内容**：CrackMe.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[03:05:39][zip手包] 选定主文件: CrackMe.exe
[03:05:43][算法扫描] (未发现算法指纹)(n/a)
[03:05:53][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[03:05:53][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\CrackMe.exe_5bb49009/scripts/solve_enum_mve74fhp.py
[03:05:53][验证闭环] 本地复现失败（1 个契约无命中）
[03:05:53][验证闭环] 已提取失败证据（将回灌给 AI）: 189 字符
[03:05:53][验证闭环] 已生成修正提示（599 字符），将随结果回传触发重试
[03:05:53][算法扫描] 注入深度求解提示：(未发现算法指纹)
```

</details>

<sub>日志：`run-1792351238693-7.log`</sub>

---

### ❌ cnbragon

**难度** Easy · **编号** PCHAL-2026-0614 · **载体** ZIP · **附件** `4e785e8e-9fc0-493a-ad8f-059bf1e4b804.zip`（71.8 KB）

**解压内容**：KanxueCTF2016Keygenme.exe

**执行路径**：IDA

**工具识别**：Base91变表(medium), AES(high)

**AI 深挖耗时**：199.9s

**收工闸触发**：收敛×2

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**证据回灌重试**：1 次

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[03:28:52][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[03:28:52][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\KanxueCTF2016Keygenme.exe_f99d940d/scripts/solve_enum_mve7y08l.py
[03:28:53][验证闭环] 本地复现失败（1 个契约无命中）
[03:28:53][验证闭环] 已提取失败证据（将回灌给 AI）: 430 字符
[03:28:53][本地求解] 2 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\KanxueCTF2016Keygenme.exe_f99d940d/scripts/solve_enum_mve7y0c3.py
[03:28:53][验证闭环] 已生成修正提示（847 字符），将随结果回传触发重试
[03:28:53][6/6] 检查是否产出已验证 flag 并提交平台...
[03:28:53][自动测试] 1/1 cnbragon: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792351736289-8.log`</sub>

---

### ❌ kanxue-ctf-gxustudent

**难度** Easy · **编号** PCHAL-2026-0615 · **载体** ZIP · **附件** `8262c97c-2d27-40c0-96fe-34abb71d65b5.zip`（123.9 KB）

**解压内容**：kanxue-ctf-gxustudent.exe

**执行路径**：IDA

**工具识别**：Base91变表(medium), Base64变表(medium), AES(high)

**AI 深挖耗时**：120.1s

**收工闸触发**：收敛×1

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[03:29:28][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\kanxue-ctf-gxustudent.exe_f2352aee/scripts/solve_enum_mve7yrbu.py
[03:29:28][验证闭环] 本地复现失败（1 个契约无命中）
[03:29:28][验证闭环] 已提取失败证据（将回灌给 AI）: 263 字符
[03:29:28][验证闭环] 已生成修正提示（673 字符），将随结果回传触发重试
[03:29:28][算法扫描] 注入深度求解提示：Base91变表, Base64变表, AES
[03:30:57][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[03:31:28][6/6] 检查是否产出已验证 flag 并提交平台...
[03:31:28][自动测试] 1/1 kanxue-ctf-gxustudent: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792351891267-9.log`</sub>

---

### ❌ QuiZow

**难度** Easy · **编号** PCHAL-2026-0616 · **载体** ZIP · **附件** `b33043fa-47df-479a-9e7d-87bf593520be.zip`（21.2 KB）

**解压内容**：CrackMe_QuiZow_20161227, QuiZow_CrackMe.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：221.5s

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[01:35:58][zip手包] 共 2 个文件: CrackMe_QuiZow_20161227, QuiZow_CrackMe.exe
[01:35:58][zip手包] 选定主文件: CrackMe_QuiZow_20161227
[01:35:58][zip手包] 同包伴生文件（已登记，AI 可 read_file）: QuiZow_CrackMe.exe
[01:36:03][算法扫描] (未发现算法指纹)(n/a)
[01:36:19][算法扫描] 注入深度求解提示：(未发现算法指纹)
[01:38:57][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[01:40:01][6/6] 检查是否产出已验证 flag 并提交平台...
[01:40:01][自动测试] 1/1 QuiZow: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792345202810-10.log`</sub>

---

### ❌ (unknown)

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[01:40:43][自动测试] 1/1 (unknown): 跳过（connect-failed）
```

</details>

<sub>日志：`run-1792345814728-11.log`</sub>

---

### ❌ CM

**难度** Easy · **编号** PCHAL-2026-0617 · **载体** ZIP · **附件** `1a44e66f-c8be-4f36-aa4f-2189069301bf.zip`（86.7 KB）

**解压内容**：CM.exe

**执行路径**：IDA

**工具识别**：Base91变表(medium)

**AI 深挖耗时**：151.3s

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[01:50:26][zip手包] 解压: E:\ctf\pratice\ai\CM\1a44e66f-c8be-4f36-aa4f-2189069301bf.zip
[01:50:27][zip手包] 共 1 个文件: CM.exe
[01:50:27][zip手包] 选定主文件: CM.exe
[01:50:32][算法扫描] Base91变表(medium)
[01:50:41][算法扫描] 注入深度求解提示：Base91变表
[01:52:06][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[01:53:12][6/6] 检查是否产出已验证 flag 并提交平台...
[01:53:12][自动测试] 1/1 CM: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792345993844-12.log`</sub>

---

### ❌ PeSafe

**难度** Easy · **编号** PCHAL-2026-0618 · **载体** ZIP · **附件** `28993fb7-13e4-4b56-adee-275a66631a7d.zip`（155.6 KB）

**解压内容**：crackme_pesafe.exe

**执行路径**：IDA

**工具识别**：Base91变表(medium)

**AI 深挖耗时**：344.8s

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[01:53:25][zip手包] 解压: E:\ctf\pratice\ai\PeSafe\28993fb7-13e4-4b56-adee-275a66631a7d.zip
[01:53:26][zip手包] 共 1 个文件: crackme_pesafe.exe
[01:53:26][zip手包] 选定主文件: crackme_pesafe.exe
[01:53:31][算法扫描] Base91变表(medium)
[01:53:40][算法扫描] 注入深度求解提示：Base91变表
[01:58:45][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[01:59:25][6/6] 检查是否产出已验证 flag 并提交平台...
[01:59:25][自动测试] 1/1 PeSafe: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792346371278-13.log`</sub>

---

### ❌ HellScream

**难度** Easy · **编号** PCHAL-2026-0619 · **载体** ZIP · **附件** `3cae5ddc-76cf-4629-b7f2-2fd17d44a32d.zip`（23.3 KB）

**解压内容**：BS272.exe, o.txt, out.txt, res.txt, in.txt, inp.txt, E0.txt, sub403E30.c, sub403E30.json

**执行路径**：IDA

**工具识别**：SHA256(medium)

**AI 深挖耗时**：108.6s

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[02:01:55][zip手包] 共 9 个文件: BS272.exe, o.txt, out.txt, res.txt, in.txt, inp.txt, E0.txt, sub403E30.c, sub403E30.json
[02:01:55][zip手包] 选定主文件: BS272.exe
[02:01:55][zip手包] 同包伴生文件（已登记，AI 可 read_file）: o.txt, out.txt, res.txt, in.txt, inp.txt, E0.txt, sub403E30.c, sub403E30.json
[02:02:05][算法扫描] SHA256(medium)
[02:02:19][算法扫描] 注入深度求解提示：SHA256
[02:03:37][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[02:04:08][6/6] 检查是否产出已验证 flag 并提交平台...
[02:04:08][自动测试] 1/1 HellScream: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792346651002-0.log`</sub>

---

### ❌ Youngter-drive

**难度** Easy · **编号** PCHAL-2026-0623 · **载体** ZIP · **附件** `7289daa8-a5d5-430e-87a0-92ce805d8f15.zip`（9.6 KB）

**解压内容**：Youngter-drive.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：272.5s

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[02:04:22][zip手包] 解压: E:\ctf\pratice\ai\Youngter-drive\7289daa8-a5d5-430e-87a0-92ce805d8f15.zip
[02:04:23][zip手包] 共 1 个文件: Youngter-drive.exe
[02:04:23][zip手包] 选定主文件: Youngter-drive.exe
[02:04:48][算法扫描] (未发现算法指纹)(n/a)
[02:04:57][算法扫描] 注入深度求解提示：(未发现算法指纹)
[02:08:35][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[02:09:30][6/6] 检查是否产出已验证 flag 并提交平台...
[02:09:30][自动测试] 1/1 Youngter-drive: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792346974388-1.log`</sub>

---

### ❌ reverse3

**难度** Easy · **编号** PCHAL-2026-0624 · **载体** ZIP · **附件** `a9d22a0e-928d-4bb4-8525-e38c9481469e.rar`（10.8 KB）

**解压内容**：reverse_3.exe

**执行路径**：IDA

**工具识别**：Base64(low)

**AI 深挖耗时**：16.6s

**本地验证**：检测到 1 个 [VERIFY] 契约；🔸 只命中中间值 `{i_l0ve_you}`；（已识别形态并给出下一步）

**证据回灌重试**：1 次

**结果**：🔸 只命中中间值 — 只命中中间值 {i_l0ve_you}

<details><summary>关键过程日志</summary>

```
[02:10:21][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[02:10:21][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\reverse_3.exe_b2666ae9/scripts/solve_enum_mve55140.py
[02:10:21][验证闭环] 本地复现通过（命中中间值/密钥，非 flag）：{i_l0ve_you}
[02:10:21][验证闭环] 已提取失败证据（将回灌给 AI）: 166 字符
[02:10:21][本地求解] 3 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\reverse_3.exe_b2666ae9/scripts/solve_enum_mve55179.py
[02:10:22][验证闭环] 命中中间值并识别类型 可打印明文，已生成定向下一步提示
[02:10:22][6/6] 检查是否产出已验证 flag 并提交平台...
[02:10:22][自动测试] 1/1 reverse3: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792347027143-2.log`</sub>

---

### ❌ firmware

**难度** Easy · **编号** PCHAL-2026-0625 · **载体** UNKNOWN · **附件** `51475f91-7b90-41dd-81a3-8b82df4f29d0.bin`（3968.5 KB）

**执行路径**：固件/Kali

**收工闸触发**：收敛×1

**结果**：⛔ 未产出契约 — 未产出 [VERIFY] 契约

<details><summary>关键过程日志</summary>

```
[02:10:39][5/6] 交给本地逆向流程解题: E:\ctf\pratice\ai\firmware\51475f91-7b90-41dd-81a3-8b82df4f29d0.bin
[02:15:10][Tool Use] 收敛催促：第 45 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]
[02:15:47][6/6] 检查是否产出已验证 flag 并提交平台...
[02:15:47][自动测试] 1/1 firmware: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792347350732-3.log`</sub>

---

### ❌ equation

**难度** Easy · **编号** PCHAL-2026-0626 · **载体** ZIP · **附件** `ea7c3b5c-a04d-48ca-a741-8715d31ff2b5.zip`（5.3 KB）

**解压内容**：equation.html

**执行路径**：Web/JS

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[02:20:32][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[02:20:32][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\equation.html_91d2845b/scripts/solve_enum_mve5i47l.py
[02:20:32][验证闭环] 本地复现失败（1 个契约无命中）
[02:20:32][验证闭环] 已提取失败证据（将回灌给 AI）: 125 字符
[02:20:32][本地求解] 3 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\equation.html_91d2845b/scripts/solve_enum_mve5i4ch.py
[02:20:32][验证闭环] 已生成修正提示（577 字符），将随结果回传触发重试
[02:20:32][6/6] 检查是否产出已验证 flag 并提交平台...
[02:20:32][自动测试] 1/1 equation: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792347633460-4.log`</sub>

---

### ❌ 新年快乐

**难度** Easy · **编号** PCHAL-2026-0627 · **载体** ZIP · **附件** `93c43c5c-3d4d-4d17-a9a1-4ffb65ebb2fb.zip`（9.2 KB）

**解压内容**：新年快乐.exe

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：86.1s

**本地验证**：检测到 1 个 [VERIFY] 契约；🔸 只命中中间值 `HappyNewYear!`；（已识别形态并给出下一步）

**证据回灌重试**：1 次

**结果**：🔸 只命中中间值 — 只命中中间值 HappyNewYear!

<details><summary>关键过程日志</summary>

```
[02:23:04][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[02:23:04][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\新年快乐.exe_3d633df1/scripts/solve_enum_mve5ldx5.py
[02:23:04][验证闭环] 本地复现通过（命中中间值/密钥，非 flag）：HappyNewYear!
[02:23:04][验证闭环] 已提取失败证据（将回灌给 AI）: 74 字符
[02:23:05][本地求解] 3 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\新年快乐.exe_3d633df1/scripts/solve_enum_mve5le0i.py
[02:23:05][验证闭环] 命中中间值并识别类型 可打印明文，已生成定向下一步提示
[02:23:05][6/6] 检查是否产出已验证 flag 并提交平台...
[02:23:05][自动测试] 1/1 新年快乐: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792347788434-5.log`</sub>

---

### ❌ 内涵的软件

**难度** Easy · **编号** PCHAL-2026-0628 · **载体** PE（Portable Executable） · **附件** `70125468-0786-4705-bd91-87037f8f3e16.exe`（180.1 KB）

**执行路径**：IDA

**工具识别**：(未发现算法指纹)(n/a)

**AI 深挖耗时**：33.3s

**本地验证**：检测到 1 个 [VERIFY] 契约；❌ 全部契约复现失败

**证据回灌重试**：1 次

**结果**：❌ 契约复现失败 — 1 个契约复现失败

<details><summary>关键过程日志</summary>

```
[02:24:13][重试] 追加一轮 AI（验证失败（附真实解密输出），强制基于证据修正）
[02:24:34][验证闭环] 检测到 1 个 [VERIFY] 契约，开始本地复现...
[02:24:34][本地求解] 1 个尝试 -> C:\Users\Administrator\Desktop\工具\ctf-tool-v2\cases\70125468-0786-4705-bd91-87037f8f3e16.exe_3c771401/scripts/solve_enum_mve5nasy.py
[02:24:34][验证闭环] 本地复现失败（1 个契约无命中）
[02:24:34][验证闭环] 已提取失败证据（将回灌给 AI）: 221 字符
[02:24:34][验证闭环] 已生成修正提示（670 字符），将随结果回传触发重试
[02:24:34][6/6] 检查是否产出已验证 flag 并提交平台...
[02:24:34][自动测试] 1/1 内涵的软件: 跳过（no-verified-flag）
```

</details>

<sub>日志：`run-1792347877383-6.log`</sub>

---
