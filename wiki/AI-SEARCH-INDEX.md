# AI-SEARCH-INDEX — 逆向知识库全局检索索引

> **用途**：AI 收到逆向问题时，**先读本文件**定位资源，再按需 `wiki_search` / `wiki_read` 加载。
> **设计**：借鉴 Des-CTF-Knowledge 的「结构化索引 + 分段定位 + Payload 速查」范式，改造为**逆向专用**。
> 文章/工具/条目增删时同步更新本索引。

---

## 零、快速入口

| 我想要的 | 最快路径 |
|---------|---------|
| 具体 Payload/套路/脚本片段 | → [PAYLOAD-CHEATSHEET.md](PAYLOAD-CHEATSHEET.md)（直接翻对应章节） |
| 找相似题（历年大赛逆向） | → `wiki_search` 关键词，或看 [reverse/_INDEX.md](reverse/_INDEX.md) |
| 知道某类题怎么解 | → 读对应专项页（见下方「按技术标签检索」） |
| 环境/工具链故障 | → [frida/environment-troubleshooting.md](frida/environment-troubleshooting.md) |

---

## 一、按技术标签检索

### 算法识别 / 常量反演
- **知识**: [native-key-inversion.md](frida/native-key-inversion.md)（从 native 常量反演 key，正逆互校）
- **速查**: PAYLOAD-CHEATSHEET §算法特征
- **关键词**: `TEA` `0x9E3779B9` `RC4` `S盒` `AES` `XOR流` `查表` `循环移位` `ROL/ROR` `正逆互校`

### 动态取证 / Frida
- **知识**: [in-process-decrypt.md](frida/in-process-decrypt.md)（进程内解密出 flag）、[advanced-native-and-jce.md](frida/advanced-native-and-jce.md)（native四定位/RegisterNatives/JCE自吐/反检测）
- **技能**: `read_skill ctf-frida-dynamic`
- **关键词**: `hook` `RegisterNatives` `Cipher.init` `Cipher.doFinal` `native方法扫描` `进程内解密` `spawn/attach`

### 环境 / 工具链
- **知识**: [environment-troubleshooting.md](frida/environment-troubleshooting.md)（frida版本/双adb/装APK/IDA-JEB窗口/JEB连不上 一分钟自检）
- **关键词**: `frida-ps` `queryIntentActivities` `version match` `adb` `package服务` `Broken pipe`

### 多阶段 / 界面驱动
- **知识**: [android-multistage.md](frida/android-multistage.md)（多关 APK 停在首页的推进）
- **关键词**: `多阶段` `手势` `停首页` `SharedPreferences` `SQLite` `状态注入跳关` `driveAppIteratively`

### 编码 / 参数坑
- **知识**: [param-encoding.md](frida/param-encoding.md)（key/IV 编码、IV 长度坑）
- **关键词**: `IV长度` `Incorrect IV length` `base64` `hex` `乱码` `填充`

### 固件 / IoT
- **知识**: [firmware/unpack-and-emulate.md](firmware/unpack-and-emulate.md)
- **关键词**: `binwalk` `squashfs` `QEMU` `固件` `仿真`

### 反调试 / 反检测
- **知识**: [advanced-native-and-jce.md](frida/advanced-native-and-jce.md) §反检测绕过
- **关键词**: `反调试` `ptrace` `frida检测` `strstr` `pthread_create` `svc` `SSL pinning`

### 脱壳
- **知识**: [advanced-native-and-jce.md](frida/advanced-native-and-jce.md) §脱壳
- **关键词**: `脱壳` `DEX魔数` `dex\n035` `内存dump` `frida-dexdump` `UPX` `OEP`

### 运行型 / 公式型 / 短密文（CTF² 实战方法论）

- **运行型（伴生输出反演）**: [reverse/method_runtime_challenges.md](reverse/method_runtime_challenges.md)
- **并行扫描/置换网络**: [reverse/method_parallel_scan_inversion.md](reverse/method_parallel_scan_inversion.md)（Blelloch up/down-sweep 精确逆序、MPI 单位标签求置换）
- **Excel 公式校验器**: [reverse/method_excel_formula_verifier.md](reverse/method_excel_formula_verifier.md)（OOXML 解压、公式→ReLU/矩阵乘、stride 反推、逐字符枚举）
- **国密算法（SM2/SM3/SM4）**: [reverse/method_gm_crypto.md](reverse/method_gm_crypto.md)（10 秒分型看常量：SM4 S盒 0xD6 / SM3 IV 0x7380166f / SM2 ECC；对称解密·哈希爆破·nonce 复用三类打法）
- **短密文秒解/协议封装**: [reverse/method_short_ciphertext_triage.md](reverse/method_short_ciphertext_triage.md)（单字节全扫、前缀匹配、剥控制字符头）
- **关键词**: `运行型` `flag.out` `Blelloch` `up-sweep` `MPI` `单位标签` `xlsx` `SUMPRODUCT` `stride` `enc.txt` `协议头` `控制字符` `国密` `SM4` `SM3` `SM2` `gmssl`

### 历年大赛逆向题（结构化条目库）
- **库**: [reverse/_INDEX.md](reverse/_INDEX.md) — 每题含 `attack_chain`（解法步骤）、`reasoning_chain`（思维链）、`failed_attempts`（避坑）
- **关键词**: 见各条目 tags

---

## 二、按输入类型分流（对齐 ctf-dispatch）

| 输入 | 路径 |
|---|---|
| `.apk/.dex/.jar` | ctf-reverse-android 技能 + JEB MCP |
| `.exe/.dll/.so/.elf` | ctf-reverse-binary 技能 + IDA MCP |
| `.pyc/.pyo/PyInstaller` | ctf-reverse-langs §1 |
| `.luac/.wasm/.go/.rust` | ctf-reverse-langs |
| 固件/bin | ctf-iot-firmware |
| 逻辑读懂但手算不完 | ctf-reverse-tooling（Z3/angr/Unicorn）|

---

## 三、检索协议（给 AI）

1. **遇到逆向问题**：先看本索引的「技术标签」，定位到对应专项页 → `wiki_read` 读整页。
2. **需要具体套路/脚本**：`wiki_search "<关键词>"`；命中条目带 `reasoning_chain` / `attack_chain` 的优先读。
3. **找相似题**：`wiki_search` 用 题目特征词（算法名/混淆方式/工具）；条目库每题有 `one_liner` 一句话概括。
4. **本索引与条目库随解题持续更新**：解完题把新套路沉淀进 `PAYLOAD-CHEATSHEET` 或 `reverse/` 条目。
