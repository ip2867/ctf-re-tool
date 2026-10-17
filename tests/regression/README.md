# 回归题集（Regression Suite）

## 这是什么

`tests/regression/` 是**多题实测**的题集：单测只能证明"机制在合成样本上成立"，
而回归题集证明"在真实题目上不误报、不失效"。

每道题一个目录，含：

| 文件 | 入库 | 说明 |
|---|---|---|
| `expect.json` | ✅ | 预期链路（应命中什么、不得误报什么、耗时上限） |
| 题目二进制 | ❌ | 体积大且属第三方题目，**不入库**（`.gitignore` 已排除） |

## 为什么题目文件不入库

1. **体积**：13 道题约 1MB，随每次提交膨胀。
2. **版权**：题目二进制属于出题方/赛事。
3. **答案**：部分 `expect.json` 含答案哈希，配合二进制即可反推题解。

## 本地准备

把题目文件按各 `expect.json` 的 `main` 字段放到对应目录，例如：

```
tests/regression/
├── disguise-loader-xor-dword/
│   ├── expect.json
│   └── Disguise.exe          ← 手动放入（文件大小 464384 字节）
├── challenge-elf32/
│   ├── expect.json
│   └── Challenge             ← 手动放入
└── ...
```

放置后用 `node tests/run_regression.js` 验证；缺少题目的 case 会被跳过（不判失败）。

## 设计原则

- **只放原题**，不放解密后的中间产物（否则测的是"已知答案"而不是"自主解题"）。
- **正例与负例同等重要**：正例验证能力生效，负例验证不误伤。
  实测教训：首版扫描器把 11 道正常 ELF 全报成"内嵌 ELF"——正是负例断言抓住了这个缺陷。
- `expect.json` 中的答案一律用 **SHA256** 保存，避免仓库直接暴露题解。

## 当前覆盖

| Case | 类型 | 验证点 |
|---|---|---|
| disguise-loader-xor-dword | PE 多阶段 | 编码内嵌 PE 定位 + stage2 算法识别 |
| bankguardian-pe-algo | PE | 正常 PE 不误报"内嵌载荷" |
| challenge-elf32 | ELF32 | 标准 SM4 识别 |
| dock-check-elf64 | ELF64 | 零指纹时正确报"未发现" |
| obfuscat3-elf64 | ELF64 | 混淆题不误报 |
| missioncritical1-elf32 | ELF64 | 不误报 |
| parallelism-elf64 | ELF64 | 运行型题不误报 |
| not-baby-parallelism-elf64 | ELF64 | 运行型题不误报 |
| plutochat-elf64-pcap | ELF64 | 自定义分组密码识别 |
| romanromance-elf64 | ELF64 | 不误报 |
| time-travel-elf64 | ELF64 | 运行型题不误报 |
| palatinepack-elf32-zip | ELF64 | 标准 AES 识别 |
| excellm-xlsx | ZIP/XLSX | 非二进制优雅跳过 |
