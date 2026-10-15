---
title: Excel 公式逆向（OOXML/表格计算型校验器）
category: reverse-method
vuln_type: excel-formula-verifier
difficulty: medium-hard
tags: [xlsx, OOXML, Excel公式, SUMPRODUCT, ReLU, 神经网络, 置换, sheet, 解压, ExceLLM, 公式数]
keywords: [xlsx逆向, Excel公式, OOXML解压, sheet隐藏, SUMPRODUCT, MAX(0)=ReLU, --(...)=布尔, workbook.xml, sharedStrings, 权重表, stride, 逐字符独立, 暴力枚举]
one_liner: xlsx/docx/pptx 本质是 ZIP 容器——解压后把 Excel 公式当代码读：SUMPRODUCT=矩阵乘、MAX(0,·)=ReLU、--(·>0)=阶跃，真逻辑常在隐藏 sheet；逐字符独立校验的题对每位暴力 32..126 枚举唯一命中。
attack_chain:
- 解压即逆向：xlsx/docx/pptx 是 ZIP，改后缀或按 PK 魔数直接解压；读 `xl/workbook.xml` 拿 sheet 清单（hidden 标记=真逻辑常藏身处），`xl/_rels/workbook.xml.rels` 对上 sheetN.xml 与名字
- 主文件挑选：真校验器 = 公式最多的 sheet（`<f>` 元素数），展示壳常只有 `IF(VERIFY!Z1=1,"Correct","Incorrect")` 一个公式；docProps（core/app/custom.xml）是元数据噪声
- 公式语义映射：`SUMPRODUCT(范围A,范围B)`=向量点积/矩阵乘；`MAX(0,x)`=ReLU；`--(表达式>0)`=布尔转整数/阶跃激活；`MOD(QUOTIENT(CODE(...),2^k),2)`=按位展开（MSB first）
- 数据流分诊：找到输入单元格（如 LLM!B2=flag 字符串）→ BITS（位展开）→ WEIGHTS（纯常量权重）→ VERIFY（约束汇总如 `--(SUM(27个H)=27)`）
- 权重表布局反推：列主序+每组固定 stride 行很常见（W1 8行/bias 8行/W2 8行/Hbias 1行 → stride=26）；**从 VERIFY 公式里的行号锚点差值反推 stride，别猜**
- 反演：逐字符独立校验（组间无耦合）→ 每位暴力枚举 32..126 可打印 ASCII，命中约束的唯一字符即答案；27 次独立枚举无需全局搜索
- 验证：拼出全文后前向复算（重放公式），约束全部满足（如 SUM=27）才算数
failed_attempts:
- 选了 241B 的 docProps/custom.xml 当主文件送进固件流程 → 元数据无逻辑，按公式数挑 sheet
- 展示壳 sheet1（1 公式）与真校验器 sheet4（244 公式）同级时误选前者 → 公式数是 sheet 间的主导判据
- 权重表 stride 猜 8/20 → 解集爆炸（每位置 0~95 个候选）就是 stride 错的信号；解集唯一 = stride 正确
- 只看一个 sheet 就下结论"信息不足" → BITS/WEIGHTS 在伴生 sheet 里，先读 workbook.xml.rels 把全部 sheet 找齐
- 模拟真实 Excel 运行 → 不需要：公式是纯函数，写 Python 复现前向计算即可
