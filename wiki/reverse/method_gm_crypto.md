---
title: 国密算法（SM2/SM3/SM4）逆向解题方法论
category: reverse-method
vuln_type: gm-crypto
difficulty: medium-hard
tags: [国密, SM4, SM3, SM2, gmssl, S盒, Feistel, 哈希, ECC, 椭圆曲线, 特征识别]
keywords: [国密, SM4, SM3, SM2, gmssl, 0xD6,0x90,0xE9, SM4 S盒, 32轮, 非平衡Feistel, 线性变换L, SM3 IV, 7380166f, 椭圆曲线, ECC, 签名伪造, 长度扩展]
one_liner: 国密三件套分工完全不同——SM4 是对称分组密码（32轮非平衡Feistel+线性变换L，S盒特征 0xD6,0x90,0xE9），SM3 是哈希（IV 0x7380166f 开头，打法同 SHA 系：爆破/长度扩展/截断比较），SM2 是椭圆曲线公钥（打法同 ECDSA：nonce 复用/弱随机数/曲线参数异常）。
attack_chain:
- 分型先看 S 盒/常量：8字节S盒以 D6 90 E9 FE CC E1 3D B7 开头 → SM4；摘要 IV 以 0x7380166f 开头、8 字节块 + 64 轮 → SM3；大整数模运算 + 256 位曲线参数 → SM2
- SM4 解密（对称，最常考）：key/iv 均 16 字节，直接 gmssl 解：`from gmssl.sm4 import CryptSM4, SM4_DECRYPT; c=CryptSM4(); c.set_key(key, SM4_DECRYPT); c.crypt_ecb(data)` 或 `crypt_cbc(iv, data)`；先试 ECB 再试 CBC
- SM4 变体识别：S 盒被改（自定义置换）→ 无法直接 gmssl 解，需按"32 轮 + T 变换"手写或用标准 S 盒替换后对比；轮密钥顺序反了也是常见变体（先试逆序轮密钥）
- SM3 打法（哈希类，与 SHA 相同套路）：①若是"SM3(输入)==常量"→ 短输入爆破/字典；②若逐字节比较 → 可截断比较逐字节逆推；③若 MAC 用 SM3 且长度可控 → 长度扩展攻击（SM3 的 Merkle–Damgård 结构与 SHA256 同，扩展方式一致）
- SM2 打法（ECC 类）：等价 ECDSA 攻击面——nonce 复用（两组签名解出私钥 d = (z1-z2)/(s1-s2)）、nonce 弱随机（k 范围小则爆破）、签名验证曲线参数被替换（无效曲线攻击）
- 找不到 gmssl 时降级：SM4 的黄金特征就是 S 盒第 1 字节 0xD6，用它搜二进制定位算法与轮常数 0x00070e15 等
failed_attempts:
- 把 SM4 当 AES 解（都 16 字节 key/block，但 S 盒与结构完全不同）→ 必须确认 S 盒首字节是 0xD6 才能判 SM4，AES 首字节是 0x63
- SM3 只当"识别关键词"没给打法 → SM3 是哈希，不能"解密"，要按哈希类思路（爆破/长度扩展/截断比较）
- 见到椭圆曲线就放弃 → SM2 的 CTF 考点几乎全在签名/nonce 侧信道（复用、弱随机），不是破 ECC 本身
- gmssl 未装时直接卡死 → 先 pip install gmssl；装不上的环境按 32 轮 Feistel 手写 SM4（S 盒+轮函数已确定）
- 忽略国密的"国标常量"：SM4 系统参数 FK={0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc}、CK 固定表、SM3 IV 固定——这些常量出现在二进制里就是国密的铁证
---

# 国密算法（SM2 / SM3 / SM4）逆向解题方法论

> 国密三件套在 CTF 逆向里**分型完全不同**，判错类型 = 全盘错。先花 10 秒确认是哪一个，再选打法。

## 一、10 秒分型（看常量，不看名字）

| 特征 | 判定 | 打法类型 |
|---|---|---|
| 8 字节 S 盒，首 8 字节 `D6 90 E9 FE CC E1 3D B7` | **SM4** | 对称解密（gmssl） |
| 常量 `0xa3b1bac6 0x56aa3350 0x677d9197 0xb27022dc`（FK） | **SM4** | 同上（铁证） |
| 摘要 IV 以 `0x7380166f` 开头，64 字节块、64 轮 | **SM3** | 哈希类（爆破/长度扩展） |
| 大整数模运算 + 256 位曲线参数（`FFFFFFFE FFFFFFFF ...` SM2 推荐曲线） | **SM2** | ECC 公钥类 |

## 二、SM4（最常考）——对称分组密码

**结构**：128 位分组、128 位密钥、**32 轮非平衡 Feistel** + 线性变换 L。与 AES 同是 16 字节块，但 S 盒/结构完全不同。

**标准解法（gmssl 一行）**：

```python
from gmssl.sm4 import CryptSM4, SM4_DECRYPT
c = CryptSM4(); c.set_key(key16, SM4_DECRYPT)
pt = c.crypt_ecb(ct)          # ECB
pt = c.crypt_cbc(iv16, ct)    # CBC（iv 16 字节）
```

**顺序**：先 ECB 再 CBC；key 试 ascii / hex 两种编码；CBC 的 iv 试"独立给出 / 全零 / 密文首块"。

**变体（注意）**：
- **S 盒被换** → gmssl 直接解会得到垃圾；需按 32 轮 T 变换手写，或把自定义 S 盒代入标准轮函数。
- **轮密钥逆序** → 解出乱码，试 `rk[::-1]`。
- **加白化/额外异或** → 对比标准实现定位差异（SM4 无白化，出现即变体）。

## 三、SM3——哈希，不是加密

**结构**：256 位摘要、512 位分组、64 轮，Merkle–Damgård（与 SHA-256 同架构）。IV = `7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e`。

**打法（与 SHA 系完全相同）**：
1. `SM3(输入) == 常量` → 短输入爆破/字典（CTF 里输入通常很短）。
2. **逐字节比较** → 截断比较可逐字节逆推。
3. **MAC = SM3(key || msg) 且 msg 长度可控** → **长度扩展攻击**（Merkle–Damgård 结构，扩展法与 SHA-256 一致：伪造 padding 后继续压缩）。
4. 哈希取模/截断后比较 → 爆破到碰撞。

## 四、SM2——椭圆曲线公钥

**结构**：基于 256 位素域推荐的椭圆曲线，签名算法类 ECDSA。

**CTF 考点（不是破 ECC 本身，而是实现缺陷）**：
- **nonce（k）复用**：两条签名用同一 k → `d = (z1 - z2) / (s1 - s2) mod n`（最常考）。
- **nonce 弱随机/范围小** → 爆破 k 或格攻击。
- **曲线参数被替换/未校验** → 无效曲线攻击（small subgroup）。
- **验证方漏检某字段** → 伪造签名绕过。

## 五、环境与降级

- Python：`pip install gmssl`（已验证本机 Python312 已装）。
- 工具验证契约：`{"algo":"sm4_ecb", ...}`（已支持）；CBC 附 `"iv"`+`"iv_encoding"`。
- gmssl 不可用时按"32 轮 + S 盒 + 线性变换 L"手写 SM4——S 盒与轮常数已由标准固定，手写无歧义。

## 六、快速核对清单

- [ ] S 盒首字节是 0xD6（SM4）还是 0x63（AES）？
- [ ] 摘要 IV 是否以 0x7380166f 开头（SM3）？
- [ ] 是否有 ECC 曲线参数与签名运算（SM2）？
- [ ] SM4：ECB/CBC 都试了吗？key 的 hex/ascii 两种编码试了吗？
- [ ] SM3：按哈希打（爆破/长度扩展），没试过"解密"吧？
- [ ] SM2：先找 nonce 复用/弱随机，别一上来就想破曲线。
