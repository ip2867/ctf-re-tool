---
name: ctf-crypto-identify
description: 通过常量/结构特征识别加密算法，并给出对应的还原策略与解密脚手架。反编译代码中出现魔数、S盒、轮循环时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# 加密算法识别与还原

## 特征速查表

| 特征 | 算法 | 还原要点 |
|---|---|---|
| `0x9E3779B9` | TEA/XTEA/XXTEA | 看 32 轮循环 + 移位数：`<<4 >>5`=TEA；`<<4 >>5`+key数组轮换=XTEA；按块遍历+奇偶配对=XXTEA |
| S盒 `63 7C 77 7B F2 6B 6F C5` | AES | 找密钥扩展(KeyExpansion)确认 key 长度 16/24/32；ECB/CBC 看 IV |
| S盒 `D6 90 E9 FE CC E1 3D B7` | SM4 | 32轮非平衡Feistel结构+线性变换L；gmssl 库直接解（ECB/CBC） |
| 常量 `a3b1bac6 56aa3350 677d9197 b27022dc`（FK） | SM4（铁证） | 系统参数 FK 出现在二进制即为 SM4；轮常数 CK 表同理 |
| 摘要 IV 以 `0x7380166f` 开头 + 64 轮 | SM3 | **哈希不是加密**：`SM3(输入)==常量`→爆破；逐字节比较→截断逆推；`SM3(key\|\|msg)`→长度扩展攻击 |
| 256 位曲线参数 + 大数模运算 + 签名 | SM2 | ECC 公钥类：考点在 nonce 复用（`d=(z1-z2)/(s1-s2)`）/弱随机/曲线参数未校验，不是破曲线 |
| `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476` | MD5 | 不可逆，只能碰撞/查表；若比较"MD5(输入)==常量"则爆破或逐字节截断比较可逆推 |
| `0x6A09E667 0xBB67AE85` | SHA256 | 同上 |
| `0xEDB88320` | CRC32 | 碰撞爆破（短 flag 可行）；注意自定义初值/异或值 |
| 256字节 S盒初始化循环 + i/j 双索引 | RC4 | KSA+PRGA；注意变体：drop-N、密钥调度改、状态大小 |
| 8 字节块 + 16 轮 Feistel | DES | key 8字节；ECB/CBC |
| `0x428A2F98` | SHA-256 常量（区分用） | |
| base64 表被改 | 自定义码表 Base64 | 从代码提取码表，translate 回标准表 |
| 逐字节 XOR + 固定 key | XOR | key 长度=密文周期；已知明文首部(如"flag{")可直接推 key |
| `0x61C88647` / `0x9E3779B9` 累减 | TEA 变体(delta取反) | 注意 delta 有时是 `-0x61C88647` |

## 还原策略（按信息量）

1. **算法+密钥+密文齐全** → 直接写解密脚本，输出 `[VERIFY]` 供工具复现
2. **算法知道，密钥未知但运行时可取** → 输出 Frida Hook 方案，动态拿 key
3. **自定义算法** → 逐轮还原：先看输入输出长度，再逆数据流；复杂轮函数用 Z3 约束求解（约束=比较逻辑）
4. **哈希比较** → 判断可否截断比较逐字节爆破；否则字典/规则爆破（rockyou + 变形规则）

## 字节序陷阱

- TEA 系列在 C 里常用 `uint32_t` 直接操作 → x86 小端；Python 用 `struct.pack('<I')` 还是 `'>I'` 必须与原实现一致
- AES 的 state matrix 列优先 vs 行优先
- 密钥 "1234567812345678" 是 ASCII 16 字节 ≠ hex 解码的 8 字节——分清 `key.encode()` 与 `bytes.fromhex(key)`

## 输出契约

识别完成后输出（供工具本地枚举）：
```
[HYPOTHESES][
 {"algo":"tea","key":"<hex或ascii>","ciphertext":"<hex>","encoding":"hex","variant":"le32"},
 {"algo":"xxtea","key":"...","ciphertext":"...","encoding":"hex","variant":"be32"}
][/HYPOTHESES]
```
支持 algo：tea/xtea/xxtea/rc4/xor/aes_ecb/aes_cbc/des_ecb/des_cbc/des3_ecb/sm4_ecb/sm4_cbc/sm3/chacha20/salsa20/base64/base64_custom/custom。
国密提示：SM4 先试 `sm4_ecb` 再试 `sm4_cbc`（附 `iv`+`iv_encoding`）；S 盒被改的变体 gmssl 解不出，需按 32 轮手写。
SM3 是哈希（不可逆），`algo:"sm3"` 仅用于"SM3(候选)==目标"的对比，不产出明文。
完整国密方法（SM2/SM3/SM4 分型与打法）见知识库 `wiki/reverse/method_gm_crypto.md`。
注意：crc32 碰撞不适合放进 HYPOTHESES（自动求解窗口 30 秒跑不完），按需单独给完整碰撞脚本；custom 需附 `code` 字段（完整 Python `def decrypt(data,key)`）。
