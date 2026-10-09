# 从 native 常量反演密钥

> 适用：校验在 native（.so）里做，Java 层只看到 `native int[] encryptStage2(String)` 之类；
> 目标常量数组写死在 so 的 `.rodata` 或 smali 的 `const` 数组里，题目要你"反推输入"。
> 来源：某 APK native 校验题实战验证（包名与 so 名已脱敏）。

## 判断信号

- Java 层：`public final native int[] encryptStage2(String)`，返回值与一个 `int[16]` 常量比较（`Arrays.equals`）。
- 常量长这样（smali `K0/a.smali` 的 `fill-array-data`）：
  `[0xfa,0x71,0x57,0xb9,0x06,0x7d,0xa7,0x9c,0x04,0x00,0xe5,0xef,0x77,0x9b,0xbb,0x5f]`
- 结论：这是**可逆变换**——写正向、推逆向，反推出的字符串即为要求的 key。

## 逆向推导流程（每步都要双向自检）

1. **IDA 反编译** `Java_..._encryptStage2`，读出主循环。本例：
   ```
   v = ROL8( b ^ S ^ (13*i + 66), 3 ) + i + 7*S        (mod 256)
   S = S + b + (i ^ v)                                  (mod 256)   // S 初值 81
   ```
2. **写正向函数**，拿常量当 target 回车验；再**写逆向函数**，反推输入。
3. **必须正向复算校验**：把反推出 key 重新正向加密，确认与 target 常量**逐字节相等**，才能拿它去解下一关（否则就是猜）。

逆向（本例，逐字节依赖 S 的滚动状态）：

```python
M = 0xff
def forward(bs):
    S = 81; out = []
    for i, b in enumerate(bs):
        v = (( (b ^ S ^ ((13*i+66) & M)) << 3 | (b ^ S ^ ((13*i+66) & M)) >> 5 ) + i + 7*S) & M
        S = (S + b + (i ^ v)) & M
        out.append(v)
    return out

def inverse(target):
    S = 81; out = []
    for i, v in enumerate(target):
        t = (v - i - 7*S) & M
        x = ((t >> 3) | (t << 5)) & M          # ROR8 = 逆 ROL8
        b = (x ^ S ^ ((13*i+66) & M)) & M
        S = (S + b + (i ^ v)) & M              # S 用同一个 v（每步 v 已知）继续滚动
        out.append(b)
    return bytes(out)

TARGET = [0xfa,0x71,0x57,0xb9,0x06,0x7d,0xa7,0x9c,0x04,0x00,0xe5,0xef,0x77,0x9b,0xbb,0x5f]  # 题目常量（示意）
key = inverse(TARGET)
assert forward(list(key)) == TARGET            # 双向自检，必须过
print(key)                                     # b'<反演出的16字节key>'
```

## 要点

- **滚动状态（S）要按"每步实际的 v"推进**，不是按反推出的 b——顺序错了整串就废。
- **8 位截断**：`ROL8/ROR8`、加减法都要 `& 0xff`。C 里 `int` 运算若最后才截断，要注意中间是否溢出影响后续。
- **双向自检是硬门槛**：单向能过不代表对；`forward(inverse(target)) == target` 才算数。
- 反推出的字符串常直接就是下一关的密钥（本例 = Stage3 的 AES key）。

## 关联

- 拿它解密出 flag → `frida/in-process-decrypt.md`
- 常量怎么定位（smali/so） → `frida/android-multistage.md`

## 通用化提示

本类"native 字节变换 + 常量比较"极常见（TEA/XTEA/XXTEA、自定义 ROL/ROR、异或链）。
换题时改的只是三处：**每字节算式、状态更新式、S 初值**；正逆互校的框架不变。
