# 加密参数编码与 IV 长度坑

> 适用：契约/脚本里的 `key`、`iv`、`ciphertext` 编码不统一（hex / base64 / 明文混用），
> 导致解密报 `Incorrect IV length (16 required)`、`Incorrect padding`、或解出乱码。
> 来源：实战两次踩坑（Python 侧 `iv_bytes`、Hook 侧 `normalizeCrypto`）。

## 症状 → 根因

| 症状 | 根因 |
|---|---|
| `Incorrect IV length (16 required)` | IV 被按错误编码解：例如明文 `ExampleVector123`（16 字节）被当 base64 解出 12 字节 |
| `Incorrect padding` | key 或密文编码错（少解/多重解一层 base64） |
| 解出明文但乱码 | 用了错的编码组合（密文 base64 但按 hex 解） |

黄金案例：IV 常量藏在 SQLite 初始化里，是 **base64** `RXhhbXBsZVZlY3RvcjEyMw==`（= 明文 `ExampleVector123`）。
AI 契约里 `iv` 直接写了这个 base64 串；若实现里"借用 key 的编码"去解 IV，就会解错长度。

## 正确做法：IV/key 各用各的编码，且自适应

**Python（契约复现侧）**

```python
def iv_bytes(a):
    iv = a.get("iv", "")
    if not iv: return None
    if a.get("iv_encoding"):                    # 显式编码优先
        return to_bytes(iv, a["iv_encoding"])
    s = str(iv).strip()
    cands = []
    try: cands.append(s.encode("latin-1", "replace"))
    except: pass
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try: cands.append(bytes.fromhex(s))
        except: pass
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) and len(s) % 4 == 0:
        try: cands.append(base64.b64decode(s + "=" * (-len(s) % 4)))
        except: pass
    for c in cands:                             # 优先取 16 字节的
        if len(c) == 16: return c
    for c in cands:
        if len(c) in (8, 24, 32): return c
    return cands[0] if cands else None
```

**Hook（JS 侧）** 同理，把 key/iv 归一成"确定可用"的字节（本项目统一转 hex 注入）：

```javascript
function pick16(val, encHint){
  if (!val) return null;
  var s = String(val).trim(), cands = [];
  if (encHint === 'hex')    cands.push(hexToArr(s));
  if (encHint === 'base64') cands.push(b64ToArr(s));
  if (encHint === 'ascii')  cands.push(asciiToArr(s));
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) cands.push(hexToArr(s));
  cands.push(b64ToArr(s)); cands.push(asciiToArr(s));
  for (var i=0;i<cands.length;i++) if (cands[i] && cands[i].length === 16) return cands[i];  // 优先 16
  return cands[0] || null;
}
```

## 铁律

1. **IV 的编码独立于 key 的编码**——绝不能"沿用 key 的编码"。这是本题 `Incorrect IV length` 的直接原因。
2. **优先显式编码字段**（`iv_encoding` / `key_encoding`）；没有再做候选枚举。
3. **候选排序按长度**：AES 要 16 字节 IV；解出 16 的先选。
4. 约定统一后写进契约：[VERIFY] 里带上 `key_encoding`、`iv_encoding`、`encoding`，避免二义。

## 关联

- 契约怎么写 → `frida/in-process-decrypt.md`（工具侧收割）
- CTF 常见 key 形态多为可打印 ASCII → 默认 ascii，再枚举 hex/base64
