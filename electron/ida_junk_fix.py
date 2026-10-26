"""IDA 内花指令边界修复（del_items + create_insn + define_func）

用法（通过 ida-pro-mcp 的 py_eval / py_exec_file 执行）：
    fix_junk_align(0x2620, 0x11322)          # 自动找未对齐跳转目标并修复
    fix_junk_all(0x2620, 0x11322)            # 迭代到收敛 + 重建函数

原理：
  花指令让反汇编器把垃圾字节当成指令操作数 → 指令边界整体错位。
  而"跳转目标必须是指令起点"是硬约束（否则程序跑不起来）。
  所以扫描所有跳转，若目标处不是 is_code（或落在别的指令内部）：
     1) ida_bytes.del_items(target, DELIT_SIMPLE, N)  ← 先破坏错误边界
     2) ida_ua.create_insn(target)                    ← 再强制 MakeCode
     3) 沿新指令顺延，继续修复后续未对齐目标
  迭代直到没有新的未对齐目标，最后 auto_wait + 重建函数边界。

注意：
  - 必须 del_items 在前：create_insn 无法在"已有指令内部"创建新指令（会 Failed to create instruction）
  - 只处理"目标落在非 code 区域"的情况；目标落在另一条指令**内部**时，需先 undefine 那条指令
"""
import ida_bytes
import ida_ua
import ida_funcs
import ida_auto
import idc


def _is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_flags(ea))


def _head(ea):
    return idc.get_item_head(ea)


def make_code_at(ea, max_chain=64):
    """在 ea 处强制建立指令；若 ea 落在别的指令内部，先破坏那条指令。返回 (made, log)。"""
    log = []
    made = 0
    cur = ea
    for _ in range(max_chain):
        if cur == idc.BADADDR:
            break
        if _is_code(cur):
            log.append('%s already code' % hex(cur))
            break
        h = _head(cur)
        if h != cur and h != idc.BADADDR:
            # ea 落在从 h 开始的指令/数据内部 → 先把 h 到 cur 这段 undefine
            span = cur - h + 16
            ida_bytes.del_items(h, ida_bytes.DELIT_SIMPLE, span)
            log.append('del_items(%s, %d) [was covering %s]' % (hex(h), span, hex(cur)))
            cur = h
        ok = ida_ua.create_insn(cur)
        if not ok:
            log.append('create_insn(%s) FAIL' % hex(cur))
            break
        sz = idc.get_item_size(cur)
        made += 1
        log.append('%s -> %d bytes' % (hex(cur), sz))
        cur += sz
    return made, log


def collect_jump_targets(start, end):
    """收集代码区内所有跳转/调用的目标地址。"""
    t = set()
    ea = start
    while ea < end and ea != idc.BADADDR:
        if _is_code(ea):
            m = idc.print_insn_mnem(ea)
            if m and (m.startswith('j') or m == 'call' or m.startswith('loop')):
                v = idc.get_operand_value(ea, 0)
                if v != idc.BADADDR and start <= v < end:
                    t.add(v)
            n = idc.get_item_size(ea)
            ea += n if n > 0 else 1
        else:
            ea += 1
    return t


def find_unaligned(start, end):
    """返回所有"跳转目标处不是指令起点"的地址。"""
    bad = []
    for t in sorted(collect_jump_targets(start, end)):
        if not _is_code(t):
            bad.append(t)
        else:
            h = _head(t)
            if h != t:
                bad.append(t)   # 落在别的指令内部
    return bad


def fix_junk_align(start, end, max_rounds=8, verbose=True):
    """迭代修复，返回统计。"""
    total = 0
    rpt = []
    for rnd in range(1, max_rounds + 1):
        bad = find_unaligned(start, end)
        if not bad:
            rpt.append('round %d: 无未对齐目标，收敛' % rnd)
            break
        made_this = 0
        for t in bad:
            n, _log = make_code_at(t)
            made_this += n
        rpt.append('round %d: %d 个未对齐目标 → 新建 %d 条指令' % (rnd, len(bad), made_this))
        total += made_this
        if made_this == 0:
            rpt.append('  无法继续')
            break
    if verbose:
        print('\n'.join(rpt))
    return {'made': total, 'report': rpt}


def rebuild_funcs(start, end):
    """删除并重建所有落在代码区内的函数（强制 IDA 重算边界）。"""
    res = []
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if f and start <= f.start_ea < end:
            fs = f.start_ea
            ida_funcs.del_func(fs)
            ok = ida_funcs.add_func(fs)
            res.append((hex(fs), bool(ok)))
    return res


def coverage(start, end):
    c = 0
    ea = start
    while ea < end:
        if _is_code(ea):
            c += 1
            n = idc.get_item_size(ea)
            ea += n if n > 0 else 1
        else:
            ea += 1
    return {'code_items': c, 'total': end - start, 'pct': round(c * 100.0 / (end - start), 1)}


def fix_junk_all(start, end):
    """完整流程：对齐 → auto_wait → 重建函数 → 再统计。"""
    before = coverage(start, end)
    r = fix_junk_align(start, end)
    ida_auto.auto_wait()
    funcs = rebuild_funcs(start, end)
    ida_auto.auto_wait()
    after = coverage(start, end)
    print('BEFORE %s' % before)
    print('AFTER  %s' % after)
    print('REBUILT %d funcs' % len(funcs))
    return {'before': before, 'after': after, 'fix': r, 'funcs': funcs}
