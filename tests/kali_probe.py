#!/usr/bin/env python3
"""Kali 动态调试连通性自检（独立脚本，不依赖工具运行）。

用途：解题前花 10 秒确认「远端能不能真的动调」，避免把预算烧在
"SSH 连不上 / ptrace 被禁 / 没有 gdb"这种环境问题上。

读取顺序与工具一致：%APPDATA%\\ctf-reverse-tool\\config.json 的 kali 段，
也可用环境变量 KALI_HOST/KALI_PORT/KALI_USER/KALI_PASS 覆盖。

用法：
    python tests/kali_probe.py            # 只读配置并体检
    python tests/kali_probe.py --json     # 机器可读输出
退出码：0 全部通过；1 有失败项；2 未配置或 SSH 不可达
"""
import os
import sys
import json
import socket
import subprocess

CONFIG_PATHS = [
    os.path.join(os.environ.get('APPDATA', ''), 'ctf-reverse-tool', 'config.json'),
    os.path.join(os.environ.get('APPDATA', ''), 'ctf-reverse-assistant', 'config.json'),
]

# 体检项：(名称, 远端命令, 判定关键字)
CHECKS = [
    ('arch',         'uname -m',                                    None),
    ('kernel',       'uname -r',                                    None),
    ('ptrace_scope', 'cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0', ('0', '1')),
    ('gdb',          'command -v gdb || echo MISSING',              'gdb'),
    ('gdbserver',    'command -v gdbserver || echo MISSING',        'gdbserver'),
    ('python3',      'python3 -V 2>&1 || echo MISSING',             'Python 3'),
    ('z3',           'python3 -c "import z3;print(z3.get_version_string())" 2>&1', None),
    ('capstone',     'python3 -c "import capstone;print(capstone.__version__)" 2>&1', None),
    ('unicorn',      'python3 -c "import unicorn;print(unicorn.__version__)" 2>&1', None),
    ('strace',       'command -v strace || echo MISSING',           'strace'),
    ('objdump',      'command -v objdump || echo MISSING',          'objdump'),
    ('gcc',          'command -v gcc || echo MISSING',              'gcc'),
    ('qemu-riscv32', 'command -v qemu-riscv32 || echo MISSING',     None),
]

# 明确标记失败特征：Traceback / ModuleNotFoundError 都算"没装上"
BAD_MARKERS = ('MISSING', 'EXC', 'Traceback', 'ModuleNotFoundError',
               'No module named', 'not found', 'Error')



def load_kali_config():
    host = os.environ.get('KALI_HOST')
    port = int(os.environ.get('KALI_PORT') or 22)
    user = os.environ.get('KALI_USER')
    pwd = os.environ.get('KALI_PASS')
    if host and user:
        return {'sshHost': host, 'sshPort': port, 'sshUser': user, 'sshPass': pwd}
    for p in CONFIG_PATHS:
        if not os.path.exists(p):
            continue
        try:
            cfg = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        k = cfg.get('kali') or {}
        if k.get('sshHost') and k.get('sshUser'):
            return k
    return None


def tcp_alive(host, port, timeout=3.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def main():
    as_json = '--json' in sys.argv
    k = load_kali_config()
    if not k:
        msg = '未配置 kali（config.json 的 kali.sshHost/sshUser 为空，或环境变量未设）'
        print(json.dumps({'ok': False, 'error': 'UNCONFIGURED', 'detail': msg}) if as_json else '[FAIL] ' + msg)
        return 2

    host, port = k['sshHost'], int(k.get('sshPort') or 22)
    if not tcp_alive(host, port):
        msg = f'SSH 端口不可达 {host}:{port}（虚拟机是否开机？IP 是否变化？）'
        print(json.dumps({'ok': False, 'error': 'REFUSED', 'detail': msg}) if as_json else '[FAIL] ' + msg)
        return 2

    try:
        import paramiko
    except ImportError:
        msg = '本机缺少 paramiko：pip install paramiko'
        print(json.dumps({'ok': False, 'error': 'NO_PARAMIKO', 'detail': msg}) if as_json else '[FAIL] ' + msg)
        return 1

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port=port, username=k['sshUser'],
                    password=k.get('sshPass'), timeout=15,
                    allow_agent=False, look_for_keys=False)
    except Exception as ex:
        msg = f'SSH 认证/握手失败：{type(ex).__name__}: {ex}'
        print(json.dumps({'ok': False, 'error': 'AUTH', 'detail': msg}) if as_json else '[FAIL] ' + msg)
        return 2

    results = []
    for name, cmd, expect in CHECKS:
        try:
            _, out, err = cli.exec_command(cmd, timeout=25)
            text = (out.read() + err.read()).decode(errors='replace').strip()
        except Exception as ex:
            text = f'EXC {ex}'
        text = text.split('\n')[0][:120]
        if expect is None:
            ok = not any(m in text for m in BAD_MARKERS)
        elif isinstance(expect, tuple):
            ok = text in expect
        else:
            ok = expect in text
        # 可选组件缺失只标记 WARN，不阻塞
        optional = name in ('gdbserver', 'unicorn', 'qemu-riscv32', 'strace', 'z3')
        results.append({'name': name, 'value': text, 'ok': ok, 'optional': optional})

    # 实测 ptrace：TRACEME + raise(SIGSTOP)（直接 CONT 会在 exec 前抢跑，
    # 实测会拿到 "No such process"；必须先等显式 SIGSTOP 再 CONT）
    pt_cmd = (
        "cat > /tmp/_pt_probe.c << 'EOF'\n"
        "#include <stdio.h>\n#include <unistd.h>\n#include <signal.h>\n"
        "#include <errno.h>\n#include <string.h>\n"
        "#include <sys/ptrace.h>\n#include <sys/wait.h>\n#include <sys/user.h>\n"
        "int main(void){pid_t p=fork();if(p==0){"
        "if(ptrace(PTRACE_TRACEME,0,0,0)!=0){perror(\"tm\");_exit(2);}"
        "raise(SIGSTOP);execl(\"/bin/true\",\"true\",(char*)0);_exit(3);}"
        "int st;if(waitpid(p,&st,0)<0){perror(\"w1\");return 1;}"
        "if(ptrace(PTRACE_CONT,p,0,0)!=0){perror(\"cont\");return 1;}"
        "if(waitpid(p,&st,0)<0){perror(\"w2\");return 1;}"
        "struct user_regs_struct r;"
        "if(ptrace(PTRACE_GETREGS,p,0,&r)==0)"
        "printf(\"PTRACE_OK %llx\\n\",(unsigned long long)r.rip);"
        "else printf(\"GETREGS_FAIL %s\\n\",strerror(errno));"
        "ptrace(PTRACE_DETACH,p,0,0);return 0;}\nEOF\n"
        "gcc -O2 -o /tmp/_pt_probe /tmp/_pt_probe.c 2>/dev/null && /tmp/_pt_probe || echo PTRACE_FAIL"
    )

    try:
        _, out, err = cli.exec_command(pt_cmd, timeout=60)
        pt = (out.read() + err.read()).decode(errors='replace').strip().split('\n')[-1][:120]
    except Exception as ex:
        pt = f'EXC {ex}'
    results.append({'name': 'ptrace_attach', 'value': pt, 'ok': 'PTRACE_OK' in pt, 'optional': False})

    cli.close()

    hard_fail = [r for r in results if not r['ok'] and not r['optional']]
    payload = {
        'ok': not hard_fail,
        'host': f'{k["sshUser"]}@{host}:{port}',
        'results': results,
        'failed': [r['name'] for r in hard_fail],
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f'Kali 自检 {k["sshUser"]}@{host}:{port}')
        for r in results:
            mark = 'OK  ' if r['ok'] else ('WARN' if r['optional'] else 'FAIL')
            print(f'  [{mark}] {r["name"]:14s} {r["value"]}')
        print('\n结论:', '可用' if payload['ok'] else '有阻塞项 -> ' + ', '.join(payload['failed']))
    return 0 if payload['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
