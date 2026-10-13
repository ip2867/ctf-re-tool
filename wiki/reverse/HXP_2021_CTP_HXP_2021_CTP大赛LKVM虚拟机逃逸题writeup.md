# 逆向题：HXP 2021 CTP大赛LKVM虚拟机逃逸题writeup

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：HXP 2021 CTP 2021 ｜ 难度：hard

```yaml
title: HXP 2021 CTP大赛LKVM虚拟机逃逸题writeup
contest: HXP 2021 CTP
year: 2021
difficulty: hard
vuln_type: web_unknown
tags:
- pwn
- lkvm
- kvmtool
- virtio
- oob-read-write
- rop
- jop
- hypervisor-escape
- cve-2021-45464
attack_chain:
- '攻击面: virtio-console/net/balloon 0xD2000000-0xD20000FF MMIO'
- 越界读/写：config结构体后0x100字节
- 信息泄露：bln_dev指针+lkvm基址
- '控制RIP: exit_lists数组指针覆盖'
- virtio_pci__data_out VIRTIO_PCI_QUEUE_PFN调用init_vq
- vq=0x16 让bdev->vqs[0x16]指向exit_lists
- echo c > /proc/sysrq-trigger 触发内核崩溃调用退出处理
- t->init(kvm) 跳到ROP/JOP链
- '伪init_item: 0x41填充'
- 'ret gadget: virtio_net_exec_script'
- 跳到 mov rax,[rbx+0x28]; mov rdi,rbx; ...
- 最终execl("/bin/sh", "", null) 宿主机shell
key_payload: bdev->vqs[0x16] = exit_lists指针 + echo c > /proc/sysrq-trigger
one_liner: HXP 2021 LKVM虚拟化逃逸：virtio OOB读写+JOP+execl宿主shell
lesson: lkvm exit_lists可被OOB覆盖+内核崩溃触发宿主RCE
quality: high
full_path: HXP_2021_CTP大赛LKVM虚拟机逃逸题writeup.full.md
meta_path: HXP_2021_CTP大赛LKVM虚拟机逃逸题writeup.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 'HXP 2021 CTP大赛LKVM虚拟机逃逸题writeup。HXP 2021 LKVM虚拟化逃逸：virtio OOB读写+JOP+execl宿主shell。关键路径：攻击面: virtio-console/net/balloon 0xD2000000-0xD20000FF MMIO → 越界读/写：config结构体后0x100字节 → 信息泄露：bln_dev指针+lkvm基址。经验...'
category: web
subcategory: web_other
time_required: long
difficulty_score: 4
code_blocks_count: 0
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/24005.html
reasoning_chain:
- 触发点：lkvm 暴露 0xD2000000-0xD20000FF MMIO 区域是 virtio-console/net/balloon 三设备共享区 → 假设：virtio_pci__data_in 在 config_offset=-20 时无边界检查，可 OOB 读写
- 动作：读 offset > sizeof(virtio_balloon_config) → 观察：拿到 bln_dev 指针 + lkvm 基址 → 下一步：信息泄露
- 假设：virtio_pci__data_out 中 VIRTIO_PCI_QUEUE_PFN 子句调用 init_vq(vq)，而 vq 无范围检查 → 动作：设 vq=0x16 让 bdev->vqs[0x16] = exit_lists 指针
- 下一步：触发 lkvm 退出处理函数 t->init(kvm) → 动作：echo c > /proc/sysrq-trigger 内核崩溃触发 exit_lists 遍历
- 假设：exit_lists 是 init_item 链表，每个 t->init 偏移 +0x18 是函数指针 → 动作：伪 init_item 用 0x41 填充 + 控制 rdi
- 下一步：ret gadget virtio_net_exec_script（mov rax,[rbx+0x28]; mov rdi,rbx; call [rax]）→ 动作：JOP 链 execl("/bin/sh", "", null) → 观察：弹宿主机 shell
failed_attempts:
- 试图直接 mmap 覆盖 exit_lists → 失败：bdev->vqs 数组本身不可写，只能通过 virtio_pci__data_out 间接注入
- 试图用 ROP gadget chain 完整劫持 RIP → 失败：lkvm 没暴露传统栈溢出，必须走 JOP
key_observations:
- lkvm 的 virtio PCI config 访问 config_offset = -20 是关键 OOB 漏洞（CVE-2021-45464）
- bdev->vqs[vq] 中 vq 无边界检查是 OOB 写指针的入口，配合 exit_lists 形成 RIP 劫持
- echo c > /proc/sysrq-trigger 触发内核崩溃会调 lkvm 退出 handler，是 escape 触发器
- JOP (Jump Oriented Programming) 在 hypervisor 逃逸中比 ROP 更常见，因为栈空间受限
prerequisites:
- lkvm/kvmtool 源码（virtio/balloon.c + pci.c）
- virtio 协议规范（PCI bar / MMIO config / queue）
- JOP gadget 链构造（rax/rdi 寄存器控制）
- CVE 申请流程与 kernel panic 调试
```
