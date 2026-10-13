# 逆向题：2024 盘古石晋级赛 IPA 和 APK 部分（iOS + Android 取证）

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：2024 盘古石晋级赛 2024 ｜ 难度：medium

```yaml
title: 2024 盘古石晋级赛 IPA 和 APK 部分（iOS + Android 取证）
contest: 2024 盘古石晋级赛
year: 2024
difficulty: medium
vuln_type:
- forensic_disk
- misc_unknown
tags:
- iOS IPA 毛雪柳手机取证
- iCost 记账 APP default.realm Realm 数据库
- Mattermost 内部 IM
- base.apk 伏季雅手机
- 威尼斯诈骗 APP
- w2a.W2Ah5.jsgjzfx.org.cn 包名
- __W2A__h5.jsgjzfx.org.cn 打包 ID
- io.dcloud.PandoraEntry 启动项
- 雷电 APP 智能分析
- app.db Mattermost
attack_chain:
- '毛雪柳 iOS: iCost 记账 APP Documents/default.realm → realm 数据库'
- 2 月收入 9600+2357=11957 元
- Mattermost IM 共享目录 /private/var/mobile/Containers/Shared/AppGroup/BBE0D501-AB0B-422E-9B4D-02E2D86130D4
- gxyt 老板 user_id=enf863dp1ifi3ffos7bpduynny + gxyt@163.com
- 私聊频道 "发财" 加入时间 1713931168391 → 2024-04-24-11-59-28
- 老板最后发送时间 1714011890182 → 2024-04-25-10-24-50
- '伏季雅 Android: 诈骗 APP 威尼斯，包名 w2a.W2Ah5.jsgjzfx.org.cn'
- 服务器 192.168.137.125 + 打包 ID __W2A__h5.jsgjzfx.org.cn + 启动 io.dcloud.PandoraEntry
- 义言手机 Mattermost app.db 服务器 192.168.137.97
- 数据库名 aHR0cDovLzE5Mi4xNjguMTM3Ljk3OjgwNjU=.db
key_payload: iCost APP default.realm + realm studio 2 月 type=1 收入 11957
one_liner: 盘古石晋级赛：iOS 毛雪柳记账 iCost+ Mattermost + Android 伏季雅威尼斯诈骗 APP + 义言 Mattermost 多检材协同；雷电 APP 智能分析一键导出 base.apk 元数据。
lesson: iOS 取证从 iTunes 备份 + 雷电 APP 分析 + realm studio 看 realm 数据库是 2024 主流流程；Mattermost 数据库名 = base64(URL).db 是反取证隐藏套路；雷电模拟器自带 APP 智能分析比 jadx 快很多。
quality: high
full_path: 2024盘古石晋级赛IPA和apk部分.full.md
meta_path: 2024盘古石晋级赛IPA和apk部分.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: '2024 盘古石晋级赛 IPA 和 APK 部分（iOS + Android 取证）。盘古石晋级赛：iOS 毛雪柳记账 iCost+ Mattermost + Android 伏季雅威尼斯诈骗 APP + 义言 Mattermost 多检材协同；雷电 APP 智能分析一键导出 base.apk 元数据。。关键路径：毛雪柳 iOS: iCost 记账 APP Documents/default...'
category: forensic
subcategory: disk_forensics
subcategories:
- disk_forensics
- misc_other
time_required: medium
difficulty_score: 3
code_blocks_count: 0
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/183403.html
reasoning_chain:
- 触发点：毛雪柳手机 iCost 记账 APP → 假设：realm 数据库存账目 → 动作：找 Documents/default.realm
- 动作：realm studio 打开 → 筛选 type=1 收入 + 2 月时间范围 → 观察：2 条 9600+2357=11957
- 动作：拿到 flag2 11957
- 触发点：Mattermost IM 内部聊天 → 假设：shared AppGroup 目录 → 动作：/private/var/mobile/Containers/Shared/AppGroup/BBE0D501-AB0B-422E-9B4D-02E2D86130D4
- 动作：分析 chat 记录 → 观察：老板 user_id=enf863dp1ifi3ffos7bpduynny → email=gxyt@163.com → flag3
- 动作：私聊频道 '发财' 加入时间 1713931168391 → 转 2024-04-24-11-59-28 → flag4
- 动作：老板最后发送时间 1714011890182 → 2024-04-25-10-24-50 → flag5
- 触发点：伏季雅 Android 威尼斯诈骗 APP → 假设：包名 w2a.W2Ah5.jsgjzfx.org.cn → 动作：雷电 APP 智能分析
- 观察：服务器 192.168.137.125 + 打包 ID __W2A__h5.jsgjzfx.org.cn + 启动 io.dcloud.PandoraEntry → flag6
- 触发点：义言手机 Mattermost app.db → 假设：服务器 192.168.137.97 → 动作：db 名 aHR0cDovLzE5Mi4xNjguMTM3Ljk3OjgwNjU=.db
- 动作：base64 解 → http://192.168.137.97:8065 → flag
failed_attempts:
- 试图直接 sqlite3 读 default.realm → 失败：realm 是自定义格式必须 realm studio
- 试图不在 Mattermost 数据库中查 gxyt → 失败：必须看 chat 频道记录
- 试图不打 1713931168391 时间戳转换 → 失败：unix ms 必须转北京时间
key_observations:
- iOS 取证从 iTunes 备份 + 雷电 APP 分析 + realm studio 看 realm 数据库是 2024 主流流程
- Mattermost 数据库名 = base64(URL).db 是反取证隐藏套路
- 雷电模拟器自带 APP 智能分析比 jadx 快很多
- unix 时间戳（毫秒）转北京时间是取证必会技能
prerequisites:
- realm studio 数据库查看
- 雷电 APP 智能分析 Android APK 元数据
- Mattermost 数据库结构 + Chat 频道解析
- iOS / Android 取证基础（备份 / 数据导出）
```
