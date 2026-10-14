---
id: forensics-linux-kernel
title: "Модуль: ядро Linux, модули и изоляция"
category: forensics
parent: forensics-linux-artifacts-advanced
difficulty: hard
order: 6
tags: [linux, kernel, modules, ebpf, initramfs, selinux, apparmor, forensics, roadmap]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ Linux-хостов"
estimated_minutes: 13
summary: "Этап ветки «Linux»: что происходит на уровне ядра — модули, eBPF, initramfs и мандатный контроль доступа."
---

Пользовательские артефакты рассказывают, что делал человек. Артефакты ядра
рассказывают, что делала **машина** — и именно туда прячется продвинутое вредоносное
ПО. Модуль про четыре слоя: загружаемые модули, трассировку eBPF, раннюю загрузку
через initramfs и мандатный доступ (SELinux/AppArmor).

## Что покрывает этот модуль

- **Модули ядра** — какие загружены, кто их подписал и что они прячут.
- **eBPF** — программы, живущие в ядре, и их следы.
- **initramfs** — что запускается до монтирования настоящего корня.
- **SELinux / AppArmor** — политики, отказы и их логи.

## Рекомендуемый порядок изучения

1. `linux-kernel-modules` — базовый уровень: `lsmod` и `/proc/modules`.
2. `linux-ebpf-forensics` — современный руткит-вектор через eBPF.
3. `linux-initramfs` — как малварь проникает раньше файловой системы.
4. `linux-selinux-apparmor` — почему злоумышленник отключает мандатный контроль.

## Что вы будете уметь

- Проверять загруженные модули и их подписи.
- Искать подозрительные eBPF-программы и их авторов.
- Разбирать initramfs-образы и находить внедрённый код.
- Читать отказы SELinux/AppArmor и понимать, что пытались сделать.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| `/proc/modules`, `lsmod` | какие модули загружены | `lsmod`, `modinfo` |
| `bpftool prog list` | что живёт в eBPF | `bpftool` |
| `/boot/initramfs-*.img` | что запускается раньше корня | `lsinitramfs` |
| `/var/log/audit/audit.log` | отказы SELinux | `ausearch` |

## Куда дальше

Открывай урок **«Модули ядра и руткиты»** — начнём с того, как вообще загружается
код в ядро.
