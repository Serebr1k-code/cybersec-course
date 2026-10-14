---
id: forensics-storage-layers
title: "Модуль: слои хранения и виртуальные диски"
category: forensics
parent: forensics-img-acquisition
difficulty: hard
order: 4
tags: [lvm, raid, vmdk, qcow2, write-blocker, roadmap]
prerequisites: [forensics-img-acquisition]
useful_for:
  - "CTF Forensics категория"
  - "Анализ виртуальных машин"
  - "Работа с серверными томами"
estimated_minutes: 14
summary: "Этап ветки «Съём образов»: слои абстракции между железом и ФС — LVM, RAID-метаданные, форматы виртуальных дисков и аппаратные write blockers."
lab:
  kind: shell
  title: "Практика: снять слои хранения (LVM и QCOW2)"
  toolset: [core, hex, lvm]
  workdir: /home/student/task
  files: [task.md, notes.txt, pv.img, vm.qcow2]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Посмотри sector 1 образа: `xxd -s 512 -l 32 pv.img` — ищи `LABELONE` и `LVM2 001`."
    - "Разбери Physical Volume: `pvscan pv.img` и `pvs pv.img`."
    - "Найди текстовые метаданные LVM (имена VG/LV): `strings pv.img | grep nto{`."
    - "Второй слой — виртуальный диск: `xxd -l 16 vm.qcow2` (магия QFI) и `qemu-img info vm.qcow2`."
---

Прежде чем монтировать ФС, часто приходится снимать **слои абстракции**: LVM между разделом и томом, RAID-метаданные между дисками, формат виртуального диска между гипервизором и гостевым диском. Этот модуль — про эти слои и про корректный сбор образов. Пропустив их, вы будете смотреть на «мусор» вместо файловой системы.

## Что покрывает этот модуль

- **LVM** — Physical Volume, Volume Group, Logical Volume; метаданные в начале PV; сборка из образа.
- **RAID-метаданные** — как найти суперблоки mdadm и собрать массив из отдельных дисков.
- **Форматы виртуальных дисков** — VMDK, QCOW2, VHD/VHDX, VDI; конвертация и монтирование.
- **Аппаратные и программные write blockers** — как не испортить оригинал при снятии образа.

## Рекомендуемый порядок изучения

1. `forensics-lvm` — самый частый «скрытый» слой на серверах; без него логический том не виден.
2. `forensics-vdisk-formats` — работа с образами ВМ: конвертация `qemu-img`, монтирование.
3. `forensics-write-blockers` — процедура сбора: как гарантировать неизменность доказательства.

## Что вы будете уметь

- Находить метаданные LVM и собирать LV из сырого образа.
- Собирать mdadm-RAID из набора дисков по суперблокам.
- Конвертировать и монтировать VMDK/QCOW2/VHD без запуска ВМ.
- Организовать сбор образа с write blocker и проверить хеши.

## Ключевые структуры

| Слой | Магия/признак | Инструмент |
|------|---------------|------------|
| LVM PV | `LABELONE` + `LVM2 001` | `pvscan`, `vgcfgrestore` |
| mdadm RAID | суперблок 1.2 по offset | `mdadm --assemble` |
| VMDK | `KDMV` (sparse) / `# Disk DescriptorFile` | `qemu-img`, `vmdkmount` |
| QCOW2 | `QFI\xfb` | `qemu-img`, `qemu-nbd` |
| VHD | `conectix` в конце | `qemu-img`, `guestfish` |

## Инструмент: pvs и pvscan (LVM)

Прежде чем читать логические тома, нужно найти физические. Это делают
`pvscan` (обзор) и `pvs` (таблица):

```
$ pvscan pv.img
  PV /dev/loop0  VG vg0  lvm2 [1.00 GiB / 0 free]
$ pvs pv.img
  PV         VG   Fmt  Attr PSize   PFree
  pv.img     vg0  lvm2 a--  1.00g      0
```

`LABELONE` в секторе 1 и строка `LVM2 001` — подпись Physical Volume. Собрав
цепочку PV → VG → LV, вы получаете логический том, который и нужно
проанализировать; ниже виртуального тома может лежать ещё слой (QCOW2).

## Квиз

```quiz
- question: "Что нужно найти в образе, чтобы собрать логический том LVM?"
  options:
    - "загрузочный сектор NTFS"
    - "метаданные PV (LABELONE / LVM2 001)"
    - "B-tree каталога HFS+"
    - "таблицу FAT"
  answer: 1
  explanation: "LVM хранит метаданные PV в начале физического тома; по ним собирается VG и LV."
- question: "Зачем нужен аппаратный write blocker при снятии образа?"
  options:
    - "чтобы ускорить копирование"
    - "чтобы гарантировать, что оригинал не будет изменён"
    - "чтобы сжать образ"
    - "чтобы расшифровать диск"
  answer: 1
  explanation: "Write blocker физически запрещает запись на носитель — это требование доказуемости."
- question: "Какая сигнатура соответствует формату QCOW2?"
  options:
    - "KDMV"
    - "QFI\\xfb"
    - "conectix"
    - "XFSB"
  answer: 1
  explanation: "QCOW2 начинается с магии QFI\\xfb."
```

## Где пригодится

- **CTF:** образы серверов с LVM/RAID и виртуальных машин.
- **DFIR:** корректный сбор и анализ сложных хранилищ.
- **Пентест:** разбор извлечённых дисков и снимков ВМ.
- **Судебная экспертиза:** соблюдение процедуры сбора доказательств.
