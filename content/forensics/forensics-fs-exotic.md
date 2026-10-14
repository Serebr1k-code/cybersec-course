---
id: forensics-fs-exotic
title: 'Модуль: экзотические файловые системы'
category: forensics
parent: forensics-filesystems
difficulty: hard
order: 5
tags: [refs, udf, iso9660, f2fs, squashfs, jffs2, ubifs, nilfs, minix, filesystem, roadmap]
prerequisites: [forensics-filesystems]
useful_for:
  - 'CTF Forensics категория'
  - 'Анализ образов дисков'
  - 'Embedded / IoT'
estimated_minutes: 14
summary: 'Этап ветки «Файловые системы»: ReFS, UDF/ISO9660, F2FS, SquashFS, JFFS2/UBIFS и NILFS/Minix — как опознать и разобрать ФС, которых нет в «обычном» наборе NTFS/ext4/FAT.'
---

Базовые уроки закрыли NTFS, ext4, FAT/exFAT, XFS и HFS+. Но в реальных задачах и в
инцидентах постоянно попадаются **носители другого класса**: серверный том ReFS, диск
DVD/Blu-ray или firmware-образ с UDF/ISO, флеш-память Android с F2FS, прошивка роутера
со SquashFS и JFFS2/UBIFS. Обычный набор инструментов на них молчит или показывает
«data», и без понимания формата данные не достать.

## Что покрывает этот модуль

- **ReFS** — Resilient File System от Microsoft: метаданные в B+-деревьях, integrity
  streams, block cloning; почему `$MFT` не находится.
- **UDF / ISO9660** — оптические диски, firmware-образы и гибридные ISO: дескрипторы
  тома, Joliet/Rock Ridge, El Torito.
- **F2FS** — Flash-Friendly File System на Android-устройствах и встраиваемых носителях.
- **SquashFS** — сжатая read-only ФС прошивок и initramfs.
- **JFFS2 / UBIFS** — журнальные ФС «сырой» NOR/NAND-памяти во встраиваемых устройствах.
- **NILFS / Minix и прочая экзотика** — редко встречающиеся, но узнаваемые форматы.

## Рекомендуемый порядок

1. `forensics-fs-refs` — серверный Windows; логика B+-деревьев вместо MFT.
2. `forensics-fs-udf-iso` — оптические и firmware-образы; база для многих прошивок.
3. `forensics-fs-f2fs` — Android/embedded flash; частая ФС в мобильных образах.
4. `forensics-fs-squashfs` — сжатые прошивки и initramfs.
5. `forensics-fs-jffs2-ubifs` — «сырая» NAND/NOR-память встраиваемых устройств.
6. `forensics-fs-nilfs-minix` — экзотика и log-structured ФС со снапшотами.

## Что вы будете уметь

- Опознавать ФС по сигнатуре в hex, даже когда `file` не помогает.
- Читать суперблок и вычислять границы ФС.
- Извлекать содержимое правильным инструментом, а не «наугад».
- Понимать, почему удалённые данные в одних ФС находятся легко, а в других — почти нет.

## Как опознать эти ФС

| ФС | Где встречается | Сигнатура / признак | Инструмент |
|----|-----------------|---------------------|------------|
| ReFS | Windows Server | OEM-поле `ReFS` в boot sector | `refsutil`, X-Ways, EnCase |
| ISO9660 | CD/DVD, ISO-образы | `CD001` по offset `0x8001` | `isoinfo`, `7z`, `pycdlib` |
| UDF | DVD/Blu-ray, firmware | `BEA01`/`NSR02` в VRS | `udfread`, `7z`, `bsdtar` |
| F2FS | Android flash | магия `10 20 F5 F2` по offset `0x400` | `dump.f2fs`, `sload.f2fs` |
| SquashFS | прошивки, initramfs | `hsqs` по offset `0` | `unsquashfs`, `binwalk` |
| JFFS2 | NOR/NAND flash | магия `85 19` (0x1985) | `jefferson` |
| UBIFS | NAND через UBI | `UBI#` + узел UBIFS | `ubireader` |

## Почему это отдельный этап

Эти ФС объединяет одно: **их метаданные не сводятся к «таблице файлов»**, которую
показывает `fls`. ReFS прячет их в деревьях, F2FS — в checkpoint/NAT, прошивки —
в сжатых блоках и журналах узлов. Поэтому здесь важнее понимать формат, чем знать
одну команду. Освоив этап, вы перестанете пасовать перед образом, который «не открывается».

## Квиз

```quiz
- question: "Почему на томе ReFS не находится таблица $MFT?"
  options:
    - "ReFS шифрует $MFT"
    - "В ReFS метаданные хранятся в B+-деревьях, а не в единой таблице $MFT"
    - "ReFS не поддерживает файлы"
    - "ReFS использует только FAT-таблицы"
  answer: 1
  explanation: "ReFS не использует MFT: метаданные разложены по B+-деревьям, поэтому NTFS-инструменты не видят привычную структуру."
- question: "Какая сигнатура указывает на SquashFS в начале файла?"
  options:
    - "CD001"
    - "hsqs"
    - "XFSB"
    - "ReFS"
  answer: 1
  explanation: "SquashFS начинается с магии hsqs (little-endian)."
- question: "Где в ISO9660 лежит первичный дескриптор тома (PVD)?"
  options:
    - "В секторе 0"
    - "По offset 0x8001 (сектор 16)"
    - "В конце образа"
    - "По offset 1024"
  answer: 1
  explanation: "PVD — первый дескриптор в области дескрипторов, начинающейся с сектора 16; байт типа 0x01, затем CD001."
```

## Где пригодится

- **CTF:** образы, которые «не открываются» стандартным набором.
- **DFIR:** серверные ReFS-тома, оптические носители, встраиваемые устройства.
- **Embedded/IoT:** разбор прошивок роутеров, камер, приставок.
- **Mobile:** F2FS на Android-устройствах.
