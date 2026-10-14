---
id: linux-file-timestamps
title: 'Временные метки Linux: atime, mtime, ctime и birth'
category: forensics
parent: forensics-linux-runtime
difficulty: medium
order: 3
tags: [linux, timestamps, atime, mtime, ctime, stat, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Что означают atime/mtime/ctime/birth в Linux, чем они отличаются и как правильно строить таймлайн.'
lab:
  kind: shell
  title: 'Практика: Временные метки Linux'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Ты смотришь на файл и хочешь понять, когда его создали, изменили и читали. `ls -l`
показывает одну дату. Но на самом деле у файла их несколько, и они значат **разное**.
Путаница в метках — самая частая ошибка в таймлайне.

## Наш пример: подозрительный файл

Возьмём `/opt/.hidden/x`.

## Шаг 1: полный набор меток

```
$ stat /opt/.hidden/x
  File: /opt/.hidden/x
  Size: 245760      Blocks: 480        IO Block: 4096   regular file
Device: 253,0       Inode: 123456      Links: 1
Access: (0755/-rwxr-xr-x)  Uid: (0/root)   Gid: (0/root)
Access: 2026-01-14 03:33:10.123456789 +0000
Modify: 2026-01-14 03:31:02.987654321 +0000
Change: 2026-01-14 03:33:12.000000000 +0000
 Birth: 2026-01-14 03:31:02.987654321 +0000
```

## Шаг 2: что каждая метка значит

- **Access (atime)** — последнее **чтение** файла.
- **Modify (mtime)** — последнее **изменение содержимого**.
- **Change (ctime)** — последнее изменение **метаданных** (права, владелец, ссылки).
  Меняется и при изменении содержимого тоже.
- **Birth** — время создания inode (не на всех ФС).

Ключевое: `ctime` нельзя подделать, не изменив его сам. Если злоумышленник меняет
`mtime` через `touch -d`, `ctime` всё равно обновится на «сейчас».

## Шаг 3: ловим подделку mtime

Предположим, атакующий выставил mtime в прошлое:

```
$ touch -d "2020-01-01 00:00:00" /opt/.hidden/x
$ stat /opt/.hidden/x | grep -E 'Modify|Change'
Modify: 2020-01-01 00:00:00.000000000 +0000
Change: 2026-01-14 03:35:00.000000000 +0000
```

`Modify` в 2020, а `Change` — сегодня. Это противоречие и есть улика: содержимое
якобы старое, а метаданные менялись только что.

## Шаг 4: atime может врать

Многие системы монтируют ФС с `noatime`/`relatime`, чтобы не писать на диск при каждом
чтении. Тогда `atime` не обновляется вовсе:

```
$ mount | grep ' / '
/dev/sda1 on / type ext4 (rw,relatime)
```

`relatime` означает, что atime обновляется не всегда. Не делай выводов «файл не
читали» только по atime.

## Шаг 5: строим таймлайн

Правильный порядок: используй **все** метки и сопоставляй с другими источниками
(журналы, MFT/`ext4`-журнал, bash_history).

```
$ find /opt -newermt "2026-01-14 03:00" ! -newermt "2026-01-14 04:00" -exec stat -c '%y %n' {} \;
```

Так находишь всё, что трогали в окне атаки.

## Что мы теперь знаем

- atime = чтение, mtime = содержимое, ctime = метаданные, birth = создание.
- `ctime` обновляется всегда — по нему ловят подделку mtime.
- `noatime`/`relatime` делают atime ненадёжным.
- Расхождение mtime/ctime — прямой признак timestomping.
- Таймлайн строят по всем меткам и сопоставляют с другими источниками.

## Если не сработало

- ФС без birth? Используй журнал (ext4 journal) или `debugfs`.
- Метки одинаковы? Возможно, файл только что скопирован (cp сбрасывает метки).
- Нужен порядок? Учти наносекунды — они различимы.

## Квиз

Проверь себя.

```quiz
- question: Что означает mtime?
  options:
    - 'последнее чтение'
    - 'последнее изменение содержимого'
    - 'последнее изменение прав'
    - 'время создания'
  answer: 1
  explanation: 'Modify time меняется при изменении данных файла.'
- question: Какую метку нельзя подделать напрямую?
  options:
    - 'atime'
    - 'mtime'
    - 'ctime'
    - 'birth'
  answer: 2
  explanation: 'ctime обновляется при любом изменении метаданных, включая touch.'
- question: Признак timestomping?
  options:
    - 'atime старее mtime'
    - 'mtime в прошлом, а ctime — свежий'
    - 'файл пустой'
    - 'файл в /tmp'
  answer: 1
  explanation: 'Несоответствие mtime (старый) и ctime (новый) выдаёт подделку.'
- question: Почему atime ненадёжен?
  options:
    - 'его не существует'
    - 'при relatime/noatime он обновляется не всегда'
    - 'его ставит браузер'
    - 'он всегда равен mtime'
  answer: 1
  explanation: 'Опции монтирования подавляют обновление atime.'
```
