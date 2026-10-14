---
id: net-smb
title: 'SMB в форензике: файловый обмен и его следы'
category: forensics
parent: forensics-net-services
difficulty: medium
order: 1
tags: [network, smb, cifs, fileshare, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как из SMB-трафика извлечь переданные файлы, имена, пути и действия, даже без доступа к серверу.'
lab:
  kind: shell
  title: 'Практика: SMB в форензике'
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

В корпоративной сети файлы ходят по **SMB**. В дампе — гигабайты трафика, и где-то
среди них переданный документ или эксфильтрованный архив. Как достать файл прямо из
сети? Разберём.

## Наш пример: SMB-сессия

## Шаг 1: узнаём протокол

```
$ tshark -r capture.pcap -Y 'smb2' -c 3
  1  ... SMB2 Negotiate Protocol Request
  2  ... SMB2 Negotiate Protocol Response
```

SMB2 (порт 445) — современный обмен файлами Windows. SMB1 (порт 139) — устаревший, но
встречается на старых системах.

## Шаг 2: что делали

```
$ tshark -r capture.pcap -Y 'smb2.cmd==5' -T fields -e smb2.filename | sort -u | head
\\secret\finance\report.xlsx
\\secret\finance\archive.zip
```

`smb2.cmd==5` — это Create (открытие файла). Так видно, какие пути открывали. Список
файлов — уже ценный результат.

## Шаг 3: извлекаем файлы

Для SMB есть готовые экспортеры:

```
$ tshark -r capture.pcap --export-objects smb,./exported/ 2>/dev/null
$ ls ./exported/
report.xlsx  archive.zip
```

`--export-objects smb` собирает переданные объекты. Если трафик не шифрован (SMB3 с
шифрованием усложняет), файлы достаются целиком.

## Шаг 4: сопоставляем с хостом

Кто обращался:

```
$ tshark -r capture.pcap -Y 'smb2' -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head
```

Пара «кто → к какому серверу» показывает боковое перемещение. Частое обращение к
админским шарам (`C$`, `ADMIN$`) — признак атаки.

## Шаг 5: следы на сервере

Если сервер доступен, там свои логи:

```
$ grep -i 'report.xlsx' /var/log/samba/*.log
```

А в Windows — Security Event Log (5140/5145) фиксирует доступ к объектам.

## Что мы теперь знаем

- SMB2 — порт 445, современный файловый обмен.
- `smb2.cmd==5` показывает открытые файлы.
- `tshark --export-objects smb` извлекает переданные файлы.
- Обращение к `C$`/`ADMIN$` — признак атаки.
- Серверные логи дублируют доступ.

## Если не сработало

- SMB3 с шифрованием? Нужны ключи сессии.
- Файл не экспортируется? Проверь, не сжат ли он (compression).
- Нужны метаданные? Ищи NTFS-артефакты на сервере.

## Квиз

Проверь себя.

```quiz
- question: Какой порт использует современный SMB?
  options:
    - '21'
    - '445'
    - '80'
    - '53'
  answer: 1
  explanation: 'SMB напрямую работает на TCP 445 (SMB2/3).'
- question: Как извлечь переданные файлы из SMB-дампа?
  options:
    - 'grep'
    - 'tshark --export-objects smb'
    - 'cp'
    - 'tar'
  answer: 1
  explanation: '--export-objects собирает объекты протокола в каталог.'
- question: Что означает smb2.cmd==5?
  options:
    - 'закрытие'
    - 'открытие/создание файла (Create)'
    - 'чтение'
    - 'запись'
  answer: 1
  explanation: 'Command 5 — Create, то есть открытие файла.'
- question: Признак атаки при обращении к шаре?
  options:
    - 'доступ к public'
    - 'частый доступ к C$/ADMIN$'
    - 'чтение файла'
    - 'выход из сети'
  answer: 1
  explanation: 'Админские шары C$/ADMIN$ — типичный объект бокового перемещения.'
```
