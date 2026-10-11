---
id: forensics-registry-deep
title: "Реестр глубоко: кусты, транзакции и восстановление"
category: forensics
parent: forensics-registry-hives
difficulty: hard
order: 1
tags: [registry, hives, transaction, recovery, regripper, windows, dfir]
prerequisites: [forensics-registry-hives, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 45
summary: "Внутреннее устройство кустов реестра (hbin/cell), транзакционные журналы .LOG, восстановление удалённых ключей и продвинутые ветки (Amcache, SRUM, AppCompatCache)."
---
Реестр Windows изнутри — это B-tree из «ячеек» (cells) внутри кустов (hives), с транзакционными журналами и возможностью восстановления удалённых ключей. Понимание внутреннего устройства критично для глубокого DFIR: только так вы достанете ключи, удалённые атакующим, и разберёте «грязные» кусты. Этот урок — про hbin/cell, журналы `.LOG`, восстановление и продвинутые ветки.

## Структура куста

Куст начинается с заголовка `regf` (base block), затем идут **hbin** (bins по 4 КБ), внутри которых — **cells** (ячейки). Ячейка может быть ключом (`nk`), значением (`vk`), списком значений (`value list`), подключами (`subkey list`), списком блоков (`db`). Размер ячейки — 4-байтовый заголовок (sign + size).

```bash
$ xxd -l 16 NTUSER.DAT
00000000: 7265 6766 0f00 0000 ...   regf....
$ hivexsh NTUSER.DAT
> ls
```

Типы ячеек:

| Signature | Тип |
|-----------|-----|
| `regf` | base block |
| `hbin` | bin (4 КБ) |
| `nk` | key node |
| `vk` | value |
| `lf`/`lh`/`li`/`ri` | списки подключей |
| `sk` | security descriptor |
| `db` | big data |

## Инструменты доступа

```bash
# hivex: навигация и экспорт
$ hivexsh -f NTUSER.DAT <<'EOF'
ls
cd Software\Microsoft\Windows\CurrentVersion\Run
lsval
EOF
$ hivexregedit --export NTUSER.DAT '\Software\...\Run' run.reg
$ reglookup NTUSER.DAT | head
$ reglookup-recover NTUSER.DAT | head     # восстановление удалённых
```

`reglookup-recover` сканирует ячейки и извлекает данные, на которые больше нет ссылок — это удалённые ключи.

## Транзакционные журналы .LOG

Рядом с кустом лежат `.LOG1`/`.LOG2` — журналы транзакций. Если куст «грязный» (dirty, флаг в base block), последние изменения ещё в журналах и не записаны в основной файл. Их нужно применить.

```bash
$ ls SAM*
SAM  SAM.LOG1  SAM.LOG2
# yarp: применить журналы
$ python3 yarp.py SAM
$ python3 yarp.py SAM -l SAM.LOG1 -l SAM.LOG2
```

`yarp` (Yet Another Registry Parser) применяет транзакции и отдаёт актуальный куст. Без этого вы можете потерять самые свежие (и самые интересные) ключи.

## Восстановление удалённых ключей

Удалённый ключ освобождает ячейку (помечает свободной), но данные остаются, пока ячейку не переиспользуют. `reglookup-recover`/`hivex` сканируют все ячейки, включая свободные.

```bash
$ reglookup-recover NTUSER.DAT > all.txt
$ grep -iE 'evil|persist|run' all.txt | head
# hivex: поиск по «осиротевшим» ячейкам
$ hivexregedit --export NTUSER.DAT '\' 2>/dev/null | grep -i evil
```

Это особенно ценно, когда атакующий удалил ключ автозапуска после срабатывания.

## Продвинутые ветки

| Ветка | Куст | Что даёт |
|-------|------|----------|
| `Amcache` | Amcache.hve | запуск/установка + SHA1 |
| `SRUM` | SRUDB.dat (не реестр) | сеть/CPU по процессам |
| `AppCompatCache` | SYSTEM | присутствие/запуск |
| `BAM` | SYSTEM | запущенные программы |
| `UserAssist` | NTUSER.DAT | GUI-запуски |
| `TypedPaths`/`RunMRU` | NTUSER.DAT | введённые пути/команды |
| `USBSTOR` | SYSTEM | USB-устройства |
| `Shellbags` | UsrClass.dat | просмотренные папки |

## Восстановление из теневых копий

Если ключ удалён и ячейка переиспользована, спасают теневые копии (`System Volume Information`): там старые версии кустов с историей.

```bash
$ vshadowmount disk.img /mnt/vss
$ hivexregedit --export /mnt/vss/.../NTUSER.DAT '\Software\...\Run' old.reg
```

## Разобранный пример

Дан «грязный» `NTUSER.DAT` с журналами. Нужно достать недавно созданный ключ.

```bash
# 1. Проверить «грязность» (флаг в base block)
$ xxd -l 8 NTUSER.DAT
# 2. Применить журналы
$ python3 yarp.py NTUSER.DAT
$ ls -la NTUSER.DAT*           # появился очищенный куст
# 3. Разобрать Run-ключ
$ hivexregedit --export NTUSER.DAT '\Software\Microsoft\Windows\CurrentVersion\Run' run.reg
$ cat run.reg
"Updater"="C:\\ProgramData\\evil\\run.exe"
# 4. Восстановить удалённые ключи
$ reglookup-recover NTUSER.DAT | grep -i 'evil\|updater'
# 5. Сверить с теневой копией
$ vshadowmount disk.img /mnt/vss && hivexregedit --export /mnt/vss/.../NTUSER.DAT '\...\Run' old.reg
```

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Навигация | `hivexsh`, `hivexregedit` |
| Парсинг | `reglookup`, `python-registry` |
| Восстановление | `reglookup-recover` |
| Журналы | `yarp` |
| Теневые копии | `vshadowmount`, `vshadowinfo` |
| Плагины | `RegRipper` |

## Частые ошибки

- **Игнорировать `.LOG`** — теряете свежие ключи.
- **Не проверять флаг «грязности»** — куст может быть неконсистентным.
- **Пропускать `reglookup-recover`** — не найдёте удалённое.
- **Забывать про теневые копии** — единственный источник переиспользованных ячеек.
- **Путать куст и ветку** — `Amcache` в отдельном файле.
- **Анализировать на живой системе** — кусты заблокированы.

## Что дальше / решение

Конвейер: `yarp` (журналы) → `hivexsh`/`reglookup` (навигация) → `reglookup-recover` (удалённое) → `RegRipper` (плагины) → теневые копии (история). Связка: `forensics-registry-hives` (кусты), `forensics-windows-execution` (Amcache/SRUM), `forensics-usb-devices` (USB), `forensics-shellbags`.

## Big data и сжатые значения

Значения реестра больше 16 КБ хранятся в **big data** — цепочке ячеек `db`, на которые ссылается `vk`. Для очень больших или сжатых значений (например, `AppCompatCache`, `Amcache`) данные могут быть сжаты (LZX/XPRESS).

```bash
# RegRipper корректно разбирает big data
$ rip.pl -r SYSTEM -p appcompatcache
# python-registry тоже
$ python3 -c "from Registry import Registry; r=Registry.Registry('SYSTEM'); print(r.open('ControlSet001'))"
# hivex выдаёт значения, но для big data нужен парсер
$ hivexregedit --export SYSTEM '\ControlSet001\...' out.reg
```

`ShimCache`/`AppCompatCache` — классический пример значения, разбитого на big data и сжатого; «сырой» `hivexregedit` покажет мусор, а `AppCompatCacheParser`/RegRipper — читаемый результат.

## Анти-форензика реестра

Атакующий может:
- **Удалить ключ** — данные остаются в свободных ячейках (`reglookup-recover`).
- **Перезаписать значение** — старое может сохраниться в журналах/теневых копиях.
- **Изменить LastWrite-время** ключа — сверяйте с EVTX/теневых копий.
- **Создать ключ с «легитимным» именем** — обращайте внимание на пути и значения.

```bash
# восстановить удалённые ключи Run
$ reglookup-recover NTUSER.DAT | grep -iE 'Run|evil|updater'
# сравнить LastWrite с событиями
$ reglookup NTUSER.DAT | grep -i 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
```

## Сравнение с теневой копией

Разница между текущим кустом и версией из теневой копии мгновенно показывает, что атакующий изменил/удалил.

```bash
$ vshadowmount disk.img /mnt/vss
$ hivexregedit --export /mnt/vss/.../NTUSER.DAT '\' current_from_vss.reg
$ hivexregedit --export NTUSER.DAT '\' current.reg
$ diff <(sort current_from_vss.reg) <(sort current.reg) | head
```

## Практические замечания

- **`reglookup-recover` может выдать много «шума»** — фильтруйте по ключевым словам.
- **Ячейки переиспользуются** — чем активнее система, тем меньше восстановится.
- **Теневые копии ограничены** по времени/количеству.
- **Куст из живой системы** может быть «грязным» — применяйте `.LOG` через `yarp`.
- **`python-registry`** удобен для скриптов, `hivex` — для ручной навигации.

## Краткое резюме

Внутреннее устройство реестра (hbin/cell, транзакционные журналы `.LOG`, big data) определяет, что можно восстановить: свежие изменения — через `yarp` (журналы), удалённые ключи — через `reglookup-recover` (свободные ячейки) и теневые копии. Сравнение текущего куста с версией из снапшота мгновенно показывает изменения атакующего. Для глубокого разбора используйте `hivexsh`/`reglookup` для навигации, `RegRipper` для плагинов и `yarp` для «грязных» кустов — вместе они дают полную картину, недоступную поверхностным инструментам.

## Квиз

```quiz
- question: "Что означает расхождение primary и secondary sequence number в заголовке куста?"
  options:
    - "куст зашифрован"
    - "куст был открыт и, возможно, не закрыт корректно — нужны журналы .LOG"
    - "куст пуст"
    - "куст — это EVTX"
  answer: 1
- question: "Какая ячейка реестра обозначает значение (value)?"
  options:
    - "nk"
    - "vk"
    - "sk"
    - "hbin"
  answer: 1
- question: "Где хранятся транзакционные журналы куста?"
  options:
    - "NTUSER.DAT.LOG1/.LOG2"
    - "Prefetch"
    - "SRUDB.dat"
    - "Amcache.hve"
  answer: 0
- question: "Что фиксирует ShimCache (AppCompatCache)?"
  options:
    - "пароли"
    - "присутствие (а на части ОС — выполнение) файлов"
    - "сетевые соединения"
    - "USB"
  answer: 1
- question: "Что такое LastWriteTime ключа?"
  options:
    - "время последнего изменения ключа (подключей/значений)"
    - "время создания файла"
    - "время входа пользователя"
    - "время загрузки"
  answer: 0
```

## Где пригодится

- **CTF:** задачи на скрытый автозапуск и восстановление удалённых ключей.
- **DFIR:** вскрытие персистентности, следов выполнения, USB-истории.
- **Threat Hunting:** Amcache/ShimCache/SRUM для доказательства запуска.
- **Судебная экспертиза:** работа с «грязными» кустами и журналами.
- **SOC:** детект модификаций ключевых веток реестра.
