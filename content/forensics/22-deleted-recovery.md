---
id: forensics-deleted-recovery
title: "Восстановление удалённых данных: inode, slack, unallocated"
category: forensics
parent: forensics-fs-structure
difficulty: medium
order: 2
tags: [recovery, deleted, slack-space, unallocated, sleuthkit, extundelete]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery"
  - "Incident Response"
estimated_minutes: 40
summary: "Как находить удалённые файлы: удалённые inode и directory entries, slack space, unallocated-пространство, журналы ФС и инструменты восстановления."
---
Удаление файла в большинстве ФС не стирает содержимое — обнуляются лишь метаданные, а блоки данных остаются, пока их не перезапишут. Восстановление удалённых данных — ключевой навык форензика: именно там находятся следы атак, пароли и флаги. Этот урок — про удалённые inode и directory entries, slack-пространство, unallocated-область, журналы ФС и инструменты восстановления (`tsk_recover`, `extundelete`, `ntfsundelete`, `photorec`).

## Что происходит при удалении

| ФС | Что затирается | Что остаётся |
|----|----------------|--------------|
| ext4 | запись каталога, ссылка inode | inode (частично), блоки данных |
| FAT | первый байт имени = `0xE5` | кластеры (цепочка может сохраниться) |
| NTFS | флаг «in use» в MFT-записи | MFT-запись, `$DATA` (runlist), USN-запись |

Пока блоки не переиспользованы новыми файлами, содержимое извлекаемо. Отсюда правило: **после удаления минимизируйте запись на носитель**.

## Удалённые inode и directory entries

```bash
# список удалённых записей (d/d)
$ fls -r -d -o 2048 disk.img
r/r * 15: secret.txt
d/d * 40: deleted_dir
# метаданные удалённого inode
$ istat -o 2048 disk.img 15
# извлечь содержимое удалённого файла по inode
$ icat -o 2048 disk.img 15 > secret.txt
# список всех inode (в т.ч. удалённых)
$ ils -o 2048 disk.img
$ ils -o 2048 -m disk.img > deleted.bodyfile
```

`fls -d` показывает `*` для удалённых; `icat` извлекает, если блоки целы; если переиспользованы — вернётся мусор или пусто.

## Directory entry и восстановление имени

Имя удалённого файла может сохраниться в записи каталога (с флагом удаления) или в журнале. В ext4 имя живёт в directory entry, а inode-номер в нём может указывать на переиспользованный inode — тогда `icat` вернёт чужой файл. Проверяйте `istat`: если `Links: 0` и `Deleted`, но размер/времена совпадают с ожидаемым — вероятно, содержимое цело.

```bash
$ debugfs -R "lsdel" disk.img      # список удалённых inode
$ debugfs -R "dump <15> /tmp/out" disk.img
```

## Slack-пространство

**File slack** — остаток последнего кластера файла (от логического конца до границы кластера). Там часто остаются фрагменты предыдущих данных (RAM-slack, drive-slack).

```bash
# dump slack по inode
$ icat -o 2048 -s disk.img 15 > slack.bin
# volume slack: между концом ФС и концом раздела
$ dd if=disk.img of=volslack.bin bs=512 skip=$((END_SECTOR)) status=none
$ strings -n 8 slack.bin | grep -i flag
```

## Unallocated-пространство

Unallocated — свободные блоки, хранящие «мусор» удалённых файлов. Это главный источник для carving.

```bash
# дамп всех нераспределённых блоков
$ blkls -o 2048 disk.img > unalloc.bin
$ strings -n 8 unalloc.bin | grep -iE 'flag|password|CTF{'
# восстановление по сигнатурам
$ foremost -i unalloc.bin -o carved/
$ photorec unalloc.bin
```

## Журналы ФС

**ext4** ведёт журнал `jbd2`, куда пишутся метаданные (иногда данные). `extundelete`/`ext4magic` читают журнал и восстанавливают недавно удалённые файлы даже когда inode переиспользован.

```bash
$ sudo extundelete disk.img --restore-all
$ sudo ext4magic disk.img -r -d recovered/
$ sudo extundelete disk.img --restore-file home/user/secret.txt
```

**NTFS** ведёт `$LogFile` (транзакции) и `$UsnJrnl:$J` (журнал изменений). USN-записи содержат причину изменения (`FILE_DELETE`) и имя — по ним восстанавливают историю даже для удалённых файлов.

```bash
$ MFTECmd.exe -f '$J' --csv out --csvf usn.csv
$ MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
```

## Инструменты восстановления

| Инструмент | ФС | Режим |
|-----------|-----|-------|
| `tsk_recover -e` | все (TSK) | mass-recover с unallocated |
| `extundelete` | ext3/ext4 | журнал |
| `ext4magic` | ext4 | журнал + inode |
| `ntfsundelete` | NTFS | MFT |
| `photorec` | все | carving по сигнатурам |
| `foremost`/`scalpel` | все | carving |
| `debugfs lsdel` | ext4 | список inode |

```bash
$ tsk_recover -o 2048 -e disk.img rec/
$ sudo ntfsundelete /dev/sda1 -u -p 100 -t txt   # восстановить все .txt
```

## Разобранный пример

Дан `disk.img` (ext4). Пользователь удалил `secret.txt`.

```bash
# 1. Найти удалённый inode
$ fls -r -d -o 2048 disk.img
r/r * 20: secret.txt
# 2. Извлечь
$ icat -o 2048 disk.img 20
cat: invalid...
$ strings <(icat -o 2048 disk.img 20) | head
CTF{undelete_ext4}
# 3. Если inode переиспользован — журнал
$ sudo extundelete disk.img --restore-file home/user/secret.txt
$ grep -r CTF{ RECOVERED_FILES/ 2>/dev/null
CTF{undelete_ext4}
```

## Частые ошибки

- **Писать на носитель** после удаления — перезапишет блоки.
- **Верить, что `icat` всегда вернёт файл** — проверяйте `istat` на переиспользование.
- **Забывать `-d`** — обычный `fls` не покажет удалённое.
- **Игнорировать журналы** — extundelete/`$UsnJrnl` спасают при переиспользованных inode.
- **Не проверять slack/unallocated**, когда inode пуст.
- **Монтировать rw** — ФС «подчистит» удалённые записи.

## Что дальше / решение

Конвейер: `fls -d` (inode) → `icat` (извлечь) → при неудаче `extundelete`/`$UsnJrnl` (журнал) → `blkls`+`foremost` (carving). Связка: `forensics-filesystems` (структуры), `forensics-ntfs-mft`/`forensics-ext4-journal` (журналы), `forensics-carving` (сигнатуры), `forensics-usn` (USN).

## Восстановление каталогов и целых деревьев

Восстанавливать по одному файлу утомительно — для дерева каталогов используйте массовые режимы. `tsk_recover` извлекает всё, включая unallocated, сохраняя пути; `extundelete --restore-all` восстанавливает целые каталоги из журнала.

```bash
# массовое извлечение с unallocated
$ tsk_recover -o 2048 -e disk.img rec_all/
# только конкретный каталог (по inode)
$ tsk_recover -o 2048 -d 128 disk.img rec_dir/
# ext4: восстановить всё, что нашлось в журнале
$ sudo extundelete disk.img --restore-all
$ find RECOVERED_FILES -type f | wc -l
# NTFS: восстановить все файлы с данным расширением
$ sudo ntfsundelete /dev/sda1 -u -t docx -p 100
```

Полезно строить bodyfile удалённых inode (`ils -m`) и смотреть времена: часто удалённый файл лежит «между» другими по времени — это помогает локализовать нужный фрагмент в unallocated.

## Практические ограничения и деградация

Восстановление возможно не всегда. Ограничения:

- **Перезапись блоков** — новые файлы затирают старые; чем активнее система, тем меньше шансов.
- **TRIM на SSD** — контроллер обнуляет блоки, физически уничтожая удалённые данные. На SSD восстановление часто невозможно.
- **Шифрование** (BitLocker/LUKS/FileVault) — без ключа нет доступа и к удалённому.
- **Журнал перезаписан** — ext4-журнал циклический; extundelete бессилен спустя время.
- **Метаданные занулены** — восстановится содержимое без имени/пути (только carving).

Поэтому: снимайте образ немедленно, работайте с копией, документируйте каждый шаг и не рассчитывайте на «магию» — иногда корректный вывод «данные утрачены» и есть результат расследования.

## Проверка целостности восстановленного

Восстановленный файл может быть частично перезаписан — проверяйте консистентность:

```bash
$ file rec_all/secret.txt
$ md5sum rec_all/secret.txt
$ strings -n 6 rec_all/secret.txt | grep -i 'CTF{'
# сверка с записью в MFT/журнале (размер, времена)
$ istat -o 2048 disk.img 20 | grep -E 'Size|Modified'
```

Если размер/времена совпадают с метаданными, а содержимое читается — восстановление корректно. Если блоки переиспользованы, `strings` вернёт чужие данные — такой файл помечайте как повреждённый.

## Квиз

```quiz
- question: "Какая команда sleuthkit даёт дамп нераспределённых блоков?"
  options:
    - "`fls`"
    - "`blkls`"
    - "`icat`"
    - "`istat`"
  answer: 1
- question: "Как в FAT помечается удалённая запись каталога?"
  options:
    - "нулями"
    - "первым байтом имени `0xE5`"
    - "флагом `*`"
    - "она удаляется полностью"
  answer: 1
- question: "Что такое slack space?"
  options:
    - "весь свободный диск"
    - "остаток последнего кластера файла"
    - "журнал ФС"
    - "MFT"
  answer: 1
- question: "Как восстановить удалённый файл ext4 по inode?"
  options:
    - "`icat -o <offset> img <inode>`"
    - "`mount`"
    - "`unzip`"
    - "`exiftool`"
  answer: 0
- question: "Почему нельзя восстанавливать с живого RW-раздела?"
  options:
    - "медленно"
    - "новые записи затрут удалённые данные"
    - "нет прав"
    - "ФС не поддерживает"
  answer: 1
```

## Где пригодится

- **CTF:** классические задачи «восстанови удалённый файл».
- **Data recovery:** спасение данных после случайного удаления.
- **Incident Response:** поиск удалённых злоумышленником улик.
- **Криминалистика:** доказательство существования удалённых данных.
- **Анти-форензика:** понимание, как данные можно скрыть в slack/unallocated.
