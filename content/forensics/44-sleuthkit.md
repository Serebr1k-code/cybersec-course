---
id: forensics-sleuthkit
title: "Sleuth Kit и Autopsy: глубокий разбор образов"
category: forensics
parent: forensics-img-acquisition
difficulty: hard
order: 2
tags: [sleuthkit, tsk, autopsy, fls, icat, mactime, tsk_recover, ingest]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response"
  - "Судебная экспертиза"
estimated_minutes: 55
summary: "Полный арсенал Sleuth Kit: mmls/fsstat/fls/icat/istat/ifind/blkls/mactime/tsk_recover, построение bodyfile-таймлайна и работа в Autopsy с ingest-модулями."
---

Sleuth Kit (TSK) — де-факто стандарт для офлайн-анализа образов дисков. Он работает на уровне файловой системы: не монтирует образ, а разбирает структуры ФС напрямую, поэтому не изменяет улики. Autopsy — графическая оболочка поверх TSK с ingest-модулями (хеши, keyword search, восстановление, EXIF и т. д.). Этот урок — про полный арсенал TSK: какие утилиты есть, что каждая делает и как из них собрать таймлайн.

## Модель работы TSK

TSK не монтирует ФС — он читает образ (raw/E01) как байтовый поток и разбирает метаданные. Ключевое понятие — **offset раздела** (в секторах) и **inode/MFT-номер** файла.

Слои:
- **Image layer** — образ (raw, E01, VMDK через libewf/libvmdk).
- **Volume system layer** — таблица разделов (`mmls`).
- **File system layer** — ФС внутри раздела (`fsstat`, `fls`, `icat`).
- **File layer** — конкретный файл (`istat`, `icat`).

Утилиты (все принимают `-o <offset>` в **секторах**):

| Утилита | Назначение |
|---------|-----------|
| `mmls` | таблица разделов (volume system) |
| `fsstat` | параметры ФС раздела |
| `fls` | список файлов/каталогов (в т. ч. удалённых) |
| `istat` | метаданные inode/MFT-записи |
| `icat` | извлечь содержимое по inode |
| `ifind` | найти inode по имени/блоку |
| `ils` | список inode (в т. ч. удалённых) |
| `blkls` | дамп блоков (allocated/unallocated) |
| `blkcat`/`blkcalc` | работа с отдельными блоками |
| `ffind` | найти имя по inode |
| `hfind` | поиск по хеш-базам (NSRL) |
| `mactime` | построение таймлайна из bodyfile |
| `tsk_recover` | массовое извлечение файлов |
| `sorter` | сортировка/категоризация файлов |

```bash
sudo apt install -y sleuthkit autopsy
```

## Разбор разделов и ФС

```bash
# 1. Таблица разделов -> offset
mmls disk.img
# 002:  000:00  0000204800  0000409599  0000204800  Linux (0x83)
OFF=2048

# 2. Параметры ФС
fsstat -o $OFF disk.img | head -40
# File System Type: NTFS / ext4 / FAT

# 3. Если образ — E01, TSK читает напрямую
mmls image.E01
# или через ewfmount
ewfmount image.E01 /mnt/ewf && mmls /mnt/ewf/ewf1
```

## fls / icat / istat / ifind

```bash
# Рекурсивный список, полные пути, machine-readable
fls -r -p -o $OFF disk.img
fls -r -m "C:/" -o $OFF disk.img > bodyfile.txt     # для таймлайна

# Только удалённые
fls -r -d -o $OFF disk.img

# Извлечение по inode
icat -o $OFF disk.img 12 > secret.bin

# Метаданные inode: времена MACB, размер, runlist
istat -o $OFF disk.img 12

# Найти inode по имени (если fls показывает путь)
ifind -o $OFF -n "secret.txt" disk.img
# Найти inode по имени в конкретном каталоге
ifind -o $OFF -d 5 -n "flag.txt" disk.img

# Найти файл, занимающий блок (по unallocated)
blkcalc -o $OFF -u 12345 disk.img    # unallocated -> исходный блок
ifind -o $OFF -d <inode> -p 12345 disk.img
```

`ffind` — обратный `ifind`: по inode даёт имя(имена), полезно для hard links и удалённых записей.

```bash
ffind -o $OFF disk.img 12
```

## ils / blkls: удалённые inode и свободное место

```bash
# Все inode, помеченные удалёнными
ils -o $OFF disk.img
ils -o $OFF -m disk.img        # в формате bodyfile

# Дамп нераспределённых блоков
blkls -o $OFF disk.img > unalloc.bin
# Только allocated
blkls -o $OFF -a disk.img > alloc.bin

# Список блоков, назначенных файлу
istat -o $OFF disk.img 12 | grep -A20 'Direct Blocks\|Runlist'
```

## tsk_recover: массовое извлечение

```bash
# Все файлы (allocated) в out/
tsk_recover -o $OFF disk.img out/

# Включая удалённые
tsk_recover -o $OFF -e disk.img out_deleted/

# Ограничить конкретным каталогом по inode
tsk_recover -o $OFF -d 5 disk.img out_root/
```

`-e` = extract unallocated (удалённые). После извлечения — `grep`/`binwalk`/`file` по дереву.

## mactime: таймлайн из bodyfile

```bash
# Собираем bodyfile (MFT/fls) со всех источников
fls -r -m "C:/" -o $OFF disk.img > bodyfile.txt
# Добавляем NTFS $MFT-строки из USN и др. источников (см. урок forensics-usn)

# Строим человекочитаемый таймлайн
mactime -b bodyfile.txt -d > timeline.csv
mactime -b bodyfile.txt 2024-01-01..2024-01-02 > window.txt

# Сортируем и ищем аномалии
sort -t, -k1 timeline.csv | head -50
```

Формат bodyfile: `MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`. `mactime` собирает из него единый таймлайн с сортировкой по времени.

## hfind и sorter: фильтрация шума

```bash
# Индекс NSRL (known-good хеши) для отсева системных файлов
hfind -i nsrl-md5 /usr/share/nsrl/NSRLFile.txt 2>/dev/null
hfind nsrl-md5 <md5>          # проверка одного хеша
hfind -f bodyfile.txt nsrl-md5  # пометить известные файлы

# sorter: категоризация файлов (images, archives, ...)
sorter -d out -o $OFF disk.img
```

## Autopsy: GUI и ingest-модули

Autopsy поверх TSK добавляет:
- **Ingest modules**: Hash Lookup, File Type ID, Keyword Search, Email Parser, EXIF, Web Artifacts, Recent Activity, Timeline, Android, RegRipper.
- **Views**: File Views, Data Artifacts, Timeline (построен на mactime/Plaso).
- **Reports**: HTML/PDF/Excel.

Типовой сценарий в Autopsy:
1. New Case → Add Data Source → Disk Image → выбрать образ и offset.
2. Выбрать ingest-модули (Hash Lookup, File Type ID, Keyword Search с regex `CTF\{`).
3. Дождаться завершения → вкладки Data Artifacts / Timeline / Keyword Hits.
4. Экспортировать файл: правый клик → Extract File(s).

```bash
# Запуск Autopsy (Java)
autopsy
# или CLI-вариант анализа через TSK (см. выше)
```

## Разобранный пример: CTF-образ целиком

```bash
# 1. Разделы
mmls image.img
OFF=$(mmls image.img | awk '/Linux|NTFS|FAT/{print $3; exit}')

# 2. Тип ФС и параметры
fsstat -o $OFF image.img | head

# 3. Список с удалёнными и путями
fls -r -p -o $OFF image.img | tee fls.txt

# 4. Интересные имена
grep -iE 'flag|secret|pass|key' fls.txt

# 5. Извлечь найденное
icat -o $OFF image.img <inode> > out.bin
strings out.bin | grep -i flag

# 6. Если удалён — tsk_recover
tsk_recover -o $OFF -e image.img rec/
grep -rai 'CTF{' rec/

# 7. Таймлайн
fls -r -m "X:/" -o $OFF image.img > bf.txt
mactime -b bf.txt > tl.csv
grep -i flag tl.csv
```

## Частые ошибки

- **Путать `-o` в секторах и байтах** — все утилиты TSK (`fls`, `icat`, `istat`, `fsstat`) ждут **секторы**; `mount offset=` — **байты**.
- **Не указывать `-o` при вложенных разделах** — ошибка «cannot determine file system type» или мусор.
- **Смотреть только allocated** — забудьте `tsk_recover -e`/`blkls` и пропустите удалённое.
- **Открывать E01 посегментно** (`.E01`, `.E02` отдельно) — это один образ; передавайте `.E01` или используйте `ewfmount`.
- **Забывать `-m` в fls для bodyfile** — без него не построить таймлайн.
- **Запускать Autopsy на живом диске** — только образ.

## Квиз

```quiz
- question: "В каких единицах TSK принимает `-o` (offset раздела)?"
  options:
    - "в байтах"
    - "в секторах"
    - "в мегабайтах"
    - "в кластерах"
  answer: 1
- question: "Какая утилита извлекает содержимое файла по inode?"
  options:
    - "`mmls`"
    - "`icat`"
    - "`mactime`"
    - "`fsstat`"
  answer: 1
- question: "Что делает `tsk_recover -e`?"
  options:
    - "шифрует файлы"
    - "извлекает в том числе удалённые (unallocated) файлы"
    - "строит таймлайн"
    - "конвертирует E01"
  answer: 1
- question: "Из чего `mactime` строит таймлайн?"
  options:
    - "из E01"
    - "из bodyfile (формат fls -m)"
    - "из PCAP"
    - "из реестра"
  answer: 1
- question: "Что делает `blkls` без `-a`?"
  options:
    - "дамп нераспределённых (unallocated) блоков"
    - "дамп всех блоков"
    - "список разделов"
    - "поиск inode"
  answer: 0
```

## Где пригодится

- **CTF:** любые задачи с образами дисков — базовый инструментарий.
- **Incident Response:** офлайн-анализ без изменения улик.
- **Судебная экспертиза:** воспроизводимый разбор и отчёты (Autopsy).
- **Data recovery:** извлечение удалённых файлов и целых деревьев.
- **Threat Hunting:** таймлайн-анализ (`mactime`) для поиска аномалий.
