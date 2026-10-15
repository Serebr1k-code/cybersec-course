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
lab:
  kind: shell
  title: "Практика: восстановить удалённый файл из образа"
  toolset: [core, fls, icat]
  workdir: /home/student/task
  files: [task.md, notes.txt, disk.dd]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Определи образ: `file disk.dd`."
    - "Посмотри удалённые файлы: `fls -rd disk.dd`."
    - "Найди inode файла `secret_flag.txt` (число перед двоеточием)."
    - "Вытащи содержимое: `icat disk.dd 13 > found.txt`."

---

## Вопрос, с которого всё начинается

У тебя образ диска `image.img`, и ты хочешь найти в нём всё подозрительное, не
монтируя его. Монтировать нельзя: любая запись испортит улики. Нужен набор
инструментов, который читает образ как поток байтов и разбирает файловую систему
напрямую.

Это и есть **Sleuth Kit (TSK)** — де-факто стандарт офлайн-анализа. В этом уроке мы
пройдём по нему сверху вниз: от таблицы разделов до единого таймлайна — на одном
конкретном образе.

## Шаг 1: слои образа и offset

TSK работает послойно:

- **Image layer** — сам образ (raw, E01).
- **Volume system layer** — таблица разделов (`mmls`).
- **File system layer** — ФС внутри раздела (`fsstat`, `fls`, `icat`).
- **File layer** — конкретный файл (`istat`, `icat`).

Начинаем с разделов:

```bash
$ mmls image.img
GUID Partition Table (EFI)
01: -----  0000002048-0000409599  NTFS / exFAT
```

Раздел начинается с сектора 2048. Запомним `OFF=2048`. Все утилиты TSK принимают
`-o` именно в **секторах**, а не в байтах — это самая частая ошибка новичка.

Смотрим параметры ФС:

```bash
$ fsstat -o 2048 image.img | head
File System Type: NTFS
```

Если образ в формате E01 (EnCase), TSK читает его напрямую — не надо распаковывать
посегментно (`.E01`, `.E02` — это один образ, а не несколько).

## Шаг 2: список файлов — fls

`fls` — «file list». Рекурсивный список с путями:

```bash
$ fls -r -p -o 2048 image.img | tee fls.txt
r/r 4-128-1: $AttrDef
...
r/r 120-128-4: Users/bob/Documents/notes.txt
```

Только удалённые (флаг `-d`):

```bash
$ fls -r -d -o 2048 image.img
r/r * 121-128-1: Users/bob/secret.txt
```

Машиночитаемый формат для таймлайна (флаг `-m`):

```bash
$ fls -r -m "C:/" -o 2048 image.img > bodyfile.txt
```

## Шаг 3: метаданные и содержимое — istat и icat

`istat` печатает метаданные записи (времена MACB, размер, runlist):

```bash
$ istat -o 2048 image.img 120
MFT Entry: 120  Sequence: 128
$STANDARD_INFORMATION Attribute Values:
  Modified:  2024-01-12 10:14:03
  Created:   2024-01-12 10:13:50
```

`icat` вынимает содержимое по inode:

```bash
$ icat -o 2048 image.img 121 > secret.bin
$ strings secret.bin | grep -i flag
CTF{sleuthkit_never_touches_evidence}
```

## Шаг 4: искать по имени и обратно — ifind и ffind

`ifind` находит inode по имени; `ffind` — наоборот, имя по inode:

```bash
$ ifind -o 2048 -n "secret.txt" image.img
121
$ ffind -o 2048 image.img 121
Users/bob/secret.txt
```

`ffind` особенно полезен для hard links: у одного inode может быть несколько имён, и
он покажет все.

## Шаг 5: удалённые inode и свободное место — ils и blkls

```bash
$ ils -o 2048 image.img | head
class|host|device|start_time
...
$ blkls -o 2048 image.img > unalloc.bin
$ strings -n 6 unalloc.bin | grep -iE 'CTF\{|flag\{'
```

`ils` перечисляет inode, включая удалённые. `blkls` дампит **нераспределённые** блоки
(без флага `-a`). Именно там живёт то, что удалено и ещё не перезаписано.

## Шаг 6: массовое извлечение — tsk_recover

```bash
$ tsk_recover -o 2048 image.img out/            # только allocated
$ tsk_recover -o 2048 -e image.img rec/         # включая удалённые
$ grep -rai 'CTF{' rec/
```

`-e` = extract unallocated. После извлечения удобно грепать и `binwalk`-ить всё
дерево целиком.

## Шаг 7: таймлайн — mactime

`mactime` собирает единый таймлайн из **bodyfile**. Формат bodyfile такой:
`MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`. Строим его через `fls -m`:

```bash
$ fls -r -m "C:/" -o 2048 image.img > bodyfile.txt
$ mactime -b bodyfile.txt -d > timeline.csv
$ grep -i secret timeline.csv
2024-01-12 10:31:22, ... ,Users/bob/secret.txt
```

Получилась хронология: когда что создано, изменено, удалено. Сортируем и ищем
аномалии — всплески активности, странные времена, ночные запуски.

## Шаг 8: фильтрация шума — hfind и sorter

В образе тысячи системных файлов, и они мешают. `hfind` отсеивает «известно-хорошие»
по хеш-базе NSRL:

```bash
$ hfind -i nsrl-md5 /usr/share/nsrl/NSRLFile.txt
$ hfind nsrl-md5 <md5>          # проверка одного хеша
```

`sorter` раскладывает файлы по категориям (изображения, архивы, документы):

```bash
$ sorter -d out -o 2048 image.img
```

## Шаг 9: Autopsy — графическая оболочка

Autopsy — GUI поверх TSK. Он добавляет **ingest-модули** (автоматический разбор при
добавлении образа): Hash Lookup, File Type ID, Keyword Search, EXIF, Web Artifacts,
Timeline. Типовой сценарий:

1. New Case → Add Data Source → Disk Image.
2. Выбрать образ и offset.
3. Отметить ingest-модули, задать keyword-поиск по regex `CTF\{`.
4. Дождаться завершения → вкладки Data Artifacts / Timeline / Keyword Hits.
5. Экспорт: правый клик → Extract File(s).

```bash
$ autopsy
```

Для командной строки всё то же самое делается утилитами TSK из шагов выше.

## Шаг 10: полный прогон от начала до конца

Соберём всё вместе — так выглядит типовой разбор CTF-образа целиком:

```bash
# 1. Разделы и offset
$ mmls image.img
$ OFF=2048

# 2. Тип ФС
$ fsstat -o $OFF image.img | head

# 3. Список с удалёнными и путями
$ fls -r -p -o $OFF image.img | tee fls.txt
$ grep -iE 'flag|secret|pass|key' fls.txt
r/r * 121-128-1: Users/bob/secret.txt

# 4. Извлечь найденное
$ icat -o $OFF image.img 121 > out.bin
$ strings out.bin | grep -i flag
CTF{sleuthkit_never_touches_evidence}

# 5. Если удалён и не читается — recover + grep
$ tsk_recover -o $OFF -e image.img rec/
$ grep -rai 'CTF{' rec/

# 6. Таймлайн
$ fls -r -m "C:/" -o $OFF image.img > bf.txt
$ mactime -b bf.txt > tl.csv
$ grep -i secret tl.csv
```

Шесть команд — и мы прошли путь от сырого образа до строки с флагом и её места в
хронологии. Именно поэтому TSK считают базовым инструментом: он не требует
монтирования, не меняет образ и покрывает почти все задачи по разбору дисков.

## Что мы теперь знаем

- TSK читает образ послойно и **не изменяет** улики.
- `mmls` даёт offset раздела; `-o` у TSK — в **секторах**.
- `fls` перечисляет файлы (`-d` — удалённые, `-m` — bodyfile).
- `istat` — метаданные, `icat` — содержимое, `ifind`/`ffind` — поиск inode.
- `blkls` + `tsk_recover -e` достают удалённое; `mactime` строит таймлайн.

## На что смотреть дальше

- **Путаница секторов и байтов** — самая частая ошибка; TSK ждёт секторы.
- **Забыли `-o`** при вложенных разделах — получите «cannot determine file system type».
- **Смотрите только allocated** — без `-e`/`blkls` пропустите удалённое.
- **E01 нельзя открывать посегментно** — это один образ, передавайте `.E01`.
- **Без `-m` в `fls`** не построить таймлайн.

## Извлечение по сигнатурам из нераспределённого

`blkls` даёт сырые нераспределённые блоки, но файл в них может быть «разорван». Когда
метаданные потеряны, работают по **сигнатурам** — так ищут JPEG, PDF, ZIP без inode:

```bash
$ blkls -o 2048 image.img > unalloc.bin
$ binwalk -e unalloc.bin
$ photorec image.img            # интерактивно, по типам файлов
$ foremost -t jpg,pdf,zip -i image.img -o out/
```

Это «carving» — восстановление по заголовку и размеру, без опоры на файловую систему.
Метод достаёт то, что `tsk_recover` не видит: файлы, чьи метаданные уже перезаписаны.

## NTFS-специфика: ADS и `-f ntfs`

NTFS хранит **альтернативные потоки данных** (ADS) — `file.txt:hidden` не виден в
обычном листинге. TSK читает их, если задать тип ФС явно:

```bash
$ fls -r -o 2048 -f ntfs image.img | grep -i ':' | head
$ icat -o 2048 -f ntfs image.img 130 > ads.bin
```

Скрытый поток — классическое место для сокрытия данных; проверяйте файлы со странным
синтаксисом имени.

## Проверка целостности перед разбором

TSK не меняет образ, но сам образ нужно верифицировать до и после анализа:

```bash
$ md5sum image.img > image.md5
$ md5sum -c image.md5
```

Совпадение хеша до и после — доказательство, что разбор не затронул улику.

## Если не сработало

- «Cannot determine file system type» → задайте `-o <сектор>` и, при необходимости, `-f ntfs`.
- `icat` даёт мусор → файл разорван; ищите через `blkls` + `binwalk`/`photorec`.
- E01 не читается → передавайте только `.E01` (сегменты TSK находит сам).
- Удалённый файл пуст → его блоки перераспределены; остаётся carving.

## Квиз

Проверь себя.

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
    - "из bodyfile (формат `fls -m`)"
    - "из PCAP"
    - "из реестра"
  answer: 1
- question: "Что делает `ffind`?"
  options:
    - "находит имя по inode"
    - "дамп блоков"
    - "список разделов"
    - "считает хеши"
  answer: 0
```

## Куда дальше

Мы освоили универсальный инструментарий TSK. Дальше посмотрим, как правильно снимать
сами образы: `dd`, `dc3dd`, write blockers и хеширование — чтобы улики были
допустимы. А пока запомни: **TSK не монтирует и не пишет — он разбирает и доказывает**.

## Где пригодится

- **CTF:** любые задачи с образами дисков — базовый инструментарий.
- **Incident Response:** офлайн-анализ без изменения улик.
- **Судебная экспертиза:** воспроизводимый разбор и отчёты (Autopsy).
- **Data recovery:** извлечение удалённых файлов и целых деревьев.
- **Threat Hunting:** таймлайн-анализ (`mactime`) для поиска аномалий.
