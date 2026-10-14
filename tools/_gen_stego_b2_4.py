#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch 2c — archives/binary stego lessons + binary hub."""
import io, tarfile, zlib, struct
from _gen_stego_lib import emit, lab_json, write

# ---------------------------------------------------------------------------
# git object
# ---------------------------------------------------------------------------
git_flag = "nto{git_dangling_blob}"
git_obj = zlib.compress(b"blob %d\x00" % len(git_flag) + git_flag.encode())

# ---------------------------------------------------------------------------
# docker layer (tar.gz)
# ---------------------------------------------------------------------------
docker_flag = "nto{docker_layer_extra_file}"
_buf = io.BytesIO()
with tarfile.open(fileobj=_buf, mode="w:gz") as t:
    for name, data in [
        ("manifest.json", b'[{"Config":"config.json","Layers":["layer.tar"]}]'),
        ("config.json", b'{"created":"2026-01-01","config":{"Labels":{}}}'),
        ("etc/app.conf", b"debug=false\n"),
        ("etc/secret", docker_flag.encode()),
    ]:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
docker_layer = _buf.getvalue()

# ---------------------------------------------------------------------------
# ELF with overlay
# ---------------------------------------------------------------------------
elf_flag = "nto{elf_overlay_appended}"
_e_shoff = 64
_e_shnum = 1
_e_shentsize = 64
elf_hdr = bytearray(64)
elf_hdr[0:4] = b"\x7fELF"
elf_hdr[4] = 2          # 64-bit
elf_hdr[5] = 1          # little-endian
elf_hdr[6] = 1          # version
elf_hdr[0x28:0x30] = struct.pack("<Q", _e_shoff)     # e_shoff
elf_hdr[0x3a:0x3c] = struct.pack("<H", _e_shentsize)  # e_shentsize
elf_hdr[0x3c:0x3e] = struct.pack("<H", _e_shnum)      # e_shnum
shdr = bytes(_e_shentsize)
elf_bytes = bytes(elf_hdr) + shdr + elf_flag.encode() + b"\x00"

# ---------------------------------------------------------------------------
# Mach-O with LC_NOTE
# ---------------------------------------------------------------------------
macho_flag = "nto{macho_lc_note}"
_mh = struct.pack("<IIIIIIII", 0xfeedfacf, 0x01000007, 3, 2, 1, 40, 0, 0)  # 32 bytes
_data_off = 0x20 + 40
_note_cmd = struct.pack("<II", 0x31, 40) + b"stego\x00".ljust(16, b"\x00") + struct.pack("<QQ", _data_off, len(macho_flag))
macho_bytes = _mh + _note_cmd + macho_flag.encode()

# ===========================================================================
# stego-git-objects
# ===========================================================================
git_body = r"""
## Вопрос, с которого всё начинается
Ты нашёл каталог `.git` или бэкап репозитория. В истории нет ничего секретного —
но в объектах Git может висеть **отсоединённый blob**: файл, который когда-то
добавили и удалили. Он не виден в `git log`, но лежит в `.git/objects` как
zlib-сжатый объект. Задача: достать его.

## Наш пример
Возьмём `blob.bin` — сырой Git-объект (как он лежит в `.git/objects/ab/cdef...`).
Разберём его формат и извлечём содержимое.

## Шаг 1: модель объектов Git
Git хранит всё как объекты четырёх типов: `blob` (файл), `tree` (каталог),
`commit`, `tag`. Объект — это строка заголовка `<тип> <длина>\0`, за которой идут
данные, всё вместе сжато zlib. Имя объекта — SHA-1 от **несжатого** содержимого.
Файл объекта лежит по пути `.git/objects/<первые2>/<остальные38>`.

## Шаг 2: формат blob
```
$ xxd -l 16 blob.bin
00000000: 789c 4b4c 4a06 00cb 3f01 8b05 0000 00    x.LJ...?.......
```

`78 9c` — заголовок zlib. Распакуем:

```python
import zlib
raw = zlib.decompress(open('blob.bin','rb').read())
print(raw)
```

Вывод:

```
b'blob 22\x00nto{git_dangling_blob}'
```

Заголовок `blob 22\0` сообщает тип и длину; дальше — содержимое.

## Шаг 3: где искать «висячие» объекты
- `git fsck --lost-found` — находит достижимые и висячие объекты.
- `git cat-file -p <sha>` — показать объект.
- `.git/logs/` (reflog) — история перемещений HEAD.
- `git stash list`, удалённые ветки — объекты остаются.

Даже после `git rm` и commit объект живёт, пока не собран `git gc`.

## Шаг 4: packfiles
В «упакованном» репозитории объекты лежат в `.git/objects/pack/*.pack` — с
дельтами и индексом `.idx`. Извлечь объект: `git verify-pack -v` + `git cat-file`,
или `git unpack-objects`. Формат pack сложнее, но принцип тот же.

## Шаг 5: стеганография в Git
- **Blob с мусором.** В объект можно дописать байты после полезного содержимого —
  Git их сохранит.
- **Сообщения коммитов.** Метаданные (author/committer, message) — произвольный
  текст, легко кодирует данные.
- **`.git/objects/info/alternates`** — путь к другому хранилищу.
- **`.gitattributes`/hooks** — служебные файлы.

## Что мы теперь знаем
- Git-объекты — это zlib-сжатые `<тип> <длина>\0<данные>`.
- Удалённые файлы остаются как висячие blob до `git gc`.
- `git fsck --lost-found` и `git cat-file` — основные инструменты.
- Метаданные коммитов — дополнительный канал.

## Квиз

Проверь себя.

```quiz
- question: "Как устроен Git-объект blob?"
  options:
    - "zlib-сжатая строка 'blob <len>\\0<данные>'"
    - "Простой текстовый файл"
    - "JSON"
    - "ZIP-архив"
  answer: 0
  explanation: "Заголовок тип+длина, затем содержимое, всё сжато zlib."
- question: "Что такое висячий (dangling) объект?"
  options:
    - "Объект, на который больше не ссылается ни одна ветка/тег"
    - "Объект с ошибкой"
    - "Пустой файл"
    - "Симлинк"
  answer: 0
  explanation: "Он остаётся в хранилище до сборки мусора."
- question: "Как найти потерянные объекты?"
  options:
    - "git fsck --lost-found"
    - "git push"
    - "ls .git"
    - "git clone"
  answer: 0
  explanation: "fsck находит недостижимые объекты и складывает их в lost-found."
- question: "Где ещё в репозитории можно спрятать данные?"
  options:
    - "В сообщениях коммитов и в мусоре после содержимого blob"
    - "Только в имени репозитория"
    - "Только в README"
    - "Нигде"
  answer: 0
  explanation: "Метаданные коммитов и хвост blob — свободное место."
```

## Куда дальше
Git-объекты — контейнер разработчика. Следующий — Docker-образ: tar-слои, белые
пятна (whiteouts) и лишние файлы. О нём — в следующем уроке.

## Где пригодится
- **CTF:** задачи с `.git`, бэкапами репозиториев.
- **Форензика:** восстановление удалённых файлов из истории.
- **Blue team:** утечки через объекты Git.
""".strip()

git_parser = (
    "import zlib\n"
    "raw = zlib.decompress(open('blob.bin','rb').read())\n"
    "print(raw.split(b'\\x00', 1)[1].decode())\n"
)
git_task = ("# Задача: висячий blob в Git-объекте\n\n"
            "`blob.bin` — сырой Git-объект (zlib-сжатый).\n\n"
            "1. `xxd -l 16 blob.bin`.\n"
            "2. `python3 gitobj.py` — распаковка и содержимое.\n"
            "3. `python3 gitobj.py | grep nto > found.txt`.\n")
emit("stego-git-objects", """---
id: stego-git-objects
title: "Git-объекты: висячие blob и packfiles как носитель"
category: stego
parent: stego-module-binary-adv
difficulty: medium
order: 1
tags: [stego, git, blob, zlib, packfile, dangling]
prerequisites: [stego-binary-carriers]
useful_for:
  - "CTF Stego: каталог .git и бэкапы репозиториев"
  - "Форензика: восстановление удалённых файлов"
  - "Blue team: утечки через объекты Git"
estimated_minutes: 16
summary: "Формат Git-объектов (zlib + 'blob <len>\\0'), висячие объекты, packfiles, метаданные коммитов как канал. Извлечение blob из сырого объекта."
lab:
  kind: shell
  title: "Практика: распаковка Git-объекта"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, blob.bin, gitobj.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Начни с `xxd -l 16 blob.bin` — заголовок zlib."
    - "Данные — zlib.decompress."
    - "Заголовок 'blob <len>\\0' отделяется нулевым байтом."
    - "`python3 gitobj.py | grep nto > found.txt`."
---

""" + git_body + "\n", lab_json(
    "stego-git-objects", git_flag, git_task,
    [("blob.bin", ("b64", git_obj)), ("gitobj.py", ("text", git_parser))],
    [{"match": "gitobj\\.py", "example": "python3 gitobj.py", "output": git_flag + "\n"}]))

# ===========================================================================
# stego-docker-layers
# ===========================================================================
docker_body = r"""
## Вопрос, с которого всё начинается
Docker-образ — это набор слоёв. Каждый слой — tar-архив с изменениями файловой
системы. Ты запускаешь контейнер, видишь приложение. Но в образе могут лежать
файлы, которых нет в работающем контейнере: удалённые (whiteouts), лишние, или
данные в метаданных слоя. Задача: найти их.

## Наш пример
Возьмём `layer.tar.gz` — один слой образа. Разберём его как tar и найдём
необычный файл.

## Шаг 1: образ = манифест + слои
Современный образ (`docker save` / OCI) — это tar-архив, содержащий:
- `manifest.json` — список слоёв и конфига;
- `config.json` — метаданные (env, cmd, labels, история);
- `layer.tar` — собственно слои (часто сжатые gzip).

Каждый слой — самостоятельный tar с файлами. Слои накладываются друг на друга.

## Шаг 2: whiteouts — «удалённые» файлы
Docker удаляет файл из слоя, создавая **whiteout**: пустой файл
`.wh.<имя>`. Сам файл при этом может остаться в предыдущем слое. Данные,
«удалённые» таким образом, никуда не исчезают — они в нижних слоях.

## Шаг 3: где прячут данные в слоях
- **Лишние файлы.** Любой файл в слое, не нужный приложению, — носитель.
- **Мусор в нижних слоях.** Файл, «удалённый» в следующем слое, всё ещё читается
  из предыдущего.
- **`config.json`.** Labels, `created_by` (история сборки) — произвольный текст.
- **Метаданные tar.** Расширенные заголовки (pax) и padding блоков.
- **Неиспользуемые blob в registry.** Слои, на которые не ссылается манифест.

## Шаг 4: извлечение вручную
```python
import tarfile
t = tarfile.open('layer.tar.gz', 'r:gz')
for m in t.getmembers():
    if m.name.endswith('secret'):
        print(t.extractfile(m).read().decode())
```

Вывод:

```
nto{docker_layer_extra_file}
```

## Шаг 5: инструменты
- `docker save img -o img.tar` + `tar tf img.tar`.
- `dive img` — визуальный анализ слоёв и мусора.
- `crane`/`skopeo` — работа с registry и слоями.
- `tar tvf layer.tar` — список файлов.

## Что мы теперь знаем
- Docker-образ — tar из манифеста, конфига и слоёв-тар.
- Whiteout-файлы «удаляют» файл, не стирая данные в нижних слоях.
- Лишние файлы и метаданные слоя — каналы.
- `dive` — удобный инструмент анализа слоёв.

## Квиз

Проверь себя.

```quiz
- question: "Что представляет собой слой Docker-образа?"
  options:
    - "tar-архив с изменениями файловой системы"
    - "Один бинарный файл"
    - "JSON-файл"
    - "SQLite-база"
  answer: 0
  explanation: "Слой — tar (часто сжатый) с файлами и whiteouts."
- question: "Что такое whiteout в слое?"
  options:
    - "Пустой файл .wh.<имя>, помечающий удаление файла"
    - "Белый фон контейнера"
    - "Слой только для чтения"
    - "Лог контейнера"
  answer: 0
  explanation: "Whiteout маскирует файл из нижнего слоя, не удаляя его."
- question: "Почему «удалённые» файлы остаются доступны?"
  options:
    - "Они сохраняются в нижних слоях, whiteout лишь маскирует"
    - "Docker их дублирует"
    - "Они зашифрованы"
    - "Их восстанавливает git"
  answer: 0
  explanation: "Слои иммутабельны; удаление — это маска в верхнем слое."
- question: "Где в образе ещё можно спрятать данные?"
  options:
    - "В config.json (labels, история), лишних файлах и неиспользуемых blob"
    - "Только в имени образа"
    - "Только в теге"
    - "Нигде"
  answer: 0
  explanation: "Метаданные и нереференсные слои — свободное место."
```

## Куда дальше
Образы и архивы разобраны. Дальше — исполняемые форматы: ELF и Mach-O, где данные
прячут в note-секциях и overlay.

## Где пригодится
- **CTF:** задачи с Docker-образами и слоями.
- **Форензика:** восстановление «удалённых» файлов из образов.
- **Blue team:** поиск секретов, оставшихся в слоях.
""".strip()

docker_parser = (
    "import tarfile\n"
    "t = tarfile.open('layer.tar.gz', 'r:gz')\n"
    "for m in t.getmembers():\n"
    "    if m.name.endswith('secret'):\n"
    "        print(t.extractfile(m).read().decode())\n"
)
docker_task = ("# Задача: лишний файл в слое Docker\n\n"
               "`layer.tar.gz` — слой образа (tar.gz). В нём есть файл, не нужный\n"
               "приложению.\n\n"
               "1. `tar tzf layer.tar.gz`.\n"
               "2. `python3 dlayer.py` — чтение файла.\n"
               "3. `python3 dlayer.py | grep nto > found.txt`.\n")
emit("stego-docker-layers", """---
id: stego-docker-layers
title: "Docker-слои: whiteouts, лишние файлы и метаданные"
category: stego
parent: stego-module-binary-adv
difficulty: medium
order: 2
tags: [stego, docker, oci, layer, tar, whiteout]
prerequisites: [stego-git-objects]
useful_for:
  - "CTF Stego: Docker-образы и слои"
  - "Форензика: восстановление файлов из образов"
  - "Blue team: секреты в слоях"
estimated_minutes: 16
summary: "Структура Docker/OCI-образа: манифест, config.json и слои-tar. Whiteouts, лишние файлы, история сборки и неиспользуемые blob как носители данных."
lab:
  kind: shell
  title: "Практика: лишний файл в слое"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, layer.tar.gz, dlayer.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Слой — это tar.gz: `tar tzf layer.tar.gz`."
    - "Ищи файл, не относящийся к приложению."
    - "`python3 dlayer.py` печатает его содержимое."
    - "`python3 dlayer.py | grep nto > found.txt`."
---

""" + docker_body + "\n", lab_json(
    "stego-docker-layers", docker_flag, docker_task,
    [("layer.tar.gz", ("b64", docker_layer)), ("dlayer.py", ("text", docker_parser))],
    [{"match": "dlayer\\.py", "example": "python3 dlayer.py", "output": docker_flag + "\n"}]))

# ===========================================================================
# stego-elf-notes
# ===========================================================================
elf_body = r"""
## Вопрос, с которого всё начинается
Бинарник ELF (Linux) — это заголовок, секции, сегменты. Ты запускаешь его,
работает. Но у ELF есть note-секции (`.note.*`) для произвольных «заметок»
(например, build-id), а также возможность **дописать данные после конца файла**
(overlay). Ни то, ни другое на работу не влияет — идеальное место для закладки.

## Наш пример
Возьмём `bin` — ELF-файл с данными, дописанными после последней секции. Найдём
overlay.

## Шаг 1: ELF-заголовок
Первые байты ELF:
- `7f 45 4c 46` — магия `\x7fELF`;
- класс (`01` = 32-bit, `02` = 64-bit);
- порядок байт (`01` = little-endian);
- версия;
- `e_shoff` (смещение таблицы секций), `e_shnum` (число секций),
  `e_shentsize` (размер записи) — в фиксированных смещениях.

Для 64-битного ELF: `e_shoff` — по смещению `0x28`, `e_shentsize` — `0x3a`,
`e_shnum` — `0x3c`.

## Шаг 2: overlay
«Конец ELF» — это максимум из конца таблицы секций (`e_shoff + e_shnum*e_shentsize`)
и конца таблицы сегментов. Всё, что лежит после, — overlay. Загрузчик его
игнорирует, но байты на месте. Простейшая закладка:

```python
import struct
d = open('bin','rb').read()
e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
end = e_shoff + e_shnum * e_shentsize
print(d[end:])
```

Вывод:

```
b'nto{elf_overlay_appended}\x00'
```

## Шаг 3: note-секции
Формат записи `.note`:
`[namesz(4)][descsz(4)][type(4)][name][desc][padding]`. Тип `NT_GNU_BUILD_ID`
(3) содержит build-id. Тип можно задать произвольный, а `desc` — произвольной
длины. `readelf -n bin` покажет заметки.

## Шаг 4: другие каналы в ELF
- **Секция `.comment`** — строки компилятора, легко дополнить.
- **Padding секций** — выравнивание до границы, туда помещаются данные.
- **Строковые таблицы** (`.strtab`, `.dynstr`) — строки, которые не используются.
- **Неиспользуемые символы** в таблице символов.
- **Заголовок** — поля `e_ident[7..15]` (padding) и зарезервированные байты.

## Шаг 5: инструменты
- `readelf -a bin` — заголовки, секции, заметки.
- `objdump -s -j .note.gnu.build-id bin` — содержимое заметки.
- `binwalk bin` — поиск встроенных/дописанных данных.
- `python3` + `struct` — ручной разбор.

## Что мы теперь знаем
- ELF: заголовок, таблицы секций/сегментов, секции, overlay.
- Overlay после конца ELF не влияет на работу, но хранит данные.
- Note-секции — штатное место для произвольных «заметок».
- `readelf` и `binwalk` — основные инструменты.

## Квиз

Проверь себя.

```quiz
- question: "Что такое overlay в ELF?"
  options:
    - "Данные, дописанные после конца ELF-структуры"
    - "Секция .text"
    - "Точка входа"
    - "Динамическая библиотека"
  answer: 0
  explanation: "Overlay лежит за пределами таблиц и игнорируется загрузчиком."
- question: "Как определить конец ELF-структуры?"
  options:
    - "Максимум из конца таблицы секций и таблицы сегментов"
    - "По размеру файла"
    - "По первой строке"
    - "По точке входа"
  answer: 0
  explanation: "Overlay начинается после последней легитимной структуры."
- question: "Что хранит note-секция?"
  options:
    - "Заметки вида namesz/descsz/type + name + desc"
    - "Исходный код"
    - "Пароли"
    - "Картинки"
  answer: 0
  explanation: "Например, NT_GNU_BUILD_ID — build-id."
- question: "Какая команда покажет заметки ELF?"
  options:
    - "readelf -n bin"
    - "ls -l bin"
    - "cat bin"
    - "file bin"
  answer: 0
  explanation: "readelf -n выводит содержимое note-секций."
```

## Куда дальше
ELF разобран. Родственный формат — Mach-O (macOS), где данные прячут в
load-командах LC_NOTE. О нём — в следующем уроке.

## Где пригодится
- **CTF:** задачи с бинарниками и «странным» хвостом.
- **Форензика:** поиск данных в исполняемых уликах.
- **Blue team:** детект закладок в бинарниках.
""".strip()

elf_parser = (
    "import struct\n"
    "d = open('bin','rb').read()\n"
    "e_shoff = struct.unpack_from('<Q', d, 0x28)[0]\n"
    "e_shnum = struct.unpack_from('<H', d, 0x3c)[0]\n"
    "e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]\n"
    "end = e_shoff + e_shnum*e_shentsize\n"
    "print(d[end:].split(b'\\x00')[0].decode())\n"
)
elf_task = ("# Задача: overlay после конца ELF\n\n"
            "`bin` — ELF-файл с данными, дописанными после таблицы секций.\n\n"
            "1. `xxd -l 64 bin`.\n"
            "2. `python3 elf.py` — вычисление конца ELF и чтение overlay.\n"
            "3. `python3 elf.py | grep nto > found.txt`.\n")
emit("stego-elf-notes", """---
id: stego-elf-notes
title: "ELF: overlay после конца файла и note-секции"
category: stego
parent: stego-module-binary-adv
difficulty: medium
order: 3
tags: [stego, elf, overlay, note-section, binary, readelf]
prerequisites: [stego-docker-layers]
useful_for:
  - "CTF Stego: бинарники и странный хвост"
  - "Форензика: данные в исполняемых уликах"
  - "Blue team: детект закладок в бинарниках"
estimated_minutes: 16
summary: "Структура ELF: заголовок, таблицы секций/сегментов, note-секции. Overlay после конца файла, произвольные note-записи, .comment и padding как каналы."
lab:
  kind: shell
  title: "Практика: overlay за концом ELF"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, bin, elf.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Магия ELF — `\\x7fELF`."
    - "e_shoff — 8 байт по смещению 0x28 (64-бит)."
    - "`python3 elf.py` вычисляет конец и печатает overlay."
    - "`python3 elf.py | grep nto > found.txt`."
---

""" + elf_body + "\n", lab_json(
    "stego-elf-notes", elf_flag, elf_task,
    [("bin", ("b64", elf_bytes)), ("elf.py", ("text", elf_parser))],
    [{"match": "elf\\.py", "example": "python3 elf.py", "output": elf_flag + "\n"}]))

# ===========================================================================
# stego-macho
# ===========================================================================
macho_body = r"""
## Вопрос, с которого всё начинается
Mach-O — формат исполняемых файлов macOS. Внутри — заголовок и цепочка
**load-команд**: сегменты, символы, подпись. Среди них есть `LC_NOTE` — команда
для произвольной «заметки» (её использует, например, отладчик). Данные в ней
могут быть любыми, и система их не проверяет. Ты получил Mach-O с `LC_NOTE` —
как достать содержимое?

## Наш пример
Возьмём `macho` — 64-битный Mach-O с одной командой `LC_NOTE`. Разберём
заголовок и пройдём по load-командам.

## Шаг 1: заголовок Mach-O
Первые 32 байта 64-битного Mach-O (`mach_header_64`):
- `magic` — `0xfeedfacf` (little-endian);
- `cputype`, `cpusubtype`;
- `filetype`;
- `ncmds` — число load-команд;
- `sizeofcmds` — суммарный размер;
- `flags`, `reserved`.

Всё little-endian. После заголовка (смещение 32) начинается первая load-команда.

## Шаг 2: разбор load-команд
Каждая команда: `[cmd(4)][cmdsize(4)][тело]`. Команды выровнены по 4/8 байт.
Интересующие нас:
- `LC_SEGMENT_64` (0x19) — сегменты `__TEXT`, `__DATA`;
- `LC_SYMTAB` (0x02) — таблица символов;
- `LC_CODE_SIGNATURE` (0x1d) — подпись;
- `LC_NOTE` (0x31) — заметка: `data_owner[16]`, `offset(8)`, `size(8)`.

## Шаг 3: LC_NOTE
Структура `note_command`:
`[cmd=0x31(4)][cmdsize=40(4)][data_owner(16)][offset(8)][size(8)]`.
`data_owner` — строка владельца, `offset` — смещение данных в файле, `size` —
длина. Данные — произвольные.

```python
import struct
d = open('macho','rb').read()
ncmds = struct.unpack_from('<I', d, 0x10)[0]
p = 0x20
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, p)
    if cmd == 0x31:
        owner = d[p+8:p+24].split(b'\x00')[0].decode()
        off, size = struct.unpack_from('<QQ', d, p+24)
        print(owner, d[off:off+size].decode())
    p += cmdsize
```

Вывод:

```
stego nto{macho_lc_note}
```

## Шаг 4: где ещё прячут данные в Mach-O
- **`LC_NOTE`** — штатная произвольная заметка.
- **Padding load-команд** — выравнивание создаёт свободные байты.
- **`__cstring`/`__const`** — строковые сегменты, неиспользуемые строки.
- **Fat/universal binary** — несколько архитектур в одном файле, между ними
  padding.
- **Code signature** — данные подписи (её можно не проверять).

## Шаг 5: инструменты
- `otool -l macho` — список load-команд.
- `otool -h macho` — заголовок.
- `lipo -info macho` — архитектуры fat-файла.
- `nm`, `strings`, `binwalk` — вспомогательно.

## Что мы теперь знаем
- Mach-O: заголовок (magic 0xfeedfacf) и цепочка load-команд.
- `LC_NOTE` хранит произвольную заметку с владельцем, offset и size.
- Padding команд, строковые сегменты и fat-padding — дополнительные каналы.
- `otool -l` — основной инструмент разбора.

## Квиз

Проверь себя.

```quiz
- question: "Как называется структура, идущая после заголовка Mach-O?"
  options:
    - "Load-команды (сегменты, символы, подпись)"
    - "Секции ELF"
    - "Чанки PNG"
    - "Записи tar"
  answer: 0
  explanation: "Заголовок + цепочка load-команд — основа Mach-O."
- question: "Что хранит LC_NOTE?"
  options:
    - "Владельца, offset и size произвольной заметки"
    - "Пароль"
    - "Исходный код"
    - "Сжатую картинку"
  answer: 0
  explanation: "note_command: data_owner[16], offset, size."
- question: "Какова магия 64-битного Mach-O (little-endian)?"
  options:
    - "0xfeedfacf"
    - "0x7f454c46"
    - "0x89504e47"
    - "0x504b0304"
  answer: 0
  explanation: "mach_header_64 magic = 0xfeedfacf."
- question: "Какая команда выведет load-команды?"
  options:
    - "otool -l macho"
    - "readelf -a macho"
    - "objdump -d macho"
    - "file macho"
  answer: 0
  explanation: "otool -l печатает load-команды Mach-O."
```

## Куда дальше
Бинарные форматы разобраны. Дальше — инструментальные приёмы: CyberChef, binwalk
и decision-tree для CTF. А пока запомни: в любом контейнере есть «служебное»
поле, которое никто не проверяет.

## Где пригодится
- **CTF:** задачи с macOS-бинарниками.
- **Форензика:** анализ Mach-O улик.
- **Blue team:** закладки в подписанных бинарниках.
""".strip()

macho_parser = (
    "import struct\n"
    "d = open('macho','rb').read()\n"
    "ncmds = struct.unpack_from('<I', d, 0x10)[0]\n"
    "p = 0x20\n"
    "for _ in range(ncmds):\n"
    "    cmd, cmdsize = struct.unpack_from('<II', d, p)\n"
    "    if cmd == 0x31:\n"
    "        owner = d[p+8:p+24].split(b'\\x00')[0].decode()\n"
    "        off, size = struct.unpack_from('<QQ', d, p+24)\n"
    "        print(d[off:off+size].decode())\n"
    "    p += cmdsize\n"
)
macho_task = ("# Задача: LC_NOTE в Mach-O\n\n"
              "`macho` — 64-битный Mach-O с одной командой LC_NOTE (0x31).\n\n"
              "1. `xxd -l 32 macho`.\n"
              "2. `python3 macho.py` — разбор load-команд.\n"
              "3. `python3 macho.py | grep nto > found.txt`.\n")
emit("stego-macho", """---
id: stego-macho
title: "Mach-O: load-команды, LC_NOTE и padding"
category: stego
parent: stego-module-binary-adv
difficulty: medium
order: 4
tags: [stego, macho, macos, lc-note, load-command, binary]
prerequisites: [stego-elf-notes]
useful_for:
  - "CTF Stego: macOS-бинарники"
  - "Форензика: анализ Mach-O улик"
  - "Blue team: закладки в подписанных бинарниках"
estimated_minutes: 16
summary: "Структура Mach-O: заголовок (magic 0xfeedfacf) и цепочка load-команд. LC_NOTE с произвольной заметкой, padding команд, строковые сегменты и fat-binary как носители."
lab:
  kind: shell
  title: "Практика: разбор LC_NOTE"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, macho, macho.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Magic 64-битного Mach-O — 0xfeedfacf."
    - "ncmds — по смещению 0x10, команды начинаются с 0x20."
    - "`python3 macho.py` идёт по командам и печатает данные LC_NOTE."
    - "`python3 macho.py | grep nto > found.txt`."
---

""" + macho_body + "\n", lab_json(
    "stego-macho", macho_flag, macho_task,
    [("macho", ("b64", macho_bytes)), ("macho.py", ("text", macho_parser))],
    [{"match": "macho\\.py", "example": "python3 macho.py", "output": macho_flag + "\n"}]))

# ===========================================================================
# binary hub
# ===========================================================================
binary_hub = """---
id: stego-module-binary-adv
title: "Модуль: Двоичные форматы и архивы (Git, Docker, ELF, Mach-O)"
category: stego
parent: stego-binary-carriers
difficulty: medium
order: 5
tags: [stego, roadmap, git, docker, elf, macho, binary]
prerequisites: [stego-binary-carriers]
useful_for:
  - "CTF Stego: репозитории, образы, бинарники"
  - "Форензика: данные в двоичных уликах"
  - "Blue team: закладки в артефактах сборки"
estimated_minutes: 8
summary: "Навигационный модуль по двоичным носителям: Git-объекты (zlib + blob), Docker-слои (tar + whiteouts), ELF (overlay, note-секции) и Mach-O (load-команды, LC_NOTE). Общий приём — найти «служебное» поле или хвост."
---

## Зачем этот модуль

Современные артефакты разработки и исполнения — репозитории, образы, бинарники —
сложные контейнеры. У каждого есть служебные области: висячие объекты, whiteouts,
note-секции, load-команды. Именно там прячут данные, и именно их не проверяют
инструменты.

## Что разберём

- **stego-git-objects** — Git-объекты (zlib + `blob <len>\\0`), висячие blob,
  packfiles.
- **stego-docker-layers** — Docker/OCI-образы: манифест, слои-tar, whiteouts.
- **stego-elf-notes** — ELF: overlay после конца файла, note-секции, `.comment`.
- **stego-macho** — Mach-O: load-команды, `LC_NOTE`, padding, fat-бинарь.

## Как проходить

По порядку. В каждом уроке — реальный двоичный артефакт и короткий Python-парсер
(`zlib`, `tarfile`, `struct`).

## Что вы будете уметь

- Распаковывать Git-объект и находить висячие blob.
- Разбирать слои Docker-образа и whiteouts.
- Вычислять конец ELF и читать overlay.
- Проходить по load-командам Mach-O.
"""
write("content/stego/stego-module-binary-adv.md", binary_hub + "\n")

print("batch 2c done")
