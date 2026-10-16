---
id: forensics-python-tooling
title: "Python-форензика: pytsk3, Volatility3 API, pyshark"
category: forensics
parent: forensics-tooling
difficulty: medium
order: 5
tags: [python, pytsk3, volatility3, pyshark, automation, scripting]
prerequisites: [forensics-tooling]
useful_for:
  - "CTF Forensics категория"
  - "Автоматизация анализа"
  - "Incident Response"
estimated_minutes: 52
summary: "Скриптование форензика на Python: доступ к файловым системам через pytsk3, использование API Volatility3, разбор PCAP через pyshark и построение собственных пайплайнов для нестандартных задач."
lab:
  kind: shell
  title: 'Практика: карвинг встроенного ZIP из образа'
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, disk.img, carve.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'ZIP начинается с сигнатуры `PK\x03\x04` (50 4b 03 04).'
    - 'Найди смещение сигнатуры в образе.'
    - 'Вырежи байты от сигнатуры и открой как ZIP (в памяти).'
    - '`python3 carve.py | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

Готовые инструменты (`fls`, `vol`, `tshark`) покрывают большинство задач. Но иногда нужен **свой пайплайн**: обработать тысячи файлов, извлечь нестандартное поле, связать артефакты из разных источников. Тут на сцену выходит Python — язык форензика де-факто.

## Наш пример: вытащить все PST-файлы из образа

У нас есть образ `disk.img`, и задача конкретная: найти и извлечь **все** файлы почты `.pst`, не монтируя образ. Сделаем это скриптом на Python с библиотекой `pytsk3`.

## Шаг 1: pytsk3 — доступ к файловой системе

`pytsk3` — привязка The Sleuth Kit к Python. Открываем образ, смотрим разделы:

```python
import pytsk3

img = pytsk3.Img_Info("disk.img")
vol = pytsk3.Volume_Info(img)
for p in vol:
    print(p.addr, p.start, p.len, p.desc.decode())
```

Важная тонкость: `pytsk3.FS_Info` принимает **offset в байтах**, а не в секторах. Если раздел начинается с сектора 2048, offset = `2048 * 512`:

```python
fs = pytsk3.FS_Info(img, offset=2048 * 512)
root = fs.open_dir(path="/")
for e in root:
    name = e.info.name.name.decode(errors="ignore")
    print(name)
```

Имена декодируем с `errors="ignore"` — в ФС встречаются не-UTF8 байты.

## Шаг 2: рекурсивный обход

Файловая система — дерево. Обходим его рекурсией, различая каталоги и файлы по `meta.type`:

```python
def walk(fs, path="/", depth=0):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".", ".."):
            continue
        if e.info.meta and e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            walk(fs, path.rstrip("/") + "/" + name, depth+1)
        else:
            print(path + "/" + name)
```

## Шаг 3: извлекаем найденные файлы

Дополняем обход условием: если файл заканчивается на `.pst`, читаем его содержимое через `read_random` и сохраняем:

```python
import pytsk3, os
img = pytsk3.Img_Info("disk.img")
fs = pytsk3.FS_Info(img, offset=2048*512)

def extract(fs, path, outdir):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".", ".."):
            continue
        full = path.rstrip("/") + "/" + name
        if e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            extract(fs, full, outdir)
        elif name.lower().endswith(".pst"):
            data = e.read_random(0, e.info.meta.size)
            open(os.path.join(outdir, name), "wb").write(data)
            print("extracted", full, e.info.meta.size)

extract(fs, "/", "/evidence/pst")
```

Скрипт рекурсивно обходит ФС и вытаскивает все PST, не монтируя образ. Работаем **read-only** — оригинал не меняется.

## Шаг 4: другие библиотеки

Python даёт доступ ко всем ключевым источникам:

| Библиотека | Область |
|------------|---------|
| pytsk3 | файловые системы |
| volatility3 | память |
| pyshark | сеть (PCAP) |
| yara-python | сигнатуры |
| python-registry | реестр |

Для памяти на практике удобнее вызывать `vol` через `subprocess` и парсить JSON, чем копаться в API:

```python
import subprocess, json
def run_vol(dump, plugin):
    out = subprocess.run(["vol","-r","json","-f",dump,plugin],
                         capture_output=True, text=True)
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
for rec in run_vol("mem.raw", "windows.pslist"):
    print(rec["PID"], rec["ImageFileName"])
```

Для сети `pyshark` оборачивает `tshark`. На больших PCAP используйте `only_summaries=True`, чтобы не грузить все слои в память:

```python
import pyshark
cap = pyshark.FileCapture("big.pcap", only_summaries=True)
for p in cap:
    print(p.protocol, p.length, p.info)
```

## Шаг 5: воспроизводимость и логирование

Форензические скрипты должны запускаться воспроизводимо. Фиксируйте зависимости:

```bash
$ python3 -m venv /opt/forensics-venv
$ source /opt/forensics-venv/bin/activate
$ pip install pytsk3 volatility3 pyshark yara-python python-registry
$ pip freeze > requirements.txt
```

Логируйте ход выполнения — это часть доказательства:

```python
import logging
logging.basicConfig(filename="/evidence/run.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
```

Читайте данные **потоково** (не грузите образ целиком), оборачивайте доступ к полям в `try/except` (поля есть не всегда), параметризуйте вход/выход вместо хардкода путей.

## Полный прогон: от образа до манифеста

Соберём всё вместе в один рабочий скрипт. Задача — не просто вытащить PST, а оставить **манифест** (список файлов с путями, размерами и хешами), который потом приложим к отчёту.

```python
import pytsk3, hashlib, csv, logging, os

logging.basicConfig(filename="/evidence/run.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

img = pytsk3.Img_Info("disk.img")
fs  = pytsk3.FS_Info(img, offset=2048 * 512)   # offset в БАЙТАХ
out = "/evidence/pst"
os.makedirs(out, exist_ok=True)
rows = []

def walk(path="/"):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".", ".."):
            continue
        full = path.rstrip("/") + "/" + name
        meta = e.info.meta
        if meta is None:
            continue
        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            walk(full)
        elif name.lower().endswith(".pst"):
            data = e.read_random(0, meta.size)
            sha = hashlib.sha256(data).hexdigest()
            open(os.path.join(out, name), "wb").write(data)
            rows.append({"path": full, "size": meta.size, "sha256": sha})
            logging.info("extracted %s (%d bytes)", full, meta.size)

walk()
with open("/evidence/pst-manifest.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["path", "size", "sha256"])
    w.writeheader(); w.writerows(rows)
print("done:", len(rows), "files")
```

Запуск:

```bash
$ python3 extract_pst.py
done: 3 files
$ cat /evidence/pst-manifest.csv
path,size,sha256
/Users/bob/AppData/Local/Microsoft/Outlook/outlook.pst,52428800,9f2c...
/Documents/archive.pst,10485760,3a7e...
/Downloads/backup.pst,2097152,77bd...
```

Теперь у нас не «какие-то файлы», а проверяемый набор: любой коллега повторит скрипт и получит те же хеши. Это и есть воспроизводимость, о которой мы говорили в уроке про доказательства.

## Обработка ошибок: почему без неё нельзя

В реальном образе поля отсутствуют, а байты «битые». Скрипт без защиты падает на первом же странном файле и теряет всю работу:

```python
try:
    data = e.read_random(0, meta.size)
except (IOError, OSError) as err:
    logging.warning("read failed %s: %s", full, err)
    continue
```

Правила простые: оборачивайте доступ к полям и чтение в `try/except`, декодируйте имена с `errors="ignore"`, читайте большие файлы **порциями** (`read_random(off, chunk)`) и логируйте каждое исключение. Тогда падение одного файла не убивает прогон.

## Частые вопросы

**Чем pytsk3 отличается от вызова `fls`?** Результат тот же, но в Python вы получаете структуры, а не текст, — можно фильтровать, агрегировать и связывать с другими данными программно.

**Можно ли так же читать удалённые файлы?** Да: у удалённого файла `meta.flags` содержит признак `UNALLOC`, но inode и содержимое часто ещё целы — читайте так же, как обычный файл.

**Как быть с зашифрованным образом?** Сначала расшифруйте контейнер (LUKS/BitLocker) на копии, затем подавайте расшифрованный образ в `pytsk3`.

**Нужен ли GUI?** Нет. Для пакетной обработки скрипт быстрее и воспроизводимее, а GUI (Autopsy) удобен для первого прохода.

## Что мы теперь знаем

- **pytsk3** даёт программный доступ к ФС; offset задаётся в **байтах**.
- Рекурсивный обход ФС — основа собственных пайплайнов.
- Volatility3 удобно вызывать через `subprocess` и парсить JSON.
- `pyshark` оборачивает `tshark`; `only_summaries=True` критично для больших PCAP.
- Фиксируйте зависимости (`requirements.txt`) для воспроизводимости.
- Читайте потоково, логируйте, обрабатывайте исключения.

## Если не сработало: производительность и ошибки

Частые грабли в собственных скриптах:

- **Загрузка всего в память.** Большие PCAP/образы убьют процесс — читайте потоково и используйте генераторы.
- **Неверные единицы.** `pytsk3` — байты, sleuthkit CLI — секторы.
- **Кодировки.** Декодируйте имена с `errors="ignore"`.
- **Отсутствие обработки ошибок.** Поля `pyshark` есть не всегда — оборачивайте доступ в `try/except`.
- **Работа с оригиналом.** Только read-only.

Полезный приём — связать несколько библиотек в одном скрипте: обойти ФС через `pytsk3`, прогнать найденные файлы через `yara-python`, а результаты свести в CSV-манифест. Сохраняйте такие скрипты как артефакты — коллеги переиспользуют их, а вы не пишете одно и то же дважды.

## yara-python: скан извлечённых файлов

Вытащив файлы, прогони их по сигнатурам — прямо в том же скрипте, не выгружая во внешний
инструмент:

```python
import yara, os
rules = yara.compile(filepath="malware.yar")
for name in os.listdir(out):
    for m in rules.match(os.path.join(out, name)):
        print(name, m.rule, m.strings)
```

`rules.match` возвращает сработавшие правила и **смещения** совпавших строк — по ним
видно, где именно в файле сигнатура. Компилируй правила **один раз, вне цикла**:
повторная компиляция на каждом файле убивает производительность на больших наборах.
Это связывает два блока — доступ к ФС (`pytsk3`) и детект (`yara-python`) — в один
пайплайн.

## Параллельная обработка больших образов

Один процесс не упрётся в CPU, но упрётся в **память**: наивное `read_random(0, size)`
для гигабайтных файлов съедает всю RAM. Два правила спасают прогон.

Первое — **читай порциями** и хешируй потоково:

```python
h = hashlib.sha256()
off = 0
while off < meta.size:
    chunk = e.read_random(off, min(1 << 20, meta.size - off))
    h.update(chunk)
    off += len(chunk)
```

Второе — **разделяй работу** между процессами, но помни: `pytsk3`-хендлы не
передаются между процессами, поэтому каждый воркер открывает **свой** объект `FS_Info`.

```python
from multiprocessing import Pool
with Pool(4) as p:
    results = p.map(scan_partition, partitions)
```

Такой скрипт обработает образ за минуты там, где наивный цикл висит часами, а память
останется в разумных пределах.

## YARA из Python: скан образа по сигнатурам

Когда задача — найти в образе все файлы, похожие на конкретный образец, вручную
обходить дерево и сверять байты бессмысленно. `yara-python` даёт ту же логику, что и
утилита `yara`, но прямо внутри пайплайна:

```python
import yara
rules = yara.compile(filepath="malware.yar")
for path in walk_files(fs):
    data = read_file(fs, path)
    for match in rules.match(data=data):
        print(path, match.rule, match.namespace)
```

Компилируйте правила **один раз** до цикла — `yara.compile` дорогой, а `rules.match`
на каждый файл дешёвый. Для больших образов передавайте `data=` (скан буфера), а не
имя файла: файл уже прочитан через pytsk3, лишний ввод-вывод не нужен. Если правил
много, используйте `yara.compile(filepaths={...})` и обращайтесь к нужному
пространству имён.

## Строим таймлайн из метаданных файловой системы

Метаданные, которые pytsk3 отдаёт бесплатно, — это готовый таймлайн. У каждой записи
`e.info.meta` есть поля `crtime`, `mtime`, `atime`, `ctime` (в секундах эпохи), размер
и флаги. Соберём их в список и отсортируем:

```python
import datetime
rows = []
def collect(fs, path="/"):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".", "..") or not e.info.meta:
            continue
        full = path.rstrip("/") + "/" + name
        if e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            collect(fs, full)
        else:
            rows.append((e.info.meta.mtime, full, e.info.meta.size))
collect(fs)
rows.sort()
for ts, p, sz in rows[:20]:
    print(datetime.datetime.utcfromtimestamp(ts), p, sz)
```

Такой таймлайн сразу показывает всплески записи — момент, когда злоумышленник
разворачивал полезную нагрузку. Дальше его сшивают с журналами ОС и сетевыми дампами.

## Параллелизм и потоковая обработка больших образов

Образ на сотни гигабайт нельзя прочитать в память целиком. Два правила: **читайте
потоково** и **не плодите лишние копии**. `read_random(offset, size)` позволяет читать
окно нужного размера, а не весь файл:

```python
CHUNK = 1 << 20
def sha256_stream(fs, entry):
    h = hashlib.sha256()
    off = 0
    size = entry.info.meta.size
    while off < size:
        h.update(entry.read_random(off, min(CHUNK, size - off)))
        off += CHUNK
    return h.hexdigest()
```

Для ускорения распараллельте **независимые файлы** через `concurrent.futures`:
`ThreadPoolExecutor` подходит, если узкое место — ввод-вывод (один образ, много
небольших файлов), `ProcessPoolExecutor` — если тяжёлый CPU (YARA, хеширование,
энтропия). Держите число воркеров небольшим (4-8): случайное чтение с диска от
избыточной параллели доступа только замедляется. И всегда логируйте, какой диапазон
уже обработан, чтобы прогон можно было возобновить после сбоя, не начиная заново.

## Квиз

Проверь себя.

```quiz
- question: "Какая библиотека даёт программный доступ к файловым системам в Python?"
  options:
    - "pyshark"
    - "pytsk3"
    - "yara-python"
    - "python-registry"
  answer: 1
  explanation: "pytsk3 — привязка The Sleuth Kit к Python."
- question: "В каких единицах pytsk3 ждёт offset раздела?"
  options:
    - "в секторах"
    - "в байтах"
    - "в кластерах"
    - "в блоках"
  answer: 1
  explanation: "pytsk3.FS_Info принимает offset в байтах."
- question: "Что даёт pyshark?"
  options:
    - "доступ к полям пакетов через обёртку tshark"
    - "монтирование диска"
    - "расшифровку TLS"
    - "сбор RAID"
  answer: 0
  explanation: "pyshark оборачивает tshark и предоставляет поля пакетов в Python."
- question: "Почему Volatility3 часто вызывают через subprocess?"
  options:
    - "API не существует"
    - "CLI с JSON-выводом проще и стабильнее для парсинга"
    - "API требует GPU"
    - "Так быстрее"
  answer: 1
  explanation: "JSON-вывод CLI удобно парсить; это надёжнее прямого API."
- question: "Зачем фиксировать requirements.txt?"
  options:
    - "для воспроизводимости окружения"
    - "для шифрования образа"
    - "для сжатия PCAP"
    - "для сборки RAID"
  answer: 0
  explanation: "Фиксация версий гарантирует, что скрипт даст тот же результат позже."
```

## Куда дальше

Мы научились строить собственные пайплайны. Это последний урок блока про инструменты — дальше вы можете комбинировать всё изученное: ФС (`pytsk3`), память (`vol`), сеть (`pyshark`), детект (YARA) — в один скрипт под конкретную задачу. А пока главное запомни: **Python объединяет разрозненные утилиты в воспроизводимый пайплайн; читай потоково, логируй, фиксируй зависимости**.

## Где пригодится

- **CTF:** нестандартные задачи, где нужен свой скрипт.
- **IR:** автоматизация повторяющихся шагов.
- **Threat Hunting:** массовая обработка артефактов.
- **Разработка:** собственные форензические инструменты.
