---
id: forensics-python-tooling
title: "Python-форензика: pytsk3, Volatility3 API, pyshark"
category: forensics
parent: forensics-tooling
difficulty: medium
order: 3
tags: [python, pytsk3, volatility3, pyshark, automation, scripting]
prerequisites: [forensics-tooling]
useful_for:
  - "CTF Forensics категория"
  - "Автоматизация анализа"
  - "Incident Response"
estimated_minutes: 52
summary: "Скриптование форензика на Python: доступ к файловым системам через pytsk3, использование API Volatility3, разбор PCAP через pyshark и построение собственных пайплайнов для нестандартных задач."
---

Готовые инструменты покрывают большинство задач, но иногда нужен **свой пайплайн**: обработать тысячи файлов, извлечь нестандартное поле, связать артефакты. Python — язык форензика де-факто: библиотеки `pytsk3` (ФС), `volatility3` (память), `pyshark` (сеть), `python-registry`, `yara-python` дают программный доступ ко всему.

## pytsk3: доступ к файловым системам

`pytsk3` — привязка The Sleuth Kit к Python. Позволяет открыть образ и обойти ФС программно.

```python
import pytsk3

img = pytsk3.Img_Info("disk.img")
# Список разделов
vol = pytsk3.Volume_Info(img)
for p in vol:
    print(p.addr, p.start, p.len, p.desc.decode())
# Открыть конкретный раздел по offset
fs = pytsk3.FS_Info(img, offset=2048*512)
# Обход корня
root = fs.open_dir(path="/")
for e in root:
    name = e.info.name.name.decode()
    meta = e.info.meta
    if meta:
        print(name, meta.type, meta.size)
```

Полезные приёмы: рекурсивный обход (`fs.open_dir`), чтение файла (`fs.open(path).read_random`), работа с удалёнными (проверка `meta.flags`), доступ к потокам ADS.

```python
# Рекурсивный обход и поиск по расширению
def walk(fs, path="/", depth=0):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".", ".."):
            continue
        if e.info.meta and e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            walk(fs, path.rstrip("/") + "/" + name, depth+1)
        else:
            if name.lower().endswith((".jpg", ".png")):
                print(path + "/" + name)
```

## Volatility3 API

Volatility3 можно использовать как библиотеку:

```python
import volatility3
from volatility3.framework import contexts, constants
from volatility3.framework.layers import physical
from volatility3.plugins.windows import pslist

ctx = contexts.Context()
# ... настройка слоёв и символов
# Обычно проще вызывать через CLI и парсить JSON:
```

На практике чаще вызывают `vol` из скрипта и парсят JSON-вывод — это надёжнее, чем копаться в API:

```python
import subprocess, json
def run_vol(dump, plugin):
    out = subprocess.run(["vol","-r","json","-f",dump,plugin],
                         capture_output=True, text=True)
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
for rec in run_vol("mem.raw","windows.pslist"):
    print(rec["PID"], rec["ImageFileName"])
```

## pyshark: разбор PCAP

`pyshark` оборачивает tshark и даёт доступ к полям пакетов:

```python
import pyshark
cap = pyshark.FileCapture("capture.pcap", display_filter="http.request")
for pkt in cap:
    try:
        print(pkt.ip.src, pkt.http.host, pkt.http.request_uri)
    except AttributeError:
        pass
cap.close()
```

Для больших PCAP используйте `only_summaries=True` (быстрее) и фильтры, чтобы не грузить всё в память.

## YARA и реестр из Python

```python
# yara-python
import yara
rules = yara.compile(filepath="rules.yar")
matches = rules.match("/evidence/suspect.bin")
for m in matches:
    print(m.rule, m.strings)

# python-registry
from Registry import Registry
reg = Registry.Registry("SYSTEM")
key = reg.open("ControlSet001\\Services\\bam\\State\\UserSettings")
for sk in key.subkeys():
    print(sk.name(), [v.name() for v in sk.values()])
```

## Разобранный пример

```python
# Найти все файлы с расширением .pst и вытащить их из образа
import pytsk3, os
img = pytsk3.Img_Info("disk.img")
fs = pytsk3.FS_Info(img, offset=2048*512)
def extract(fs, path, outdir):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".",".."): continue
        full = path.rstrip("/")+"/"+name
        if e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            extract(fs, full, outdir)
        elif name.lower().endswith(".pst"):
            data = e.read_random(0, e.info.meta.size)
            open(os.path.join(outdir, name), "wb").write(data)
            print("extracted", full, e.info.meta.size)
extract(fs, "/", "/evidence/pst")
```

Скрипт рекурсивно обходит ФС и вытаскивает все PST-файлы, не монтируя образ.

## Краевые случаи и подводные камни

- **Offset раздела.** pytsk3 ждёт offset в байтах, не секторах.
- **Кодировки имён.** Декодируйте с `errors="ignore"`.
- **Память.** Большие PCAP/образы в память не грузите — читайте потоково.
- **Символы.** Volatility API требует корректных символов.
- **Скорость.** Python медленнее CLI; для массовых операций оптимизируйте.
- **Версии.** API библиотек меняется; фиксируйте зависимости.
- **Целостность.** Открывайте образы read-only.
- **Ошибки.** Оборачивайте доступ к полям пакетов в try/except (поля не всегда есть).

## Построение собственного пайплайна

Типовая задача: обработать образ, извлечь артефакты, построить отчёт. Пример пайплайна на Python:

```python
import pytsk3, os, csv, hashlib

IMG = "disk.img"
OFFSET = 2048 * 512
OUT = "/evidence/extracted"
os.makedirs(OUT, exist_ok=True)

img = pytsk3.Img_Info(IMG)
fs = pytsk3.FS_Info(img, offset=OFFSET)

manifest = []
def walk(fs, path="/"):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".", ".."):
            continue
        full = path.rstrip("/") + "/" + name
        meta = e.info.meta
        if meta is None:
            continue
        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            walk(fs, full)
        else:
            data = e.read_random(0, meta.size)
            sha = hashlib.sha256(data).hexdigest()
            manifest.append((full, meta.size, sha))

walk(fs)
with open(os.path.join(OUT, "manifest.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["path", "size", "sha256"])
    w.writerows(manifest)
print("files:", len(manifest))
```

Такой скрипт даёт манифест всех файлов с хешами — основу для дальнейшего анализа и отчёта.

## Парсинг вывода Volatility3

```python
import subprocess, json

def vol(dump, plugin, **kwargs):
    cmd = ["vol", "-r", "json", "-f", dump, plugin]
    for k, v in kwargs.items():
        cmd += [f"--{k}", str(v)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]

# Найти процессы с внешними соединениями
procs = {p["PID"]: p["ImageFileName"] for p in vol("mem.raw", "windows.pslist")}
for c in vol("mem.raw", "windows.netscan"):
    if c.get("State") == "ESTABLISHED" and c.get("ForeignAddr", "").startswith(("10.", "192.")):
        print(procs.get(c.get("PID")), c.get("ForeignAddr"), c.get("ForeignPort"))
```

Так вы программно связываете процессы и соединения — основа hunt-скриптов.

## Работа с pyshark эффективно

```python
import pyshark

# Только summary (быстро) — без разбора всех полей
cap = pyshark.FileCapture("big.pcap", only_summaries=True)
for p in cap:
    print(p.protocol, p.length, p.info)

# Фильтр на уровне tshark
cap = pyshark.FileCapture("big.pcap", display_filter="dns.flags.response == 0")
names = set()
for p in cap:
    try:
        names.add(p.dns.qry_name)
    except AttributeError:
        pass
cap.close()
print(len(names), "unique domains")
```

`only_summaries=True` критично для больших захватов: не грузит все слои в память.

## YARA и реестр

```python
import yara
rules = yara.compile(filepaths={"beacon": "beacon.yar", "flag": "flag.yar"})
for root, _, files in os.walk("/evidence"):
    for fn in files:
        path = os.path.join(root, fn)
        for m in rules.match(path):
            print(m.rule, path)

from Registry import Registry
reg = Registry.Registry("SOFTWARE")
try:
    key = reg.open("Microsoft\\Windows\\CurrentVersion\\Run")
    for v in key.values():
        print(v.name(), v.value())
except Exception as e:
    print("no key", e)
```

## Автоматизация и артефакты

- Сохраняйте скрипты в репозиторий (`record_artifact`) — коллеги переиспользуют.
- Пишите **потоково**, чтобы не съесть RAM.
- Логируйте прогресс и ошибки (в отдельный файл).
- Обрабатывайте исключения (отсутствующие поля/файлы).
- Тестируйте на маленьких образцах.

## Типичные ошибки

- **Загрузка всего в память.** Большие PCAP/образы убьют процесс.
- **Неверные единицы.** pytsk3 — байты, sleuthkit CLI — секторы.
- **Кодировки.** Декодируйте имена с `errors="ignore"`.
- **Отсутствие обработки ошибок.** pyshark-поля не всегда есть.
- **Работа с оригиналом.** Только read-only.
- **Нет версионирования.** Скрипт со временем «дрейфует».
- **Хардкод путей.** Параметризуйте вход/выход.

## Управление зависимостями и воспроизводимость

Форензические скрипты должны запускаться воспроизводимо:

```bash
# Виртуальное окружение и фиксация версий
python3 -m venv /opt/forensics-venv
source /opt/forensics-venv/bin/activate
pip install pytsk3 volatility3 pyshark yara-python python-registry
pip freeze > requirements.txt
# Позже — восстановить окружение
pip install -r requirements.txt
```

Фиксируйте версии: обновление библиотеки может изменить поведение скрипта.

## Логирование и обработка ошибок

```python
import logging
logging.basicConfig(filename="/evidence/run.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
try:
    process(path)
except Exception as e:
    logging.error("failed on %s: %s", path, e)
```

Лог выполнения — часть доказательства: он показывает, что именно делал скрипт.

## Производительность

- Читайте **блоками**, не целиком.
- Используйте **генераторы** вместо списков.
- Ограничивайте параллелизм (диск/CPU).
- Кэшируйте промежуточные результаты.
- Для PCAP — `only_summaries`/фильтры.

## Итоговый чек-лист

1. Определить задачу и выбрать библиотеку.
2. Написать скрипт с потоковой обработкой и логированием.
3. Зафиксировать зависимости (`requirements.txt`).
4. Протестировать на образце.
5. Прогнать на полном датасете.
6. Сохранить как артефакт для повторного использования.

## Пример: связка всех библиотек

```python
# 1) Обойти ФС и найти базы
import pytsk3, sqlite3, yara, os

img = pytsk3.Img_Info("disk.img")
fs = pytsk3.FS_Info(img, offset=2048*512)
rules = yara.compile(filepath="flag.yar")

def scan(fs, path="/"):
    for e in fs.open_dir(path=path):
        name = e.info.name.name.decode(errors="ignore")
        if name in (".",".."): continue
        full = path.rstrip("/")+"/"+name
        if e.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            scan(fs, full)
        else:
            data = e.read_random(0, e.info.meta.size)
            for m in rules.match(data=data):
                print("HIT", m.rule, full)

scan(fs)
```

Один скрипт объединяет доступ к ФС, YARA и обход — типовой шаблон для нестандартных задач.

## Итог

Python превращает набор утилит в автоматизированный пайплайн. pytsk3 даёт ФС, Volatility3 (через CLI+JSON) — память, pyshark — сеть, yara-python — детект. Фиксируйте зависимости, логируйте, читайте потоково и сохраняйте скрипты как артефакты.

## Ключевые выводы

- Python объединяет pytsk3, Volatility3 и pyshark в один пайплайн.
- Читайте потоково и логируйте — большие датасеты не помещаются в память.
- Фиксируйте зависимости (`requirements.txt`) для воспроизводимости.
- Обрабатывайте исключения: поля/файлы не всегда есть.
- Сохраняйте скрипты как артефакты для повторного использования.

## Мини-таблица библиотек

| Библиотека | Область |
|------------|---------|
| pytsk3 | файловые системы |
| volatility3 | память |
| pyshark | сеть (PCAP) |
| yara-python | сигнатуры |
| python-registry | реестр |

Этого набора достаточно для большинства кастомных пайплайнов.

## Что дальше / решение

1. Выбрать библиотеку под задачу (pytsk3/volatility/pyshark).
2. Написать скрипт с потоковой обработкой.
3. Протестировать на маленьком образце.
4. Прогнать на полном датасете, логировать прогресс.
5. Сохранить скрипт как артефакт для повторного использования.

Дальше — `forensics-autopsy` и `forensics-yara-sigma` для готовых инструментов.

## Квиз

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
```

## Где пригодится

- **CTF:** нестандартные задачи, где нужен свой скрипт.
- **IR:** автоматизация повторяющихся шагов.
- **Threat Hunting:** массовая обработка артефактов.
- **Разработка:** собственные форензические инструменты.
