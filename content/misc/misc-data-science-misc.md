---
id: misc-data-science-misc
title: "Данные и статистика в misc"
category: misc
parent: misc-ctf-meta
difficulty: medium
order: 3
tags: [pandas, статистика, визуализация, данные, аномалии]
prerequisites: [misc-git-forensics, misc-ctf-meta]
useful_for:
  - "CTF misc: обработка датасетов"
  - "Поиск аномалий в данных"
  - "Анализ логов и таблиц"
estimated_minutes: 40
summary: "Data science в CTF: pandas для таблиц, статистика и поиск выбросов, визуализация (matplotlib), обработка больших данных и разборы с кодом."
---

## Что такое data science в CTF

Часть задач даёт **данные**: CSV-логи, таблицы, временные ряды. Флаг спрятан в закономерности, аномалии или статистике. Здесь помогают навыки анализа данных: pandas, numpy, статистика и визуализация.

## pandas для данных

pandas — основной инструмент для табличных данных.

```python
import pandas as pd
df = pd.read_csv("data.csv")
print(df.head())
print(df.describe())
print(df["value"].value_counts().head())
```

Частые операции: фильтрация (`df[df.x > 0]`), группировка (`df.groupby("cat").mean()`), сортировка, объединение (`merge`).

## Статистика и аномалии

Выбросы находят через:

- **z-score:** `(x - mean) / std`; `|z| > 3` — подозрительно;
- **IQR:** точки вне `[Q1 - 1.5·IQR, Q3 + 1.5·IQR]`;
- **частоты:** редкие значения могут быть флагом.

```python
import numpy as np
x = df["value"].to_numpy()
z = (x - x.mean()) / x.std()
print(df[np.abs(z) > 3])
```

## Визуализация

График часто делает аномалию очевидной.

```python
import matplotlib.pyplot as plt
plt.plot(df["time"], df["value"]); plt.savefig("plot.png")
plt.hist(df["value"], bins=50); plt.savefig("hist.png")
```

Для больших данных — `df.plot(kind="scatter")` или seaborn. В CTF часто достаточно увидеть «выброс» глазами.

## Работа с большими данными

- **chunked reading:** `pd.read_csv(..., chunksize=10**6)`;
- **только нужные колонки:** `usecols=[...]`;
- **векторизация:** numpy вместо циклов;
- **потоковая обработка:** читать файл построчно, если он гигантский.

```python
for chunk in pd.read_csv("huge.csv", chunksize=10**6):
    process(chunk)
```

## Разобранный пример

Дан CSV с координатами, нужно найти «выбивающуюся» точку.

```python
import pandas as pd, numpy as np
df = pd.read_csv("points.csv")
df["z"] = np.abs((df.x - df.x.mean()) / df.x.std())
print(df[df.z > 3])
```

Выброс — и есть флаг (или координаты, где его искать).

## Частые ошибки и подводные камни

- **Загрузка гигантского файла целиком.** Используйте chunksize.
- **Игнорирование пропусков.** `NaN` ломает статистику; `dropna`/`fillna`.
- **Неверный тип.** Числа, прочитанные как строки, ломают арифметику (`astype`).
- **Слепая статистика.** Всегда визуализируйте — глазами видно то, что не видно в числах.
- **Переусложнение.** Часто достаточно `value_counts` и одного графика.

## Справочная таблица

| Задача | Код |
|--------|-----|
| Читать CSV | `pd.read_csv` |
| Описание | `df.describe()` |
| Фильтр | `df[df.x > 0]` |
| Группировка | `df.groupby("c").mean()` |
| Выбросы | z-score, IQR |
| График | `df.plot`, `plt.hist` |
| Большой файл | `chunksize` |

## Что дальше / решение

1. Загрузите данные (`read_csv`, `read_json`).
2. Осмотрите: `head`, `describe`, `value_counts`.
3. Ищите аномалии (z-score, IQR) и стройте графики.
4. Для больших файлов — chunksize и векторизация.
5. Проверьте найденную закономерность на формате флага.

## NumPy и векторизация

Когда строк миллионы, циклы Python слишком медленные. NumPy выполняет операции над целыми массивами на C и ускоряет код в десятки раз.

```python
import numpy as np
a = np.random.rand(10_000_000)
print(a.mean(), a.std())
mask = a > 0.999
print(mask.sum())
```

Ключевые приёмы: **векторизация** (заменить цикл на операцию над массивом), **булевы маски** (`a[mask]`), **broadcasting** (операции между массивами разных форм), **агрегации** (`sum`, `mean`, `argmax`). В CTF это решает задачи, где «наивный цикл не успевает по времени».

```python
# найти индексы выбросов без цикла
z = np.abs((a - a.mean()) / a.std())
print(np.where(z > 4)[0][:10])
```

## Временные ряды

Если данные — это метки времени, полезно привести их к `datetime` и работать с окнами.

```python
import pandas as pd
df = pd.read_csv("events.csv", parse_dates=["ts"])
df = df.set_index("ts").sort_index()
print(df.resample("1min").size().head())   # число событий в минуту
```

Всплеск в одном окне — частый признак атаки или «правильного» действия. Для поиска периодичности строят автокорреляцию или смотрят на разности между соседними событиями.

## Аномалии: практические примеры

- **Числовой выброс.** Одно значение резко отличается — z-score или IQR.
- **Временной выброс.** Событие вне кластера — таймлайн.
- **Частотный выброс.** Редкое значение в категориальном столбце.
- **Структурный выброс.** Строка с неверным числом полей.

```python
# структурный выброс: строки с неверным числом колонок
bad = [i for i, line in enumerate(open("data.csv")) if line.count(",") != 4]
print(bad[:10])
```

## Визуализация как инструмент разведки

Стройте несколько типов графиков: временной ряд, гистограмму, scatter. Часто флаг виден как надпись на scatter-графике (например, точки образуют текст) или как пик в спектре.

```python
import matplotlib.pyplot as plt
plt.scatter(df.x, df.y, s=1); plt.axis("equal"); plt.savefig("scatter.png")
```

Приём «нарисуй данные» (plot the data) — один из самых недооценённых: иногда данные — это картинка, закодированная в координатах.

## Частые вопросы по данным

- **Файл не влезает в память?** chunksize, генераторы, только нужные колонки.
- **Числа читаются как строки?** `pd.to_numeric(errors="coerce")` или `astype`.
- **Пропуски?** `df.dropna()` или `df.fillna(0)` — в зависимости от задачи.
- **Нужна скорость?** Переводите горячие участки на NumPy.

## Мини-шпаргалка pandas/numpy

```python
import pandas as pd, numpy as np
df = pd.read_csv("data.csv")          # загрузка
df.head(); df.describe(); df.info()   # осмотр
df[df.col > 0]                        # фильтр
df.groupby("cat")["v"].mean()         # группировка
df.sort_values("v", ascending=False)  # сортировка
df["z"] = (df.v - df.v.mean()) / df.v.std()   # z-score
df.nlargest(5, "v")                   # топ-5
a = df.v.to_numpy(); a.mean(); a.std(); np.where(a > 3)  # numpy
```

Этот набор покрывает 90% задач на табличные данные.

## Итог по данным в CTF

Данные — это не «скучная» часть misc, а отдельный класс задач: аномалии, закономерности, визуальные паттерны. Держите под рукой pandas/numpy, всегда осматривайте данные (`head`/`describe`), стройте графики и ищите выбросы статистикой. Для больших файлов — chunksize и векторизация. Часто «флаг» — это просто выбивающаяся строка, которую видно после одной агрегации.

## Кейс: разбор лога веб-сервера

Дано: `access.log` в формате Common Log. Нужно найти подозрительный запрос.

```python
import pandas as pd, re
rows = []
for line in open("access.log"):
    m = re.match(r'(\S+) - - \[(.*?)\] "(\S+) (\S+) .*?" (\d+) (\d+)', line)
    if m:
        rows.append(m.groups())
df = pd.DataFrame(rows, columns=["ip","time","method","path","status","size"])
print(df["ip"].value_counts().head(10))     # топ IP
print(df[df["status"] == "200"]["path"].value_counts().head())
```

Так находят брутфорс (много запросов с одного IP), сканирование (много 404) и «странные» пути (`/admin`, `/.git`). Часто флаг — в path редкого запроса.

## Кейс: координаты как изображение

Иногда данные — это `(x, y)`-точки, которые складываются в картинку или текст.

```python
import pandas as pd, matplotlib.pyplot as plt
df = pd.read_csv("points.csv")
plt.figure(figsize=(8,8))
plt.scatter(df.x, df.y, s=2, c="black")
plt.axis("equal"); plt.axis("off"); plt.savefig("render.png")
```

Приём «нарисуй точки» часто вскрывает флаг, закодированный в координатах. Аналогично строят графики для звука, температур, частот.

## Кейс: аномалии во временном ряду

Дан ряд измерений, одна точка — «всплеск».

```python
import pandas as pd
df = pd.read_csv("series.csv")
df["diff"] = df.value.diff().abs()
print(df.nlargest(5, "diff"))
```

Наибольшая разность указывает на аномалию; значение рядом — флаг или подсказка.

## Инструменты-помощники

- **jq** — быстрый разбор JSON (`curl ... | jq .`).
- **csvkit** — CLI для CSV (`csvstat`, `csvgrep`).
- **gnuplot** — быстрые графики из CLI.
- **awk** — однострочники по колонкам.

```bash
awk -F, '$3 > 100 {print $1}' data.csv | head
```

## Работа с JSON и логами

Помимо CSV, данные часто приходят в JSON (логи, API-выгрузки, события). Разбор:

```python
import json, pandas as pd
events = [json.loads(l) for l in open("events.jsonl")]
df = pd.json_normalize(events)
print(df.columns)
print(df["user"].value_counts())
```

`json_normalize` разворачивает вложенные объекты в колонки — это спасает, когда структура глубокая. Для CLI-разбора — `jq`:

```bash
curl -s http://api/data | jq '.items[] | {id, user, ts}' | head
```

## Регулярные выражения для парсинга

Много данных — это неструктурированный текст, и его надо распарсить регулярками:

```python
import re
line = '1.2.3.4 - - [10/Oct/2024:12:00:00] "GET /flag HTTP/1.1" 200'
m = re.search(r'\[(.*?)\].*?"(\w+) (.*?) HTTP', line)
print(m.groups())   # ('10/Oct/2024:12:00:00', 'GET', '/flag')
```

Для массового парсинга компилируйте шаблон (`re.compile`) и используйте `findall`. Осторожно с жадными квантификаторами (`.*` против `.*?`).

## Многопоточность для больших данных

Если обработка каждой записи тяжёлая (например, сетевой запрос), распараллельте:

```python
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=32) as ex:
    results = list(ex.map(fetch, urls))
```

Для CPU-bound задач берите `ProcessPoolExecutor`. Но сначала убедитесь, что узкое место — не в I/O и не в самой модели.

## Практикум: три задачи

**1. Топ IP в логе.** `df["ip"].value_counts().head()` — один вызов.
**2. Найти «неправильную» строку.** Сравнить число полей с ожидаемым.
**3. Восстановить изображение из координат.** scatter-график с `axis("equal")`.

Эти три приёма покрывают большинство data-science задач в CTF.

## Квиз

```quiz
- question: "Какая библиотека для таблиц в Python?"
  options:
    - "pandas"
    - "requests"
    - "scapy"
    - "pwntools"
  answer: 0
  explanation: "DataFrame — основа."
- question: "Что означает |z-score| > 3?"
  options:
    - "Значение — выброс"
    - "Среднее"
    - "Медиана"
    - "Ноль"
  answer: 0
  explanation: "Отклонение от среднего."
- question: "Как читать гигантский CSV?"
  options:
    - "С параметром chunksize"
    - "Целиком в память"
    - "Через nmap"
    - "Через binwalk"
  answer: 0
  explanation: "Порционная обработка."
- question: "Зачем визуализировать данные?"
  options:
    - "Аномалии видно глазами"
    - "Чтобы сжать файл"
    - "Чтобы зашифровать"
    - "Чтобы ускорить CPU"
  answer: 0
  explanation: "График выявляет выбросы."
```

## Где пригодится

- **CTF misc/forensics:** логи, таблицы, временные ряды.
- **Работа:** анализ данных и аномалий.
- **OSINT:** обработка собранных данных.
- **Обучение:** база data science.
