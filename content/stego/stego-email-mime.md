---
id: stego-email-mime
title: "Стеганография в электронной почте: SMTP-заголовки, MIME и вложения"
category: stego
parent: stego-document-carriers
difficulty: medium
order: 4
tags: [stego, email, smtp, mime, base64, headers, phishing]
prerequisites: [stego-document-carriers, stego-text-whitespace]
useful_for:
  - "CTF Stego: разбор .eml и вложений"
  - "Форензика: анализ фишинговых писем"
  - "Работа: почтовые шлюзы и DLP"
estimated_minutes: 18
summary: "Как прячут данные в письмах: MIME-границы и multipart-структура, base64/quoted-printable, X-заголовки и Message-ID, HTML-часть с zero-width, скрытые вложения. Разбор .eml через Python и hexdump."
---

## Вопрос, с которого всё начинается

У тебя есть файл `mail.eml` — сохранённое письмо. Открываешь в почтовом клиенте:
обычный текст и картинка. Но письмо — это **текстовый** файл с массой служебных
заголовков и кодирований. Здесь прятать данные особенно удобно: клиент показывает
одно, а в исходнике живёт другое. Разберём структуру.

## Наш пример

Открываем письмо:

```
$ file mail.eml
mail.eml: RFC 822 mail text, ASCII text
$ head -20 mail.eml
Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [203.0.113.5])
	by mx.corp.local with ESMTP id a1b2c3
	for <victim@corp.local>; Mon, 1 Jun 2024 10:00:00 +0000
Message-ID: <20240601100000.1234@example.com>
From: "Sender" <sender@example.com>
To: <victim@corp.local>
Subject: Quarterly report
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b0und4ry_xyz"
```

Уже видно два канала: **заголовки** (`Received`, `Message-ID`) и **MIME-граница**
(`boundary`). Разберём по порядку.

## Шаг 1: заголовки SMTP

Каждый заголовок — строка `Имя: значение`. Полезные для сокрытия:

1. **`X-`заголовки.** Произвольные, никем не проверяются:
   ```
   X-Mailer: Corp Mailer 1.0
   X-Campaign-ID: nto{sm4tp_x_h34d3r}
   ```
2. **`Message-ID`.** По стандарту — произвольная строка в угловых скобках. Идеальное
   место для payload.
3. **`Received`-цепочка.** Каждый релей добавляет свою строку. Свободный текст.
4. **Длинные заголовки и folding.** Заголовок можно «сложить» на несколько строк
   (продолжение начинается с пробела) — в отступах прячут биты, как в текстовой
   стеганографии.

## Шаг 2: MIME-границы и части

`multipart`-письмо состоит из частей, разделённых строкой `--boundary`. Сама граница —
произвольная строка, заданная в `Content-Type`. Её можно подобрать так, чтобы она
кодировала данные.

```
$ grep -n 'boundary' mail.eml
11:Content-Type: multipart/mixed; boundary="b0und4ry_xyz"
```

Также можно добавить **лишние части** (клиент их проигнорирует) или «пустые» MIME-блоки.

## Шаг 3: кодирования — base64 и quoted-printable

Вложения и нетекстовые части кодируются **base64**. Это удобно: в base64-строке можно
незаметно менять **padding** (`=`) или переставлять эквивалентные варианты. Но чаще
payload прячут прямо в **декодированном** вложении (это уже знакомые нам форматы —
PNG, PDF).

```
$ python3 parse_mail.py
parts:
  text/plain
  text/html
  image/png (name=report.png, 4210 bytes)
X-header X-Campaign-ID: nto{sm4tp_x_h34d3r}
```

`quoted-printable` — второе кодирование (для текста). Здесь легко спрятать данные в
«мягких переносах» (`=\n`) и в выборе, какие символы кодировать.

## Шаг 4: HTML-часть и скрытые вложения

Если письмо содержит HTML-часть, работают все приёмы из урока про HTML/CSS:

- **zero-width символы** в тексте,
- невидимый текст (цвет фона),
- комментарии `<!-- ... -->`,
- скрытые ссылки.

Плюс отдельный класс — **скрытые вложения**: файл с `Content-Disposition: attachment;
filename="report.pdf"`, но с необычным `Content-Type`, или вложение, закодированное
двойным base64. Почтовый клиент может его не показать, а данные там.

## Шаг 5: пайплайн разбора

1. `file mail.eml` — убедиться, что это письмо.
2. `head -40 mail.eml` — заголовки; искать `X-`, `Message-ID`, необычные поля.
3. `python3 parse_mail.py` — разобрать через `email` (стандартная библиотека):
   ```
   import email
   msg = email.message_from_file(open('mail.eml'))
   for part in msg.walk():
       print(part.get_content_type(), part.get_filename())
   ```
4. Для HTML-части — `grep -o '<!--.*-->'` и скрипт по zero-width.
5. Для вложений — декодировать base64 и разбирать как обычный файл (`binwalk`, `strings`).
6. Помнить про `quoted-printable` и folded-заголовки.

## Что мы теперь знаем

- Письмо — **текстовый файл** с заголовками и MIME-частями.
- Каналы: `X-`заголовки, `Message-ID`, `Received`, folding.
- **MIME-граница** и лишние части — свободное место.
- **base64/quoted-printable** дают свои микро-каналы; вложения — обычные файлы.
- HTML-часть использует все приёмы веб-стеганографии.

## Разбор .eml на Python: полный скрипт

Стандартная библиотека `email` умеет всё: разбирать заголовки, декодировать
кодированные слова, обходить MIME-части. Минимальный анализатор:

```python
import email, email.header

msg = email.message_from_file(open('mail.eml', encoding='utf-8', errors='replace'))

# 1. Все заголовки как пары (имя, раскодированное значение)
for k, v in msg.items():
    val = ''.join(str(s, c or 'utf-8') if isinstance(s, bytes) else s
                  for s, c in email.header.decode_header(v))
    print(f'{k}: {val}')

# 2. Обход частей с декодированием
for part in msg.walk():
    ct = part.get_content_type()
    fn = part.get_filename()
    payload = part.get_payload(decode=True)  # base64/quoted-printable -> bytes
    print(ct, fn, len(payload) if payload else 0)
```

Запуск и вывод:

```
$ python3 parse_mail.py
Return-Path: <sender@example.com>
X-Campaign-ID: nto{sm4tp_x_h34d3r}
text/plain None 512
text/html None 1840
image/png report.png 4210
```

`get_payload(decode=True)` сам раскодирует base64 и quoted-printable — не нужно
делать `base64 -d` вручную. А `decode_header` превращает `=?utf-8?B?...?=` в
читаемый текст.

## Заголовки глубоко: DKIM, Received и Authentication-Results

- **`Received`-цепочка** читается **снизу вверх**: самый нижний `Received` — первый
  сервер, принявший письмо, верхний — последний (твой MX). В комментариях к IP и
  hostname удобно прятать данные — они не проверяются.
- **`DKIM-Signature`** содержит `b=` (base64-подпись) и `bh=` (хеш тела). Их нельзя
  менять, не сломав подпись, но **дополнительные** `X-`поля рядом — можно.
- **`Authentication-Results`** — результат проверок SPF/DKIM/DMARC; длинная строка,
  куда тоже можно дописать лишнее.
- **`Message-ID`** — по RFC произвольная строка в `<...>`; идеальный носитель.

```
$ grep -nE '^(Received|Message-ID|DKIM-Signature|X-):' mail.eml
7:Message-ID: <20240601100000.1234@example.com>
12:X-Campaign-ID: nto{sm4tp_x_h34d3r}
```

## Кодирования: base64, quoted-printable и 8bit

Три способа передать нетекстовые данные в текстовом письме:

1. **base64** — блоки по 4 символа, в конце `=`-паддинг. Микро-канал: можно менять
   паддинг или переставлять эквивалентные варианты; но чаще payload прячут в самом
   декодированном вложении.
2. **quoted-printable** — непечатаемые байты как `=XX`, перенос строки как `=\n`
   («мягкий перенос»). Канал: где ставить мягкие переносы и какие символы
   кодировать (`a` или `=61` — одно и то же).
3. **8bit / binary** — сырые байты без кодирования (редко, но бывает).

Декодирование вручную для проверки:

```
$ python3 -c "import quopri,sys; print(quopri.decodestring(open('body.txt','rb').read()).decode('utf-8','replace'))"
```

## Вложения: Content-Type mismatch и вложенные письма

Почтовый клиент верит заголовкам, а не содержимому. Отсюда приёмы:

- **`Content-Type` не совпадает с реальным.** Заголовок говорит `text/plain`, а
  внутри — PNG (проверяется `file`). Клиент покажет «текст», а данные спрятаны.
- **Двойное расширение** `report.pdf.exe` — визуально «PDF».
- **Вложенное письмо** `message/rfc822` — письмо в письме; рекурсивный разбор
  обязателен (`msg.walk()` его обойдёт).
- **Двойной base64** — вложение, чей декодированный вид снова base64.

```
$ python3 -c "
import email
m=email.message_from_file(open('mail.eml'))
for p in m.walk():
    d=p.get_payload(decode=True)
    if d and p.get_filename():
        open(p.get_filename(),'wb').write(d)
"
$ file report.png
report.png: PNG image data, 800 x 600, 8-bit/color RGB
```

## Инструменты: munpack, ripmime, exiftool

- **`munpack mail.eml`** — вытащить все вложения в текущую папку.
- **`ripmime -i mail.eml -d out/`** — то же, но с рекурсией во вложенные письма.
- **`exiftool`** — метаданные уже извлечённого вложения (EXIF, XMP).
- **`binwalk`** — поиск вложенных форматов в декодированном вложении.
- **`strings | grep -i nto`** — быстрый поиск по всему `.eml`.

## Edge cases и подводные камни

- **Кодировка заголовков.** `Subject` может быть в `=?koi8-r?B?...?=` — декодируй,
  иначе увидишь base64-мусор.
- **CRLF.** Письмо по стандарту использует `\r\n`; часть парсеров на `\n` спотыкается.
- **Лишние MIME-части.** Клиент их игнорирует, `walk()` — покажет; проверяй все.
- **Переносы в заголовках (folding).** Продолжение начинается с пробела/таба —
  именно в отступах часто прячут биты.
- **HTML-часть.** Все приёмы из урока про HTML/CSS работают внутри письма.

## Что дальше / решение

Сквозной пример решается так: `parse_mail.py` показывает все заголовки и части;
`X-Campaign-ID` отдаёт `nto{sm4tp_x_h34d3r}`; вложение `report.png` сохраняем и
разбираем как картинку. Если заголовки пусты — идём в HTML-часть (zero-width,
комментарии) и в декодированные вложения.

## Шпаргалка: каналы в письме

| Канал | Как найти | Инструмент |
|-------|-----------|------------|
| X-заголовки | `grep '^X-'` | grep |
| Message-ID | `grep '^Message-ID'` | grep |
| Received-цепочка | `grep '^Received'` | grep |
| Folding | отступы в заголовках | `cat -A` |
| MIME-граница | `grep boundary` | grep |
| base64/quoted-printable | декод | `email`, `quopri` |
| Вложения | walk + decode | `munpack`, `ripmime` |
| HTML-часть | zero-width, комментарии | скрипт |

## Частый вопрос: письмо как доказательство

В форензике `.eml` — это ещё и **доказательство**. Поэтому важно сохранить письмо
целиком (с заголовками и вложениями), не «пересохраняя» его из клиента: клиент
нормализует заголовки и теряет folding. Используй экспорт «в исходном виде» или
`curl`/`fetchmail`, а целостность подтверждай хешем:

```
$ sha256sum mail.eml
$ grep -c '^Received:' mail.eml
```

Число `Received`-строк показывает, через сколько серверов прошло письмо; необычно
много или мало — повод присмотреться. А сравнив `Message-ID` с датой в `Received`,
можно поймать подделку времени.

## Итоговая проверка

Пройди по списку: заголовки (`grep '^X-'`), `Message-ID`, `Received`, MIME-части
(`walk`), декодированные вложения (`file`), HTML-часть (zero-width). Если все пять
пунктов пусты — данные, скорее всего, в самом вложении как в обычном файле.

## Квиз

Проверь себя.

```quiz
- question: Где в письме чаще всего прячут данные в заголовках?
  options:
    - "В X-заголовках, Message-ID и Received"
    - "В поле To"
    - "В поле From"
    - "Только в Subject"
  answer: 0
- question: Что такое MIME boundary?
  options:
    - "Произвольная строка-разделитель частей multipart-письма"
    - "Пароль почтового ящика"
    - "Адрес сервера"
    - "Алгоритм шифрования"
  answer: 0
- question: Как декодировать вложение из письма?
  options:
    - "Разобрать MIME и декодировать base64-часть"
    - "Открыть письмо в браузере"
    - "Использовать nmap"
    - "Переименовать .eml в .zip"
  answer: 0
- question: Какой приём из веб-стеганографии работает в HTML-части письма?
  options:
    - "Zero-width символы и HTML-комментарии"
    - "DCT-коэффициенты"
    - "LSB в пикселях"
    - "Эхо-сокрытие"
  answer: 0
- question: Что такое folded-заголовок?
  options:
    - "Заголовок, продолженный на нескольких строках с отступом"
    - "Зашифрованный заголовок"
    - "Удалённый заголовок"
    - "Сжатый заголовок"
  answer: 0
```

## Куда дальше

Мы разобрали почту как носитель. Дальше — **память**: как данные прячут в RAM и
процессах, и как их оттуда достают (fileless-малварь, page slack). А пока главное
запомни: **письмо — это текст**, и всё, что клиент не показывает, доступно в исходнике.

## Где пригодится

- **CTF Stego:** разбор `.eml` и вложений.
- **Форензика:** анализ фишинговых писем и заголовков.
- **Работа:** настройка почтовых шлюзов и DLP.
- **Bug bounty:** скрытые вложения и обход фильтров.
