---
id: osint-email-headers
title: "Анализ email-заголовков: SPF, DKIM, DMARC и трекинг"
category: osint
parent: osint-infra-artifacts
difficulty: medium
order: 4
tags: [email, headers, spf, dkim, dmarc, smtp, phishing]
prerequisites: [osint-dns-recon]
useful_for:
  - "CTF категория OSINT"
  - "Антифишинг и blue team"
  - "Расследования"
estimated_minutes: 25
summary: "Как читать заголовки письма: цепочка Received, IP отправителя, SPF/DKIM/DMARC, вложения, трекинг-пиксели и определение подделок."
---
Письмо — это не только текст. У каждого email есть **заголовки** (headers): служебные поля, которые фиксируют путь письма через почтовые серверы, подлинность домена отправителя и даже данные о клиенте отправителя. Умение читать заголовки — обязательный навык в OSINT, антифишинге и расследованиях. По заголовкам можно определить реальный IP отправителя, его почтовый провайдер, подделку домена и используемый клиент.

## Теория: анатомия заголовков

Основные поля:

| Поле | Значение |
|------|----------|
| `From` | Отображаемое имя и адрес (легко подделать) |
| `Return-Path` | Адрес для bounce (реальный отправитель на уровне SMTP) |
| `Reply-To` | Куда уйдёт ответ (часто отличается у фишеров) |
| `Received` | Цепочка серверов, через которые прошло письмо |
| `Message-ID` | Уникальный ID, содержит домен генератора |
| `Date` | Время отправки (по часам отправителя!) |
| `Authentication-Results` | Результаты SPF/DKIM/DMARC |
| `Received-SPF` | Результат SPF |
| `DKIM-Signature` | Криптоподпись домена |
| `X-Mailer` / `User-Agent` | Почтовый клиент отправителя |
| `X-Originating-IP` | Иногда реальный IP клиента |
| `Content-Type` / `boundary` | Структура MIME (части письма) |

**Важно:** `From` подделывается тривиально. Доверять нужно `Received`, `Return-Path`, `Authentication-Results` и DKIM-подписи.

## Где взять заголовки

- **Gmail:** открыть письмо → ⋮ → «Показать оригинал» (Show original).
- **Outlook:** «Свойства» → «Заголовки интернета».
- **Thunderbird:** View → Message Source (Ctrl+U).
- **Файл `.eml`:** заголовки — в начале файла до пустой строки.

Сохраните как `.eml` и парсите локально. Файл `.eml` — это канонический формат для анализа.

## Разбор цепочки Received

`Received` читаются **снизу вверх** (последний добавленный — сверху). Каждая строка:

```
Received: from mail.example.com (mail.example.com [93.158.134.210])
        by mx.google.com with ESMTPS id abc123
        for <me@gmail.com>; Mon, 12 May 2025 14:33:01 +0300
```

Здесь: отправитель `mail.example.com` с IP `93.158.134.210` → принят Google. Смотрим на **самый нижний (первый) Received** — это исходный сервер отправителя.

```bash
grep -i '^Received:' message.eml
```

Признаки подделки: рассинхрон часов между хопами, отсутствие PTR у IP, «localhost» в нижнем Received (значит, письмо сгенерировано локально скриптом).

## SPF, DKIM, DMARC

### SPF

SPF проверяет, что IP отправителя авторизован доменом. Смотрим:

```bash
grep -i 'Received-SPF\|spf=' message.eml
```

Результаты: `pass`, `fail`, `softfail`, `neutral`, `none`.

### DKIM

DKIM — подпись письма приватным ключом домена. Проверяется публичным ключом из DNS (`selector._domainkey.domain`).

```bash
grep -i 'DKIM-Signature' -A5 message.eml
# извлечь селектор и домен
dig +short selector1._domainkey.example.com TXT
```

Если DKIM `pass` — домен отправителя подлинный (или у него утёк ключ).

### DMARC

DMARC-политика говорит, что делать при провале SPF/DKIM. Проверяется через `_dmarc.domain`:

```bash
dig +short _dmarc.example.com TXT
# "v=DMARC1; p=none; rua=mailto:dmarc@example.com; sp=reject; pct=100"
```

`p=none` — только мониторинг (спуфинг возможен), `p=reject` — жёсткая защита, `p=quarantine` — в спам. Атрибут `sp` задаёт политику для поддоменов.

### Комплексная проверка домена

```bash
DOMAIN=example.com
dig +short "$DOMAIN" TXT | grep spf1
dig +short _dmarc."$DOMAIN" TXT
dig +short default._domainkey."$DOMAIN" TXT
```

## Разобранный пример: фишинг или легитимное письмо?

Дано: `message.eml` от «банка».

Шаг 1 — смотрим `From` и `Return-Path`:

```bash
grep -iE '^(From|Return-Path|Reply-To):' message.eml
# From: Sberbank <info@sberbank.ru>
# Return-Path: <bounce@evil.example>
```

Расхождение `From` и `Return-Path` — первый красный флаг.

Шаг 2 — SPF/DKIM/DMARC:

```bash
grep -iE 'Received-SPF|Authentication-Results' message.eml
# Authentication-Results: mx.google.com; spf=fail dkim=none dmarc=fail
```

`spf=fail dkim=none dmarc=fail` → домен подделан.

Шаг 3 — IP отправителя:

```bash
grep -i '^Received:' message.eml | tail -1
# from evil.example (evil.example [45.13.22.100]) by ...
whois 45.13.22.100 | grep -Ei 'country|netname|org'
# country:        NL
# netname:        HOSTING-EXAMPLE
```

Хостинг в NL + нет PTR — типичная автоматическая рассылка.

Шаг 4 — `X-Mailer`/`User-Agent`:

```bash
grep -iE 'X-Mailer|User-Agent' message.eml
# X-Mailer: PHPMailer 6.5
```

PHPMailer — рассылка через скрипт, а не корпоративный клиент.

Шаг 5 — вложения и ссылки:

```bash
grep -iE 'Content-Disposition|filename=' message.eml
grep -oiE 'https?://[^ ">]+' message.eml | sort -u
# https://sberbank-secure.evil.example/login
```

Ссылка ведёт на `sberbank-secure.evil.example` (тайпсквот). Вывод: фишинг.

## Продвинутые приёмы

- **Трекинг-пиксели:** в HTML-части — `<img src="https://tracker/...">`. Показывает, что письмо прочитано, и раскрывает ваш IP.
- **Гомоглифы и тайпсквоты:** `sberbank` vs `sberbank` с кириллической `а`. Проверяйте punycode:

```bash
python3 -c "print('sberbank'.encode('idna'))"
```

- **Message-ID домен:** `Message-ID: <...@mailer.example>` — раскрывает почтовый сервер.
- **Скрытые заголовки:** `X-Originating-IP`, `X-Sender-IP` иногда содержат реальный IP клиента.
- **Анализ вложений:** хеши → VirusTotal; метаданные документа (см. урок про метаданные).
- **GeoIP и ASN:** по IP отправителя — провайдер, страна, hosting (VPS часто = автоматическая рассылка).

## Автоматизация

```bash
pipx install mail-parser
python3 -c "
import mailparser
m = mailparser.parse_from_file('message.eml')
print('From:', m.from_)
print('Return-Path:', m.headers.get('Return-Path'))
print('Received IPs:', m.received_ips)
print('Attachments:', [a['filename'] for a in m.attachments])
"
```

- **`email-forensics`**, **`emlAnalyzer`** — специализированные разборщики.
- **VirusTotal** — загрузка `.eml` или хешей вложений.
- **urlscan.io** — проверка ссылок без перехода (в песочнице).

## Частые ошибки

- **Верить `From`.** Подделывается за секунды; смотрите `Return-Path` и `Received`.
- **Читать Received сверху вниз.** Правильно — снизу вверх.
- **Игнорировать `Authentication-Results`.** Это готовый вердикт SPF/DKIM/DMARC.
- **Переходить по ссылкам из подозрительного письма в своём браузере.** Используйте urlscan.io.
- **Не проверять вложения.** Хешируйте и проверяйте на VirusTotal, не открывая.
- **Забыть про трекинг-пиксели.** Открытие письма сообщает отправителю о вас.
- **Путать `Reply-To` и `Return-Path`.** Первый — для ответа человеку, второй — для bounce.

## Справочные таблицы

| Результат SPF | Значение |
|---|---|
| pass | IP авторизован доменом |
| fail | IP не авторизован (жёсткий отказ) |
| softfail | вероятно не авторизован (мягкий) |
| neutral | нет утверждения |
| none | SPF не опубликован |

| Политика DMARC | Действие |
|---|---|
| p=none | только мониторинг |
| p=quarantine | в спам |
| p=reject | отклонить |
| sp=... | политика для поддоменов |

## SMTP-энумерация и проверка домена отправителя

Заголовки показывают уже отправленное письмо, но тот же домен можно проверить напрямую:

```bash
# проверка SPF/DMARC/MX домена отправителя
dig +short MX example.com
dig +short TXT example.com | grep -i spf
dig +short TXT _dmarc.example.com

# энумерация пользователей через SMTP (VRFY/RCPT)
smtp-user-enum -M RCPT -U users.txt -t mail.example.com
```

`swaks` позволяет вручную протестировать SMTP и увидеть реальные ответы сервера:

```bash
swaks --to user@example.com --server mail.example.com --quit-after RCPT
# -> 250 user@example.com  (пользователь существует)
# -> 550 5.1.1 <x@example.com> User unknown
```

Разные ответы `250`/`550` на RCPT TO выдают существующих пользователей — ценно для фишинговой симуляции и оценки защищённости домена.

## Трекинг-пиксели и приватность получателя

Почти все массовые рассылки встраивают невидимые картинки:

```html
<img src="https://track.example.com/open?id=USER123" width="1" height="1">
```

При загрузке письма клиент запрашивает картинку → сервер отправителя узнаёт, что письмо открыто, когда, и часто ваш IP/клиент. Меры:

- Отключите автоматическую загрузку удалённого контента в почтовом клиенте.
- Просматривайте подозрительные письма в изолированном браузере/VM.
- В `.eml` ищите `<img>` и внешние `http(s)`-ссылки перед открытием.

Это и OSINT-техника (вы видите чужой трекинг), и OPSEC-мера (вы не светитесь у отправителя).

## Кодировки, MIME и вложения

Тело письма часто закодировано, и «сырой» вид сбивает с толку:

- **Заголовки** с не-ASCII кодируются по RFC 2047: `=?utf-8?B?...?=` (base64) или `=?utf-8?Q?...?=` (quoted-printable).
- **Тело** в `Content-Transfer-Encoding: base64` или `quoted-printable`.
- **Вложения** описаны через `Content-Disposition: attachment; filename="..."`.

Декодировать вручную не нужно — используйте парсер, но понимать структуру важно:

```bash
# показать структуру MIME-частей
grep -iE 'Content-Type|Content-Transfer-Encoding|Content-Disposition' message.eml
```

Проверка хеша вложения до открытия:

```bash
# извлечь вложение и посчитать SHA-256 для VirusTotal
munpack -q -t message.eml 2>/dev/null
sha256sum invoice.pdf
```

Имя вложения — тоже улика: двойное расширение (`invoice.pdf.exe`), RTL-переопределение для маскировки расширения, юникод-гомоглифы в имени.

## Итоговый вердикт по письму

Соберите признаки в таблицу и оцените письмо целиком:

| Признак | Легитимно | Подозрительно |
|---|---|---|
| SPF | pass | fail/softfail/none |
| DKIM | pass | none/fail |
| DMARC | pass | fail |
| Return-Path | совпадает с From | чужой домен |
| Reply-To | тот же домен | другой домен |
| X-Mailer | корпоративный клиент | PHPMailer/скрипт |
| Ссылки | официальный домен | тайпсквот/гомоглиф |
| Вложения | ожидаемые | исполняемые/двойное расширение |

Если SPF/DKIM/DMARC все `fail` и `Return-Path` не совпадает с `From` — это почти наверняка фишинг или спуфинг. Совпадение всех признаков в «легитимной» колонке — повод считать письмо подлинным, но проверка ссылок и вложений всё равно обязательна.

## Что дальше / решение

Заголовки — это вход в анализ почтовой инфраструктуры. Дальше: **анализ SPF/DKIM/DMARC домена** как отдельная проверка, **SMTP-энумерация** пользователей, **IOC-enrichment** по найденным IP/доменам и **анализ метаданных вложений**. Итог: `From` не значит ничего, `Received` снизу + `Authentication-Results` + IP/ASN + вложения дают полную картину происхождения письма.

## Квиз

```quiz
- question: "Какое поле заголовка труднее всего подделать?"
  options:
    - "`From`"
    - "`DKIM-Signature` (криптоподпись)"
    - "`Reply-To`"
    - "`Subject`"
  answer: 1
- question: "В каком порядке читают цепочку `Received`?"
  options:
    - "Сверху вниз"
    - "Снизу вверх"
    - "По алфавиту"
    - "Неважно"
  answer: 1
- question: "Что означает `p=none` в DMARC-записи?"
  options:
    - "Строгий запрет спуфинга"
    - "Только мониторинг, спуфинг не блокируется"
    - "DKIM отключён"
    - "SPF не проверяется"
  answer: 1
- question: "Где в письме может быть реальный IP отправителя?"
  options:
    - "В `Subject`"
    - "В нижней строке `Received` и `X-Originating-IP`"
    - "В `Date`"
    - "В теле письма"
  answer: 1
- question: "Зачем нужен urlscan.io?"
  options:
    - "Для сканирования портов"
    - "Для проверки ссылок в песочнице без перехода"
    - "Для расшифровки DKIM"
    - "Для чтения EXIF"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** в письме-приложении спрятана подсказка/флаг в заголовках.
- **Blue team / антифишинг:** подтвердить подделку домена и выявить рассылку.
- **Bug bounty:** анализ писем, которые цель шлёт (спуфинг, open relay, утечки).
- **Пентест:** оценка защищённости почтового домена (SPF/DKIM/DMARC).
- **Расследования:** установить реальный источник письма и инфраструктуру отправителя.
