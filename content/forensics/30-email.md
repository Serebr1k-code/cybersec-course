---
id: forensics-email
title: "Форензика электронной почты: заголовки, вложения, фишинг"
category: forensics
parent: forensics-pcap
difficulty: medium
order: 1
tags: [email, eml, headers, phishing, spf, dkim, attachment, msg]
prerequisites: [forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (фишинг)"
  - "OSINT (анализ отправителя)"
estimated_minutes: 40
summary: "Разбор писем .eml/.msg: заголовки Received, аутентификация SPF/DKIM/DMARC, вложения и макросы, восстановление маршрута и выявление фишинга."
---
Электронная почта — один из главных векторов атак (фишинг, малварь во вложениях) и одновременно богатый источник форензических артефактов. Заголовки письма фиксируют маршрут через серверы, механизмы аутентификации показывают подделку отправителя, а вложения несут полезную нагрузку. Этот урок — про разбор `.eml`/`.msg`, маршрут `Received`, SPF/DKIM/DMARC, извлечение вложений и выявление фишинга.

## Структура письма и MIME

Письмо — это текст с заголовками, пустой строкой и телом. Тело при наличии вложений кодируется по **MIME**: `multipart/mixed` (или `multipart/alternative`), каждая часть со своим `Content-Type`, `Content-Transfer-Encoding` (обычно `base64` или `quoted-printable`), `Content-Disposition` (inline/attachment). `.eml` — сырое письмо; `.msg` — проприетарный формат Outlook (OLE).

```bash
$ head -40 mail.eml
From: "PayPal" <service@paypa1-secure.com>
To: victim@example.com
Subject: =?UTF-8?B?VXJnZW50IQ==?=      # base64-закодированная тема
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_NextPart_000"
```

Закодированная тема (`=?UTF-8?B?...?=`) — частый приём маскировки; декодируйте `mhonarc`/`ripmime` или `python email`.

## Заголовки Received и маршрут

Каждый MTA добавляет заголовок `Received` **сверху вниз** (самый верхний — последний сервер). Читать маршрут нужно **снизу вверх**: от отправителя к получателю.

```bash
$ grep -i '^Received:' mail.eml
Received: from mail.paypa1-secure.com (unknown [203.0.113.9])
    by mx.example.com (Postfix) with ESMTP id 1234
    for <victim@example.com>; Fri, 1 Mar 2024 12:00:00 +0000
Received: from [10.0.0.5] (unknown [203.0.113.9])
    by mail.paypa1-secure.com; Fri, 1 Mar 2024 11:59:58 +0000
```

Ключевые поля: `from <хост> (<IP>)`, `by <MTA>`, `with <протокол>`, дата. Расхождение имени и IP, приватные IP, «unknown» — признаки подделки. Проверяйте обратные DNS-записи и репутацию IP.

## Аутентификация: SPF, DKIM, DMARC

- **SPF** — список IP, которым разрешено отправлять от имени домена; проверяется по `Return-Path`/HELO.
- **DKIM** — криптоподпись письма; заголовок `DKIM-Signature` с `d=` (домен), `s=` (селектор), `b=` (подпись).
- **DMARC** — политика на основе SPF/DKIM; результат в `Authentication-Results`.

```bash
$ grep -i 'Authentication-Results\|DKIM-Signature\|Received-SPF' mail.eml
Authentication-Results: mx.example.com;
  spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=paypa1-secure.com;
  dkim=none; dmarc=fail
```

`spf=fail` + `dmarc=fail` = явная подделка отправителя. Проверить вручную:

```bash
$ dig +short TXT paypa1-secure.com          # SPF-запись
$ dig +short TXT _dmarc.paypa1-secure.com   # DMARC
$ dig +short TXT selector._domainkey.domain # DKIM-ключ
```

## Извлечение вложений

```bash
# ripmime: разложить письмо на части
$ ripmime -i mail.eml -d out/
$ ls out/
# munpack (из mpack)
$ munpack -t mail.eml
# вручную: найти base64-блок и декодировать
$ awk '/^Content-Transfer-Encoding: base64/{f=1;next}/^$/{if(f)f=2;next}f==2{print}' mail.eml | base64 -d > attach.bin
# python
$ python3 -c "import email,base64;m=email.message_from_file(open('mail.eml'));[open(p.get_filename(),'wb').write(p.get_payload(decode=True)) for p in m.walk() if p.get_filename()]"
```

После извлечения — `file` (тип), `sha256sum` (IOC), анализ макросов (`forensics-office-macros`), PDF (`forensics-pdf`), архивов (`forensics-archives`).

## Выявление фишинга

Признаки:
- **Поддельный домен**: `paypa1-secure.com`, `rnicrosoft.com`, homoglyph (кириллические символы).
- **Ссылки**: `HREF` ведёт не туда, что видимый текст; URL-шортener; IP вместо домена.
- **Вложения**: исполняемые, архивы с паролем, макросы, `.iso`/`.lnk`.
- **Срочность**: «Urgent», «Verify now», психологическое давление.
- **Заголовки**: SPF/DKIM/DMARC fail, несоответствие `From` и `Return-Path`.

```bash
# извлечь все URL из письма
$ grep -oE 'https?://[^ >"]+' mail.eml | sort -u
# найти расхождение видимого текста и href (HTML-часть)
$ python3 -c "import email,re;m=email.message_from_file(open('mail.eml'));[print(re.findall(r'href=\"([^\"]+)\"',p.get_payload())) for p in m.walk() if p.get_content_type()=='text/html']"
```

## Разобранный пример

Дан `phish.eml`. Нужно доказать фишинг и извлечь нагрузку.

```bash
# 1. Заголовки и маршрут
$ grep -iE '^From:|^Return-Path:|^Received:' phish.eml
From: "Bank" <secure@bank-alerts.co>
Return-Path: <bounce@evil.tld>          # не совпадает с From -> подделка
Received: from evil.tld (203.0.113.9) ...
# 2. Аутентификация
$ grep -i 'Authentication-Results' phish.eml
spf=fail; dkim=none; dmarc=fail
# 3. Вложение
$ ripmime -i phish.eml -d out/
$ file out/*
out/invoice.pdf: PDF document
out/invoice.pdf.js: JavaScript source       # двойное расширение!
# 4. Хеш для IOC
$ sha256sum out/*
```

Итог: поддельный `From`, провал SPF/DMARC, вложение с двойным расширением — классический фишинг с маскировкой.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Разбор `.eml` | `mhonarc`, `python email` |
| Извлечь вложения | `ripmime`, `munpack` |
| Разбор `.msg`/`.pst` | `libpff`, `pffexport` |
| SPF/DKIM/DMARC | `dig`, `opendkim-testmsg` |
| URL/HTML-анализ | `grep`, BeautifulSoup |
| Макросы | `olevba` |
| Хеши IOC | `sha256sum` |

## Частые ошибки

- **Читать `Received` сверху вниз** — маршрут восстанавливается снизу вверх.
- **Верить видимому `From`** — смотрите `Return-Path` и `Authentication-Results`.
- **Пропустить вложение** — ищите все части MIME, включая inline.
- **Не декодировать тему/имена** — base64/`quoted-printable` прячут содержимое.
- **Игнорировать двойные расширения** (`invoice.pdf.js`).
- **Не считать хеш вложения** — он нужен для IOC и VT.

## Что дальше / решение

Конвейер: `grep` заголовков → проверка SPF/DKIM/DMARC → `ripmime` (вложения) → `file`/`sha256` → анализ вложений (`forensics-office-macros`, `forensics-pdf`). Связка: `forensics-email-pst` (PST/OST), `forensics-office-macros` (макросы), `forensics-pdf`, `forensics-carving`.

## Разбор .msg и .pst

`.msg` (одно письмо Outlook) и `.pst`/`.ost` (хранилища) — форматы на базе OLE/ESE. `libpff` извлекает письма, вложения и удалённые элементы.

```bash
$ pffinfo archive.pst                 # метаданные хранилища
$ pffexport -m all archive.pst -t out/   # экспорт писем
$ pffexport -m attachments archive.pst -t att/
$ python3 -c "import extract_msg;m=extract_msg.Message('mail.msg');print(m.subject,m.sender)"
```

`PST` содержит папки (Inbox, Sent, Deleted Items), календарь, контакты. **Deleted Items** и «recoverable deleted» часто хранят письма, удалённые пользователем, — ценно для расследования. `ost` — локальная копия Exchange.

## Хранение, экспорт и юридические аспекты

Письма — это персональные данные; при работе соблюдайте политику и фиксируйте цепочку. Экспортируйте с сохранением заголовков (для атрибуции) и метаданных.

```bash
# конвертировать письмо в PDF с заголовками (для отчёта)
$ python3 -c "import email,subprocess;..."   # или mutt/neomutt -e 'set print_command=...'
# хеш письма и вложения
$ sha256sum mail.eml att/* | tee hashes.txt
```

Для массового разбора используйте `mailpile`/`notmuch` или скрипты на Python `email`/`mailbox`. В отчёте указывайте: отправитель (проверенный), маршрут, результат SPF/DKIM/DMARC, вложения с хешами.

## Быстрый чек-лист разбора письма

1. Декодировать тему и заголовки (base64/quoted-printable).
2. Восстановить маршрут `Received` снизу вверх.
3. Проверить SPF/DKIM/DMARC.
4. Извлечь все вложения (`ripmime`/`pffexport`).
5. `file` + `sha256sum` по вложениям.
6. Разобрать вложения (макросы/PDF/архивы).
7. Извлечь и проанализировать URL.
8. Зафиксировать IOC.

## Быстрая атрибуция отправителя

Самый быстрый способ оценить письмо — посмотреть на пару `From` и `Return-Path`/`Envelope-From`. Если они расходятся (например, `From: bank.com`, `Return-Path: evil.tld`), это почти всегда подделка. Дополните проверкой `Received-SPF` и `Authentication-Results`: провал SPF при совпадающем домене означает спуфинг, а отсутствие DKIM — что письмо не подписано. Для массовых рассылок смотрите IP отправителя и его обратный DNS — несоответствие имени и PTR усиливает вывод о компрометации или спуфинге. Занесите все IOC (домены, IP, хеши вложений) в отчёт.

## Квиз

```quiz
- question: "В каком порядке читаются заголовки Received?"
  options:
    - "сверху вниз"
    - "снизу вверх (от первого сервера к последнему)"
    - "случайно"
    - "по алфавиту"
  answer: 1
- question: "Что проверяет DKIM?"
  options:
    - "IP отправителя"
    - "криптоподпись письма"
    - "размер"
    - "вложение"
  answer: 1
- question: "Какой заголовок показывает реальный адрес возврата?"
  options:
    - "From"
    - "Return-Path"
    - "Subject"
    - "X-Mailer"
  answer: 1
- question: "Как разобрать макросы в .docm-вложении?"
  options:
    - "`oletools.olevba`"
    - "`binwalk`"
    - "`tshark`"
    - "`exiftool`"
  answer: 0
- question: "Признак фишингового письма?"
  options:
    - "`spf=pass`"
    - "расхождение From и Return-Path, spf=fail"
    - "подпись DKIM"
    - "plain text"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с .eml и фишингом.
- **Incident Response:** анализ фишинговой атаки.
- **OSINT:** установление реального отправителя.
- **SOC:** триаж подозрительных писем.
- **Пентест:** тестирование почтовой защиты.
