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
lab:
  kind: shell
  title: "Практика: разбор фишингового письма"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, notes.txt, message.eml]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прочитай заголовки: `cat message.eml` (или `head -20`)."
    - "Цепочка `Received` читается от последнего хопа к первому; ищи IP отправителя."
    - "Нестандартный заголовок `X-Invoice-Note` содержит base64."
    - "Достань и раскодируй: `grep X-Invoice-Note message.eml | cut -d' ' -f2 | base64 -d > found.txt`."
---

## Вопрос, с которого всё начинается

Сотрудник получил письмо «от банка» и перешёл по ссылке. Нужно понять: поддельное ли
письмо и что было во вложении. У нас есть файл `phish.eml` — сырое письмо целиком.

Письмо — это не просто текст: его заголовки фиксируют маршрут через серверы, механизмы
аутентификации показывают подделку отправителя, а вложения несут нагрузку. В этом уроке
мы докажем фишинг и достанем нагрузку.

## Наш пример: phish.eml

Смотрим ключевые заголовки:

```bash
$ grep -iE '^From:|^Return-Path:|^Received:' phish.eml
From: "Bank" <secure@bank-alerts.co>
Return-Path: <bounce@evil.tld>
Received: from evil.tld (203.0.113.9) ...
```

Первое, что бросается в глаза: `From` и `Return-Path` **не совпадают**. `Return-Path` —
это реальный адрес возврата, и он указывает на чужой домен `evil.tld`. Это почти всегда
признак подделки.

## Шаг 1: маршрут через заголовки Received

Каждый почтовый сервер (MTA) добавляет заголовок `Received` **сверху**. Значит, самый
верхний — последний сервер, а читать маршрут нужно **снизу вверх**:

```bash
$ grep -i '^Received:' phish.eml
Received: from evil.tld (203.0.113.9)
    by mx.example.com; Fri, 1 Mar 2024 12:00:00 +0000
Received: from [10.0.0.5] (unknown [203.0.113.9])
    by evil.tld; Fri, 1 Mar 2024 11:59:58 +0000
```

Поля: `from <хост> (<IP>)`, `by <сервер>`, дата. Расхождение имени и IP, приватные
адреса, «unknown» — признаки подделки.

## Шаг 2: аутентификация SPF/DKIM/DMARC

Три механизма проверяют, имел ли отправитель право слать письмо:

- **SPF** — список IP, которым разрешено отправлять от имени домена.
- **DKIM** — криптоподпись письма.
- **DMARC** — политика на основе SPF и DKIM.

Результат проверки лежит в заголовке `Authentication-Results`:

```bash
$ grep -i 'Authentication-Results' phish.eml
Authentication-Results: mx.example.com;
  spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=bank-alerts.co;
  dkim=none; dmarc=fail
```

`spf=fail` плюс `dmarc=fail` — явная подделка отправителя. Проверить можно вручную:

```bash
$ dig +short TXT bank-alerts.co          # SPF-запись домена
$ dig +short TXT _dmarc.bank-alerts.co   # политика DMARC
```

## Шаг 3: извлекаем вложения

Письмо с вложением устроено как **MIME** — контейнер из частей, каждая со своим типом и
кодировкой. Разложить его на части проще всего `ripmime`:

```bash
$ ripmime -i phish.eml -d out/
$ file out/*
out/invoice.pdf: PDF document
out/invoice.pdf.js: JavaScript source
```

Вот и нагрузка: файл называется `invoice.pdf`, но рядом появился `invoice.pdf.js` —
**двойное расширение**. Пользователь видит «PDF», а выполняется JavaScript.

## Шаг 4: фиксируем IOC

```bash
$ sha256sum out/*
```

Хеши вложений — это **IOC** (индикаторы компрометации): по ним файл ищут в VirusTotal и
в других системах. Хеш письма тоже сохраняем — для отчёта.

## Шаг 5: декодируем тему и части

Заголовки и тема часто закодированы, чтобы их не читали глазами:

```bash
$ head -5 phish.eml
Subject: =?UTF-8?B?VXJnZW50IQ==?=
```

Конструкция `=?UTF-8?B?...?=` — это base64-кодированный текст. `python email` или
`mhonarc` декодируют её в читаемое «Urgent!».

## Шаг 6: анализируем ссылки и HTML

В HTML-части письма видимый текст ссылки может отличаться от настоящего адреса:

```bash
$ grep -oE 'https?://[^ >"]+' phish.eml | sort -u
$ python3 -c "import email,re;m=email.message_from_file(open('phish.eml'));[print(re.findall(r'href=\"([^\"]+)\"',p.get_payload())) for p in m.walk() if p.get_content_type()=='text/html']"
```

Расхождение «видим `bank.com`, а href ведёт на `evil.tld`» — классика фишинга.

## Шаг 7: .msg и .pst

Кроме `.eml`, бывают форматы Outlook: `.msg` (одно письмо) и `.pst`/`.ost` (хранилище).
Их разбирает `libpff`:

```bash
$ pffexport -m all archive.pst -t out/
$ python3 -c "import extract_msg;m=extract_msg.Message('mail.msg');print(m.subject,m.sender)"
```

Папка **Deleted Items** в PST часто хранит письма, удалённые пользователем, — ценный
источник для расследования.

## Как устроено письмо внутри

Письмо — это заголовки, пустая строка и тело. При вложении тело делится на части по
**MIME**:

```
Content-Type: multipart/mixed; boundary="----=_NextPart_000"
------=_NextPart_000
Content-Type: text/plain
Content-Transfer-Encoding: base64
```

У каждой части свой `Content-Type`, кодировка (`base64` или `quoted-printable`) и
`Content-Disposition` (`inline` или `attachment`). Именно поэтому вложение не «видно»
глазами — оно закодировано.

## Быстрый чек-лист разбора

1. Декодировать тему и заголовки (base64/quoted-printable).
2. Восстановить маршрут `Received` снизу вверх.
3. Проверить SPF/DKIM/DMARC в `Authentication-Results`.
4. Извлечь все вложения (`ripmime`/`pffexport`).
5. `file` + `sha256sum` по вложениям.
6. Разобрать вложения (макросы/PDF/архивы).
7. Извлечь и проанализировать URL.
8. Зафиксировать IOC (домены, IP, хеши).

Пункты идут от дешёвого к дорогому — не перескакивайте через первые.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Разбор `.eml` | `mhonarc`, `python email` |
| Извлечь вложения | `ripmime`, `munpack` |
| Разбор `.msg`/`.pst` | `libpff`, `pffexport` |
| SPF/DKIM/DMARC | `dig`, `opendkim-testmsg` |
| URL/HTML-анализ | `grep`, BeautifulSoup |
| Макросы | `olevba` |

## Подробнее про .msg и .pst

`.pst`/`.ost` — это хранилища Outlook на базе ESE. `libpff` умеет выгружать письма,
вложения и **удалённые** элементы:

```bash
$ pffinfo archive.pst
$ pffexport -m all archive.pst -t out/
$ pffexport -m attachments archive.pst -t att/
```

Папка **Deleted Items** и область «recoverable deleted» часто хранят письма, удалённые
пользователем, — для расследования это золото. `.ost` — локальная копия Exchange.

## Юридические аспекты

Письма — это персональные данные, поэтому при работе соблюдайте политику и фиксируйте
цепочку хранения. Экспортируйте письма с сохранением заголовков (для атрибуции) и
метаданных, считайте хеши письма и вложений:

```bash
$ sha256sum mail.eml att/* | tee hashes.txt
```

В отчёте укажите проверенного отправителя, маршрут через серверы, результат
SPF/DKIM/DMARC и вложения с хешами. Для массового разбора используйте скрипты на Python
(`email`/`mailbox`) или `notmuch`.

## Быстрая атрибуция отправителя

Самый быстрый способ оценить письмо — сравнить `From` и `Return-Path`/`Envelope-From`.
Если они расходятся (`From: bank.com`, `Return-Path: evil.tld`), это почти всегда
подделка. Дополните проверкой `Received-SPF` и `Authentication-Results`: провал SPF при
совпадающем домене означает спуфинг, а отсутствие DKIM — что письмо не подписано. Для
массовых рассылок смотрите IP отправителя и его обратный DNS: несоответствие имени и PTR
усиливает вывод о спуфинге. Все IOC (домены, IP, хеши вложений) — в отчёт.

## Что мы теперь знаем

- `From` и `Return-Path` должны совпадать; расхождение — признак подделки.
- `Received` читается снизу вверх — от отправителя к получателю.
- `spf=fail` и `dmarc=fail` доказывают спуфинг отправителя.
- `ripmime` разбирает MIME и извлекает вложения; двойные расширения — приём маскировки.
- Хеши вложений — IOC; тема и заголовки могут быть закодированы base64.

## На что смотреть дальше

- **Не верить видимому `From`** — смотрите `Return-Path` и `Authentication-Results`.
- **Искать все части MIME**, включая inline-вложения.
- **Декодировать тему и имена** — base64/quoted-printable прячут содержимое.
- **Не игнорировать двойные расширения** (`invoice.pdf.js`).
- **Проверять обратный DNS** отправителя — несоответствие PTR усиливает вывод о спуфинге.

## Квиз

Проверь себя.

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

## Куда дальше

Письмо привело нас к веб-серверу — следующему частому месту компрометации. В следующем
уроке мы разберём скомпрометированный сайт: найдём webshell в логах и файловой системе.
А пока запомни: **письмо выдаёт подделку заголовками, а не текстом**.

## Где пригодится

- **CTF:** задачи с .eml и фишингом.
- **Incident Response:** анализ фишинговой атаки.
- **OSINT:** установление реального отправителя.
- **SOC:** триаж подозрительных писем.
- **Пентест:** тестирование почтовой защиты.
