---
id: forensics-tls-decrypt
title: "Расшифровка TLS: SSLKEYLOGFILE и keylog"
category: forensics
parent: forensics-network-deep
difficulty: hard
order: 1
tags: [tls, sslkeylogfile, wireshark, pcap, network, forensics, decryption]
prerequisites: [forensics-network-deep, forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ сетевого трафика"
estimated_minutes: 40
summary: "Как расшифровать TLS-трафик в Wireshark: SSLKEYLOGFILE, извлечение сессионных ключей из памяти/дампа, RSA-ключ, и почему forward secrecy усложняет задачу."
lab:
  kind: shell
  title: 'Практика: расшифровка TLS 1.2 по SSLKEYLOGFILE'
  toolset: [core, hex, python3]
  workdir: /home/student/task
  files: [task.md, client_random.txt, server_random.txt, keylog.txt, record.bin, decrypt_tls.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'SSLKEYLOGFILE даёт `CLIENT_RANDOM <random> <master_secret>`.'
    - 'Ключевой блок выводится через TLS PRF: PRF(master, "key expansion", server_random+client_random).'
    - 'Для AES-128-GCM: client key = первые 16 байт, fixed_iv = байты 32..36.'
    - '`python3 decrypt_tls.py | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

У тебя есть `https.pcap` — захват трафика с машины после инцидента. Но почти всё
внутри — «шифрованный шум»: современные сайты работают по **TLS** (Transport Layer
Security), протоколу шифрования. Открыв файл в Wireshark, ты увидишь только
рукопожатия и случайные байты.

Хорошая новость: TLS можно расшифровать, **если получить ключи**. Вопрос — какие
именно ключи и где их взять. В этом уроке мы это и разберём.

## Наш пример: HTTPS-сессия к подозрительному серверу

Откроем захват и посмотрим, что вообще видно без ключей:

```bash
$ tshark -r https.pcap -Y 'tls.handshake.type==1' -T fields -e ip.dst -e tls.handshake.extensions_server_name | head
185.220.101.7	evil.tld
```

Даже без ключей виден **SNI** (Server Name Indication) — имя сайта, которое клиент
передаёт открыто при рукопожатии. Значит, соединение шло к `evil.tld`. Но **что
именно** передавалось, пока скрыто.

## Шаг 1: как TLS договаривается о ключе

При соединении клиент и сервер проводят **рукопожатие** и договариваются о
**сессионном ключе** — симметричном ключе, которым потом шифруют данные. Способов
договориться два:

- **RSA key exchange** (устаревший): клиент шифрует сессионный ключ **публичным
  RSA-ключом** сервера. Если у тебя есть **приватный** RSA-ключ сервера — расшифруешь.
- **ECDHE/DHE** (современный, *forward secrecy*): ключ вычисляется из эфемерных
  («одноразовых») значений, которые нигде не сохраняются. Приватный RSA-ключ сервера
  **не поможет** — нужны сами сессионные ключи.

**Forward secrecy** («прямая секретность») — свойство, при котором компрометация
долгосрочного ключа не раскрывает прошлые сессии. Именно поэтому старый трюк «взять
ключ сервера и расшифровать» больше не работает на современных сайтах.

## Шаг 2: самый простой путь — SSLKEYLOGFILE

Если на машине, чей трафик мы анализируем, есть **keylog-файл**, всё решается в одну
команду. Браузеры и многие приложения по переменной окружения `SSLKEYLOGFILE`
записывают сессионные ключи в файл формата **NSS Key Log**:

```bash
$ SSLKEYLOGFILE=/tmp/keys.log firefox &
```

Файл выглядит так:

```
CLIENT_RANDOM <client_random> <master_secret>
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
```

Подаём его Wireshark (или `tshark`) через опцию `tls.keylog_file`:

```bash
$ tshark -r https.pcap -o tls.keylog_file:keys.log -Y 'http.request' -T fields -e http.host -e http.request.uri
evil.tld	/gate.php
```

Содержимое расшифровано. Мы видим обращение к `evil.tld/gate.php` — типичный
адрес C2-«шлюза».

## Шаг 3: если keylog нет — ищем RSA-ключ или ключи в памяти

Проверим, использует ли сервер forward secrecy. Утилита `openssl s_client` подключается
к серверу и показывает выбранный шифр:

```bash
$ openssl s_client -connect evil.tld:443 -cipher DEFAULT </dev/null 2>/dev/null | grep -i 'Cipher is'
Cipher is ECDHE-RSA-AES256-GCM-SHA384
```

`ECDHE` в названии шифра означает forward secrecy. Значит, RSA-ключ не поможет —
ищем сессионные ключи в **дампе памяти**. Плагин Volatility извлекает их оттуда:

```bash
$ vol -f mem.raw windows.ssl_keyscan
```

Найденные ключи конвертируют в тот же NSS-keylog и подают в Wireshark. Если сервер
был бы **без** forward secrecy (шифр с `RSA` без `E`), хватило бы приватного ключа:

```bash
$ tshark -r https.pcap -o tls.keys_list:"10.0.0.5,443,http,server.key" -Y http
```

## Шаг 4: извлекаем данные

Теперь, когда трафик читается, извлечём то, что передавалось. Тело POST-запроса —
это данные, которые клиент отправил на сервер:

```bash
$ tshark -r https.pcap -o tls.keylog_file:keys.log -Y 'http.request.method=="POST"' -T fields -e http.file_data | head
dXNlcj1ib2ImcGFzcz0uLi4=
```

А все переданные файлы можно вытащить одной командой:

```bash
$ tshark -r https.pcap -o tls.keylog_file:keys.log --export-objects http,http_obj/
$ file http_obj/*
http_obj/1: PNG image data
```

## Шаг 5: TLS 1.3 и QUIC

В **TLS 1.3** forward secrecy обязательна, поэтому RSA-ключ сервера бесполезен
всегда — работают только `*_TRAFFIC_SECRET` из keylog. Формат keylog чуть другой:

```
CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
```

Wireshark версии 3.0+ понимает TLS 1.3. **QUIC** (HTTP/3) — это TLS поверх UDP;
он расшифровывается тем же keylog.

## Когда ключей нет вообще

Если нет ни keylog, ни дампа памяти, ни RSA-ключа, а forward secrecy включён —
пассивно расшифровать нельзя. Остаются:

- **метаданные**: SNI, сертификаты, JA3-отпечатки, тайминги и объёмы (часто и этого
  хватает, чтобы доказать факт связи с C2);
- **активный перехват** (MITM-прокси) — но это меняет трафик и требует установки
  своего сертификата на клиента, то есть применимо только при контроле над ним.

## Полный разбор: расшифровываем сессию

Соберём расшифровку в один сценарий.

1. **Получаем PCAP** с HTTPS-трафиком к подозрительному серверу.
2. **Ищем источник ключей.** Для TLS 1.3 без keylog-файла сессионные ключи есть только в памяти клиента/сервера.
3. **Снимаем keylog.** Если контролируем клиента, включаем `SSLKEYLOGFILE=/tmp/keys.log` до запуска браузера.
4. **Указываем ключи в Wireshark.** `Preferences → Protocols → TLS → (Pre)-Master-Secret log filename`.
5. **Читаем расшифрованное.** Появляются HTTP-запросы, тела, куки — то, что было скрыто.
6. **TLS 1.3.** С keylog работает так же; без него — только метаданные (SNI, сертификаты).

Ключ: для TLS 1.3 «приватный ключ сервера» **не помогает** — forward secrecy делает сессионные ключи одноразовыми.

## Шпаргалка

| Способ | Что нужно | Работает для |
|--------|-----------|--------------|
| SSLKEYLOGFILE | доступ к клиенту | TLS 1.2 и 1.3 |
| RSA-ключ сервера | приватный ключ | только TLS 1.2 (RSA) |
| Ключи из памяти | дамп RAM | обе версии |
| Метаданные | ничего | SNI, сертификаты |

`ssl.log` Zeek + JA3 дают «кто с кем» даже без расшифровки.

## Частые вопросы

**Почему приватный ключ не расшифровывает?** Из-за forward secrecy (ECDHE): сессионный ключ не выводится из долговременного.

**Где искать ключи в памяти?** В дампе процесса браузера/сервера — структуры OpenSSL; помогает `volatility` и плагины поиска ключей.

**QUIC (HTTP/3) расшифровывается?** Только с keylog (NSS keylog format); по-другому — нет.

**Можно ли расшифровать задним числом без keylog?** Практически нет — это и есть цель forward secrecy.

## Что мы теперь знаем

- Современный трафик зашифрован TLS; без ключей видно только метаданные (SNI, JA3).
- **SSLKEYLOGFILE** — файл с сессионными ключами; самый простой путь расшифровки.
- **Forward secrecy** (ECDHE/DHE, TLS 1.3) делает приватный RSA-ключ бесполезным.
- Если keylog нет — сессионные ключи достают из **дампа памяти**.
- `tshark -o tls.keylog_file` расшифровывает, а `--export-objects` вынимает файлы.

## На что смотреть дальше

- **Расшифровывать FS-трафик RSA-ключом** — не выйдет; проверь шифр заранее.
- **Не проверить forward secrecy** перед попыткой.
- **Игнорировать keylog** — это самый быстрый путь, ищи его первым.
- **Путать ключи клиента и сервера** в `keys_list`.
- **Забывать про TLS 1.3** — там другие имена секретов.
- **Не снять дамп памяти** — ключи исчезнут после перезагрузки.

## Квиз

Проверь себя.

```quiz
- question: "Что содержит SSLKEYLOGFILE?"
  options:
    - "пароли сервера"
    - "строки CLIENT_RANDOM <hex> <master_secret>"
    - "сертификаты"
    - "список DNS"
  answer: 1
- question: "Почему приватный RSA-ключ сервера не расшифрует современный TLS?"
  options:
    - "ключ слишком короткий"
    - "из-за forward secrecy (ECDHE/DHE) ключ сервера не выводит сессионные ключи"
    - "TLS не использует RSA"
    - "ключ зашифрован"
  answer: 1
- question: "Где можно взять ключи сессии, если нет SSLKEYLOGFILE?"
  options:
    - "в дампе памяти процесса"
    - "в EVTX"
    - "в prefetch"
    - "в реестре"
  answer: 0
- question: "Что видно в TLS-трафике даже без ключей?"
  options:
    - "тела HTTP-ответов"
    - "SNI (имя хоста), сертификаты, JA3, тайминги"
    - "пароли"
    - "cookies"
  answer: 1
- question: "Как подключить keylog к Wireshark?"
  options:
    - "Preferences → Protocols → TLS → (Pre)-Master-Secret log filename"
    - "через фильтр tls.key"
    - "переименовать pcap"
    - "никак"
  answer: 0
```

## Куда дальше

Мы научились расшифровывать TLS. В следующем уроке поднимемся на уровень выше и
разберём **Zeek** — анализатор, который превращает весь захваченный трафик в
структурированные логи, по которым удобно строить картину атаки. А пока запомни:
**для расшифровки TLS нужны ключи; сначала ищи keylog, потом — дамп памяти, и
всегда проверяй forward secrecy**.

## Где пригодится

- **CTF** — задачи, где флаг передаётся по HTTPS и есть keylog/дамп.
- **DFIR** — анализ C2 и утечек по зашифрованному каналу.
- **Анализ малвари** — расшифровка TLS-трафика бота (при наличии дампа).
- **Red team awareness** — понимание, что forward secrecy защищает прошлый трафик.
- **Сетевая форензика** — метаданные TLS как источник при невозможности расшифровки.
