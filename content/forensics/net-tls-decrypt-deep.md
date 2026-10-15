---
id: net-tls-decrypt-deep
title: 'Глубокая расшифровка TLS: ключи, сессии и перехват'
category: forensics
parent: forensics-net-services
difficulty: hard
order: 3
tags: [network, tls, ssl, decrypt, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 55
summary: 'Как расшифровать TLS-трафик при наличии ключей: SSLKEYLOGFILE, приватный ключ RSA и проблемы с TLS 1.3/forward secrecy.'
lab:
  kind: shell
  title: 'Практика: Глубокая расшифровка TLS'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Почти весь трафик сегодня зашифрован TLS. Чтобы понять, что передавалось, его надо
расшифровать. Это возможно — но только при наличии **ключей**. Разберём три пути и их
ограничения.

## Наш пример: дамп HTTPS

## Шаг 1: почему «просто посмотреть» не выйдет

TLS 1.3 и (E)CDHE-шифры используют **forward secrecy**: ключ сессии выводится из
эфемерных значений и после сессии уничтожается. Поэтому одного приватного ключа
сервера **недостаточно**:

```
$ tshark -r https.pcap -Y 'tls.handshake.type==1' -c 1
```

Handshake виден, но данные — нет.

## Шаг 2: путь 1 — SSLKEYLOGFILE

Самый надёжный способ: заставить клиент (браузер, curl) записать ключи сессии в файл.

```
$ SSLKEYLOGFILE=/tmp/keys.log firefox
```

Затем в Wireshark/tshark указываем файл:

```
$ tshark -r https.pcap -o tls.keylog_file:/tmp/keys.log -Y 'http' -T fields -e http.request.uri | head
```

Так расшифровываются и TLS 1.3. В расследовании этот путь требует доступа к клиенту
**до** инцидента или на живом хосте.

## Шаг 3: путь 2 — приватный ключ сервера

Для старых шифров (RSA key exchange) достаточно приватного ключа сервера:

```
$ tshark -r https.pcap -o tls.keys_list:"10.10.20.5,443,http,/evidence/server.key"
```

Но с forward secrecy (современный дефолт) это не работает. Проверь шифр:

```
$ tshark -r https.pcap -Y 'tls.handshake.ciphersuite' -T fields -e tls.handshake.ciphersuite | head
0x1301
```

`0x1301` = TLS_AES_128_GCM_SHA256 (TLS 1.3) — приватный ключ бесполезен.

## Шаг 4: путь 3 — перехват (MITM)

Если есть легитимный прокси с подменой сертификата, все сессии расшифровываются на
нём. Логи прокси содержат URL и тела:

```
$ grep -i '203.0.113.5' /var/log/squid/access.log | tail
```

Это работает, если клиент доверяет корневому сертификату прокси. Смотри, не
установлен ли подозрительный корневой сертификат — это признак компромисса.

## Шаг 5: что искать в расшифрованном

- URL и заголовки запросов;
- тела POST (формы, JSON);
- cookie и токены;
- загруженные/скачанные файлы.

## Что мы теперь знаем

- TLS 1.3/ECDHE нельзя расшифровать одним приватным ключом.
- `SSLKEYLOGFILE` даёт ключи сессии (в т.ч. TLS 1.3).
- Старые RSA-шифры — приватный ключ сервера.
- MITM-прокси расшифровывает, если клиент доверяет его CA.
- Проверяй подозрительные корневые сертификаты.

## Если не сработало

- Ключей нет? Ищи их в памяти и на диске.
- Нужны метаданные без расшифровки? Смотри SNI и сертификаты.
- TLS 1.3? Только keylog или MITM.

## Как устроена TLS-сессия

Чтобы понять, что можно расшифровать, нужно разложить рукопожатие на этапы:

1. **ClientHello** — клиент предлагает версии и наборы шифров, шлёт `SNI`.
2. **ServerHello** — сервер выбирает шифр, версию, отправляет сертификат.
3. **Key exchange** — стороны договариваются о сессионных ключах.
4. **Finished** — подтверждение; далее прикладные данные шифруются.

Ключевой момент — **шаг 3**. При RSA key exchange клиент шифрует pre-master secret
публичным ключом сервера, и **приватный ключ сервера расшифровывает его**. При
(E)CDHE стороны генерируют эфемерные ключи, обмениваются публичными частями, и
сессионный ключ **никогда не передаётся** — его нельзя вывести из долговременного
ключа. Это и есть forward secrecy.

```
$ tshark -r https.pcap -Y 'tls.handshake.type==16' -c 2   # ClientKeyExchange
```

Если видишь `ClientKeyExchange` с зашифрованным pre-master — шифр RSA, ключ сервера
поможет. Если только `ECDHE`-параметры — нужен keylog или MITM.

## SSLKEYLOGFILE: практика

Клиенты с поддержкой NSS/OpenSSL (Firefox, Chrome, curl) умеют писать сессионные
ключи в файл, если задать переменную окружения:

```
$ SSLKEYLOGFILE=/tmp/keys.log curl https://target.local/
$ head -2 /tmp/keys.log
CLIENT_RANDOM <hex> <hex-master-secret>
CLIENT_HANDSHAKE_TRAFFIC_SECRET <hex> <hex>
```

Формат строки зависит от версии TLS: для TLS 1.3 пишутся
`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`,
`CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, для TLS 1.2 — `CLIENT_RANDOM`.
Сопоставление идёт по первому полю (`CLIENT_RANDOM` = client random из handshake).

Затем в `tshark`:

```
$ tshark -r https.pcap -o tls.keylog_file:/tmp/keys.log -Y 'http.request' \
    -T fields -e http.host -e http.request.uri
```

Метод работает для любой версии TLS, но требует доступа к клиенту **в момент**
соединения. В расследовании его применяют на живом хосте или настраивают заранее.

## Приватный ключ сервера: когда работает

Если сессия использует RSA-шифры (устаревшие, но встречаются), достаточно ключа:

```
$ tshark -r https.pcap -o tls.keys_list:"10.10.20.5,443,http,/evidence/server.key" \
    -Y 'http' -T fields -e http.request.uri | head
```

Синтаксис `keys_list`: `IP,порт,протокол,путь_к_ключу`. Несколько ключей разделяются
запятой. Но сначала проверь шифр:

```
$ tshark -r https.pcap -Y 'tls.handshake.ciphersuite' \
    -T fields -e tls.handshake.ciphersuite | sort -u
0x009c
0x1301
```

`0x009c` = TLS_RSA_WITH_AES_128_GCM_SHA256 — ключ поможет. `0x1301` = TLS 1.3 —
нет. Смешанные наборы означают: часть сессий расшифруется, часть нет.

## Что можно узнать без расшифровки

Отсутствие ключей не означает «нет данных». Из метаданных извлекается много:

- **SNI** — какой хост запрашивали (`tls.handshake.extensions_server_name`);
- **сертификат** — CN/SAN, издатель, сроки, отпечаток;
- **JA3/JA3S** — отпечаток клиента и сервера, помогает фингерпринтить ПО;
- **объёмы и тайминги** — размеры потоков, периодичность (beaconing);
- **ALPN** — `h2`, `http/1.1` и т.д.

```
$ tshark -r https.pcap -Y 'tls.handshake.extensions_server_name' \
    -T fields -e tls.handshake.extensions_server_name | sort -u
```

## Скрытые каналы и MITM

- **Рутовой сертификат-злоумышленник.** Если на хосте появился лишний корневой CA,
  весь TLS может быть перехвачен — ищи его в хранилище (`security find-certificate`,
  `/etc/ssl/certs`).
- **Прокси-логи.** Если трафик шёл через корпоративный прокси, он уже расшифрован:
  `access.log` содержит URL, `cache` — тела.
- **Пиннинг.** Мобильные приложения часто проверяют сертификат и обходят MITM —
  тогда только keylog/дамп памяти.
- **Логи mitmproxy/Fiddler** на машине аналитика тоже содержат расшифрованные сессии.

## Ограничения

- **TLS 1.3 + ECDHE** — только keylog или MITM.
- **Гибридные/PQ обмены** (X25519Kyber) — новые, часть инструментов их не парсит.
- **Сессионные тикеты/PSK** — возобновлённые сессии расшифровываются иначе.
- **Ключ нужен «свой».** Приватный ключ одного сервера не расшифрует сессии к другому.
- Всегда хешируй pcap и keylog-файл до анализа — целостность улик.

## Что видно без расшифровки

Прежде чем гнаться за ключами, извлеки то, что TLS отдаёт открыто:

- **SNI** — имя сервера в ClientHello (`tls.handshake.extensions_server_name`);
- **сертификаты** — цепочка сервера видна в открытом виде, включая CN/SAN;
- **версия и шифры** — `tls.handshake.ciphersuite` определяет, возможна ли расшифровка
  ключом сервера;
- **объёмы и тайминги** — размеры записей выдают характер трафика.

```
$ tshark -r https.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u
$ tshark -r https.pcap -Y 'tls.handshake.type==11' -T fields -e x509sat.uTF8String | head
```

Это уже даёт карту: какие домены посещались, к какому серверу шли соединения, какой
шифр использовался.

## SSLKEYLOGFILE: как это работает

Браузеры (Firefox, Chrome) и `curl` (с NSS) умеют писать **session keys** в файл, если
задана переменная окружения:

```
$ export SSLKEYLOGFILE=/tmp/keys.log
$ firefox &                       # или: curl --tls-max 1.3 https://target
$ wc -l /tmp/keys.log
```

Файл содержит строки `CLIENT_RANDOM`/`CLIENT_HANDSHAKE_TRAFFIC_SECRET` и т. п. Это
**симметричные** ключи сессии, поэтому расшифровывается и TLS 1.3. Подключаем к дампу:

```
$ tshark -r https.pcap -o tls.keylog_file:/tmp/keys.log -Y 'http' \
    -T fields -e http.host -e http.request.uri
$ tshark -r https.pcap -o tls.keylog_file:/tmp/keys.log --export-objects http,out/
```

В расследовании ключ обычно берут с живого хоста или из памяти **до** выключения.

## Приватный ключ сервера: когда сработает

Приватный ключ сервера расшифровывает только те сессии, где ключ сессии был зашифрован
RSA (**static RSA key exchange**, шифры `TLS_RSA_*`). Проверить шифр:

```
$ tshark -r https.pcap -Y 'tls.handshake.type==2' -T fields -e tls.handshake.ciphersuite | head
0x002f   # TLS_RSA_WITH_AES_128_CBC_SHA  -> ключ сервера подойдёт
0x1301   # TLS_AES_128_GCM_SHA256        -> forward secrecy, не подойдёт
```

Подключаем ключ:

```
$ tshark -r https.pcap -o tls.keys_list:"10.10.20.5,443,http,/evidence/server.key"
```

## TLS 1.3 и forward secrecy

В TLS 1.3 все шифры эфемерные (ECDHE). Ключ сессии выводится из эфемерных пар и
**уничтожается** после сессии. Поэтому:

- приватный ключ сервера **бесполезен**;
- остаются только `SSLKEYLOGFILE`, дамп памяти с ключами или MITM.

Именно это делает TLS 1.3 «форензик-враждебным» и объясняет, почему в расследованиях так
ценятся артефакты на конечной точке.

## Извлечение ключей из памяти

Если хост ещё жив, ключи сессии лежат в памяти процесса (браузера, `curl`, сервера):

```
$ vol -f memory.raw windows.netscan
$ vol -f memory.raw windows.pstree | grep -i 'chrome\|firefox'
```

Для OpenSSL-серверов есть `sslkeylog`-плагины и скрипты (например, для GnuTLS/OpenSSL
через `libsslkeylog`). Для многих сервисов ключи живут до перезапуска — это окно, в
котором их можно снять.

## Инструменты и чек-лист

| Инструмент | Назначение |
|---|---|
| Wireshark / tshark | расшифровка, `--export-objects` |
| `tls.keylog_file` | подключение session keys |
| `tls.keys_list` | приватный ключ сервера (RSA) |
| Volatility | извлечение ключей из памяти |
| `libsslkeylog` | перехват ключей на живой системе |

Чек-лист: 1) определить шифр; 2) посмотреть SNI/сертификаты без ключей; 3) если RSA —
подключить приватный ключ; 4) если 1.3 — искать keylog или память; 5) проверить, нет ли
MITM-прокси с доверенным CA.

## Если сработало / не сработало

Если ключей нет — не застревай: метаданные (SNI, сертификаты, объёмы, тайминги) часто
дают ответ. Если есть корпоративный прокси — ищи его логи: там уже расшифровано. Если
клиент жив — попробуй снять ключи из памяти до перезапуска.

## Квиз

Проверь себя.

```quiz
- question: Почему приватного ключа сервера недостаточно для TLS 1.3?
  options:
    - 'ключ слишком короткий'
    - 'используется forward secrecy (эфемерные ключи)'
    - 'TLS 1.3 не шифрует'
    - 'нужен пароль'
  answer: 1
  explanation: 'ECDHE даёт эфемерные ключи; статичный ключ сервера не подходит.'
- question: Что делает SSLKEYLOGFILE?
  options:
    - 'шифрует диск'
    - 'записывает ключи сессий для расшифровки'
    - 'удаляет cookies'
    - 'ускоряет сеть'
  answer: 1
  explanation: 'Клиент пишет session keys, которые затем используются для расшифровки.'
- question: Как расшифровать трафик через MITM-прокси?
  options:
    - 'никак'
    - 'если клиент доверяет корневому сертификату прокси'
    - 'по паролю'
    - 'по ARP'
  answer: 1
  explanation: 'Прокси подменяет сертификаты; доверие его CA делает расшифровку возможной.'
- question: Что искать в расшифрованном TLS?
  options:
    - 'только размеры'
    - 'URL, тела, cookie и файлы'
    - 'ничего'
    - 'только заголовки'
  answer: 1
  explanation: 'Расшифровка раскрывает прикладной уровень: запросы и данные.'
```
