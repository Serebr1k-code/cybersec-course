---
id: net-voip
title: 'VoIP в форензике: звонки, SIP и RTP'
category: forensics
parent: forensics-net-services
difficulty: hard
order: 2
tags: [network, voip, sip, rtp, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как из трафика VoIP восстановить звонки: кто кому звонил (SIP) и что говорили (RTP), при наличии условий.'
lab:
  kind: shell
  title: 'Практика: VoIP в форензике'
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

Звонки идут по сети — значит, где-то есть их следы. SIP устанавливает сессию, RTP
переносит голос. Из дампа можно восстановить, кто кому звонил и когда, а иногда и
сам разговор. Разберём.

## Наш пример: VoIP-дамп

## Шаг 1: SIP — сигнализация

SIP — текстовый протокол (порт 5060/UDP или 5061/TLS):

```
$ tshark -r voip.pcap -Y 'sip' -T fields -e sip.Method -e sip.from.user -e sip.to.user | head
INVITE	alice	bob
BYE	alice	bob
```

`INVITE` — начало звонка, `BYE` — конец. `from`/`to` дают участников. Это уже
телефонный журнал.

## Шаг 2: время и длительность

```
$ tshark -r voip.pcap -Y 'sip.Method=="INVITE" || sip.Method=="BYE"' -T fields -e frame.time -e sip.Method -e sip.CSeq.method
Jan 14 03:20:00	INVITE	INVITE
Jan 14 03:22:30	BYE	BYE
```

Разница времени = длительность разговора. Сопоставляя INVITE/BYE, строишь CDR
(call detail record) прямо из трафика.

## Шаг 3: RTP — сам голос

RTP — это бинарный поток (чётные порты выше 16384):

```
$ tshark -r voip.pcap -Y 'rtp' -T fields -e rtp.ssrc -e rtp.p_type | head
1234567	0
```

`p_type=0` — кодек PCMU (G.711). Зная кодеки, RTP можно собрать в аудиофайл. В
Wireshark есть `Telephony → RTP → Stream Analysis → Save payload`.

## Шаг 4: расшифровка SRTP

Если звонки шифрованы (SRTP), нужен ключ. Он может быть в SDP-описании (при
небезопасной настройке) или на сервере:

```
$ tshark -r voip.pcap -Y 'sdp' -T fields -e sdp.media.port -e sdp.media.proto | head
```

`RTP/SAVP` означает шифрованный профиль — без ключа голос не восстановить.

## Шаг 5: следы на хосте/сервере

На сервере (Asterisk/FreeSWITCH) есть CDR:

```
$ cat /var/log/asterisk/cdr-csv/Master.csv | tail -3
"alice","bob","...","2026-01-14 03:20:00","...","3","ANSWERED"
```

Это готовый журнал звонков с длительностью и статусом.

## Что мы теперь знаем

- SIP — текстовая сигнализация (кто кому, когда).
- INVITE/BYE дают CDR прямо из трафика.
- RTP — голос; при известном кодеке собирается в аудио.
- SRTP требует ключа.
- Серверные CDR дублируют и уточняют картину.

## Если не сработало

- SIP по TLS? Нужны ключи.
- RTP не собрать? Проверь кодек и направление потоков.
- Нет дампа? Читай CDR сервера.

## SIP: структура и методы

SIP — текстовый протокол, похожий на HTTP, и это упрощает анализ. Ключевые методы:

| Метод | Смысл |
|---|---|
| `REGISTER` | устройство регистрируется на сервере |
| `INVITE` | начало сессии (звонок) |
| `ACK` | подтверждение установления |
| `BYE` | завершение сессии |
| `CANCEL` | отмена ещё не установленного звонка |
| `OPTIONS` | проверка доступности |

Ответы кодируются числами: `200 OK` — успех, `401/407` — запрос авторизации,
`486 Busy`, `480 Unavailable`. Заголовки несут участников:

```
$ tshark -r voip.pcap -Y 'sip' \
    -T fields -e frame.time -e sip.Method -e sip.From -e sip.To -e sip.CSeq | head
```

`From`/`To` содержат URI вида `sip:alice@corp.local`, `CSeq` нумерует транзакции
внутри диалога. `Call-ID` объединяет сообщения одного звонка — по нему удобно
группировать.

## Построение CDR прямо из дампа

CDR (call detail record) восстанавливается без сервера, если есть pcap:

1. Отфильтруй `INVITE` и `BYE`.
2. Сгруппируй по `Call-ID`.
3. Возьми время первого `INVITE` и последнего `BYE`.
4. Разница — длительность; `From`/`To` — участники.

`tshark` умеет делать это готовым анализом:

```
$ tshark -r voip.pcap -q -z sip,stat
$ tshark -r voip.pcap -q -z rtp,streams
```

Первая команда даёт статистику SIP (звонки, ответы, ошибки), вторая — список
RTP-потоков с парами адресов и числом пакетов. Потоков без соответствующего SIP-
диалога быть не должно — «осиротевший» RTP может означать скрытую передачу.

## RTP и кодеки

RTP не содержит текста, но структура предсказуема. Поле `payload type` говорит, каким
кодеком закодирован голос:

| PT | Кодек | Полоса |
|---|---|---|
| 0 | PCMU (G.711 µ) | 64 кбит/с |
| 8 | PCMA (G.711 A) | 64 кбит/с |
| 9 | G722 | 64 кбит/с |
| 18 | G729 | 8 кбит/с |
| 111 (dynamic) | Opus | переменная |

`SSRC` — идентификатор источника; по нему собирается поток. Чтобы получить аудио,
нужно знать кодек: `PCMU`/`PCMA` — простейшие (по 1 байту на сэмпл), `G729` —
проприетарный и требует декодера. В Wireshark: `Telephony → RTP → Show All Streams →
Save Payload` — и открыть `.au`/`.raw` в плеере.

## SRTP, шифрование и серверные артефакты

Если в SDP стоит профиль `RTP/SAVP` или `RTP/SAVPF` — медиапоток защищён **SRTP**:

```
$ tshark -r voip.pcap -Y 'sdp' -T fields -e sdp.media.proto -e sdp.attr | head
RTP/SAVP    a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<key>
```

Опасная настройка — когда ключ `a=crypto` лежит **в открытом SDP**: тогда SRTP
расшифровывается тривиально. В норме ключи выводятся через DTLS-SRTP и в SDP лишь
отпечаток сертификата. SIP по TLS (5061) тоже скрывает сигнализацию — нужны ключи.

На сервере (Asterisk/FreeSWITCH) остаются готовые журналы:

```
$ tail -3 /var/log/asterisk/cdr-csv/Master.csv
"alice","bob","...","2026-01-14 03:20:00","...","3","ANSWERED"
```

Плюс голосовая почта (`/var/spool/asterisk/voicemail/`), записи разговоров и
конфигурация пиров. Всё это — независимые источники для сверки.

## Ограничения и подводные камни

- **Без ключа нет аудио.** SRTP/DTLS-SRTP — это не «недостаток инструмента».
- **Кодек.** Проприетарные кодеки (G729) без декодера не восстановить.
- **NAT и RTP-прокси.** Внешний адрес может быть шлюзом, а не абонентом.
- **Пропущенный BYE.** Если звонок оборван, длительность придётся оценивать по
  последнему RTP-пакету.
- **QoS-порты.** Нестандартные порты RTP надо искать по `SSRC`, а не по номеру порта.
- **Только метаданные.** Если сохранён лишь CDR, голоса в нём нет — фиксируй это.

## SIP-методы и коды ответов

SIP — текстовый протокол, и его сообщения читаются как письма. Методы говорят, что
происходит:

| Метод | Смысл |
|---|---|
| REGISTER | клиент регистрируется на сервере |
| INVITE | начало звонка |
| ACK | подтверждение установления |
| BYE | завершение |
| CANCEL | отмена вызова |
| OPTIONS | проверка доступности |
| MESSAGE | мгновенное сообщение |

Ответы — по аналогии с HTTP: `1xx` — промежуточные, `2xx` — успех (`200 OK`), `3xx` —
перенаправление, `4xx` — ошибка клиента (`401` требует авторизации, `403` запрещено),
`5xx` — ошибка сервера, `6xx` — глобальный отказ. `401 Unauthorized` в дампе означает, что
пароль передавался (часто в `Digest`-хеше), — это повод искать учётные данные.

```
$ tshark -r voip.pcap -Y 'sip' -T fields -e sip.Method -e sip.Status-Code -e sip.from.user -e sip.to.user
```

## Извлечение аудио из RTP пошагово

RTP-поток привязывается к вызову через SDP (`m=audio <port> RTP/AVP 0`). Шаги:

```
$ tshark -r voip.pcap -Y 'sdp' -T fields -e sdp.media.port -e sdp.media.proto -e sdp.media.format
$ tshark -r voip.pcap -Y 'rtp' -T fields -e rtp.ssrc -e rtp.p_type | sort -u
```

Далее в Wireshark: **Telephony → RTP → Show All Streams**, выбрать поток и
**Save Payload** → указать кодек (G.711 µ-law = PCMU, p_type 0; G.711 A-law = PCMA, 8).
Либо из консоли `tshark ... --export-objects rtp,out/`. Полученный `.au`/`.raw`
конвертируется в WAV через `sox` или `ffmpeg` с указанием кодека. Без правильного кодека
аудио будет «шумом».

## SRTP и откуда берётся ключ

SRTP шифрует медиапоток. Ключ устанавливается одним из способов:

- **SDES** — ключ передаётся прямо в SDP (`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<base64>`).
  Если дамп содержит SDP в открытом виде, ключ **извлекается напрямую** — и тогда SRTP
  расшифровывается.
- **DTLS-SRTP** — ключ согласуется по DTLS-handshake; нужны ключи DTLS (по аналогии с TLS,
  ключ сервера или MITM).
- **ZRTP** — end-to-end, практически не расшифровать без конечных точек.

Первый же взгляд на SDP решает, возможна ли расшифровка:

```
$ tshark -r voip.pcap -Y 'sdp.attr' -T fields -e sdp.attr | grep -i crypto
```

## Серверные артефакты

Если есть доступ к серверу IP-телефонии, данные дублируются и уточняются:

```
$ cat /var/log/asterisk/cdr-csv/Master.csv | tail
$ cat /var/log/asterisk/full | grep -i 'registered\|invite'
$ ls /var/spool/asterisk/monitor/    # записи разговоров, если включены
```

FreeSWITCH: `cdr_csv`, `freeswitch.log`, `/var/lib/freeswitch/recordings`. Эти журналы
дают `src`, `dst`, длительность, статус (`ANSWERED`, `NO ANSWER`, `BUSY`) — готовый CDR.

## Практический разбор CTF

Задача: «кто кому звонил и что сказал». Шаги:

```
$ tshark -r voip.pcap -Y 'sip.Method=="INVITE"' -T fields -e frame.time -e sip.from.user -e sip.to.user
$ tshark -r voip.pcap -Y 'sdp' -T fields -e sdp.media.port -e sdp.attr | grep -i crypto
$ tshark -r voip.pcap -Y 'rtp' -T fields -e rtp.ssrc -e rtp.p_type | sort | uniq -c
```

Если SDP нешифрован — сохраняем payload и слушаем; флаг часто произносится голосом или
лежит в тексте SIP (`a=...`), либо в CDR. Если SRTP с SDES — берём ключ из SDP и
декодируем.

## Ограничения

- SIP по TLS (5061) — сигнализация зашифрована, нужны ключи.
- SRTP без ключа (DTLS/ZRTP) — медиа не восстановить.
- Кодек с переменной битрейтом (Opus, iLBC) — прямая склейка payload не даёт WAV;
  нужен ресемплер.
- Потерянные пакеты RTP (зеркало) — слышны «провалы» и щелчки, но текст обычно читается.

## Квиз

Проверь себя.

```quiz
- question: Что делает протокол SIP?
  options:
    - 'переносит голос'
    - 'устанавливает и завершает сессию (сигнализация)'
    - 'выдаёт IP'
    - 'шифрует диск'
  answer: 1
  explanation: 'SIP — сигнализация: INVITE, ACK, BYE.'
- question: Что переносит RTP?
  options:
    - 'имена'
    - 'сам голос (медиа)'
    - 'маршруты'
    - 'пароли'
  answer: 1
  explanation: 'RTP — транспорт медиапотока (голос/видео).'
- question: Как построить длительность звонка из дампа?
  options:
    - 'по DNS'
    - 'по разнице времени INVITE и BYE'
    - 'по ARP'
    - 'по размеру файла'
  answer: 1
  explanation: 'INVITE открывает сессию, BYE закрывает — разница и есть длительность.'
- question: Когда голос из RTP не восстановить?
  options:
    - 'всегда можно'
    - 'если используется SRTP без ключа'
    - 'если много трафика'
    - 'если порт 5060'
  answer: 1
  explanation: 'SRTP шифрует медиапоток; без ключа расшифровка невозможна.'
```
