---
id: network-voip
title: "VoIP и SIP: анализ трафика, перехват и подделка звонков"
category: network
parent: network-protocol-reversing
difficulty: hard
order: 3
tags: [network, voip, sip, rtp, rtpcap, eavesdropping]
prerequisites: [network-protocol-reversing, network-pcap-analysis]
useful_for:
  - "CTF Network (VoIP-задачи)"
  - "Пентест: телефония в корпоративной сети"
  - "Работа (SOC): детект VoIP-мошенничества"
estimated_minutes: 50
summary: "Как устроены SIP и RTP, как перехватить и восстановить разговор из PCAP и какие атаки (регистрация, toll fraud) работают."
---
VoIP переносит голос по IP. Сигнализация (SIP) устанавливает и управляет вызовами, медиа (RTP) несёт сам звук. Если трафик не зашифрован (нет TLS/SRTP), его можно перехватить, прослушать и даже подделать звонок. Телефония часто слабо защищена и напрямую связана с деньгами (toll fraud), поэтому это ценный вектор. Урок опирается на [`network-protocol-reversing`](network-protocol-reversing) и [`network-pcap-analysis`](network-pcap-analysis).

## SIP, RTP и SDP

- **SIP** (UDP/TCP 5060, TLS 5061) — сигнализация: `INVITE`, `100 Trying`, `180 Ringing`, `200 OK`, `ACK`, `BYE`, `REGISTER`, `OPTIONS`.
- **SDP** (тело SIP) — описывает медиа: `c=` (адрес), `m=audio <port> RTP/AVP <codecs>`, `a=rtpmap`.
- **RTP** — медиапоток (обычно UDP 10000-20000), кодеки G.711 (PCMU/PCMA), G.722, Opus.
- **RTCP** — статистика/контроль (потери, jitter, RTT).

```text
INVITE sip:bob@corp  ->  200 OK (SDP: m=audio 40000 RTP/AVP 0 8)
                        <-> RTP 40000 <->  (голос)
                        BYE
```

## Кодеки и извлечение аудио

- **G.711 (PCMU/PCMA)** — 8 кГц, 64 Кбит/с, просто декодируется в WAV (payload type 0/8).
- **G.722** — 16 кГц, шире полоса.
- **Opus** — современный, переменный битрейт.
- **RTP-payload** содержит закодированные сэмплы; Wireshark умеет проигрывать потоки (Telephony → VoIP Calls → Play Streams).

```bash
# Разбор RTP и статистика
tshark -r voip.pcap -Y rtp -T fields -e rtp.ssrc -e rtp.p_type | sort | uniq -c
# RTCP: потери/jitter
tshark -r voip.pcap -Y rtcp -V | grep -iE 'fraction lost|jitter|delay'
```

## Атаки

- **Прослушивание (eavesdropping)** — перехват RTP и декодирование в аудио.
- **Registration hijacking** — подмена `REGISTER`, перехват входящих.
- **Toll fraud** — звонки на дорогие направления за счёт организации.
- **DoS/INVITE flood** — перегрузка АТС.
- **SIP-скан/перебор** — внутренние номера (extensions) и пароли.
- **MITM** — вставка в сигнализацию и медиа ([`network-mitm`](network-mitm)).
- **SPIT** — спам-звонки.

## Инструменты и команды

```bash
# Инвентаризация SIP
nmap -sU -p5060 --script sip-enum-users,sip-methods 10.0.0.5
nmap -sU -p5060 --script sip-brute 10.0.0.5          # перебор экстеншенов
# sipvicious (svmap/svwar/svcrash)
svmap 10.0.0.0/24
svwar -e100-999 10.0.0.5
# Захват
tcpdump -i eth0 -n 'port 5060 or udp portrange 10000-20000' -w voip.pcap
# Разбор SIP
tshark -r voip.pcap -Y sip -T fields -e sip.Method -e sip.from.user -e sip.to.user
# Wireshark: Telephony -> VoIP Calls -> Play Streams
# CLI-извлечение RTP
rtpbreak -r voip.pcap -a -l
```

## Разобранный пример: восстановление разговора из PCAP

```bash
# 1. Есть ли SIP/RTP
tshark -r voip.pcap -Y sip -T fields -e frame.number -e sip.Method | head
# -> INVITE / 200 OK / ACK  (есть вызов)
# 2. Найти медиа-поток (порты из SDP)
tshark -r voip.pcap -Y 'sip contains "m=audio"' -T fields -e sdp.media -e sdp.media.port
# -> RTP/AVP 0 8   40000
# 3. Извлечь RTP и декодировать (Wireshark: VoIP Calls -> Play Streams)
rtpbreak -r voip.pcap -a -l
# полученные .raw/.au -> проиграть (sox/ffmpeg/audacity)
# 4. Ищем флаг/пароль в SIP-заголовках
tshark -r voip.pcap -Y 'sip contains "Authorization"' -V | grep -i -A2 'password\|response'
# 5. RTCP даёт статистику (потери, jitter)
```

## Извлечение RTP вручную (когда нет Wireshark GUI)

```bash
# Собрать payload одного SSRC и склеить
tshark -r voip.pcap -Y 'rtp.ssrc==0x1a2b3c4d' -T fields -e rtp.payload | \
  tr -d ':' | xxd -r -p > stream.raw
# Для G.711 (PCMA=alaw, PCMU=ulaw) — конвертация в WAV
sox -t raw -r 8000 -e u-law -c 1 stream.raw call.wav   # PCMU
# ffmpeg как альтернатива
ffmpeg -f mulaw -ar 8000 -ac 1 -i stream.raw call.wav
```

## Детект VoIP-мошенничества (SOC)

- **Аномальные направления** звонков (международные премиум-номера).
- **Всплеск `REGISTER`/`INVITE`** с одного IP (скан/перебор).
- **Неудачные авторизации** в SIP (401/403).
- **Регистрация** с необычного IP/гео.
- **RTP** к внешним адресам без причины.
- **Несколько параллельных вызовов** с одного эккаунта.

```bash
# Перебор экстеншенов
tshark -r voip.pcap -Y 'sip.Method=="REGISTER"' -T fields -e sip.from.user | sort | uniq -c | sort -rn | head
# Коды ответов (401/403 = попытки авторизации)
tshark -r voip.pcap -Y 'sip.Status-Code' -T fields -e sip.Status-Code | sort | uniq -c | sort -rn
```

## Защита

- **SIP over TLS** (5061) для сигнализации, **SRTP** для медиа.
- **Сильные пароли** на экстеншенах; блокировка перебора.
- **Сегментация** телефонии, ACL, отключение неиспользуемых портов.
- **SBC/прокси** на периметре с фильтрацией направлений.
- **Мониторинг аномалий** и лимиты на звонки; блокировка международных направлений по умолчанию.

## Частые ошибки

- **Искать голос в SIP** — SIP только сигнализация, медиа в RTP.
- **Игнорировать SDP** — адреса/порты/кодеки медиа там.
- **Забывать про NAT** — адреса в SDP могут быть приватными.
- **Не проверять оба направления RTP** — звук может идти только в одну сторону.
- **Считать, что RTP «просто шум»** — это G.711/Opus, декодируется.
- **Тестировать телефонию без согласования** — можно сорвать реальные звонки.

## Сравнение протоколов сигнализации

| Протокол | Порт | Шифрование | Заметки |
|----------|------|------------|---------|
| SIP | 5060/UDP,TCP | TLS 5061 | де-факто стандарт VoIP |
| H.323 | 1720 | сложно | устаревающий |
| MGCP/Megaco | 2427/2727 | нет | управление шлюзами |
| SCCP (Skinny) | 2000 | TLS | Cisco |

## Что дальше / решение

- Нужно **прослушать разговор** → извлечь RTP (rtpbreak/tshark) и декодировать в WAV.
- Нужны **креды/экстеншены** → SIP-скан и перебор (svwar/sip-brute), анализ `Authorization`.
- Нужна **защита** → SIP-TLS + SRTP, SBC, лимиты, мониторинг.
- Смежные темы → `network-mitm` (перехват), `network-pcap-analysis` (разбор), `network-scada-protocols` (другие протоколы управления).

Решение (алгоритм): 1) найти SIP в захвате; 2) извлечь SDP (порты/кодеки); 3) выделить RTP по SSRC; 4) декодировать аудио; 5) проверить сигнализацию на креды/флаги; 6) для защиты — TLS/SRTP и контроль направлений.

## SIP-аутентификация и дайджест

SIP использует **HTTP Digest** (`WWW-Authenticate: Digest ...`), и разбор заголовка даёт материал для атак:

- **401 Unauthorized** + `WWW-Authenticate` — сервер просит авторизацию.
- **REGISTER/INVITE с `Authorization: Digest`** — клиент присылает `username`, `realm`, `nonce`, `response`.
- `response` = хэш от пароля и nonce; при слабом пароле — оффлайн-перебор (`sipcrack`, `hashcat`).
- **`realm`** показывает домен; **`username`** — экстеншен.

```bash
# Вытащить Digest-заголовки из захвата
tshark -r voip.pcap -Y 'sip contains "Authorization"' -T fields -e sip.auth.username -e sip.auth.realm
# Перебор паролей SIP (оффлайн, если есть challenge/response)
sipcrack -u user -d digest.txt words.txt
```

## Toll fraud в деталях

Toll fraud — самый дорогой VoIP-инцидент. Схема: злоумышленник получает доступ к эккаунту (слабый пароль, скомпрометированная АТС, открытый SBC) и звонит на **премиум/международные** номера, получая долю от оператора.

Признаки в трафике:

- Много **коротких** `INVITE` на необычные префиксы.
- Звонки в нерабочее время.
- Один эккаунт делает параллельные вызовы.
- RTP к внешним, ранее не встречавшимся адресам.

```bash
# Кому звонят (из To-заголовков)
tshark -r voip.pcap -Y 'sip.Method=="INVITE"' -T fields -e sip.to.user | sort | uniq -c | sort -rn | head
```

## Извлечение и склейка RTP

RTP-пакеты могут приходить не по порядку и с потерями; при склейке ориентируйтесь на **sequence number** и **timestamp**:

```bash
# Порядок по seq для одного SSRC
tshark -r voip.pcap -Y 'rtp.ssrc==0x1a2b3c4d' -T fields -e rtp.seq -e rtp.timestamp | head
# Отсортировать payload по seq и склеить (см. пример выше)
# Пропуски = потерянные пакеты (артефакты в аудио)
```

Для двустороннего разговора — два SSRC (по одному на направление); декодируйте оба.

## Сравнение инструментов VoIP

| Инструмент | Назначение |
|------------|------------|
| svmap | обнаружение SIP-хостов |
| svwar | перебор экстеншенов |
| svcrash | проверка на уязвимости/DoS |
| sipcrack | оффлайн-взлом Digest |
| rtpbreak | извлечение RTP из PCAP |
| sipp | генерация SIP-нагрузки (тесты) |
| sngrep | визуальный анализ SIP в терминале |

## Что дальше по VoIP

- Нужно **прослушать** → RTP → WAV (sox/ffmpeg).
- Нужны **креды** → Digest + `sipcrack`, перебор `svwar`.
- Нужна **защита** → SIP-TLS + SRTP, SBC, лимиты, мониторинг toll fraud.
- Смежные темы → `network-mitm`, `network-pcap-analysis`, `network-scada-protocols`.

## SIP-методы и их применение в разведке

SIP определяет методы, каждый из которых полезен при реконнессансе:

- **OPTIONS** — «жив ли сервер/клиент», возвращает `Allow`/`Supported` (какие методы и кодеки).
- **REGISTER** — регистрация экстеншена; перебор выявляет существующие номера.
- **INVITE** — установка вызова; можно проверять направления.
- **SUBSCRIBE/NOTIFY** — события присутствия (presence).
- **MESSAGE** — мгновенные сообщения.

```bash
# OPTIONS для fingerprint
nmap -sU -p5060 --script sip-methods 10.0.0.5
# Ручной OPTIONS
sipp -sn uac 10.0.0.5
```

Ответы `200 OK` на OPTIONS подтверждают SIP-сервис и раскрывают возможности. Коды `401/403` на REGISTER указывают на существующий экстеншен (требуется авторизация), `404` — номер не существует.

## Мониторинг и метрики защиты VoIP

Для SOC полезно вести метрики: число неудачных авторизаций на экстеншен, доля звонков на международные направления, параллельные вызовы на эккаунт, новые IP регистраций. Аномалии по этим метрикам ловят toll fraud раньше, чем он нанесёт ущерб.

## Квиз

```quiz
- question: "Какой протокол несёт голос в VoIP?"
  options:
    - "RTP"
    - "SIP"
    - "SDP"
    - "RTCP"
  answer: 0
  explanation: "RTP переносит медиа; SIP — сигнализация; SDP описывает поток."
- question: "Где в SIP-трафике описаны адреса и порты медиа-потока?"
  options:
    - "В SDP (тело SIP-сообщения)"
    - "В заголовке INVITE"
    - "В RTP-заголовке"
    - "В DNS"
  answer: 0
  explanation: "SDP содержит c= и m= строки с адресом, портом и кодеком."
- question: "Что такое toll fraud в VoIP?"
  options:
    - "Мошенничество с дорогими звонками через скомпрометированную АТС"
    - "Подмена MAC"
    - "Шифрование звонков"
    - "Отключение RTP"
  answer: 0
  explanation: "Злоумышленники делают международные звонки за счёт организации."
- question: "Какая защита шифрует голос в VoIP?"
  options:
    - "SRTP"
    - "SIP over UDP"
    - "RTP без шифрования"
    - "NAT"
  answer: 0
  explanation: "SRTP шифрует медиа; сигнализацию защищает SIP over TLS."
- question: "Какой инструмент извлекает RTP-потоки из PCAP?"
  options:
    - "rtpbreak"
    - "smbmap"
    - "macof"
    - "onesixtyone"
  answer: 0
  explanation: "rtpbreak разбивает RTP на отдельные потоки для декодирования в аудио."
```

## Где пригодится

- **CTF:** извлечение флага/разговора из VoIP-трафика.
- **Пентест:** аудит корпоративной телефонии.
- **SOC:** детект toll fraud и перебора регистраций.
- **Работа:** защита VoIP (TLS/SRTP, сегментация).
- **Анализ:** восстановление разговоров для расследования.
