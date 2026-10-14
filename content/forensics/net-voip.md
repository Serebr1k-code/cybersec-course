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
