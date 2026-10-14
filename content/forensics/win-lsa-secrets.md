---
id: win-lsa-secrets
title: "LSA-секреты и кэш доменных учёток"
category: forensics
parent: forensics-win-artifacts-advanced
difficulty: hard
order: 4
tags: [windows, lsa, secrets, security-hive, dcc, cached-credentials, forensics]
prerequisites: [forensics-registry-hives, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Пентест Windows"
estimated_minutes: 55
summary: "Что хранит Local Security Authority: пароли сервисных учёток, ключи авто-логина, кэш доменных логинов (DCC2) — и как их извлечь из hive SECURITY."
lab:
  kind: shell
  title: 'Практика: LSA-секреты'
  toolset: [core, grep, base64]
  workdir: /home/student/task
  files: [task.md, SECURITY, SYSTEM, SAM]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`file SECURITY` — это реестровый hive (regf).'
    - 'Секреты лежат в ветвях Policy\Secrets: `strings SECURITY`.'
    - 'Ищи строки с `nto{` среди секретов служб.'
    - 'Выдели флаг: `strings SECURITY | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

У тебя есть копии hive `SECURITY`, `SYSTEM` и `SAM`. Ты знаешь, что где-то здесь лежат
**пароли сервисных учёток** и **кэш доменных логинов**, но в открытом виде их нет. Где
именно они хранятся и как их достать?

Разберём сквозной пример: извлечём секреты из hive `SECURITY`.

## Что такое LSA и её секреты

**Local Security Authority (LSA)** — подсистема Windows, отвечающая за аутентификацию.
Она хранит несколько видов секретов, нужных системе для работы:

- **Service account passwords** — пароли учёток, под которыми запущены службы. Windows
  хранит их, чтобы служба могла логиниться после перезагрузки.
- **DefaultPassword** — пароль авто-логина (если настроен автовход).
- **DPAPI_SYSTEM** — системный ключ DPAPI.
- **NL$KM** — ключ, которым зашифрован **кэш доменных логинов**.
- **Cached domain credentials (DCC)** — кэш доменных учёток для входа, когда нет связи с
  контроллером домена.

Всё это лежит в hive **SECURITY**, в ветви `Policy\Secrets` и `Cache`.

## Почему нужны три hive

Чтобы расшифровать LSA-секреты, нужен **boot key**, который выводится из hive `SYSTEM`
(ветви `Lsa\JD`, `Lsa\Skew1`, `Lsa\GBG`, `Lsa\Data`). А чтобы понять, каким учёткам
принадлежат хеши, нужен `SAM`. Поэтому классический триплет для извлечения — **SAM +
SYSTEM + SECURITY**.

## Наш пример: извлекаем секреты

Допустим, есть `SECURITY`, `SYSTEM`, `SAM`. Используем **impacket**:

```
$ secretsdump.py -security SECURITY -system SYSTEM -sam SAM LOCAL
Impacket v0.12 - Copyright ...
[*] Target system bootKey: 0x1f2a3b...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435...:31d6cfe0...:::
[*] Dumping cached domain logon information (domain/username:hash)
CORP/jdoe:$DCC2$10240#jdoe#9f1a...:
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
[*] DefaultPassword
CORP\svc_backup:nto{ls4_s3cr3ts_svc_p4ss}
[*] NL$KM
0000  4e 4c 24 4b 4d ...
[*] _SC_sqlsvc
CORP\sqlsvc:Summer2024!
```

Разберём, что мы увидели:

- **SAM-хеши** — локальные учётки (`Administrator`, `Guest`).
- **DCC2** — кэш доменных логинов. Хеш `$DCC2$` — медленный (PBKDF2), подбирается
  офлайн (hashcat mode 2100).
- **DefaultPassword** — пароль автовхода, часто в открытом виде.
- **LSA secrets** — пароли служб (например `_SC_sqlsvc`) и другие секреты.

### Что значит строка `CORP/jdoe:$DCC2$...`

`$DCC2$` — формат кэшированной доменной учётки. Число `10240` — итерации. Хеш нельзя
использовать «напрямую» как NTLM, но можно **подобрать пароль** офлайн:

```
$ hashcat -m 2100 dcc2.txt wordlist.txt
```

## Наш пример: флаг в секретах

В выводе выше виден флаг в `DefaultPassword`:
`CORP\svc_backup:nto{ls4_s3cr3ts_svc_p4ss}`. Так в CTF прячут секреты: кладут их в
LSA-секреты сервисной учётки. Чтобы найти такое, ищем в выводе `secretsdump` строки с
`nto{`:

```
$ secretsdump.py -security SECURITY -system SYSTEM -sam SAM LOCAL | grep 'nto{'
CORP\svc_backup:nto{ls4_s3cr3ts_svc_p4ss}
```

## Если hive под рукой нет

Секреты LSA можно извлечь **из памяти** процесса `lsass.exe` (mimikatz
`sekurlsa::logonpasswords`, `sekurlsa::secrets`). Это работает на живом хосте и даёт
пароли в открытом виде, если включён режим `WDigest` или есть кэш. На офлайн-образе
работает только путь через hive.

## Все виды LSA-секретов

Разберём, что именно лежит в ветви `Policy\Secrets`, чтобы понимать ценность каждого.

| Секрет | Что содержит |
|--------|--------------|
| `$MACHINE.ACC` | пароль компьютера (доменной учётки машины) |
| `DefaultPassword` | пароль авто-логина в открытом виде |
| `DPAPI_SYSTEM` | системный ключ DPAPI (машинный профиль) |
| `NL$KM` | ключ шифрования кэша доменных логинов |
| `_SC_<service>` | пароли сервисных учёток (ключевое имя начинается с `_SC_`) |
| `ASP.NET` / `IIS` | ключи машинных секций конфигураций |
| `RasDefaultCredentials` | креды подключения к сети (VPN/PPP) |

Отдельно от `Secrets` стоит ветвь **`Cache`** — в ней хранится кэш доменных логинов
(DCC). Именно её значение `NL$KM` расшифровывает.

## Формат кэшированных учёток (DCC2)

Современный кэш (`MS-Cache v2`) хранит для каждой доменной учётки:

- имя и **домен**;
- **DCC2-хеш** вида `$DCC2$<iterations>#<username>#<hex>`.

DCC2 вычисляется по алгоритму PBKDF2-HMAC-SHA1 с числом итераций (обычно 10240) от
пароля. Он **медленный** — подбирается офлайн и в разы труднее NTLM. Но если пароль
слабый, он подбирается, и мы получаем открытый пароль учётки.

Важно: DCC2 **нельзя** использовать для pass-the-hash — это не NTLM. Поэтому в задачах
либо подбирают пароль офлайн, либо ищут секрет прямо в выводе (как флаг).

## Как Windows выбирает, какие учётки кэшировать

По умолчанию Windows кэширует **последние успешные** доменные входы (по умолчанию — до
10). Это настраивается политикой `Interactive logon: Number of previous logons to cache`.
Форензик-вывод: набор кэшированных учёток показывает, **кто реально работал** на этом
хосте под доменными правами — ценный источник для восстановления картины.

## Различия Windows 10/11 и серверов

На современных системах часть секретов защищена **сильнее**:

- `WDigest` отключён по умолчанию, поэтому пароли в открытом виде в памяти не лежат.
- Включён **Credential Guard**, и LSA-секреты живут в изолированном процессе.
- Для чтения секретов из памяти нужны права `SYSTEM` и отключённый защитный режим.

На серверах с включённым Credential Guard офлайн-путь через hive остаётся рабочим, а
живой дамп памяти может не дать паролей — это нормально, не признак «неверной техники».

## Частые ошибки

- **Только SAM и SYSTEM.** Без `SECURITY` LSA-секреты не извлекутся — это разные hive.
- **Путать DCC с NTLM.** `$DCC2$` — не хеш для входа, а медленный производный ключ.
- **Ожидать пароли всегда в открытом виде.** `DefaultPassword` да, а сервисные пароли
  часто зашифрованы и расшифровываются boot key — `secretsdump` делает это сам.
- **Игнорировать `$MACHINE.ACC`.** Пароль компьютера — сильный рычаг (позволяет выдать
  себя за машину в домене).

## Шпаргалка команд

```
# Извлечение из трёх hive
secretsdump.py -security SECURITY -system SYSTEM -sam SAM LOCAL
# Только LSA-секреты
secretsdump.py -security SECURITY -system SYSTEM -just-dc-user CORP\\jdoe LOCAL
# Офлайн-подбор DCC2
hashcat -m 2100 dcc2.txt /usr/share/wordlists/rockyou.txt
# Из памяти живого хоста
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::secrets
```

## Что это даёт в отчёте

По LSA-секретам фиксируют: пароли сервисных учёток (риск горизонтального движения),
настроенный автовход (частая причина утечки), число и состав кэшированных доменных
учёток. Отдельно отмечают `$MACHINE.ACC` — компрометация пароля компьютера позволяет
выдавать себя за хост в домене.

## Мини-практика: от hive к паролю службы

Пройдём сквозной пример полностью. У нас есть три hive-файла и цель — достать пароль
сервисной учётки, которой злоумышленник мог воспользоваться для движения.

Сначала убеждаемся, что hive читаются как реестровые:

```
$ file SECURITY SYSTEM SAM
SECURITY: MS Windows registry file, NT/2000 or above
SYSTEM:   MS Windows registry file, NT/2000 or above
SAM:      MS Windows registry file, NT/2000 or above
```

Магия `regf` в первых байтах подтверждает формат. Теперь извлекаем секреты, передав все
три файла:

```
$ secretsdump.py -security SECURITY -system SYSTEM -sam SAM LOCAL
[*] Target system bootKey: 0x1f2a3b4c...
[*] Dumping cached domain logon information (domain/username:hash)
CORP/jdoe:$DCC2$10240#jdoe#9f1a7c...
[*] Dumping LSA Secrets
[*] DefaultPassword
CORP\svc_backup:nto{ls4_s3cr3ts_svc_p4ss}
[*] _SC_sqlsvc
CORP\sqlsvc:Summer2024!
```

Разберём вывод по частям. **bootKey** — корень всей расшифровки, выведенный из `SYSTEM`.
**DCC2** — кэшированная доменная учётка. **DefaultPassword** — пароль автовхода (в нашем
примере это флаг). **`_SC_sqlsvc`** — пароль сервисной учётки `sqlsvc`, которым
запускается служба SQL.

Практический смысл: пароль сервисной учётки — это готовый «ключ» для горизонтального
движения. Сервисные учётки часто имеют широкие права (доступ к БД, файловым шарам), их
пароли редко меняют, и они не требуют интерактивного входа. Поэтому в отчёте их выделяют
в отдельную категорию риска.

Проверим также `$MACHINE.ACC` — пароль компьютера:

```
[*] $MACHINE.ACC
CORP\WKSTN01$:aad3b435b51404eeaad3b435b51404ee:7c4a8d09ca3762af61e59520943dc264...
```

Пароль компьютера позволяет выдать себя за машину в домене — например, при запросе
сертификатов или доступа к ресурсам с проверкой по «машинной» учётке. Это ещё один
рычаг, который нельзя игнорировать.

Наконец, если подбор пароля нужен офлайн, берём DCC2 и запускаем hashcat в режиме 2100.
На слабом пароле результат приходит быстро; на стойком — нет, и тогда ценность
представляют уже извлечённые секреты служб.

Итог практики: из трёх hive-файлов мы получили **пароли сервисных учёток, пароль
автовхода, пароль компьютера и кэш доменных логинов**. Это полный набор «сохранённых
секретов» Windows, и именно их первыми смотрят при расследовании компрометации хоста.

## Что мы теперь знаем

- **LSA-секреты** хранятся в hive **SECURITY** (ветви `Policy\Secrets`, `Cache`).
- Для расшифровки нужен **boot key** из hive `SYSTEM`, а для привязки — `SAM`.
- `secretsdump.py -security ... -system ... -sam ... LOCAL` извлекает SAM-хеши,
  **кэш доменных логинов (DCC2)**, `DefaultPassword` и пароли служб.
- DCC2-хеш (`$DCC2$`) подбирается офлайн (hashcat mode 2100).
- Альтернатива — извлечение из памяти `lsass.exe`.

## Квиз

Проверь себя.

```quiz
- question: "В каком hive хранятся LSA-секреты?"
  options:
    - "SECURITY"
    - "SAM"
    - "SOFTWARE"
    - "DEFAULT"
  answer: 0
  explanation: "Секреты LSA лежат в hive SECURITY, ветви Policy\\Secrets и Cache."
- question: "Что такое кэш доменных логинов (DCC/DCC2)?"
  options:
    - "Хеши доменных учёток для офлайн-входа, когда нет связи с DC"
    - "Список установленных программ"
    - "Журнал браузера"
    - "Ключ шифрования диска"
  answer: 0
  explanation: "Windows кэширует доменные логины, чтобы пользователь мог войти без контроллера домена."
- question: "Почему для извлечения LSA-секретов нужен hive SYSTEM?"
  options:
    - "Из него выводится boot key, которым расшифрованы секреты"
    - "Он содержит пароли в открытом виде"
    - "Он хранит список служб"
    - "Он содержит таблицу метаданных"
  answer: 0
  explanation: "Boot key из ветвей Lsa\\JD/Skew1/GBG/Data нужен для расшифровки SECURITY."
- question: "Каким режимом hashcat подбирается хеш $DCC2$?"
  options:
    - "2100"
    - "1000"
    - "7300"
    - "5600"
  answer: 0
  explanation: "Mode 2100 — Domain Cached Credentials 2 (DCC2/MS-Cache v2)."
```

## Куда дальше

Мы собрали секреты операционной системы. Дальше перейдём к **Linux-артефактам**: `/proc`,
история shell и точки автозапуска systemd. А пока главное запомни: **SECURITY + SYSTEM +
SAM = пароли служб, автологин и кэш доменных учёток**.

## Где пригодится

- **CTF Forensics:** задачи с hive-файлами Windows.
- **DFIR:** восстановление утёкших учёток после компрометации.
- **Пентест Windows:** извлечение секретов для латерального движения.
- **Работа:** форензика конечных точек и серверов.
