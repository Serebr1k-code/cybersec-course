#!/usr/bin/env python3
"""Generate forensics gB Section B batch E: 2 hubs + 9 Windows lessons.

Run:  python3 tools/_gen_fwin_b9a.py
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson

WD = '/home/student/task'

def lab(title, files, check, hints, fs, flag, file='found.txt', toolset=None):
    return dict(
        title=title,
        toolset=toolset or ['core', 'grep'],
        workdir=WD,
        files=files,
        check=check,
        hints=hints,
        hostname='lab',
        expect={'file': WD + '/' + file, 'contains': flag},
        fs=fs,
    )

def d(p):
    return {'path': p, 'type': 'dir'}

def t(p, text, mode='644'):
    return {'path': p, 'text': text, 'mode': mode}

def b(p, b64, mode='644'):
    return {'path': p, 'b64': b64, 'mode': mode}

LESSONS = {}

# --------------------------------------------------------------------------
LESSONS['win-credential-vault'] = dict(
    title='Credential Manager и Windows Vault: разбор сохранённых учёток',
    order=1, diff='hard', mins=55,
    tags=['windows', 'credential-manager', 'vault', 'dpapi', 'credentials', 'forensics'],
    prereq=['win-dpapi', 'forensics-windows-artifacts'],
    summary='Где Windows хранит сохранённые логины и пароли (Credential Manager, Windows Vault), как устроены файлы CREDENTIAL_BLOB и Policy.vpol и как их разобрать в расследовании.',
    lab=lab(
        'Практика: разбор экспорта Vault',
        ['task.md', 'vault_decrypted.txt', 'Credentials/DFBE70A7E5B7A0E4', 'Vault/Policies/Policy.vpol'],
        "grep -q 'nto{' found.txt",
        [
            '`ls -R .` — посмотри, какие файлы остались от Credential Manager.',
            '`file Credentials/DFBE70A7E5B7A0E4` — это бинарный blob, не текст.',
            'В `vault_decrypted.txt` лежит результат расшифровки — открой его.',
            'Выдели флаг: `grep nto vault_decrypted.txt > found.txt`.',
        ],
        [
            d(WD), d(WD + '/Credentials'), d(WD + '/Vault'), d(WD + '/Vault/Policies'),
            t(WD + '/task.md', '# Задача: хранилище учёток\n\nWindows хранит логины/пароли в Credential Manager. Часть зашифрована DPAPI. В файле расшифровки спрятан флаг.\n\n1. `ls -R .` и `file Credentials/DFBE70A7E5B7A0E4`.\n2. Прочитай `vault_decrypted.txt`.\n3. `grep nto vault_decrypted.txt > found.txt`.\n'),
            t(WD + '/vault_decrypted.txt', 'target=Domain:interactive=CONTOSO\\svc_backup\nuser=svc_backup\npassword=nto{v4ult_cr3d_d3crypt3d}\ncomment=deployment account\n\nNote: CREDENTIAL_BLOB header is 0x20 bytes; the TargetName is UTF-16LE.\nPolicy.vpol holds the vault policy (AES-256 + HMAC), keyed by a DPAPI masterkey.\n'),
            b(WD + '/Credentials/DFBE70A7E5B7A0E4', 'AQAAACAAAAAgAAAAVABlAHMAdABUAGEAcgBnAGUAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
            b(WD + '/Vault/Policies/Policy.vpol', 'VlBPTAAAAAEAAAAgAAAA'),
        ],
        flag='nto{v4ult_cr3d_d3crypt3d}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

Ты разбираешь рабочую станцию, с которой злоумышленник ходил по внутренней сети
под чужими учётными записями. В журнале безопасности видны входы типа **logon type 9**
(NewCredentials) — это вход, при котором Windows подставляет сохранённую учётку, не
спрашивая пароль заново. Значит, где-то на диске лежат эти самые учётки. Где именно и
как их достать, когда машина уже выключена?

## Что такое Credential Manager и Windows Vault

**Credential Manager** («Диспетчер учётных данных») — это окно, которое открывается
командой `control /name Microsoft.CredentialManager`. Оно показывает два списка:
**Web Credentials** (логины к сайтам) и **Windows Credentials** (логины к серверам,
сетевым папкам, RDP). Пользователь видит удобный список — а форензик видит файлы.

Под этим окном работает **Windows Vault** — механизм хранения «сейфов» с секретами.
Каждый сейф — это отдельный подкаталог. Командой `vaultcmd /listcreds:"Windows Credentials"`
можно посмотреть содержимое живьём, но на образе диска нас интересуют файлы:

- `%APPDATA%\Microsoft\Credentials\<GUID>` — по одному файлу на учётку, бинарный
  **CREDENTIAL_BLOB**;
- `%LOCALAPPDATA%\Microsoft\Vault\<GUID>\` — каталог сейфа;
- `%LOCALAPPDATA%\Microsoft\Vault\<GUID>\Policy.vpol` — политика сейфа;
- `%LOCALAPPDATA%\Microsoft\Vault\<GUID>\<GUID>.vcrd` — зашифрованные записи сейфа.

Ключевое слово здесь — **зашифрованные**. Ни blob, ни `.vcrd` не читаются напрямую:
их защищает **DPAPI** (Data Protection API) — механизм Windows, который шифрует данные
ключом, привязанным к учётной записи и машине.

## Наш пример

У нас есть копия профиля пользователя, из которой мы вытащили каталог Credentials и
каталог Vault. Посмотрим, что там лежит, и попробуем добраться до содержимого.

```
$ ls -R .
.:
Credentials  Vault  task.md  vault_decrypted.txt
./Credentials:
DFBE70A7E5B7A0E4
./Vault:
Policies
./Vault/Policies:
Policy.vpol
```

Обрати внимание: файл `Credentials/DFBE70A7E5B7A0E4` назван GUID-ом — это и есть
одна сохранённая учётка. А `vault_decrypted.txt` — отдельный файл, который мы получили
на предыдущем шаге расследования (расшифровкой). Разберёмся по порядку.

## Шаг 1: определяем тип файлов

Первым делом — не текстовый ли это файл, и что внутри.

```
$ file Credentials/DFBE70A7E5B7A0E4
Credentials/DFBE70A7E5B7A0E4: data
```

`data` — значит, формат неизвестен `file`, содержимое бинарное. Это ожидаемо:
**CREDENTIAL_BLOB** — структурированная бинарная запись. Её заголовок начинается с
4-байтового поля `Flags` (значение `0x00000001` — учётка относится к домену), затем
идёт `Size`, и дальше — **TargetName** в кодировке UTF-16LE: строка вида
`Domain:interactive=CONTOSO\svc_backup`.

Зачем знать эту структуру? Чтобы, даже не имея DPAPI-ключа, вытащить из blob хотя бы
**имя цели** — оно не зашифровано. Оно отвечает на вопрос «к каким ресурсам у жертвы
были сохранённые учётки».

## Шаг 2: политика сейфа и ключи

Файл `Vault/Policies/Policy.vpol` — это политика сейфа. Внутри — метаданные: версия
схемы, число слотов с ключами, и главное — ссылка на **DPAPI masterkey**, которым
зашифрован ключ сейфа. Схема вложенности такая:

```
Policy.vpol  ->  ключ сейфа (зашифрован DPAPI-masterkey)
                       |
                       v
                 .vcrd записи (зашифрованы ключом сейфа)
```

То есть один раз расшифровав ключ сейфа (через masterkey), мы получаем доступ сразу ко
всем записям этого сейфа. Поэтому DPAPI-мастеркеи — самый ценный объект на диске.

## Шаг 3: как выглядит расшифрованная запись

Когда ключ есть, запись разворачивается в набор полей. Вот как выглядит результат
(файл `vault_decrypted.txt` в нашем примере):

```
target=Domain:interactive=CONTOSO\svc_backup
user=svc_backup
password=nto{v4ult_cr3d_d3crypt3d}
comment=deployment account
```

Из этого сразу понятно: сохранялась учётка `CONTOSO\svc_backup`, и у неё был пароль.
Именно такими учётками злоумышленники и «ходят» по сети — это ответ на вопрос
«откуда взялся logon type 9».

## Шаг 4: что искать в расследовании

Практический чек-лист по Credential Manager:

- Собери все файлы `Credentials\*` и `Vault\**` — даже без расшифровки их GUID-имена
  и TargetName дают карту сохранённых доступов.
- Найди masterkey-и: `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`. Без них расшифровки нет.
- Проверь `CREDHIST` (`%APPDATA%\Microsoft\Protect\<SID>\CREDHIST`) — там история
  пароля пользователя.
- Сопоставь найденные учётки с журналами входов: logon type 9 и явные RDP/сетевые сессии.

## Что мы теперь знаем

- Credential Manager — это GUI, а Windows Vault — файловая реализация под ним.
- Учётки лежат в `Credentials\<GUID>` (CREDENTIAL_BLOB) и в сейфах Vault (`.vcrd`).
- Всё зашифровано DPAPI; ключ-цепочка идёт через `Policy.vpol` и masterkey.
- Имя цели в blob не зашифровано и уже информативно.
- Расшифрованная запись даёт user/password/target — прямые учётные данные.

## Квиз

Проверь себя.

```quiz
- question: В каком файле хранится политика сейфа Windows Vault?
  options:
    - '%APPDATA%\Microsoft\Credentials\<GUID>'
    - '%LOCALAPPDATA%\Microsoft\Vault\<GUID>\Policy.vpol'
    - 'HKLM\SAM'
    - 'C:\Windows\System32\config\SYSTEM'
  answer: 1
  explanation: 'Политика сейфа — это Policy.vpol внутри каталога Vault; она ссылается на DPAPI-masterkey.'
- question: Почему CREDENTIAL_BLOB нельзя просто открыть в текстовом редакторе?
  options:
    - 'он сжат zip-ом'
    - 'он зашифрован DPAPI и хранит бинарную структуру'
    - 'он доступен только администратору'
    - 'он находится в реестре'
  answer: 1
  explanation: 'Blob — бинарная структура, а секрет внутри защищён DPAPI.'
- question: Какой тип входа в журнале соответствует подстановке сохранённой учётки?
  options:
    - 'logon type 2'
    - 'logon type 3'
    - 'logon type 9'
    - 'logon type 10'
  answer: 2
  explanation: 'Logon type 9 (NewCredentials) — вход с подменой учётных данных.'
- question: Что можно извлечь из blob даже без DPAPI-ключа?
  options:
    - 'пароль в открытом виде'
    - 'TargetName (имя цели)'
    - 'мастер-ключ машины'
    - 'ничего'
  answer: 1
  explanation: 'Имя цели не шифруется и видно сразу.'
```

## Куда дальше

В следующем уроке мы возьмём кэш DNS-клиента и журналы DNS Client и научимся по ним
восстанавливать, к каким доменам обращалась машина. А пока главное запомни: сохранённые
учётки Windows живут в Credential Manager и Vault, и почти всё там запечатано DPAPI.

## Где пригодится

- **DFIR / Incident Response** — восстановление учёток, которыми пользовался атакующий.
- **CTF Forensics** — задачи «найди пароль в профиле пользователя».
- **Пентест Windows** — понимание, что именно утекает с машины и как это защищено.
''',
)

# --------------------------------------------------------------------------
LESSONS['win-dns-cache'] = dict(
    title='Кэш DNS-клиента и журналы DNS Client: куда ходила машина',
    order=2, diff='medium', mins=45,
    tags=['windows', 'dns', 'dnscache', 'evtx', 'network-artifacts', 'forensics'],
    prereq=['forensics-windows-artifacts', 'win-smb-artifacts'],
    summary='Как по кэшу DNS-клиента и операционному журналу DNS Client восстановить, к каким доменам обращалась машина, и почему кэш умирает при перезагрузке.',
    lab=lab(
        'Практика: восстановление DNS-запросов',
        ['task.md', 'dnscache.txt'],
        "grep -q 'nto{' found.txt",
        [
            '`cat dnscache.txt` — это дамп кэша DNS-клиента.',
            'Каждая строка — запись вида имя -> адрес.',
            'Флаг лежит в строке с именем хоста C2-домена.',
            'Выдели флаг: `grep nto dnscache.txt > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: кэш DNS\n\nНа машине снят дамп кэша DNS-клиента. Определи, к каким доменам обращались, и найди флаг.\n\n1. `cat dnscache.txt`.\n2. Ищи строку с подозрительным доменом.\n3. `grep nto dnscache.txt > found.txt`.\n'),
            t(WD + '/dnscache.txt', 'Record Name . . . . . : dc01.corp.local\n  A (Host) Record . . : 10.0.0.10\n\nRecord Name . . . . . : update.cdn-static.net\n  A (Host) Record . . : 185.199.108.153\n\nRecord Name . . . . . : c2-beacon.evil-cdn.example\n  A (Host) Record . . : 45.77.12.9\n  Note: query flagged; tag nto{dns_c4ch3_c2_d0m41n}\n\nRecord Name . . . . . : fileserver.corp.local\n  A (Host) Record . . : 10.0.0.20\n'),
        ],
        flag='nto{dns_c4ch3_c2_d0m41n}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

Машина выключена, сетевой трафик мы не писали, но нужно понять, к каким внешним
доменам она обращалась. Есть ли на самом деле следы DNS-запросов прямо на диске — или
всё исчезает вместе с выключением питания?

## Что такое кэш DNS-клиента

Когда программа на Windows хочет обратиться к `fileserver.corp.local`, она не идёт
каждый раз на DNS-сервер: система держит **кэш DNS-клиента** — таблицу «имя → адрес»
с временем жизни (**TTL**). Живьём кэш смотрят так:

```
C:\> ipconfig /displaydns
```

и сбрасывают так: `ipconfig /flushdns`. Важнейшее свойство: **кэш хранится в памяти**
и умирает при перезагрузке. Поэтому для форензика кэш — «горячий» артефакт: его надо
снять, пока машина включена.

## Наш пример

У нас есть текстовый дамп, снятый с ещё работающей машины. Посмотрим на него.

```
$ cat dnscache.txt
Record Name . . . . . : dc01.corp.local
  A (Host) Record . . : 10.0.0.10

Record Name . . . . . : update.cdn-static.net
  A (Host) Record . . : 185.199.108.153
...
```

Каждая запись — это пара «имя → A-запись». Прочитаем целиком и подумаем, что тут
подозрительно.

## Шаг 1: что ищем в кэше

В списке видны и «нормальные» внутренние имена (`dc01.corp.local`, `fileserver`), и
внешние. Для расследования интересны:

- имена, которых не должно быть в этой сети (случайные CDN, «безобидные» домены);
- имена, совпадающие с индикаторами компрометации (IOC);
- длинные случайные поддомены — типичные для **DNS-туннелирования** (когда данные
  гоняют внутри DNS-запросов).

В нашем дампе выделяется `c2-beacon.evil-cdn.example` — имя прямо говорит о beacon-е,
а рядом лежит флаг.

## Шаг 2: операционный журнал DNS Client

Кэш живёт до перезагрузки, но есть **журнал событий** `Microsoft-Windows-DNS-Client/Operational`.
Если он включён, там фиксируются события запросов (event ID 3006, 3008, 3010 и др.).
Журнал лежит в `C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx`
и, в отличие от кэша, **переживает перезагрузку**. Его разбирают так же, как любой EVTX:
через `EvtxECmd` (Eric Zimmerman) или `python-evtx`.

Дополнительно DNS-запросы могут оставить следы в **Sysmon event ID 22** (`DnsQuery`) —
если Sysmon настроен, это самый удобный источник.

## Шаг 3: сопоставляем с трафиком

Один DNS-запрос ещё не доказывает соединение. Чтобы понять, было ли реальное
взаимодействие, кэш сопоставляют с:

- журналами прокси/фаервола (был ли исходящий коннект к найденному IP);
- сетевыми соединениями из памяти (`netscan` в Volatility) или `netstat`-выгрузкой;
- журналом `Microsoft-Windows-SmbClient` (если имя было файловым сервером).

Только связка «DNS-запрос + последующее соединение» даёт уверенный вывод.

## Что мы теперь знаем

- Кэш DNS-клиента (`ipconfig /displaydns`) — волатильный артефакт, живёт в памяти.
- Постоянный источник — операционный журнал DNS Client и Sysmon event 22.
- Кэш показывает имена и адреса, к которым обращались; помогает найти C2-домены.
- Сам по себе запрос — не соединение; нужен второй артефакт для подтверждения.

## Квиз

Проверь себя.

```quiz
- question: Переживает ли кэш DNS-клиента перезагрузку?
  options:
    - 'да, он пишется в реестр'
    - 'нет, он хранится в памяти'
    - 'да, он в EVTX'
    - 'зависит от версии Windows'
  answer: 1
  explanation: 'Кэш живёт в памяти процесса DNS-клиента и исчезает при перезагрузке.'
- question: Какая команда показывает кэш DNS на живой машине?
  options:
    - 'netstat -an'
    - 'ipconfig /displaydns'
    - 'route print'
    - 'arp -a'
  answer: 1
  explanation: 'ipconfig /displaydns выводит содержимое кэша.'
- question: Какой журнал фиксирует DNS-запросы и переживает перезагрузку?
  options:
    - 'Microsoft-Windows-DNS-Client/Operational'
    - 'Microsoft-Windows-Kernel-PnP'
    - 'Application'
    - 'Security'
  answer: 0
  explanation: 'Операционный журнал DNS Client пишет события запросов.'
- question: Что дополнительно нужно, чтобы доказать реальное соединение с C2?
  options:
    - 'только DNS-запрос'
    - 'второй артефакт: сетевой коннект/логи прокси'
    - 'имя файла'
    - 'ничего'
  answer: 1
  explanation: 'Запрос сам по себе не доказывает соединение — нужен коррелирующий след.'
```

## Куда дальше

Дальше мы разберём **Windows Error Reporting** — ещё один источник следов запуска
программ, о котором часто забывают. А пока запомни: кэш DNS волатилен, постоянный след —
операционный журнал DNS Client.

## Где пригодится

- **DFIR / Incident Response** — поиск C2-доменов и внешних контактов.
- **CTF Forensics** — задачи «к какому домену ходила машина».
- **Threat Hunting** — выявление DNS-туннелей и beacon-паттернов.
''',
)

# --------------------------------------------------------------------------
LESSONS['win-wer'] = dict(
    title='Windows Error Reporting: следы падений и запусков программ',
    order=3, diff='medium', mins=45,
    tags=['windows', 'wer', 'crash', 'reportarchive', 'execution-artifacts', 'forensics'],
    prereq=['forensics-windows-artifacts', 'win-prefetch-deep'],
    summary='Как читать каталоги WER (ReportArchive/ReportQueue), файлы Report.wer и AppCrash, и какие сведения о запущенных программах они сохраняют.',
    lab=lab(
        'Практика: разбор Report.wer',
        ['task.md', 'Report.wer'],
        "grep -q 'nto{' found.txt",
        [
            '`cat Report.wer` — это текстовый отчёт о падении программы.',
            'Найди строку с именем исполняемого файла и путём.',
            'Флаг дописан в параметр AppPath.',
            'Выдели флаг: `grep nto Report.wer > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: отчёт WER\n\nФайл Report.wer — отчёт Windows Error Reporting. Восстанови, какая программа падала и откуда запускалась, найди флаг.\n\n1. `cat Report.wer`.\n2. Найди строки EventType/AppName/AppPath.\n3. `grep nto Report.wer > found.txt`.\n'),
            t(WD + '/Report.wer', 'Version=1\nEventType=APPCRASH\nEventTime=133641256789012345\nConsent=1\nReportIdentifier=9d3f...-...\nAppName=updater.exe\nAppPath=C:\\Users\\Public\\nto{wer_p4th_l34k_3x3cut10n}\nSig[0].Name=Application Name\nSig[0].Value=updater.exe\nSig[3].Name=Fault Module Name\nSig[3].Value=ntdll.dll\n'),
        ],
        flag='nto{wer_p4th_l34k_3x3cut10n}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

Атакующий запускал свою программу с флешки в папке `C:\Users\Public`, потом удалил её.
Стандартные артефакты запуска мы уже посмотрели. Остался ли хоть какой-то след того,
что программа вообще существовала, — если она упала?

## Что такое Windows Error Reporting

**Windows Error Reporting (WER)** — служба, которая перехватывает падения программ и
системы и собирает отчёт: что упало, откуда запускалось, с какими модулями, иногда даже
мини-дамп памяти. Эти отчёты **остаются на диске** и переживают удаление самой программы.

Основные места хранения:

- `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\` — архив разобранных отчётов;
- `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\` — очередь ещё не обработанных;
- `%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive\` — отчёты пользователя;
- `C:\Windows\LiveKernelReports\` — отчёты ядра.

Внутри каталога отчёта лежит файл `Report.wer` (текстовый, INI-подобный), иногда
`memory.hdmp`/`triagedump.dmp` (дампы) и `WERInternalMetadata.xml`.

## Наш пример

У нас один файл `Report.wer`. Прочитаем его.

```
$ cat Report.wer
Version=1
EventType=APPCRASH
EventTime=133641256789012345
Consent=1
AppName=updater.exe
AppPath=C:\Users\Public\nto{wer_p4th_l34k_3x3cut10n}
Sig[0].Name=Application Name
Sig[0].Value=updater.exe
Sig[3].Name=Fault Module Name
Sig[3].Value=ntdll.dll
```

Уже из первых строк видно: падало `updater.exe`, запущенное из `C:\Users\Public`.
Путь `C:\Users\Public` — классическое место для чужеродных бинарников.

## Шаг 1: читаем ключевые поля

`Report.wer` — это набор `ключ=значение`. Форензик-ценность несут:

- `EventType` — `APPCRASH` (падение приложения), `BlueScreen` (BSOD), `APPCRASH` и т.д.;
- `AppName` / `AppPath` — имя и **полный путь** упавшей программы;
- `EventTime` — время в **FILETIME** (100-нс тики с 1601 года);
- `Sig[n]` — подписанные поля: имя модуля, адрес исключения, версия.

Поле `AppPath` особенно важно: оно сохраняет путь, даже если файла давно нет.

## Шаг 2: переводим время

`EventTime=133641256789012345` — это FILETIME. Чтобы получить человеческое время,
отнимите эпоху 1601 года и поделите на 10^7. На практике это делают инструментами
(`WER`-парсеры, `Timeline Explorer`), а не вручную. Важно помнить: WER-время — **UTC**.

## Шаг 3: что дают дампы

Если в каталоге есть `memory.hdmp` или `triagedump.dmp`, это мини-дамп упавшего
процесса. Из него можно:

- восстановить строки и аргументы командной строки;
- вытащить подключённые модули (DLL), в том числе внедрённые;
- увидеть сетевые адреса, если программа уже успела соединиться.

Именно поэтому WER-дампы часто становятся единственным следом «жила ли программа».

## Что мы теперь знаем

- WER собирает отчёты о падениях в ReportArchive/ReportQueue.
- `Report.wer` — текст: путь, имя программы, время, подписанные модули.
- Отчёты переживают удаление самой программы — это ценный execution-артефакт.
- Дампы WER позволяют заглянуть внутрь упавшего процесса.

## Квиз

Проверь себя.

```quiz
- question: Где WER хранит архив отчётов?
  options:
    - 'C:\Windows\System32\winevt\Logs'
    - 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'
    - 'HKLM\SAM'
    - '%TEMP%'
  answer: 1
  explanation: 'ReportArchive — стандартный каталог разобранных отчётов WER.'
- question: Что содержит поле AppPath в Report.wer?
  options:
    - 'хеш файла'
    - 'полный путь упавшей программы'
    - 'имя пользователя'
    - 'версию Windows'
  answer: 1
  explanation: 'AppPath сохраняет путь запуска — даже если файл удалён.'
- question: В каком формате EventTime в Report.wer?
  options:
    - 'Unix timestamp'
    - 'FILETIME (100-нс тики с 1601 года, UTC)'
    - 'строка ISO'
    - 'DOS-дата'
  answer: 1
  explanation: 'WER пишет время в FILETIME, по UTC.'
- question: Чем полезен memory.hdmp рядом с отчётом?
  options:
    - 'это лог установки'
    - 'это дамп упавшего процесса: строки, модули, адреса'
    - 'это конфиг WER'
    - 'ничем'
  answer: 1
  explanation: 'Дамп содержит память процесса на момент падения.'
```

## Куда дальше

Теперь, когда мы умеем читать следы падений, посмотрим на **журналы EDR/AV** — там
видно уже не падения, а реакции защитных продуктов. А пока запомни: WER — тихий, но
очень живучий источник путей и имён запущенных программ.

## Где пригодится

- **DFIR / Incident Response** — доказательство запуска и путь исполняемого файла.
- **CTF Forensics** — задачи на восстановление пути запуска.
- **Malware Analysis** — вытаскивание строк из WER-дампов.
''',
)

# --------------------------------------------------------------------------
LESSONS['win-edr-logs'] = dict(
    title='Журналы EDR/AV: CrowdStrike, SentinelOne, Defender',
    order=4, diff='hard', mins=55,
    tags=['windows', 'edr', 'defender', 'crowdstrike', 'sentinelone', 'detection', 'forensics'],
    prereq=['forensics-windows-artifacts', 'win-sysmon-tuning'],
    summary='Где лежат журналы защитных продуктов (Microsoft Defender, CrowdStrike Falcon, SentinelOne), как их читать и что они дают при расследовании инцидента.',
    lab=lab(
        'Практика: разбор детекта EDR',
        ['task.md', 'detections.json'],
        "grep -q 'nto{' found.txt",
        [
            '`cat detections.json` — это выгрузка событий EDR.',
            'Найди запись с наибольшей severity.',
            'В её поле details спрятан флаг.',
            'Выдели флаг: `grep nto detections.json > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: журнал EDR\n\nВыгрузка детектов EDR в JSON. Определи самую серьёзную детекцию и найди флаг.\n\n1. `cat detections.json`.\n2. Смотри severity и detection_name.\n3. `grep nto detections.json > found.txt`.\n'),
            t(WD + '/detections.json', '[\n  {"ts":"2024-03-02T10:11:12Z","severity":"low","detection_name":"Recon","details":"whoami"}, \n  {"ts":"2024-03-02T10:12:01Z","severity":"critical","detection_name":"CredentialTheft","details":"lsass memory access -> nto{edr_d3t3ct_ls4ss_dump}"},\n  {"ts":"2024-03-02T10:13:44Z","severity":"medium","detection_name":"Persistence","details":"run key added"}\n]\n'),
        ],
        flag='nto{edr_d3t3ct_ls4ss_dump}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

На машине стоял антивирус/EDR. Атакующий всё равно прошёл. Вопрос форензика: что
защита видела и записала? Часто именно журналы EDR — единственный источник, который
показывает «что происходило», даже если остальные артефакты вычищены.

## Что такое EDR и чем он отличается от AV

**AV** (антивирус) ловит по сигнатурам файлов. **EDR** (Endpoint Detection and
Response) — это агент, который постоянно наблюдает за процессами, командными строками,
сетевыми соединениями и файловой активностью и пишет **телеметрию** на сервер, а часть —
локально. Типовые продукты и их локальные следы:

- **Microsoft Defender for Endpoint** — канал `Microsoft-Windows-Windows Defender/Operational`,
  файлы `C:\ProgramData\Microsoft\Windows Defender\Support\*.log`;
- **CrowdStrike Falcon** — каталог `C:\Windows\System32\drivers\CrowdStrike\` (драйвер) и
  логи `C:\ProgramData\CrowdStrike\`;
- **SentinelOne** — `C:\ProgramData\Sentinel\` и `C:\Program Files\SentinelOne\`.

Важно понимать: большая часть данных уходит в **облачную консоль**, поэтому локально
может лежать лишь выгрузка. Для расследования часто нужна выгрузка из консоли EDR.

## Наш пример

У нас есть выгрузка детекций в JSON — так часто экспортируют данные из консоли EDR.

```
$ cat detections.json
[
  {"ts":"2024-03-02T10:11:12Z","severity":"low","detection_name":"Recon","details":"whoami"},
  {"ts":"2024-03-02T10:12:01Z","severity":"critical","detection_name":"CredentialTheft","details":"lsass memory access -> nto{edr_d3t3ct_ls4ss_dump}"},
  {"ts":"2024-03-02T10:13:44Z","severity":"medium","detection_name":"Persistence","details":"run key added"}
]
```

Три записи, три уровня серьёзности. Наша задача — выстроить их в историю.

## Шаг 1: сортируем по severity и времени

В расследовании первым делом берут **critical**. Здесь это `CredentialTheft` — доступ к
памяти `lsass`. `lsass.exe` хранит аутентификационные секреты, и обращение к его памяти —
классический приём (Mimikatz, procdump). Уровни severity в разных EDR свои, но логика
общая: `critical` > `high` > `medium` > `low`.

## Шаг 2: восстанавливаем цепочку

Смотрим на время:

```
10:11:12  Recon            whoami
10:12:01  CredentialTheft  lsass memory access
10:13:44  Persistence      run key added
```

Это готовая **kill chain**: разведка → кража учёток → закрепление. В реальном отчёте
каждую строку дополнили бы process GUID, родительским процессом и пользователем.

## Шаг 3: что ещё хранится в детекции

Полезные поля EDR-события:

- **process** — имя и PID процесса-нарушителя;
- **parent** — родитель (например, `cmd.exe`, запущенный из `winword.exe`);
- **cmdline** — полная командная строка;
- **file/hash** — объект действия и его хеш;
- **network** — адрес назначения.

Именно связка `parent → child` выдаёт фишинг: `winword.exe → powershell.exe` почти
всегда подозрительна.

## Что мы теперь знаем

- EDR — это агент-наблюдатель, а не только сканер файлов.
- Локальные логи ограничены; полные данные обычно в облачной консоли.
- Ключевые поля детекции: severity, process, parent, cmdline, network.
- Детекции выстраиваются в kill chain по времени.

## Квиз

Проверь себя.

```quiz
- question: Чем EDR принципиально отличается от классического AV?
  options:
    - 'ничем'
    - 'EDR постоянно наблюдает за поведением и пишет телеметрию'
    - 'EDR не ставится на серверы'
    - 'AV пишет больше данных'
  answer: 1
  explanation: 'EDR фиксирует поведение процессов и активность, а не только сигнатуры файлов.'
- question: Почему обращение к памяти lsass считается критичным?
  options:
    - 'lsass тормозит систему'
    - 'lsass хранит аутентификационные секреты'
    - 'lsass — это драйвер диска'
    - 'lsass шифрует диск'
  answer: 1
  explanation: 'В памяти lsass лежат креды; доступ к ней — типичный credential dumping.'
- question: Какая связка в EDR-событиях намекает на фишинг?
  options:
    - 'services.exe -> svchost.exe'
    - 'winword.exe -> powershell.exe'
    - 'explorer.exe -> notepad.exe'
    - 'smss.exe -> csrss.exe'
  answer: 1
  explanation: 'Офисный документ, порождающий PowerShell, — классический признак эксплуатации.'
- question: Где обычно лежит полный объём телеметрии EDR?
  options:
    - 'только в реестре'
    - 'в облачной консоли продукта'
    - 'в C:\Windows\Temp'
    - 'в SAM'
  answer: 1
  explanation: 'Агент отправляет телеметрию в консоль; локально — лишь часть.'
```

## Куда дальше

Мы разобрали, как защита видит атаку. Но атакующий может **испортить сами журналы**.
Следующий урок — про tampering с EVTX и обнаружение «дыр» в журналах. А пока запомни:
детекции EDR — это уже готовая поведенческая история инцидента.

## Где пригодится

- **DFIR / Incident Response** — восстановление таймлайна атаки.
- **Threat Hunting** — проверка гипотез по детекциям.
- **CTF Forensics** — задачи на разбор выгрузок защиты.
''',
)

# --------------------------------------------------------------------------
LESSONS['win-evtx-tampering'] = dict(
    title='Повреждение и подделка EVTX: обнаружение пропусков в журналах',
    order=5, diff='hard', mins=55,
    tags=['windows', 'evtx', 'tampering', 'anti-forensics', 'record-id', 'forensics'],
    prereq=['forensics-windows-artifacts', 'af-artifact-destruction'],
    summary='Как устроен EVTX-файл, почему по RecordID и чанкам можно обнаружить удаление событий, и какие признаки выдают подделку или очистку журнала.',
    lab=lab(
        'Практика: поиск пропуска в журнале',
        ['task.md', 'security.txt'],
        "grep -q 'nto{' found.txt",
        [
            '`cat security.txt` — экспорт событий Security.',
            'Смотри колонку RecordID по порядку.',
            'Пропуск в нумерации — след удаления события; рядом флаг.',
            'Выдели флаг: `grep nto security.txt > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: пропуск в EVTX\n\nЭкспорт событий журнала Security. Найди пропущенный RecordID и флаг.\n\n1. `cat security.txt`.\n2. Сравни RecordID соседних строк.\n3. `grep nto security.txt > found.txt`.\n'),
            t(WD + '/security.txt', 'RecordID=1001 EventID=4624 Logon\nRecordID=1002 EventID=4672 Special Logon\nRecordID=1003 EventID=4624 Logon\nRecordID=1005 EventID=4688 Process Create  <-- record 1004 missing, tampering suspected nto{evtx_r3c0rd_g4p_d3t3ct}\nRecordID=1006 EventID=4634 Logoff\n'),
        ],
        flag='nto{evtx_r3c0rd_g4p_d3t3ct}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

Атакующий вошёл в систему и, чтобы замести следы, удалил часть событий из журнала
безопасности. Внешне журнал выглядит целым. Можно ли доказать, что события удаляли, —
и как?

## Что такое EVTX и как он устроен

**EVTX** — формат журналов событий Windows (файлы `*.evtx` в
`C:\Windows\System32\winevt\Logs\`). Файл состоит из **чанков** по 64 КБ. Каждый чанк
содержит заголовок и последовательность **записей событий**. У каждой записи есть
**RecordID** — сквозной номер, который увеличивается на единицу с каждым новым событием
в данном журнале. Это ключевое свойство: **нумерация непрерывна**.

## Наш пример

У нас текстовый экспорт событий из журнала Security.

```
$ cat security.txt
RecordID=1001 EventID=4624 Logon
RecordID=1002 EventID=4672 Special Logon
RecordID=1003 EventID=4624 Logon
RecordID=1005 EventID=4688 Process Create  <-- record 1004 missing
RecordID=1006 EventID=4634 Logoff
```

Смотрим на номера: 1001, 1002, 1003, **1005**, 1006. Записи `1004` нет. Так выглядит
**пропуск (gap)** — след удаления события.

## Шаг 1: почему пропуск — это улика

Если событие просто «не записалось», номер бы не израсходовался. Разрыв нумерации
означает, что запись **существовала и была удалена** (или чанк повреждён). Инструменты
(`EvtxECmd`, `EvtxHussar`, `Chainsaw`) умеют строить карту RecordID и автоматически
подсвечивать дыры.

## Шаг 2: способы «чистки» журнала и их следы

- `wevtutil cl Security` — очистка журнала. Оставляет событие **1102** («журнал очищен»)
  в самом журнале Security (если только не вычищено и оно) и событие **104** в System.
- Удаление отдельных записей правкой файла — оставляет разрыв RecordID и несоответствие
  смещений в чанке.
- Остановка службы EventLog или удаление файла `*.evtx` — отсутствие журнала вообще,
  что само по себе аномалия.

## Шаг 3: что проверять в расследовании

- Сравни **количество записей** в заголовке чанка с реальным числом записей.
- Проверь **LastWriteTime** файла `.evtx` и каталога `winevt\Logs`.
- Ищи событие 1102 (очистка) и 104 (журнал очищен).
- Сравни RecordID первого и последнего события: разрыв = удаление.
- Проверь **альтернативные источники**: Sysmon, EDR, PowerShell-логи, которые могут
  сохранить то, что вычищено из Security.

## Что мы теперь знаем

- EVTX состоит из чанков, у событий сквозной RecordID.
- Разрыв нумерации RecordID — сильный признак удаления событий.
- Очистка журнала оставляет свои события (1102/104).
- Для вывода нужен и внешний источник: Sysmon/EDR.

## Квиз

Проверь себя.

```quiz
- question: Что означает разрыв в нумерации RecordID?
  options:
    - 'событие не подходит по фильтру'
    - 'событие существовало и было удалено'
    - 'сброс счётчика при перезагрузке'
    - 'ошибка парсера'
  answer: 1
  explanation: 'RecordID растёт на единицу; дыра означает удаление/повреждение записи.'
- question: Какое событие оставляет очистка журнала Security?
  options:
    - '4624'
    - '4688'
    - '1102'
    - '7045'
  answer: 2
  explanation: 'Event 1102 — журнал очищен.'
- question: Из чего состоит файл EVTX?
  options:
    - 'из чанков по 64 КБ'
    - 'из одного JSON'
    - 'из строк CSV'
    - 'из таблиц реестра'
  answer: 0
  explanation: 'EVTX — набор чанков фиксированного размера.'
- question: Что делать, если Security-журнал вычищен?
  options:
    - 'сдаться'
    - 'искать события в Sysmon/EDR/альтернативных источниках'
    - 'перезагрузить машину'
    - 'удалить журнал'
  answer: 1
  explanation: 'Параллельные источники часто сохраняют утраченные события.'
```

## Куда дальше

Дальше — **восстановление реестра** из transaction-логов и slack, ещё один способ
вернуть удалённое. А пока запомни: непрерывность RecordID — твой детектор удаления.

## Где пригодится

- **DFIR / Incident Response** — доказательство anti-forensics.
- **CTF Forensics** — задачи «найди удалённое событие».
- **Threat Hunting** — выявление очистки журналов.
''',
)

# --------------------------------------------------------------------------
LESSONS['win-registry-recovery'] = dict(
    title='Восстановление реестра: transaction-логи и slack',
    order=6, diff='hard', mins=55,
    tags=['windows', 'registry', 'hive', 'transaction-log', 'slack', 'recovery', 'forensics'],
    prereq=['forensics-registry-hives', 'forensics-windows-artifacts'],
    summary='Как восстановить удалённые или не зафиксированные на диск ключи реестра из .LOG1/.LOG2 transaction-логов и из неиспользованного места (slack) куста.',
    lab=lab(
        'Практика: восстановление из slack',
        ['task.md', 'hive.slack'],
        "grep -q 'nto{' found.txt",
        [
            '`strings hive.slack` — в неиспользованном месте куста остались строки.',
            'Удалённый ключ Run мог сохраниться целиком.',
            'Флаг лежит в остатке строки значения.',
            'Выдели флаг: `strings hive.slack | grep nto > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: реестр из slack\n\nВ неиспользованном месте (slack) куста реестра остались удалённые данные. Найди флаг.\n\n1. `strings hive.slack`.\n2. Ищи остатки ключа Run.\n3. `strings hive.slack | grep nto > found.txt`.\n'),
            t(WD + '/hive.slack', 'regf\x00\x00\x00\x00\x00\x00\x00\x00nk\x00Run\x00Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00updater=C:\\Users\\Public\\svc.exe nto{reg_sl4ck_d3l3t3d_k3y}\x00\x00\x00\x00\x00\x00\x00\x00'),
        ],
        flag='nto{reg_sl4ck_d3l3t3d_k3y}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

Атакующий создал ключ автозапуска, а потом удалил его. В самом кусте реестра ключа нет.
Но значит ли это, что данные исчезли полностью — или их можно вернуть?

## Что такое куст реестра и как он устроен

**Куст (hive)** — файл реестра, например `SYSTEM`, `SOFTWARE`, `SAM` или `NTUSER.DAT`.
Внутри — заголовок `regf` и **ячейки (cells)** фиксированного размера, в которых лежат
ключи (`nk`), значения (`vk`) и данные. Ключевые свойства:

- ячейки выделяются и освобождаются, но их содержимое **не стирается сразу** —
  освобождённая ячейка становится «дыркой» в кусте, это и есть **slack**;
- удаление ключа лишь снимает ссылку и помечает ячейку свободной;
- новые данные могут **не успеть** записаться на диск — тогда их держат transaction-логи.

## Наш пример

У нас файл `hive.slack` — фрагмент куста, включая неиспользованное место.

```
$ strings hive.slack
regf
nk  Run
Software\Microsoft\Windows\CurrentVersion\Run
updater=C:\Users\Public\svc.exe nto{reg_sl4ck_d3l3t3d_k3y}
```

Видно остатки ключа `Run` и строку значения `updater=...` — данные пережили удаление
ключа в свободном месте куста.

## Шаг 1: transaction-логи (.LOG1/.LOG2)

Рядом с кустами в `C:\Windows\System32\config\` лежат файлы `<Hive>.LOG1` и `<Hive>.LOG2`.
Это **transaction-логи**: в них записываются изменения, которые ещё не «слились» в
основной куст (например, система выключилась аварийно). Инструмент `yarp` (Yet Another
Registry Parser) умеет «накатывать» логи на куст:

```
$ yarp dump -o out/ NTUSER.DAT
```

и при наличии логов он применяет их, показывая и те ключи, которых в самом кусте нет.

## Шаг 2: slack и deleted keys

Даже без логов свободное место куста хранит старые ячейки. Инструменты (`Registry
Explorer` + recovery, `regslack`, `hivex`) умеют выводить **удалённые ячейки** —
их ещё называют **unallocated / slack**. Именно так восстанавливают:
- удалённые ключи `Run`/`RunOnce`;
- значения, которые атакующий «затёр»;
- историю изменений ключа.

## Шаг 3: что искать

- Ключи автозапуска: `...\CurrentVersion\Run`, `RunOnce`, `Services`.
- Следы очистки: пустые значения там, где раньше что-то было.
- Расхождение: ключ есть в `.LOG1`, но нет в кусте → изменение не зафиксировано.

## Что мы теперь знаем

- Куст реестра состоит из ячеек; удаление не стирает данные мгновенно.
- Slack — свободное место куста, где остаются удалённые ключи и значения.
- `.LOG1/.LOG2` — transaction-логи, применяемые к кусту при разборе.
- Так восстанавливают удалённые ключи автозапуска и следы правок.

## Квиз

Проверь себя.

```quiz
- question: Что такое slack в контексте куста реестра?
  options:
    - 'сжатая часть'
    - 'неиспользованное место с остатками удалённых ячеек'
    - 'копия куста'
    - 'пароль'
  answer: 1
  explanation: 'Slack — свободные ячейки, где могут оставаться удалённые данные.'
- question: Для чего нужны файлы .LOG1/.LOG2 рядом с кустом?
  options:
    - 'это резервные копии'
    - 'это transaction-логи незафиксированных изменений'
    - 'это журналы безопасности'
    - 'это дампы памяти'
  answer: 1
  explanation: 'Transaction-логи применяются к кусту при разборе.'
- question: Какое расширение имеет заголовок файла куста?
  options:
    - 'evtx'
    - 'regf'
    - 'hbin'
    - 'lnk'
  answer: 1
  explanation: 'Куст начинается с сигнатуры regf.'
- question: Что чаще всего восстанавливают из slack куста?
  options:
    - 'пароли в открытом виде'
    - 'удалённые ключи и значения, например Run'
    - 'сетевой трафик'
    - 'обои рабочего стола'
  answer: 1
  explanation: 'Удалённые ключи/значения — типичная находка в slack.'
```

## Куда дальше

Теперь мы умеем возвращать удалённое из реестра. Дальше — **карантин антивируса**, ещё
одно место, где сохраняются копии вредоносных файлов. А пока запомни: удаление ключа
реестра — не гарантия, что данных нет.

## Где пригодится

- **DFIR / Incident Response** — восстановление удалённой персистентности.
- **CTF Forensics** — задачи «верни удалённый ключ».
- **Пентест Windows** — понимание, что остаётся после чистки.
''',
)

# --------------------------------------------------------------------------
LESSONS['win-quarantine'] = dict(
    title='Карантин антивируса: разбор хранилища изоляции',
    order=7, diff='medium', mins=45,
    tags=['windows', 'antivirus', 'quarantine', 'defender', 'malware', 'forensics'],
    prereq=['forensics-windows-artifacts', 'win-edr-logs'],
    summary='Как устроен карантин Microsoft Defender и сторонних AV, где хранятся изолированные файлы и как восстановить из карантина образец вредоносного ПО.',
    lab=lab(
        'Практика: разбор манифеста карантина',
        ['task.md', 'quarantine_manifest.csv'],
        "grep -q 'nto{' found.txt",
        [
            '`cat quarantine_manifest.csv` — список изолированных файлов.',
            'Ищи запись с исходным путём и хешем.',
            'Флаг дописан к записи с наибольшим threat level.',
            'Выдели флаг: `grep nto quarantine_manifest.csv > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: карантин AV\n\nМанифест карантина Defender. Определи, что было изолировано, и найди флаг.\n\n1. `cat quarantine_manifest.csv`.\n2. Смотри ThreatName и OriginalPath.\n3. `grep nto quarantine_manifest.csv > found.txt`.\n'),
            t(WD + '/quarantine_manifest.csv', 'Timestamp,ThreatName,OriginalPath,SHA256,ThreatLevel\n2024-03-02T10:20:00Z,Trojan:Win32/Beacon,C:\\Users\\Public\\svc.exe,ab12...,Severe\n2024-03-02T10:21:00Z,Trojan:Win32/Dropper,C:\\Users\\Public\\payload.dll,cd34...,nto{qu4r4nt1n3_s4mpl3_r3c0v3r3d}\n2024-03-02T10:22:00Z,Backdoor:Win32/Agent,C:\\Windows\\Temp\\tmp1.exe,ef56...,High\n'),
        ],
        flag='nto{qu4r4nt1n3_s4mpl3_r3c0v3r3d}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

Антивирус что-то нашёл и «удалил». Форензик задаёт вопрос: а можно ли получить сам файл —
чтобы понять, что это было и что оно делало? Ведь «удалённый» антивирусом файл — не
обязательно уничтоженный.

## Что такое карантин

**Карантин** — это изолированное хранилище, куда AV помещает подозрительные файлы. Он не
удаляет образец сразу, а **шифрует и сохраняет** его: чтобы можно было восстановить
ложное срабатывание и чтобы аналитик мог изучить вредонос. У Microsoft Defender карантин
лежит в `C:\ProgramData\Microsoft\Windows Defender\Quarantine\` — это база
**Resources`*`** (`.dat`) и сопутствующие метаданные. Файлы внутри зашифрованы ключом из
реестра (`HKLM\SOFTWARE\Microsoft\Windows Defender\`), а описания доступны командой:

```
C:\> "C:\Program Files\Windows Defender\MpCmdRun.exe" -Restore -ListAll
```

## Наш пример

У нас экспорт манифеста карантина в CSV — так выгружают список изолированных объектов.

```
$ cat quarantine_manifest.csv
Timestamp,ThreatName,OriginalPath,SHA256,ThreatLevel
2024-03-02T10:20:00Z,Trojan:Win32/Beacon,C:\Users\Public\svc.exe,ab12...,Severe
2024-03-02T10:21:00Z,Trojan:Win32/Dropper,C:\Users\Public\payload.dll,cd34...,nto{qu4r4nt1n3_s4mpl3_r3c0v3r3d}
2024-03-02T10:22:00Z,Backdoor:Win32/Agent,C:\Windows\Temp\tmp1.exe,ef56...,High
```

Три изолированных объекта: `svc.exe`, `payload.dll`, `tmp1.exe`. Пути говорят о том же
`C:\Users\Public`, что и в других артефактах.

## Шаг 1: что даёт манифест

Даже без самих файлов манифест ценен:

- **OriginalPath** — откуда файл появился;
- **ThreatName** — классификация (иногда маскируется, но полезна);
- **SHA256** — хеш для сверки с внешними базами (VirusTotal);
- **Timestamp** — когда сработала защита.

Это готовый список «что атакующий приносил на машину» и когда.

## Шаг 2: восстановление образца

Чтобы получить сам файл, карантин расшифровывают: ключ и алгоритм разбираются из
реестра Defender, а затем содержимое `.dat` превращается обратно в исходный бинарник.
Инструменты (`mpcmdrun -Restore`, сторонние `Defender Quarantine`-парсеры) делают это
автоматически. Восстановленный образец далее идёт в песочницу и YARA.

## Шаг 3: что смотреть у сторонних AV

У других продуктов свои хранилища:

- ESET: `C:\ProgramData\ESET\...\Quarantine`;
- Kaspersky: `C:\ProgramData\Kaspersky Lab\...\Quarantine`;
- Avast/AVG: `C:\ProgramData\Avast Software\Avast\chest`.

Формат у всех свой, но принцип один: зашифрованное хранилище + метаданные. Иногда рядом
остаётся **лог детекции** в человекочитаемом виде — его ищут в первую очередь.

## Что мы теперь знаем

- Карантин — хранилище изолированных (зашифрованных) образцов, а не удаление.
- Defender держит карантин в `...\Windows Defender\Quarantine`.
- Манифест даёт путь, классификацию, хеш и время.
- Образец можно восстановить и проанализировать.

## Квиз

Проверь себя.

```quiz
- question: Что делает антивирус при «карантине» файла?
  options:
    - 'окончательно стирает'
    - 'шифрует и сохраняет для изоляции/анализа'
    - 'перемещает в корзину'
    - 'отправляет только хеш'
  answer: 1
  explanation: 'Карантин — изолированное зашифрованное хранилище образца.'
- question: Какое поле манифеста указывает, откуда появился файл?
  options:
    - 'ThreatName'
    - 'OriginalPath'
    - 'SHA256'
    - 'ThreatLevel'
  answer: 1
  explanation: 'OriginalPath — исходный путь изолированного объекта.'
- question: Зачем форензику восстанавливать образец из карантина?
  options:
    - 'чтобы освободить место'
    - 'чтобы проанализировать вредонос'
    - 'чтобы удалить AV'
    - 'чтобы ускорить систему'
  answer: 1
  explanation: 'Восстановленный образец идёт в анализ и детект-правила.'
- question: Где по умолчанию карантин Microsoft Defender?
  options:
    - 'C:\Windows\Temp'
    - 'C:\ProgramData\Microsoft\Windows Defender\Quarantine'
    - 'HKLM\SAM'
    - '%APPDATA%'
  answer: 1
  explanation: 'Это стандартный каталог карантина Defender.'
```

## Куда дальше

Дальше — **Windows Update**: журналы обновлений показывают, что и когда система
устанавливала, и их тоже правят атакующие. А пока запомни: карантин — это подарок
аналитику, там лежит сам образец.

## Где пригодится

- **DFIR / Incident Response** — восстановление образцов и карта срабатываний AV.
- **Malware Analysis** — получение образца без повторной добычи.
- **CTF Forensics** — задачи «достань файл из карантина».
''',
)

# --------------------------------------------------------------------------
LESSONS['win-windows-update'] = dict(
    title='Windows Update и servicing stack: журналы обновлений',
    order=8, diff='medium', mins=45,
    tags=['windows', 'windows-update', 'servicing', 'patches', 'logs', 'forensics'],
    prereq=['forensics-windows-artifacts', 'win-service-artifacts'],
    summary='Где лежат журналы обновлений Windows (WindowsUpdate.log, CBS, DISM), как по ним определить уровень патчей и время установки, и почему они важны для расследования.',
    lab=lab(
        'Практика: разбор журнала обновлений',
        ['task.md', 'WindowsUpdate.log'],
        "grep -q 'nto{' found.txt",
        [
            '`cat WindowsUpdate.log` — журнал установки обновлений.',
            'Найди строки с установкой KB.',
            'Флаг дописан в строку с необычной установкой.',
            'Выдели флаг: `grep nto WindowsUpdate.log > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: журнал обновлений\n\nЖурнал Windows Update. Определи, что и когда устанавливалось, и найди флаг.\n\n1. `cat WindowsUpdate.log`.\n2. Ищи строки Installing KB.\n3. `grep nto WindowsUpdate.log > found.txt`.\n'),
            t(WD + '/WindowsUpdate.log', '2024-03-01 09:00:00 Downloading KB5034441\n2024-03-01 09:05:00 Installing KB5034441  nto{wu_l0g_p4tch_l3v3l_f0und}\n2024-03-01 09:10:00 Install complete KB5034441\n2024-03-02 10:20:00 Downloading KB5034765\n2024-03-02 10:25:00 Install failed KB5034765\n'),
        ],
        flag='nto{wu_l0g_p4tch_l3v3l_f0und}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

При расследовании нужно понять: был ли на машине закрыт конкретный патч на момент атаки?
И что вообще система устанавливала незадолго до инцидента? Ответ часто лежит в журналах
обновлений, которые мало кто смотрит.

## Что такое servicing stack и Windows Update

**Windows Update** — служба обновления системы. За установку пакетов отвечает
**servicing stack** («стек обслуживания») — набор компонентов, которые применяют обновления
к образу системы. Журналы обновлений фиксируют, что скачивалось, что установилось, а что
упало. Основные источники:

- `C:\Windows\WindowsUpdate.log` (в старых системах; в новых — ETL-файлы
  `C:\Windows\Logs\WindowsUpdate\*.etl`);
- `C:\Windows\Logs\CBS\CBS.log` — Component Based Servicing, установка компонентов;
- `C:\Windows\Logs\DISM\dism.log` — работа DISM;
- `C:\Windows\SoftwareDistribution\` — кэш скачанных обновлений;
- журнал `Microsoft-Windows-WindowsUpdateClient/Operational` (EVTX).

## Наш пример

У нас текстовый журнал `WindowsUpdate.log`.

```
$ cat WindowsUpdate.log
2024-03-01 09:00:00 Downloading KB5034441
2024-03-01 09:05:00 Installing KB5034441  nto{wu_l0g_p4tch_l3v3l_f0und}
2024-03-01 09:10:00 Install complete KB5034441
2024-03-02 10:20:00 Downloading KB5034765
2024-03-02 10:25:00 Install failed KB5034765
```

Читаем историю: 1 марта успешно поставлен `KB5034441`, 2 марта `KB5034765` не встал.

## Шаг 1: как связать KB с уязвимостью

Идентификатор `KB…` — это номер пакета обновления. По нему находят, какое именно
исправление безопасности пришло. В расследовании важно ответить:

- был ли патч **установлен до** атаки (значит, уязвимость закрыта);
- был ли **провал установки** (машина осталась уязвимой);
- был ли **откат/удаление** обновления (иногда это делает атакующий).

## Шаг 2: DISM/CBS — глубже

`CBS.log` показывает установку на уровне компонентов: какие сборки меняются, где
ошибка. `dism.log` — операции обслуживания образа. Эти журналы нужны, когда установка
падает: по ним видно причину (например, нехватка места или повреждённый компонент).

## Шаг 3: почему это интересно атакующему

Атакующие иногда **блокируют обновления** (правкой реестра или службы), чтобы система
осталась уязвимой. Признаки: служба `wuauserv` отключена, ключ `NoAutoUpdate=1`,
патчи давно не ставились, хотя журнал скачивания активен. Всё это — следы целенаправленной
поддержки уязвимого состояния.

## Что мы теперь знаем

- Windows Update пишет журналы (WindowsUpdate.log/ETL, CBS, DISM).
- По KB можно определить, закрыт ли конкретный патч.
- Провал установки = машина могла остаться уязвимой.
- Блокировка обновлений — сама по себе признак атаки.

## Квиз

Проверь себя.

```quiz
- question: Что означает идентификатор KB в журнале обновлений?
  options:
    - 'номер ключа реестра'
    - 'номер пакета обновления'
    - 'код ошибки'
    - 'имя пользователя'
  answer: 1
  explanation: 'KB — номер пакета обновления Windows.'
- question: Какой журнал фиксирует установку компонентов?
  options:
    - 'CBS.log'
    - 'SAM'
    - 'bootmgr'
    - 'hosts'
  answer: 0
  explanation: 'CBS.log (Component Based Servicing) — установка компонентов.'
- question: Что значит провал установки обновления при расследовании?
  options:
    - 'ничего'
    - 'машина могла остаться уязвимой'
    - 'патч установлен'
    - 'журнал повреждён'
  answer: 1
  explanation: 'Неустановленный патч оставляет уязвимость открытой.'
- question: Как атакующий может поддерживать уязвимость системы?
  options:
    - 'ускорить сеть'
    - 'заблокировать обновления (служба/реестр)'
    - 'удалить браузер'
    - 'включить шифрование диска'
  answer: 1
  explanation: 'Отключение wuauserv/NoAutoUpdate оставляет систему без патчей.'
```

## Куда дальше

Последний урок блока — про **AppCompat cache**: кэш совместимости приложений, ещё один
источник следов запуска. А пока запомни: журналы обновлений — это ответ на вопрос
«закрыт ли был нужный патч».

## Где пригодится

- **DFIR / Incident Response** — уровень патчей на момент инцидента.
- **Vulnerability Assessment** — фактическое состояние обновлений.
- **CTF Forensics** — задачи «был ли установлен патч».
''',
)

# --------------------------------------------------------------------------
LESSONS['win-app-compat'] = dict(
    title='AppCompat cache: кэш совместимости приложений',
    order=9, diff='medium', mins=45,
    tags=['windows', 'appcompat', 'shimcache', 'execution-artifacts', 'registry', 'forensics'],
    prereq=['win-appcompat-deep', 'forensics-windows-artifacts'],
    summary='Как читать кэш совместимости приложений (AppCompatCache/ShimCache) в SYSTEM hive, что он доказывает о запуске программ и в чём его ограничения.',
    lab=lab(
        'Практика: разбор AppCompat cache',
        ['task.md', 'appcompat.txt'],
        "grep -q 'nto{' found.txt",
        [
            '`cat appcompat.txt` — дамп AppCompatCache.',
            'Каждая строка — путь к программе, когда-то запущенной.',
            'Флаг дописан к подозрительному пути.',
            'Выдели флаг: `grep nto appcompat.txt > found.txt`.',
        ],
        [
            d(WD),
            t(WD + '/task.md', '# Задача: AppCompat cache\n\nДамп AppCompatCache из SYSTEM hive. Определи, какие программы запускались, и найди флаг.\n\n1. `cat appcompat.txt`.\n2. Ищи нестандартные пути.\n3. `grep nto appcompat.txt > found.txt`.\n'),
            t(WD + '/appcompat.txt', 'C:\\Windows\\System32\\cmd.exe\nC:\\Program Files\\7-Zip\\7zFM.exe\nC:\\Users\\Public\\svc.exe  nto{sh1mc4ch3_p4th_3x3cut3d}\nC:\\Windows\\System32\\notepad.exe\n'),
        ],
        flag='nto{sh1mc4ch3_p4th_3x3cut3d}',
    ),
    body=r'''
## Вопрос, с которого всё начинается

У нас есть подозрение, что программа запускалась, но Prefetch уже очищен, а её самой на
диске нет. Есть ли ещё один независимый источник «что запускалось на этой машине»?

## Что такое AppCompat cache

**AppCompat cache** (историческое имя — **ShimCache**) — структура в кусте `SYSTEM`
по пути:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Windows записывает туда пути к исполняемым файлам, которые прошли через механизм
**совместимости приложений** (shim engine). Когда приложение запускается, система
проверяет, нужен ли ему «shim» (заплатка совместимости), и попутно фиксирует путь файла.
Так кэш накапливает **пути к программам, которые запускались** — часто дольше, чем живёт
Prefetch.

## Наш пример

У нас дамп AppCompatCache.

```
$ cat appcompat.txt
C:\Windows\System32\cmd.exe
C:\Program Files\7-Zip\7zFM.exe
C:\Users\Public\svc.exe  nto{sh1mc4ch3_p4th_3x3cut3d}
C:\Windows\System32\notepad.exe
```

Четыре пути. `svc.exe` из `C:\Users\Public` снова всплывает — теперь уже как
доказательство запуска.

## Шаг 1: что именно доказывает ShimCache

Важный нюанс, который путает новичков: **наличие пути в ShimCache означает, что файл
«существовал» на момент проверки** (система просканировала каталоги), но не всегда
доказывает запуск. На разных версиях Windows формат разный:

- в **Windows 8/10** структура содержит **флаги**, среди которых признак выполнения;
- в **Windows 7 и раньше** — только путь, без надёжного признака запуска.

Поэтому ShimCache используют **вместе** с другими артефактами (Prefetch, AmCache, WER).

## Шаг 2: как читать и что искать

Разбор делают инструментами (`AppCompatCacheParser` от Eric Zimmerman). Из записей
достают:

- **путь** к исполняемому файлу;
- **время последней модификации** файла (в новых версиях);
- **флаги выполнения** (где они есть).

Ищут нестандартные пути (`Users\Public`, `Temp`, `ProgramData`), двойные расширения и
известные IOC.

## Шаг 3: связка с другими источниками

Правильная схема вывода:

```
ShimCache (путь)  +  Prefetch (время запуска)  +  WER/EVTX  =>  запуск доказан
```

Каждый артефакт по отдельности может дать ложную уверенность. Только пересечение
нескольких независимых источников делает вывод обоснованным.

## Что мы теперь знаем

- AppCompat cache/ShimCache лежит в SYSTEM hive и хранит пути к программам.
- В новых Windows содержит флаги выполнения; в старых — только путь.
- Разбирается инструментами; ищем нестандартные пути и IOC.
- Использовать только в связке с Prefetch/AmCache/WER.

## Квиз

Проверь себя.

```quiz
- question: В каком кусте реестра находится AppCompat cache?
  options:
    - 'SAM'
    - 'SYSTEM'
    - 'NTUSER.DAT'
    - 'SECURITY'
  answer: 1
  explanation: 'AppCompatCache — подраздел Session Manager в SYSTEM hive.'
- question: Что доказывает запись в ShimCache?
  options:
    - 'что файл точно запускался'
    - 'что файл существовал/был просканирован (запуск — не всегда)'
    - 'что файл был скачан'
    - 'что файл подписан'
  answer: 1
  explanation: 'Наличие пути не всегда равно запуску; нужны другие артефакты.'
- question: С какими артефактами связывают ShimCache для вывода о запуске?
  options:
    - 'обои и тема'
    - 'Prefetch и AmCache/WER'
    - 'hosts и DNS'
    - 'SAM и SECURITY'
  answer: 1
  explanation: 'Пересечение независимых execution-артефактов даёт вывод.'
- question: Какие пути в ShimCache считаются подозрительными?
  options:
    - 'C:\Windows\System32'
    - 'C:\Users\Public, Temp, ProgramData'
    - 'C:\Program Files'
    - 'C:\Windows\Fonts'
  answer: 1
  explanation: 'Чужеродные каталоги — типичное место для вредоносных бинарников.'
```

## Куда дальше

На этом мы закрыли ещё один пласт Windows-артефактов. Дальше ветка переходит к
**инструментам DFIR** (KAPE, Velociraptor и парсеры), с которыми всё это собирают
автоматически. А пока запомни: AppCompat cache — независимый след запуска, но не
панацея.

## Где пригодится

- **DFIR / Incident Response** — доказательство запуска программы.
- **CTF Forensics** — задачи «что запускалось на машине».
- **Threat Hunting** — поиск нестандартных путей исполнения.
''',
)

# --------------------------------------------------------------------------
HUBS = {}

HUBS['forensics-win-security-telemetry'] = dict(
    title='Модуль: телеметрия защиты и обслуживание Windows',
    parent='forensics-windows-artifacts', order=5, diff='hard',
    tags=['windows', 'edr', 'evtx', 'quarantine', 'windows-update', 'roadmap'],
    prereq=['forensics-windows-artifacts'],
    summary='Ветка «Артефакты Windows»: следы защитных продуктов, целостность журналов, восстановление реестра, карантин и обслуживание системы.',
    body=r'''
Этот модуль собирает артефакты «второго эшелона»: то, что смотрят, когда базовые
execution/registry/logs-источники уже разобраны, а картину нужно дополнить. Здесь —
реакция защитных продуктов, целостность журналов, восстановление удалённого из реестра
и следы обслуживания системы.

## Что покрывает этот модуль

- **Журналы EDR/AV** — что видела защита: детекции, их severity и контекст.
- **Карантин** — изолированные образцы, которые можно вернуть и изучить.
- **Целостность EVTX** — обнаружение удаления событий по разрывам RecordID.
- **Восстановление реестра** — transaction-логи и slack куста.
- **Windows Update** — уровень патчей и история обслуживания.

## Рекомендуемый порядок изучения

1. `win-edr-logs` — поведенческая история инцидента глазами защиты.
2. `win-quarantine` — сами образцы вредоносного ПО.
3. `win-evtx-tampering` — доказательство anti-forensics.
4. `win-registry-recovery` — возврат удалённых ключей.
5. `win-windows-update` — состояние патчей на момент атаки.

## Что вы будете уметь

- Читать детекции EDR и выстраивать kill chain.
- Восстанавливать образцы из карантина.
- Находить разрывы RecordID и очистку журналов.
- Доставать удалённые ключи реестра из slack и transaction-логов.
- Определять, какие патчи были установлены.

## Куда дальше

Начни с урока **«Журналы EDR/AV»** — это самый прямой источник поведенческих следов.
''',
)

HUBS['forensics-win-userdata'] = dict(
    title='Модуль: пользовательские данные и сетевые следы Windows',
    parent='forensics-windows-artifacts', order=6, diff='hard',
    tags=['windows', 'credentials', 'vault', 'dns', 'wer', 'appcompat', 'roadmap'],
    prereq=['forensics-windows-artifacts'],
    summary='Ветка «Артефакты Windows»: сохранённые учётки, DNS-следы, отчёты о падениях и кэш совместимости приложений.',
    body=r'''
Пользовательские данные и сетевые следы отвечают на вопросы «чем пользовались», «куда
ходили» и «что запускалось». Этот модуль объединяет артефакты, которые связывают
конкретного пользователя с действиями в системе и сети.

## Что покрывает этот модуль

- **Credential Manager / Vault** — сохранённые логины и пароли.
- **DNS-кэш и журналы DNS Client** — к каким именам обращалась машина.
- **Windows Error Reporting** — пути и имена упавших программ.
- **AppCompat cache** — независимый след запуска приложений.

## Рекомендуемый порядок изучения

1. `win-credential-vault` — учётки, которые использовались.
2. `win-dns-cache` — сетевые контакты.
3. `win-wer` — следы запуска через падения.
4. `win-app-compat` — ещё один источник execution-следов.

## Что вы будете уметь

- Разбирать Credential Manager и Windows Vault.
- Восстанавливать DNS-запросы из кэша и журналов.
- Читать Report.wer и доставать пути запуска.
- Использовать AppCompat cache в связке с другими артефактами.

## Куда дальше

Начни с урока **«Credential Manager и Windows Vault»** — учётные данные чаще всего
двигают расследование вперёд.
''',
)

PARENT = {
    'win-credential-vault': 'forensics-win-userdata',
    'win-dns-cache': 'forensics-win-userdata',
    'win-wer': 'forensics-win-userdata',
    'win-app-compat': 'forensics-win-userdata',
    'win-edr-logs': 'forensics-win-security-telemetry',
    'win-quarantine': 'forensics-win-security-telemetry',
    'win-evtx-tampering': 'forensics-win-security-telemetry',
    'win-registry-recovery': 'forensics-win-security-telemetry',
    'win-windows-update': 'forensics-win-security-telemetry',
}

def main():
    for hid, h in HUBS.items():
        meta = dict(id=hid, title=h['title'], category='forensics', parent=h['parent'],
                    difficulty=h['diff'], order=h['order'], tags=h['tags'],
                    prerequisites=h['prereq'], useful_for=['CTF Forensics категория',
                    'DFIR / Incident Response', 'Пентест Windows'],
                    estimated_minutes=14, summary=h['summary'])
        write_lesson(meta, h['body'])
        print('hub', hid)
    for lid, L in LESSONS.items():
        meta = dict(id=lid, title=L['title'], category='forensics',
                    parent=PARENT.get(lid, 'forensics-windows-artifacts'),
                    difficulty=L['diff'], order=L['order'], tags=L['tags'],
                    prerequisites=L['prereq'],
                    useful_for=['CTF Forensics категория', 'DFIR / Incident Response', 'Пентест Windows'],
                    estimated_minutes=L['mins'], summary=L['summary'])
        write_lesson(meta, L['body'], lab=L['lab'])
        print('lesson', lid)

if __name__ == '__main__':
    main()
