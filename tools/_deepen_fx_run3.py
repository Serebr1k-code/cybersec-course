#!/usr/bin/env python3
"""Deepen thin forensics lessons — run 3 (ics-scada, voip, tls-decrypt, launchservices, container-escape)."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["net-ics-scada"] = """## Карта промышленных протоколов

Modbus и DNP3 — не единственные протоколы АСУ ТП. Для расследования важно быстро узнать
протокол по порту и назначению:

| Протокол | Порт | Назначение | Особенность |
|---|---|---|---|
| Modbus TCP | 502 | универсальный, PLC/датчики | простой, без auth |
| DNP3 | 20000 | энергетика, вода | сложнее, есть unsolicited |
| IEC 60870-5-104 | 2404 | энергетика (Европа) | похож на DNP3 |
| S7comm | 102 | Siemens S7 | проприетарный, есть защита |
| EtherNet/IP (CIP) | 44818 | Rockwell/Allen-Bradley | поверх TCP/UDP |
| BACnet | 47808/udp | здания (HVAC) | широковещательный |
| OPC UA | 4840 | «верхний» уровень | есть шифрование/auth |
| HART-IP | 5094 | датчики | поверх HART |

Ключевое для форензики: у классических протоколов (Modbus, DNP3, IEC-104) **нет
аутентификации** — любой, кто дошёл до порта, может читать и писать. Именно поэтому
основной детект строится на **аномалиях источника**, а не на «неверном пароле».

## Modbus детально: адреса и функции

Modbus оперирует четырьмя таблицами данных, и адрес говорит, о чём речь:

| Таблица | Адрес | Доступ | Смысл |
|---|---|---|---|
| Coils | 0xxxx | чтение/запись | дискретные выходы (реле) |
| Discrete Inputs | 1xxxx | только чтение | дискретные входы (датчики) |
| Input Registers | 3xxxx | только чтение | аналоговые входы |
| Holding Registers | 4xxxx | чтение/запись | уставки, параметры |

Функции: `1` Read Coils, `2` Read Discrete Inputs, `3` Read Holding, `4` Read Input,
`5` Write Single Coil, `6` Write Single Register, `15` Write Multiple Coils,
`16` Write Multiple Registers. Чтения (1–4) безопасны, записи (5,6,15,16) меняют
состояние. В дампе ищи именно записи:

```
$ tshark -r ot.pcap -Y 'modbus.func_code in {5 6 15 16}' \\
    -T fields -e ip.src -e modbus.reference_num -e modbus.word_cnt | sort | uniq -c | sort -rn
   500  10.10.30.99  100  8
```

## DNP3 и IEC-104

DNP3 прикладной уровень использует объекты (binary input, analog output) и функции
`READ`, `WRITE`, `SELECT`, `OPERATE`, `DIRECT_OPERATE`. Атака часто использует
`DIRECT_OPERATE` — прямая команда без предварительного `SELECT`:

```
$ tshark -r ot.pcap -Y 'dnp3.al.func==5' -T fields -e ip.src -e dnp3.al.func
10.10.30.99  5
```

IEC-104 похож: типы ASDU (например, `C_SC_NA_1` — команда одноточечного управления).
Несвойственная команда `C_*` (command) от неинженерной станции — сильный индикатор.

## Практический разбор CTF

В задачах по OT обычно дан дамп и вопрос «какой хост атаковал». Порядок:

```
$ tshark -r ot.pcap -q -z io,phs                    # какие протоколы вообще есть
$ tshark -r ot.pcap -Y 'modbus' -T fields -e ip.src | sort | uniq -c | sort -rn
$ tshark -r ot.pcap -Y 'modbus.func_code==16' -T fields -e ip.src -e modbus.reference_num
```

Хост, который массово **пишет**, а не читает, и не является инженерной станцией, — и есть
источник. Дальше сопоставляй время записей с моментом аварии по журналу оператора.

## Физические последствия и таймлайн

Кибератака на АСУ ТП — это не «украли данные», а «изменили процесс». Поэтому таймлайн
строят из нескольких слоёв:

- сетевой дамп (команды и их время);
- журнал HMI/SCADA (что видел оператор);
- журнал контроллера (что реально исполнилось);
- журнал датчиков (физический отклик: давление, температура).

Совпадение времени команды из дампа и физического отклонения — прямое доказательство
воздействия.

## Ограничения

- Серийный Modbus RTU внутри TCP-туннеля — нужен разбор полезной нагрузки вручную.
- Проприетарные расширения (S7comm, CIP) — нужны вендорные диссекторы.
- Зашифрованный OPC UA — как TLS, нужны ключи.
- Часто нет полного дампа (только зеркало на коммутаторе) — потерянные пакеты ломают
  реконструкцию сессии."""

ADDS["net-voip"] = """## SIP-методы и коды ответов

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
$ cat /var/log/asterisk/full | grep -i 'registered\\|invite'
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
- Потерянные пакеты RTP (зеркало) — слышны «провалы» и щелчки, но текст обычно читается."""

ADDS["net-tls-decrypt-deep"] = """## Что видно без расшифровки

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
$ tshark -r https.pcap -o tls.keylog_file:/tmp/keys.log -Y 'http' \\
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
$ vol -f memory.raw windows.pstree | grep -i 'chrome\\|firefox'
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
клиент жив — попробуй снять ключи из памяти до перезапуска."""

ADDS["macos-launchservices"] = """## Структура QuarantineEventsV2

`QuarantineEventsV2` — это база SQLite с единственной таблицей `LSQuarantineEvent`.
Полезные столбцы:

| Столбец | Смысл |
|---|---|
| `LSQuarantineEventIdentifier` | UUID события |
| `LSQuarantineTimeStamp` | время в Apple epoch (сек с 2001-01-01) |
| `LSQuarantineAgentName` | кто скачал (Safari, Chrome, curl) |
| `LSQuarantineAgentBundleIdentifier` | bundle-id загрузчика |
| `LSQuarantineDataURLString` | **откуда** скачан файл |
| `LSQuarantineOriginURLString` | страница-источник |
| `LSQuarantineSenderName` | отправитель (для почты/мессенджеров) |
| `LSQuarantineTypeNumber` | тип события |

Отсюда восстанавливается полный путь загрузки: `OriginURL` (страница) → `DataURL`
(сам файл) → `AgentName` (чем) → время. Это одна из самых ценных «цепочек доставки» в
macOS-форензике.

## Apple epoch и конвертация

macOS (и многое другое в экосистеме Apple) считает время в секундах от **2001-01-01
00:00:00 UTC**. Чтобы получить unix-время, прибавляем `978307200`:

```
$ python3 -c "print(1705192091 - 978307200)"   # unix -> apple
$ sqlite3 db 'SELECT datetime(LSQuarantineTimeStamp+978307200,"unixepoch") FROM LSQuarantineEvent;'
```

Обратный переход: `unix = apple + 978307200`. Ошибка в этом смещении «сдвигает» время на
31 год — типичная ошибка новичка. В `xattr` время хранится **в hex** как unix-секунды:

```
$ printf '%d\\n' 0x65a3b1f0
1705193968
$ date -d @1705193968
```

## Атрибут quarantine: разбор формата

`com.apple.quarantine` имеет вид `flags;hex_time;agent;uuid`:

```
$ xattr -l payload.dmg
com.apple.quarantine: 0083;65a3b1f0;Safari;A1B2C3D4-...
```

- `flags` — битовая маска (какие типы данных получены, был ли файл открыт);
- `hex_time` — unix-время скачивания в hex;
- `agent` — приложение, скачавшее файл;
- `uuid` — идентификатор события, связывает файл с записью в `QuarantineEventsV2`.

Связка «файл → UUID → запись в базе» позволяет доказать происхождение файла, даже если
его mtime подделан.

## LaunchServices plist: LSHandlers

Файл `com.apple.LaunchServices.secure.plist` (бинарный) хранит ассоциации «тип файла →
приложение». Читается через `plutil -p` или `plutil -convert xml1`:

```
$ plutil -p ~/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.secure.plist | head -20
$ plutil -convert xml1 -o - file.plist
```

Подмена ассоциации (например, `.txt` открывается сторонним приложением) — признак
перехвата. Смотри `LSHandlerContentType` и `LSHandlerRoleAll`.

## Сопоставление с другими артефактами macOS

LaunchServices редко даёт ответ в одиночку. Комбинируй:

| Артефакт | Путь | Что даёт |
|---|---|---|
| QuarantineEventsV2 | ~/Library/Preferences/ | загрузки с источником |
| knowledgeC.db | /private/var/db/CoreDuet/ | активность приложений по времени |
| unified log | `log show` | запуски, предупреждения Gatekeeper |
| FSEvents | /.fseventsd/ | изменения файлов |
| `~/Library/Recent Items` | профиль | недавно открытые |
| TCC.db | /Library/Application Support/com.apple.TCC/ | доступы приложений |

`knowledgeC.db` особенно ценен: таблица `ZOBJECT` хранит интервалы активности
приложений — можно увидеть, что подозрительное приложение действительно запускали.

## Практический разбор и чек-лист

1. Найти `QuarantineEventsV2` у всех пользователей.
2. Выгрузить события за окно инцидента (с конвертацией Apple epoch).
3. Проверить `xattr` на найденных файлах — связать с событием по UUID.
4. Прочитать `LaunchServices.secure.plist` — нет ли подменённых ассоциаций.
5. Сопоставить с `knowledgeC.db` и unified log — был ли реальный запуск.
6. Задокументировать цепочку «страница → файл → запуск».

## Ограничения

- `QuarantineEventsV2` периодически чистится системой (хранит не всё и не вечно).
- Файлы, скачанные через `curl`/API без флага карантина, в базе не появятся.
- Бинарные plist требуют `plutil`; текстовый просмотр даёт «мусор».
- Атака может удалить атрибут (`xattr -d`) — тогда цепочка обрывается на этом звене."""

ADDS["linux-container-escape"] = """## Namespaces детально

Контейнер изолируется набором пространств имён. Каждое можно проверить изнутри:

| Namespace | Флаг | Что изолирует | Признак слабости |
|---|---|---|---|
| PID | CLONE_NEWPID | номера процессов | hostPID → видно PID хоста |
| NET | CLONE_NEWNET | интерфейсы, порты | hostNetwork → сеть хоста |
| MNT | CLONE_NEWNS | точки монтирования | доступ к `/host` |
| UTS | CLONE_NEWUTS | hostname | видно имя хоста |
| IPC | CLONE_NEWIPC | SysV IPC, очереди | общие очереди |
| USER | CLONE_NEWUSER | uid/gid-маппинг | root внутри = root снаружи |
| CGROUP | CLONE_NEWCGROUP | иерархия cgroup | видна иерархия хоста |

Проверка изнутри:

```
$ readlink /proc/self/ns/pid /proc/self/ns/net /proc/self/ns/mnt
$ cat /proc/self/uid_map      # пустой -> не user-namespace
```

Если `/proc/self/ns/net` совпадает с хостовым (нет отдельного net-namespace) — контейнер
с `--network host`.

## Capabilities: что даёт каждое

Docker по умолчанию даёт набор capabilities, но `--privileged` выдаёт **все**. Опасные
для побега:

| Capability | Зачем опасна |
|---|---|
| CAP_SYS_ADMIN | монтирование, `mount`, часть обходов |
| CAP_SYS_PTRACE | чтение памяти процессов хоста |
| CAP_DAC_READ_SEARCH | чтение любых файлов в обход прав |
| CAP_NET_ADMIN | манипуляции сетью, ARP-спуф |
| CAP_SYS_MODULE | загрузка модулей ядра |
| CAP_SYS_RAWIO | прямой доступ к устройствам |

```
$ capsh --print | grep Current
$ grep CapEff /proc/self/status
```

Полный `CapEff: 000001ffffffffff` — это `--privileged`.

## Векторы побега: сводка

| Вектор | Условие | След на хосте |
|---|---|---|
| docker.sock внутрь | сокет смонтирован | create/start в `docker events` |
| privileged + `mount` | `--privileged` | mount в auditd, `/dev` |
| hostPID + ptrace | общий PID-ns | ptrace в auditd |
| hostNetwork + ARP | общая сеть | ARP-аномалии, spoofing |
| CVE-2019-5736 (runc) | старый runc | перезапись `/usr/bin/runc` |
| cgroup release_agent | cgroup v1 + priv | запись в `release_agent` |
| `/proc/sysrq-trigger` | privileged | reboot/dmesg |

Каждый вектор оставляет свой набор артефактов — их и ищут.

## Практический разбор: побег через docker.sock

```
$ ls -la /var/run/docker.sock          # смонтирован внутрь?
$ docker -H unix:///var/run/docker.sock ps -a
$ docker -H unix:///var/run/docker.sock events --since 2026-01-14T03:00
2026-01-14T03:31:05 container create ... image=alpine
2026-01-14T03:31:06 container start ...
```

Признаки побега: создание контейнера `alpine`/`busybox` с `-v /:/host`, короткое время
жизни, запуск из необычного родителя. Проверяем привилегии:

```
$ docker inspect <id> --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{.HostConfig.Binds}}'
true host [/:/host]
```

## Следы на хосте

- **`/var/lib/docker/overlay2/`** — слои; удалённый контейнер можно частично
  восстановить по diff-слоям.
- **journald**: `journalctl -u docker --since ...` — create/start/die с образами.
- **auditd**: правила на `mount`, `ptrace`, `init_module` покажут сам побег.
- **`/etc/crontab`, systemd-юниты** — персистентность после побега.
- **Файлы, изменённые вне контейнера** — по overlay-diff видно, что «вылезло» наружу.

## Чек-лист

1. Убедиться, что процесс в контейнере (`/proc/1/cgroup`, PID 1).
2. Проверить namespaces и capabilities.
3. Проверить, смонтирован ли `docker.sock` и привилегии контейнера.
4. Собрать `docker events` / journald за окно инцидента.
5. Найти аномальные контейнеры и их монтирования.
6. Проверить персистентность на хосте (cron, units, ключи).
7. Для Kubernetes — audit-лог API-сервера (`exec`, `create pods`)."""

def main() -> int:
    base = "content/forensics/"
    for lid, add in ADDS.items():
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
        if not m:
            print("SKIP (no quiz):", lid); continue
        if "## Квиз" in add or "## Где пригодится" in add:
            raise SystemExit("bad add for " + lid)
        out = s[:m.start()] + add + "\n\n" + s[m.start():]
        open(path, "w", encoding="utf-8").write(out)
        print("deepened", lid, "+", len(add.split()), "tokens")
    return 0

if __name__ == "__main__":
    sys.exit(main())
