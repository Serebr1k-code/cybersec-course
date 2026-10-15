#!/usr/bin/env python3
"""Batch T2b: second pass for macos-launchservices + linux-container-escape."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["macos-launchservices"] = """## Где физически лежит база LaunchServices

Пользователи часто ищут «реестр macOS» в одном файле и не находят. На самом деле
данные LaunchServices разбросаны:

- `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` — журнал
  карантина (SQLite);
- `~/Library/Preferences/com.apple.LaunchServices/` — каталог с plist-ами связей;
- `/private/var/folders/<xx>/<yyyy>/0/com.apple.LaunchServices-<uid>.csstore` —
  **основная база** связей (проприетарный формат);
- `~/Library/Application Support/com.apple.sharedfilelist/` — списки «недавних»
  для приложений.

Каталог `/private/var/folders/` — это `$TMPDIR` пользователя, и он **не входит** в
обычный Time Machine-бэкап. Поэтому `.csstore` часто отсутствует в копиях, а
`QuarantineEventsV2` остаётся — учитывай это при анализе.

## csstore: главная база связей

`.csstore` — бинарная база (CoreServices Store), в которой лежат зарегистрированные
приложения, их bundle id и ассоциации. Она не читается `plutil`, но её можно
разобрать специализированными инструментами:

```
$ ls -la /private/var/folders/*/*/0/com.apple.LaunchServices-*.csstore
-rw-r--r--  1 user staff  912384 Jan 14 03:40 com.apple.LaunchServices-501.csstore
```

Внутри — список приложений с путями и датами регистрации. Если приложение
«зарегистрировалось» позже, чем появилось на диске, это может указывать на ручное
вмешательство. Для чтения используй `mac_apt` или плагин Apollo (`launch_services`).

## Восстановление удалённых записей карантина

SQLite хранит удалённые строки в свободных страницах, и их можно вытащить:

```
$ sqlite3 QuarantineEventsV2 'PRAGMA freelist_count;'
$ strings QuarantineEventsV2 | grep -i 'http'
```

Дополнительно проверь WAL и SHM-файлы (`-wal`, `-shm`) — там могут быть ещё не
сброшенные записи. Если база повреждена, `sqlite3 .recover` вытащит максимум:

```
$ sqlite3 broken.db '.recover' | grep -i 'quarantine'
```

Так восстанавливаются записи о загрузках, которые злоумышленник пытался стереть,
удалив строки из базы.

## Инструменты для macOS-форензики

Ручные запросы — база, но для системного анализа есть готовые парсеры:

| Инструмент | Что даёт |
|---|---|
| `mac_apt` | единый парсер артефактов macOS |
| `APOLLO` | плагины по LaunchServices, quarantine, TCC |
| `MVT` (Mobile Verification Toolkit) | iocs-сверка, в т.ч. macOS |
| `plutil` | чтение бинарных plist |
| `log` / `log show` | unified log, фильтры по процессу |
| `sqlite3` | прямые запросы к базам |

Типовой прогон:

```
$ mac_apt -i /evidence/root -o /out -t LAUNCHSERVICES,QUARANTINE
```

Инструмент сам конвертирует Apple epoch и выдаёт CSV/таблицы, что удобно для отчёта.

## Разбор кейса: от загрузки до запуска

Соберём цепочку целиком:

1. `QuarantineEventsV2` показывает: `payload.dmg` скачан `03:28:11` с
   `203.0.113.5` агентом `Safari`.
2. `xattr` на найденном файле подтверждает hex-время `65a3b1f0` = `03:28`.
3. `FSEvents` фиксирует монтирование DMG и появление `.app` в `/Applications`.
4. `KnowledgeC.db` показывает запуск приложения в `03:31`.
5. `unified log` содержит предупреждение Gatekeeper о неподписанном разработчике.

Пять независимых источников, согласованных по времени, — это доказательная база, а не
догадка. Если один источник «молчит», а остальные указывают на запуск — источник
подчистили.

## Как отличить легитимную загрузку от вредоносной

Не каждый `QuarantineEvent` — инцидент. Признаки подозрительного:

- загрузчик — `curl`/`wget`, а не браузер (скриптовая загрузка);
- `DataURL` — голый IP-адрес, а не домен;
- файл в `/tmp`, `~/Library/Application Support`, скрытой папке;
- отсутствие подписи и нотаризации;
- время — вне рабочих часов;
- сразу после загрузки — запуск (по KnowledgeC/unified log).

Комбинация нескольких признаков превращает «скачал файл» в «выполнил полезную
нагрузку»."""

ADDS["linux-container-escape"] = """## Как отличить контейнер от хоста

Прежде чем говорить о побеге, нужно доказать, что процесс **был** в контейнере.
Признаки, которые проверяют по отдельности и вместе:

| Признак | Контейнер | Хост |
|---|---|---|
| PID 1 | приложение | `systemd`/`init` |
| `/proc/1/cgroup` | `docker`/`kubepods` | `system.slice` |
| `/` монтирование | `overlay`/`fuse` | `ext4`/`xfs` |
| число процессов | единицы | десятки |
| `/.dockerenv` | существует | нет |
| `/proc/self/mountinfo` | много bind-монтов | обычные ФС |

Простая проверка:

```
$ [ -f /.dockerenv ] && echo container
$ awk '$5=="overlay" || $5=="fuse-overlayfs"' /proc/self/mountinfo
```

Но помни: эти маркеры можно **подделать** (создать `/.dockerenv`, примонтировать
overlay), поэтому вывод делается по совокупности, а не по одному файлу.

## CVE-2019-5736: побег через runc

Этот вектор стоит разобрать детально, потому что он оставил много следов в реальных
инцидентах. Уязвимость позволяла перезаписать бинарник `runc` на **хосте** из
контейнера:

1. Контейнер открывает `/proc/self/exe` (это и есть `runc`).
2. Заменяет его на полезную нагрузку.
3. При следующем запуске контейнера хост исполняет подменённый `runc` от root.

Следы на хосте:

```
$ ls -la /usr/bin/runc
-rwxr-xr-x 1 root root 9876543 Jan 14 03:35 /usr/bin/runc   # свежая дата
$ sha256sum /usr/bin/runc   # не совпадает с пакетом
$ dpkg -V runc || rpm -V runc   # проверка целостности пакета
```

Проверка целостности пакетного менеджера (`dpkg -V`/`rpm -V`) — быстрый способ найти
подменённый бинарник. Также смотри `dmesg` и журналы containerd на предмет аномалий.

## Где лежат метаданные runtime

Чтобы восстановить события, нужно знать, где runtime хранит данные:

- **Docker**: `/var/lib/docker/` (образы, слои, контейнеры), `docker events`;
- **containerd**: `/var/lib/containerd/`, `ctr` и namespace;
- **Podman**: `/var/lib/containers/storage/`, rootless-конфиги в `~/.config/containers/`;
- **Kubernetes**: `/var/log/pods/`, `/var/lib/kubelet/`, audit-лог API.

Метаданные контейнера (даже удалённого) читаются из `config.v2.json`:

```
$ cat /var/lib/docker/containers/<id>/config.v2.json | jq '.Config.Image, .HostConfig.Privileged'
```

Даже если контейнер удалён, слои `overlay2` могут остаться — по ним восстанавливают,
что выполнялось.

## Таймлайн и корреляция

Побег — это последовательность событий, и её надо выстроить по времени:

1. **Создание контейнера** — `docker events` / audit-лог.
2. **Признаки ослабления** — `privileged`, `hostPID`, монтирование сокета.
3. **Действие побега** — запуск привилегированного контейнера, `nsenter`, CVE-триггер.
4. **Персистентность** — cron/systemd/ключи на хосте.
5. **Сокрытие** — чистка логов демона.

Сопоставляй три независимых источника: журнал демона, journald хоста и файловую
систему (слои, изменённые файлы). Расхождение между ними — признак подчистки.

## Инструменты

- `docker events`, `docker inspect`, `docker logs` — штатные;
- `ctr`, `crictl`, `kubectl` — для containerd/Kubernetes;
- `sysdig`/`falco` — поведенческие детекты (создание контейнера, mount хоста);
- `nsenter` — вход в namespace (в т.ч. для верификации побега);
- `journalctl -u docker -u containerd` — системные логи;
- `dive` — разбор слоёв образа.

Типовая проверка конфигурации контейнера на ослабления:

```
$ docker inspect <id> --format '{{json .HostConfig}}' | jq '{Privileged,PidMode,NetworkMode,Binds}'
```

## Дополнительные ограничения анализа

- Следы побега на хосте можно подчистить — проверяй целостность логов.
- `docker events` хранит историю ограниченно; для длинной ретроспективы нужен auditd.
- В rootless-контейнерах пути и владельцы другие — не путай с хостом.
- Не запускай подозрительный образ для «проверки» — используй `dive` и оффлайн-слои."""

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
