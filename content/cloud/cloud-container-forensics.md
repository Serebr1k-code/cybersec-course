---
id: cloud-container-forensics
title: "Облачная и контейнерная форензика: сбор следов после инцидента"
category: cloud
parent: cloud-logging-detection
difficulty: hard
order: 2
tags: [cloud, forensics, incident-response, containers, snapshots, logs]
prerequisites: [cloud-logging-detection, cloud-post-exploit]
useful_for:
  - "IR в облаке и контейнерах"
  - "Сбор и сохранение доказательств"
  - "Понимание, что оставляет следы в облаке"
estimated_minutes: 35
summary: "Как проводить форензику в облаке и контейнерах: порядок изоляции, сбор логов (CloudTrail/Flow Logs), снимки дисков и памяти, артефакты контейнеров. Практические команды и типичные ошибки."
---
## Зачем этот урок

Инцидент в контейнере или облаке требует форензики: собрать доказательства, восстановить таймлайн, не разрушив среду. Ключевая сложность — эфемерность: контейнер исчезает, а логи разбросаны по сервисам. Разберём порядок действий, инструменты и подводные камни.

## Порядок действий (порядок важен)

1. **Изоляция**: не убивайте контейнер/инстанс — вы потеряете память и FS.
2. **Снимок памяти/диска** (если возможно).
3. **Сбор логов** (CloudTrail, audit, app, container runtime).
4. **Метаданные**: какие образы, теги, секреты, env.
5. **Таймлайн**: сопоставление событий по времени.
6. **Анализ**: на оффлайн-копии, не на живой системе.

## Снимки дисков и анализ

```bash
# EBS-снимок инстанса
aws ec2 create-snapshot --volume-id vol-0abc --description "IR-2026-01"
# подключить снимок как том и проанализировать
aws ec2 create-volume --snapshot-id snap-0abc --availability-zone us-east-1a
```

Инструменты: `dd`/`dc3dd` (образ), `ewfacquire` (E01), `sleuthkit` (`fls`, `icat`, `mmls`), `autopsy`, `volatility3` (память), `plaso`/`log2timeline` (таймлайн).

```bash
dc3dd if=/dev/xvdf of=/evidence/disk.dd hash=sha256 log=/evidence/dd.log
mmls /evidence/disk.dd
fls -r -m / /evidence/disk.dd > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv
```

## Облачные логи

- **CloudTrail** — все API-вызовы (кто, что, когда, откуда).
- **GuardDuty** — детекты.
- **VPC Flow Logs** — сетевые потоки.
- **S3 access logs** — доступ к объектам.
- **K8s audit logs** — запросы к API-серверу.

```bash
aws cloudtrail lookup-events --start-time 2026-10-01T00:00:00Z \
  --lookup-attributes AttributeKey=Username,AttributeValue=svc-backup \
  --query 'Events[].CloudTrailEvent' --output text | jq -r '.eventName + " " + .sourceIPAddress'
```

## Форензика контейнеров

```bash
docker inspect <container>            # env, mounts, image
docker diff <container>               # изменённые файлы
docker commit <container> ir-image    # снимок FS (если жив)
docker export <container> -o fs.tar
crictl ps -a && crictl inspect <id>   # containerd/CRI-O
```

Kubernetes: `kubectl describe pod`, `kubectl logs --previous`, события (`kubectl get events --sort-by=.lastTimestamp`). Runtime-специфика: overlayfs-слои, `/var/lib/docker/overlay2`.

## Восстановление таймлайна

Объедините источники: CloudTrail (облачные API), audit-логи (K8s), app-логи, FS-метки (`mactime`). Стройте единый CSV и ищите корреляции: например, `AssumeRole` → запуск EC2 → аномальный сетевой поток.

```bash
log2timeline.py --storage-file timeline.plaso /evidence
psort.py -o l2tcsv -w timeline.csv timeline.plaso
```

## Разобранный пример: инцидент с кражей секрета

1. Alert: аномальный `GetSecretValue` из неизвестного IP.
2. CloudTrail: событие привязано к роли `LambdaExecRole`.
3. Смотрим, кто вызвал Lambda: `UpdateFunctionCode` незадолго до.
4. Находим изменённый код (diff) — SSRF/эксфильтрация.
5. Собираем список затронутых секретов, отзываем и ротируем.
6. Таймлайн: от `PutObject` (загрузка кода) до `GetSecretValue`.

## Частые ошибки

- Убить контейнер до снимка — потеря доказательств.
- Анализировать на живой системе (изменение меток времени).
- Игнорировать метаданные (теги образов, digest).
- Не собирать логи из всех источников (только app).
- Забывать про ротацию секретов после инцидента.
- Не фиксировать chain of custody (хэши образов).

## Что дальше / решение

После сбора — реконструируйте атаку, определите начальную точку (initial access), оцените blast radius и ротируйте всё, к чему мог получить доступ атакующий. Для защиты — централизованный сбор логов, immutable-хранилище, автоматические алерты.

## Анализ памяти

Память содержит процессы, соединения, ключи, не записанные на диск. Снимайте до перезагрузки.

```bash
# LiME (Linux)
insmod lime.ko "path=/evidence/mem.lime format=lime"
# volatility3
vol -f mem.lime windows.pslist
vol -f mem.lime linux.bash
vol -f mem.lime linux.psaux
vol -f mem.lime linux.sockstat
```

`volatility3` флаги: `-f` образ, `-r` ruleset, `-o` вывод. Плагины `linux.bash`, `linux.proc.Maps`, `linux.sockstat` показывают историю команд и сетевые соединения — ключевые для IR в контейнере.

## Kubernetes-специфика IR

- **Audit-логи API-сервера**: все `create`/`exec`/`get secret`.
- **Events**: `kubectl get events -A --sort-by=.lastTimestamp`.
- **Runtime**: `crictl ps -a`, `crictl logs <id>`, overlayfs-слои.
- **etcd**: снимок + расшифровка, если есть ключ шифрования.
- **Node**: `/var/log/pods`, `/var/lib/kubelet`, `/var/lib/containerd`.

```bash
kubectl get events -A --sort-by=.lastTimestamp | tail -50
crictl ps -a --no-trunc
crictl inspect <container-id> | jq '.status'
```

## Chain of custody

Фиксируйте: кто, когда, откуда извлёк артефакт, его хэш, где хранится. Для EBS-снимков — ID, регион, время. Для образов — digest (`sha256:...`). Для логов — неизменяемое хранилище (S3 Object Lock, WORM). Без этого доказательства могут быть оспорены.

## Таблица инструментов

| Задача | Инструмент | Ключевые флаги |
|--------|-----------|----------------|
| Образ диска | dc3dd, ewfacquire | `hash=`, `log=` |
| Файловая система | sleuthkit (fls, icat) | `-r`, `-m`, `-o` |
| Таймлайн | plaso/log2timeline | `--storage-file`, `-o l2tcsv` |
| Память | volatility3 | `-f`, `-r`, `-o` |
| Автопси | autopsy | GUI/CLI |
| Контейнеры | crictl, docker | `inspect`, `diff`, `export` |
| K8s | kubectl, kube-bench | `-A`, `--sort-by` |
| Облако | aws/gcloud/az CLI | `lookup-events`, `--query` |

## Реконструкция атаки: шаблон отчёта

1. **Initial access** — как вошли (утекший ключ, SSRF, CI).
2. **Execution** — где выполнялся код (pod, lambda, instance).
3. **Persistence** — новые пользователи, роли, cron, SA.
4. **Privilege escalation** — использованные мосты.
5. **Lateral movement** — AssumeRole, доступ к ресурсам.
6. **Exfiltration** — что и куда ушло.
7. **Impact** — blast radius, ротация, ущерб.

Каждый пункт подкрепляйте конкретными событиями с таймстампами из логов.

## Единое хранилище логов

Соберите все источники в immutable-хранилище: CloudTrail (S3 + Object Lock), VPC Flow Logs, K8s audit, app-логи (Fluent Bit → Loki/OpenSearch), runtime-логи. Это позволяет строить корреляции постфактум. Важно: логирование должно быть включено ДО инцидента — иначе доказательств просто нет.

```bash
aws cloudtrail create-trail --name ir-trail --s3-bucket-name ir-logs --is-multi-region-trail
aws cloudtrail start-logging --name ir-trail
aws logs create-log-group --log-group-name /aws/eks/cluster/audit
```

## Метрики и детекты для защитника

- Всплеск `AssumeRole` из одного IP.
- Первое обращение к новому региону.
- `CreateAccessKey` вне CI/CD-сервиса.
- `GetSecretValue` из нетипичного principal.
- Аномальный egress (data exfiltration).
GuardDuty, Security Hub и собственные правила на базе CloudTrail закрывают большую часть. Регулярно прогоняйте «what-if»: смогли бы вы заметить конкретную технику из этого курса?

## Быстрый чек-лист первого часа

1. Не тушить контейнер — снять память/FS.
2. Зафиксировать образ и digest.
3. Выгрузить CloudTrail за окно инцидента.
4. Собрать K8s audit + events.
5. Сохранить сетевые логи (VPC Flow).
6. Отозвать/ротировать затронутые секреты.
7. Составить таймлайн и blast radius.
8. Задокументировать chain of custody.

Эти восемь шагов закрывают 90% типового облачного инцидента и готовят материал для отчёта.

## Изоляция без разрушения

Ключевое правило: не тушить контейнер. Сначала снимается память (`gcore`, LiME), затем FS (`docker commit`/`export`). Для Kubernetes — `kubectl debug` с ephemeral-контейнером для сбора без остановки пода. Сохраняйте образ (digest) и логи. Только после сбора можно изолировать под/узел.

## Квиз

```quiz
- question: "Почему при облачном IR не следует сразу выключать инстанс?"
  options:
    - "Он дорогой"
    - "Теряются летучие данные: память, соединения, процессы"
    - "Он не перезапустится"
    - "Это запрещено"
  answer: 1
  explanation: "Выключение уничтожает летучие доказательства в памяти."
- question: "Как безопасно анализировать диск инстанса?"
  options:
    - "Монтировать исходный том на рабочий хост на запись"
    - "Сделать snapshot, создать из него новый том и смонтировать read-only"
    - "Удалить том"
    - "Скопировать только /etc"
  answer: 1
  explanation: "Snapshot + read-only монтирование сохраняет исходные данные."
- question: "Какой сервис AWS даёт аналитику аномалий по CloudTrail/VPC/DNS?"
  options:
    - "CloudFront"
    - "GuardDuty"
    - "S3"
    - "Route 53"
  answer: 1
  explanation: "GuardDuty агрегирует источники и выдаёт findings."
- question: "Где в контейнере искать изменения файловой системы относительно образа?"
  options:
    - "В DNS"
    - "В upperdir overlayfs (docker inspect GraphDriver.Data.UpperDir)"
    - "В Route 53"
    - "В security group"
  answer: 1
  explanation: "upperdir overlayfs содержит изменения поверх образа."
- question: "Почему VPC Flow Logs важны для расследования?"
  options:
    - "Они показывают пароли"
    - "Они фиксируют сетевые соединения (C2, эксфильтрацию)"
    - "Они удаляют данные"
    - "Они шифруют диск"
  answer: 1
  explanation: "Flow Logs дают картину сетевой активности."
```

## Где пригодится

- **IR/Blue team** — расследование облачных инцидентов.
- **Пентест** — понимание, что остаётся в логах.
- **Threat hunting** — поиск следов компрометации.
- **Сертификации** — облачные security/IR-сертификаты.
- **CTF** — категория Forensics в облачном контексте.
