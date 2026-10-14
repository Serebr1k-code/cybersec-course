#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch D: osint CI/CD + container-registry lessons."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson as _wl
def write_lesson(meta, body, lab=None):
    try: return _wl(meta, body, lab=lab)
    except SystemExit: print('skip:', meta.get('id')); return None
U = ["CTF OSINT", "Bug bounty", "Пентест: recon", "Red team"]

cicd = dict(
    id="osint-cicd-recon", title="CI/CD: разведка Jenkins, GitLab и GitHub Actions",
    category="osint", parent="osint-mod-saas-devops", difficulty="hard", order=3,
    tags=["osint","cicd","jenkins","gitlab","github-actions","devops"],
    prerequisites=["osint-jira-confluence"], useful_for=U, estimated_minutes=55,
    summary="Как находить открытые CI/CD-системы, читать их публичные метаданные и искать следы утечки секретов в конвейере.",
    lab=dict(title="Практика: инстанс Jenkins", toolset=["core","curl","jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["Jenkins отдаёт API: `curl -s https://jenkins.example.com/api/json`.",
               "Список задач: `curl -s 'https://jenkins.example.com/api/json?tree=jobs[name]'`.",
               "Заголовок `X-Jenkins` содержит версию: `curl -sI https://jenkins.example.com`.",
               "Маркер `nto{...}` — в ответе; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{j3nk1ns_4p1_3xp0s3d}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: Jenkins recon\n\n1. `curl -s https://jenkins.example.com/api/json`\n2. Найди список `jobs` и `mode`.\n3. `curl -sI https://jenkins.example.com` — заголовок `X-Jenkins`.\n4. Маркер `nto{...}` — запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов Jenkins","cases":[
            {"match":"api/json","example":"curl -s https://jenkins.example.com/api/json",
             "output":"{\"_class\":\"hudson.model.Hudson\",\"mode\":\"NORMAL\",\"nodeDescription\":\"the master Jenkins node\",\"numExecutors\":2,\"jobs\":[{\"name\":\"deploy-prod\",\"url\":\"https://jenkins.example.com/job/deploy-prod/\"},{\"name\":\"build-api\",\"url\":\"https://jenkins.example.com/job/build-api/\"}],\"x_flag\":\"nto{j3nk1ns_4p1_3xp0s3d}\"}\n"},
            {"match":"tree=jobs","example":"curl -s 'https://jenkins.example.com/api/json?tree=jobs[name]'",
             "output":"{\"jobs\":[{\"name\":\"deploy-prod\"},{\"name\":\"build-api\"}]}\n"}],
            "fallback":"curl: в этой лабе доступен только jenkins.example.com.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"jobs|\\.","example":"jq -r '.jobs[].name' api.json","output":"deploy-prod\nbuild-api\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
cicd_body = r"""## Вопрос, с которого всё начинается

Компания пишет код — значит, у неё есть конвейер сборки: CI/CD. Это Jenkins, GitLab CI, GitHub Actions. И именно здесь, в отличие от обычных сервисов, концентрируются **ключи**: токены деплоя, доступы к реестрам, переменные окружения с паролями. Если конвейер открыт наружу, разведка получает прямой путь к инфраструктуре.

Задача: найти открытые CI/CD-системы организации и прочитать их публичные метаданные — не запуская сборок.

## Наш пример: инстанс Jenkins

Держим объект `https://jenkins.example.com`. Jenkins — самый классический self-hosted CI. Первый вопрос: **открыт ли он и что внутри?**

У Jenkins есть богатый JSON API, доступный часто без входа:

```bash
curl -s https://jenkins.example.com/api/json | jq .
```

```json
{"_class":"hudson.model.Hudson","mode":"NORMAL","numExecutors":2,
 "jobs":[{"name":"deploy-prod","url":".../job/deploy-prod/"},
         {"name":"build-api","url":".../job/build-api/"}]}
```

Читаем: `mode: NORMAL` — это обычный инстанс, `jobs` — список задач. Названия `deploy-prod`, `build-api` уже рассказывают о процессе: есть деплой в прод и сборка API. Это карта конвейера, полученная без единого логина.

## Шаг 1: версия Jenkins по заголовку

Jenkins отдаёт свою версию в HTTP-заголовке `X-Jenkins`:

```bash
curl -sI https://jenkins.example.com | grep -i x-jenkins
```

```text
X-Jenkins: 2.387.1
```

Версия — ключ к проверке на известные уязвимости. Как всегда, это гипотеза, а не доказательство: сверить с базами нужно, но эксплуатировать — отдельная фаза.

## Шаг 2: разведка GitLab

GitLab устроен иначе. Публичный инстанс отдаёт версию через API:

```bash
curl -s https://gitlab.example.com/api/v4/version
```

```json
{"version":"16.2.1","revision":"abc123","kas":{"enabled":true}}
```

Публичные проекты видны через `/api/v4/projects` и `/explore`. Если проект публичный, в нём могут быть README, CI-конфиги `.gitlab-ci.yml` и даже утёкшие переменные. Страница входа `/users/sign_in` показывает, включена ли регистрация и какой SSO используется.

## Шаг 3: GitHub Actions и утечки

GitHub — отдельный слой. Публичные репозитории организации видны через API:

```bash
curl -s https://api.github.com/orgs/example/repos?per_page=100 | jq -r '.[].name'
```

```text
example/infra
example/api
example/docs
```

В репозиториях лежат `.github/workflows/*.yml` — описания конвейеров. Частая ошибка разработчиков — закоммитить секреты прямо в workflow или в `.env`. Для поиска таких утечек используют сканеры секретов (trufflehog, gitleaks):

```bash
# иллюстративно
trufflehog github --org=example
```

Найденный токен — это красная строка отчёта, а не инструмент атаки.

## Шаг 4: раннеры и границы

У CI есть исполнители — раннеры. Их регистрационные токены иногда утекают в открытые репозитории или в логи. Токен раннера позволяет зарегистрировать собственного агента в чужом конвейере — это уже серьёзная утечка.

Границы разведки: **мы читаем публичные API и конфиги, но не запускаем сборки, не используем найденные токены и не входим в систему**. Уязвимость и утечка фиксируются с доказательством, а эксплуатация — отдельная авторизуемая фаза.

## Полный прогон

```bash
# 1. Jenkins открыт?
curl -s -o /dev/null -w '%{http_code}\n' https://jenkins.example.com/api/json     # → 200
# 2. задачи
curl -s https://jenkins.example.com/api/json | jq -r '.jobs[].name'               # → deploy-prod, build-api
# 3. версия
curl -sI https://jenkins.example.com | grep -i x-jenkins                          # → 2.387.1
# 4. GitLab
curl -s https://gitlab.example.com/api/v4/version | jq -r .version                # → 16.2.1
```

Непрерывно: поддомен → API → список задач → версия → GitLab → профиль конвейера компании.

## Если не сработало

**API закрыт.** Jenkins может требовать вход — тогда опирайся на заголовок версии и страницу входа.
**Не Jenkins.** Проверь GitLab, Gitea, Drone, TeamCity, ArgoCD — у каждого свой API.
**GitHub вместо GitLab.** Работай через `api.github.com` и поиск по коду.

## Частые ошибки

**Ошибка: запускать сборку.** Даже «безобидный» билд может выполнить код и нашуметь.
**Ошибка: использовать найденный токен.** Это уже эксплуатация, а не разведка.
**Ошибка: игнорировать заголовки.** `X-Jenkins`, `Server`, `X-Gitlab` мгновенно дают версию.
**Ошибка: не смотреть конфиги.** `.gitlab-ci.yml`, `.github/workflows` — источник секретов.

## Справочная таблица: эндпоинты CI/CD

| Система | Эндпоинт | Что даёт |
|---------|----------|----------|
| Jenkins | `/api/json` | задачи, режим, узлы |
| Jenkins | заголовок `X-Jenkins` | версия |
| GitLab | `/api/v4/version` | версия |
| GitLab | `/api/v4/projects` | публичные проекты |
| GitHub | `/orgs/<org>/repos` | репозитории организации |
| ArgoCD | `/api/v1/applications` | приложения (если открыт) |

## Разбор кейса: от поддомена до утечки

Дано: домен `example.com`. Шаг первый — находим `jenkins.example.com`, `/api/json` отвечает `200`. Шаг второй — список задач показывает `deploy-prod`; значит, у компании есть автоматический деплой. Шаг третий — заголовок `X-Jenkins: 2.387.1` даёт версию. Шаг четвёртый — ищем организацию на GitHub, находим репозиторий `example/infra` и в его workflow закоммиченный токен. Вывод: открытый CI и утёкший секрет. Разведчик зафиксировал обе находки с доказательствами — и остановился, не используя токен.

## Рабочий воркбук: полное расследование CI/CD

**Этап 1. Инвентаризация.** Собери все поддомены с ключевыми словами `jenkins`, `ci`, `cd`, `build`, `gitlab`, `drone`, `argo`, `teamcity`. Проверь каждый на код ответа. Это список кандидатов.

**Этап 2. Идентификация.** По заголовкам и типовым путям определи, что за система. Jenkins выдаёт `X-Jenkins`, GitLab — `X-Gitlab` и `/api/v4/version`, ArgoCD — `/api/v1/version`.

**Этап 3. Метаданные.** Сними публичные данные: список задач, проектов, приложений. Названия раскрывают процесс и структуру команд.

**Этап 4. Утечки.** Проверь связанные репозитории на GitHub/GitLab: workflows, `.env`, историю коммитов. Сканеры секретов помогают, но и ручной просмотр конфигов даёт много.

**Этап 5. Фиксация.** Сведи всё в отчёт: какие системы открыты, какие версии, какие данные видны, где утечки. Не эксплуатируй: цель разведки — карта и доказательства.

## Частые вопросы

**Почему CI/CD опаснее обычного сайта?** Потому что конвейер держит ключи от всей инфраструктуры: деплой, реестры, базы. Утечка здесь стоит дороже всего.

**Что такое раннер?** Исполнитель задач CI. Его токен позволяет подключить чужого агента к конвейеру — серьёзная утечка.

**Можно ли читать публичные репозитории?** Да, они публичны по определению. Но использовать найденные в них секреты нельзя.

**Как быстро найти инстанс Jenkins?** По favicon-хэшу и заголовку `X-Jenkins` в Shodan/Censys.

**Это законно?** Чтение публичных API и репозиториев — да. Запуск сборок и использование токенов — нет.

## Термины

**CI/CD** — непрерывная интеграция и доставка: автоматическая сборка, тесты и деплой.

**Раннер** — исполнитель задач конвейера.

**Workflow** — описание конвейера в файле (например, `.github/workflows/ci.yml`).

**Секрет** — токен, пароль или ключ, используемый конвейером.

**ArgoCD / Drone / TeamCity** — альтернативные CI/CD-системы со своими API.

## Что мы теперь знаем

1. CI/CD-системы открыты наружу и отдают публичные API.
2. Jenkins выдаёт задачи и версию без входа.
3. GitLab раскрывает версию и публичные проекты.
4. GitHub-репозитории — источник утёкших секретов.
5. Разведка фиксирует утечки, не используя их.

## Квиз

Проверь себя.

```quiz
- question: "Какой заголовок Jenkins отдаёт свою версию?"
  options:
    - "X-Jenkins"
    - "X-Powered-By"
    - "Server-Version"
    - "X-CI"
  answer: 0
  explanation: "Заголовок X-Jenkins содержит версию инстанса."
- question: "Почему CI/CD ценен для разведки?"
  options:
    - "Там нет данных"
    - "Конвейер держит токены и доступы к инфраструктуре"
    - "Он всегда закрыт"
    - "У него нет API"
  answer: 1
  explanation: "Секреты конвейера дают путь к инфраструктуре."
- question: "Что такое раннер?"
  options:
    - "Разработчик"
    - "Исполнитель задач CI/CD"
    - "Брандмауэр"
    - "Формат файла"
  answer: 1
  explanation: "Раннер выполняет сборки; его токен — чувствительный секрет."
- question: "Как корректно поступить с найденным токеном?"
  options:
    - "Использовать его"
    - "Зафиксировать утечку с доказательством, не используя"
    - "Опубликовать"
    - "Продать"
  answer: 1
  explanation: "Разведка фиксирует; эксплуатация — отдельная фаза."
```

## Куда дальше

Дальше в модуле — **реестры контейнеров**: научимся находить образы организации и искать секреты в их слоях. А пока запомни: CI/CD — самый концентрированный источник ключей, и разведка здесь особенно ценна.

## Где пригодится

- **Пентест:** поиск открытых CI и утечек токенов.
- **Bug bounty:** репозитории и конвейеры в scope.
- **CTF (OSINT):** метаданные Jenkins/GitLab.
- **Blue team:** аудит секретов и публичной экспозиции CI.
"""
write_lesson(cicd, cicd_body, lab=cicd["lab"])

registry = dict(
    id="osint-container-registry", title="Реестры контейнеров: образы, теги и секреты в слоях",
    category="osint", parent="osint-mod-saas-devops", difficulty="hard", order=4,
    tags=["osint","docker","registry","ghcr","containers"], prerequisites=["osint-cicd-recon"],
    useful_for=U, estimated_minutes=55,
    summary="Как найти реестр контейнеров организации, перечислить образы и теги и искать утёкшие секреты в слоях образов.",
    lab=dict(title="Практика: реестр контейнеров", toolset=["core","curl","jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["Registry v2 API: `curl -s https://registry.example.com/v2/_catalog`.",
               "Теги образа: `curl -s https://registry.example.com/v2/app/tags/list`.",
               "Docker Hub: `curl -s https://hub.docker.com/v2/repositories/example/`.",
               "Маркер `nto{...}` — в ответе; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{c0nt41n3r_r3g1stry_c4t4l0g}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: реестр контейнеров\n\n1. `curl -s https://registry.example.com/v2/_catalog`\n2. `curl -s https://registry.example.com/v2/app/tags/list`\n3. `curl -s https://hub.docker.com/v2/repositories/example/`\n4. Маркер `nto{...}` — запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов реестра","cases":[
            {"match":"_catalog","example":"curl -s https://registry.example.com/v2/_catalog",
             "output":"{\"repositories\":[\"example/app\",\"example/worker\",\"example/nginx\"],\"x_flag\":\"nto{c0nt41n3r_r3g1stry_c4t4l0g}\"}\n"},
            {"match":"tags/list","example":"curl -s https://registry.example.com/v2/app/tags/list",
             "output":"{\"name\":\"example/app\",\"tags\":[\"latest\",\"1.4.2\",\"1.4.1\",\"dev\"]}\n"},
            {"match":"hub\\.docker\\.com","example":"curl -s https://hub.docker.com/v2/repositories/example/",
             "output":"{\"count\":2,\"results\":[{\"name\":\"app\",\"namespace\":\"example\",\"pull_count\":12034},{\"name\":\"worker\",\"namespace\":\"example\",\"pull_count\":881}]}\n"}],
            "fallback":"curl: в этой лабе доступны registry.example.com и hub.docker.com.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"repositories|tags|\\.","example":"jq -r '.repositories[]' cat.json","output":"example/app\nexample/worker\nexample/nginx\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
registry_body = r"""## Вопрос, с которого всё начинается

Компания собирает и раздаёт контейнеры: у неё есть образы приложений, воркеров, базовых слоёв. Где они лежат? В реестрах — Docker Hub, GitHub Container Registry (GHCR), Quay или собственном Harbor. И у этих реестров есть публичные API.

Задача: найти реестр организации, перечислить образы и теги, а затем понять, не утекли ли в слои образов секреты — не скачивая ничего лишнего.

## Наш пример: реестр организации

Держим объект `https://registry.example.com`. Первый вопрос: **открыт ли каталог образов?** У реестров стандартный API v2:

```bash
curl -s https://registry.example.com/v2/_catalog | jq .
```

```json
{"repositories":["example/app","example/worker","example/nginx"]}
```

`_catalog` перечисляет репозитории. Мы сразу видим три образа: приложение, воркер и nginx. Это карта микросервисов организации.

## Шаг 1: теги и версии

Для каждого образа смотрим теги:

```bash
curl -s https://registry.example.com/v2/app/tags/list | jq -r '.tags[]'
```

```text
latest
1.4.2
1.4.1
dev
```

Теги рассказывают о релизном цикле: `1.4.2` — актуальная версия, `dev` — разработка, `latest` — плавающий указатель. По тегам видно, как часто выходят релизы и насколько свежи образы.

## Шаг 2: Docker Hub и GHCR

Многие образы лежат не в self-hosted реестре, а в публичных. Docker Hub отдаёт список репозиториев организации:

```bash
curl -s https://hub.docker.com/v2/repositories/example/ | jq -r '.results[].name'
```

```text
app
worker
```

GHCR (`ghcr.io`) связан с GitHub: образы видны через API GitHub Packages, если пакеты публичные. Quay отдаёт свой каталог. Все три — легитимные публичные источники.

## Шаг 3: слои и секреты

Контейнерный образ — это набор слоёв. Слои можно выкачать и посмотреть, что в них. Главный риск — **секреты, зашитые в слой**: `.env` с паролями, приватные ключи, токены. Иногда их «удаляют» следующим слоем, но исходный слой остаётся в образе.

```bash
# иллюстративно: посмотреть историю слоёв
docker history example/app:1.4.2
# скачать образ и найти секреты
# skopeo copy docker://registry.example.com/example/app:1.4.2 dir:./img
# grep -rE 'password|token|secret' ./img
```

Даже метаданные образа — config JSON — содержат переменные окружения и команды сборки, которые часто раскрывают внутренние пути и хосты.

## Шаг 4: границы

Мы перечисляем публичные каталоги и метаданные. Скачивание **приватных** образов, использование найденных секретов, пуш собственных образов — вне рамок разведки. Найденный в слое токен фиксируется как доказательство и передаётся в отчёт, но не используется.

## Полный прогон

```bash
# 1. каталог
curl -s https://registry.example.com/v2/_catalog | jq -r '.repositories[]'
# → example/app, example/worker, example/nginx
# 2. теги
curl -s https://registry.example.com/v2/app/tags/list | jq -r '.tags[]'
# → latest, 1.4.2, 1.4.1, dev
# 3. Docker Hub
curl -s https://hub.docker.com/v2/repositories/example/ | jq -r '.results[].name'
# → app, worker
```

Непрерывно: реестр → каталог → теги → Docker Hub → карта контейнеров организации.

## Если не сработало

**`_catalog` закрыт.** Приватные реестры требуют токен — тогда работай через публичные (Docker Hub, GHCR).
**Образов нет.** Возможно, используются базовые публичные образы без собственных.
**Реестр нестандартный.** Проверь Harbor, Quay, GitLab Registry — у каждого свой префикс.

## Частые ошибки

**Ошибка: качать все образы.** Это трафик и риск; качай точечно и только публичное.
**Ошибка: использовать найденный секрет.** Это эксплуатация, а не разведка.
**Ошибка: игнорировать config JSON.** Метаданные образа содержат env и команды сборки.
**Ошибка: забыть про слои.** Секрет, «удалённый» верхним слоем, остаётся в нижнем.

## Справочная таблица: эндпоинты реестров

| Реестр | Эндпоинт | Что даёт |
|--------|----------|----------|
| Registry v2 | `/v2/_catalog` | список репозиториев |
| Registry v2 | `/v2/<name>/tags/list` | теги образа |
| Docker Hub | `/v2/repositories/<org>/` | репозитории организации |
| GHCR | GitHub Packages API | пакеты организации |
| Quay | `/api/v1/repository` | репозитории |

## Разбор кейса: от реестра до секрета

Дано: домен `example.com`. Шаг первый — находим `registry.example.com`, `_catalog` открыт. Шаг второй — каталог показывает образы `app`, `worker`, `nginx`. Шаг третий — теги `1.4.2`, `dev` дают релизный цикл. Шаг четвёртый — config JSON образа `worker` содержит переменную `DB_PASSWORD`, утёкшую в слой. Вывод: открытый реестр и утёкший секрет. Разведчик фиксирует обе находки с доказательствами и передаёт в отчёт, не используя пароль.

## Рабочий воркбук: полное расследование реестра

**Этап 1. Инвентаризация.** Собери поддомены и хосты: `registry`, `docker`, `harbor`, `ghcr`, `quay`. Проверь каждый на `/v2/`.

**Этап 2. Каталог.** Если `_catalog` открыт — получи список репозиториев. Если нет — иди в публичные реестры организации.

**Этап 3. Теги и метаданные.** Для каждого образа сними теги и config JSON. Это даёт версии, переменные окружения и команды сборки.

**Этап 4. Поиск секретов.** Скачай публичные образы точечно и прогони по ним поиск ключей. Проверь историю слоёв: удалённое сверху может остаться снизу.

**Этап 5. Фиксация.** Сведи реестры, образы, теги и найденные утечки в отчёт с доказательствами. Не используй секреты.

## Частые вопросы

**Почему секреты попадают в образы?** Из-за ошибок сборки: разработчик копирует `.env` в образ или задаёт пароль в `ENV`. Иногда секрет «удаляют» позже, но слой остаётся.

**Что такое слой?** Часть образа, добавляемая инструкцией Dockerfile. Слои складываются в файловую систему контейнера.

**Можно ли читать публичные образы?** Да, они публичны. Использовать найденные секреты — нет.

**Что даёт config JSON?** Переменные окружения, команды запуска и сборки, историю — часто с внутренними хостами.

**Это законно?** Перечисление публичных каталогов — да. Доступ к приватным реестрам — нет.

## Термины

**Реестр** — хранилище контейнерных образов (Docker Hub, GHCR, Harbor).

**Образ** — упакованное приложение со слоями и метаданными.

**Тег** — метка версии образа (`latest`, `1.4.2`).

**Слой** — часть образа; в слоях могут оставаться секреты.

**Config JSON** — метаданные образа с env и командами.

## Что мы теперь знаем

1. Реестры отдают публичные каталоги через API v2.
2. Теги раскрывают релизный цикл образа.
3. Docker Hub и GHCR дают список репозиториев организации.
4. Секреты утекают в слои и config JSON.
5. Разведка фиксирует утечки, не используя их.

## Квиз

Проверь себя.

```quiz
- question: "Какой эндпоинт перечисляет репозитории реестра v2?"
  options:
    - "/v2/_catalog"
    - "/api/json"
    - "/repositories"
    - "/tags"
  answer: 0
  explanation: "_catalog перечисляет репозитории реестра."
- question: "Где в образе чаще всего находят секреты?"
  options:
    - "В имени образа"
    - "В слоях и config JSON (env, команды)"
    - "В теге latest"
    - "В README реестра"
  answer: 1
  explanation: "Слои и метаданные хранят env и команды сборки."
- question: "Почему удалённый секрет может остаться в образе?"
  options:
    - "Слои неизменяемы: удаление сверху не убирает нижний слой"
    - "Секрет копируется в имя"
    - "Реестр хранит бэкапы"
    - "Так работает HTTPS"
  answer: 0
  explanation: "Нижний слой с секретом остаётся в образе."
- question: "Что допустимо в разведке реестра?"
  options:
    - "Пушить свои образы"
    - "Перечислять публичные каталоги и метаданные"
    - "Качать приватные образы"
    - "Использовать найденный токен"
  answer: 1
  explanation: "Разведка читает публичное; остальное — вне рамок."
```

## Куда дальше

Дальше модуль перейдёт к **облачной поверхности**: открытые Kubernetes, API-спеки и IaC. А пока запомни: реестр контейнеров — это каталог микросервисов организации, а его слои — частый источник утечек.

## Где пригодится

- **Пентест:** карта контейнеров и поиск утечек секретов.
- **Bug bounty:** публичные реестры в scope.
- **CTF (OSINT):** перечисление образов и тегов.
- **Blue team:** аудит секретов в образах и их публикации.
"""
write_lesson(registry, registry_body, lab=registry["lab"])
print("Batch D done: cicd, registry")
