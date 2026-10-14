---
id: web-devops-surfaces
title: "DevOps-панели как поверхность атаки: Grafana, Kibana, GitLab, Jenkins"
category: web
parent: web-enterprise-apps
difficulty: hard
order: 2
tags: [devops, grafana, kibana, gitlab, jenkins, monitoring, cicd, cve]
prerequisites: [web-enterprise-apps]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 75
summary: "DevOps-панели (мониторинг, логи, CI/CD, SCM) как цель: почему они дают креды и RCE, их общие черты и методика атаки по версиям."
---

## Вопрос, с которого всё начинается

В любой зрелой IT-компании есть панели, через которые инженеры смотрят метрики, читают логи, собирают код и запускают сборки. Это Grafana, Kibana, GitLab, Jenkins и их родственники. Для атакующего это **золотая жила**: такие панели по определению содержат доступы к инфраструктуре, а их собственная безопасность часто запущена. Панель мониторинга, открытая наружу, — это не «графики», а прямой путь к кредам. Разберём, почему так и как их атаковать.

## Что общего у DevOps-панелей

Первое: **они агрегируют доступы**. Grafana подключается к базам и Prometheus, Kibana — к Elasticsearch, GitLab — к репозиториям и runner'ам, Jenkins — к серверам сборки и облакам. То есть в конфиге каждой панели лежат **токены и пароли** ко множеству систем. Утечка конфига панели = доступ к инфраструктуре.

Второе: **они дают исполнение**. Jenkins умеет запускать произвольные скрипты (по дизайну), GitLab — пайплайны, Kibana/Grafana — плагины. Значит, вход в панель часто равен RCE.

Третье: **у них длинная история критических CVE**: Grafana LFI (CVE-2021-43798), Kibana прототип-поллюция → RCE (CVE-2019-7609), GitLab traversal (CVE-2023-2825), Jenkins file-read (CVE-2024-23897).

## Наш пример: находим Grafana

Цель — `https://grafana.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://grafana.target.example
https://grafana.target.example [200 OK] Grafana, Grafana[10.0.0], Title[Grafana]
```

Заголовок `X-Grafana-Version` или эндпоинт `/api/health` отдают точную версию:

```
$ curl -s https://grafana.target.example/api/health
{"commit":"...","database":"ok","version":"10.0.0"}
```

Версия **10.0.0** — сопоставляем с CVE (CVE-2021-43798 затрагивает 8.x; для 10.0.0 ищем другие). Точность версии решает.

## Шаг 1: почему панель мониторинга — это креды

Grafana хранит **datasource** — подключения к базам и Prometheus, часто с логинами и паролями. Если есть LFI или доступ к API datasource, эти креды добываются. Аналогично Kibana хранит подключения к Elasticsearch, GitLab — токены runner'ов, Jenkins — SSH-ключи и облачные креды.

Практический вывод: даже без RCE панель ценна. Прочитав её конфиг/API, ты получаешь **набор доступов** в другие системы — это и есть настоящая цель.

## Шаг 2: Grafana — LFI и path traversal

**CVE-2021-43798** — path traversal в Grafana, позволяющий читать локальные файлы без аутентификации:

```
$ curl --path-as-is 'https://grafana.target.example/public/plugins/alertlist/../../../../../../../../etc/passwd'
```

Через этот баг читают `grafana.ini` (креды БД, admin-пароль, SMTP), а также файлы окружения. Если Grafana развёрнута в Kubernetes, читают service-account токены → доступ к кластеру.

## Шаг 3: Kibana — прототип-поллюция и RCE

**CVE-2019-7609** — Kibana (Timelion) позволяла через **prototype pollution** добраться до RCE: подсунув специальный JS-объект, атакующий менял прототип и добивался выполнения кода на сервере. Kibana также связана с Elasticsearch, и если Elasticsearch открыт (без пароля), данные читаются напрямую.

## Шаг 4: GitLab — traversal и ExifTool RCE

GitLab (Ruby) известен: **CVE-2023-2825** — path traversal, читающий файлы; **CVE-2021-22205** — RCE через ExifTool (загрузка изображения с вредоносными метаданными). Плюс GitLab хранит **токены runner'ов**, которые дают возможность запускать пайплайны (то есть код) на инфраструктуре.

## Шаг 5: Jenkins — script console и file-read

Jenkins по дизайну позволяет выполнять Groovy-скрипты через **Script Console** (`/script`). Доступ к нему = RCE. **CVE-2024-23897** — чтение файлов через CLI (аргумент `@file`), позволяющее прочитать `secrets/initialAdminPassword` и войти админом. Плюс Jenkins хранит SSH-ключи и креды ко множеству систем.

## Шаг 6: методика атаки на DevOps-панель

1. **Обнаружение** — сканирование портов 3000 (Grafana), 5601 (Kibana), 8080 (Jenkins), 80/443 (GitLab).
2. **Версия** — `/api/health`, заголовки, статика.
3. **CVE** — сопоставление (NVD, вендорские advisories).
4. **PoC** — поиск, чтение, санитизация.
5. **Проверка** — неразрушающая (чтение файла, арифметика).
6. **Эксплуатация** — при подтверждении.
7. **Пост-эксплуатация** — дамп конфигов/токенов, движение по инфраструктуре.

## Шаг 7: как не навредить

DevOps-панели — рабочий инструмент инженеров; их падение останавливает разработку и деплой. Jenkins/GitLab могут содержать активные пайплайны. Поэтому: без массовых запросов, без изменения конфигураций, без запуска реальных сборок. Панели под мониторингом, шум = раскрытие.

## Что мы теперь знаем

- DevOps-панели агрегируют доступы (токены, пароли, ключи) и дают исполнение.
- Grafana: LFI/path traversal (CVE-2021-43798) → чтение конфигов.
- Kibana: prototype pollution → RCE; связь с Elasticsearch.
- GitLab: traversal и ExifTool RCE; токены runner'ов.
- Jenkins: Script Console и file-read (CVE-2024-23897).

## Шаг 8: как отличить DevOps-панели друг от друга

Точное определение продукта — половина успеха, потому что CVE у них разные. Признаки:

- **Grafana**: заголовок `X-Grafana-Version`, `/api/health`, порт 3000, оранжевый логотип.
- **Kibana**: `/api/status`, порт 5601, связь с Elasticsearch на 9200.
- **GitLab**: `/api/v4/version`, `/users/sign_in`, характерный фиолетовый интерфейс.
- **Jenkins**: заголовок `X-Jenkins`, `/script`, `/manage`, порт 8080.

Проверяй эти пути через `httpx` пакетно: так ты за один проход классифицируешь все панели в сети и сразу привяжешь к ним версии.

## Шаг 9: как строить отчёт по DevOps-панели

Отчёт должен содержать: продукт и точную версию (с источником — заголовок/API); применимые CVE с диапазонами; подтверждённую уязвимость (запрос + ответ); извлечённые креды/токены и **какие системы они открывают**; оценку импакта (продовые БД, пайплайны, облако). Ключевое отличие DevOps-отчёта — акцент на **доступах**, а не на самом факте RCE: панель ценна тем, что за ней стоят другие системы.

## Шаг 10: как расставить приоритеты

Приоритет выше, если панель: (1) доступна из интернета; (2) имеет уязвимость pre-auth; (3) хранит креды к продовым системам. Ниже — если панель внутренняя, пропатчена и не содержит секретов. Не трать время на бесперспективную панель, когда рядом открыт Jenkins с Script Console.

## Практика: как отличить Grafana от Kibana и Jenkins

DevOps-панели легко перепутать, а от продукта зависит вектор. Быстрая проверка по уникальным признакам:

```
$ for p in /login /app/kibana /api/health /login?next=%2F ; do
    echo "== $p"; curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "https://dev.target.example$p"
  done
== /login
200 https://dev.target.example/login
== /app/kibana
404 
== /api/health
200 
```

Grafana отдаёт `/login` и `/api/health` с JSON `{"database":"ok"}`. Kibana отвечает на `/app/kibana` и `/api/status`. Jenkins живёт на `/login` с заголовком `X-Jenkins` и `X-Jenkins-Session`. Различать их нужно до атаки: у Grafana — path traversal, у Kibana — прототип-поллюция, у Jenkins — script console.

## Практика: Grafana LFI — читаем, но не пишем

CVE-2021-43798 — path traversal в плагинах Grafana. Работает так: `/public/plugins/<plugin>/../../../../etc/passwd`. Плагин по умолчанию — `alertlist`.

```
$ curl -s --path-as-is \
  "https://dev.target.example/public/plugins/alertlist/../../../../../../etc/passwd" | head -3
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

`--path-as-is` обязателен: без него curl сам нормализует `..` и запрос не сработает. Дальше читаем `grafana.ini` (`/etc/grafana/grafana.ini`) — там `admin_user`, `admin_password`, а иногда `secret_key`. Это уже доступ к панели, а через datasources — к Prometheus/InfluxDB/Elasticsearch.

## Практика: Kibana — от прототип-поллюции к RCE

CVE-2019-7609 — прототип-поллюция в Kibana Timelion, приводящая к RCE через Node.js. Проверка: отправить в Timelion-выражение payload, который загрязняет `Object.prototype` и вызывает `child_process`. Опасность в том, что Kibana часто стоит с `xpack.security.enabled: false` — без аутентификации вообще. Поэтому первый запрос — просто `curl -s https://kibana.target.example/api/status | grep -i 'security'`.

## Практика: Jenkins script console

Script Console (`/script`) — это Groovy-интерпретатор на сервере. Если доступен — RCE в одну строку:

```
def p = ['bash','-c','id'].execute(); p.waitFor(); println p.text
```

Но чаще он за аутентификацией. Тогда идём через CVE-2024-23897 — чтение файлов через CLI-парсер Jenkins. Парсим `@`-синтаксис аргументов, чтобы вытащить `/var/jenkins_home/secrets/initialAdminPassword` или `/etc/passwd`. Это уже даёт путь к админу, а значит и к console.

## Таблица: DevOps-панели и их точки входа

| Панель | Порт по умолч. | Признак | Классический вектор |
|---|---|---|---|
| Grafana | 3000 | `/api/health`, `grafana_session` | CVE-2021-43798 LFI |
| Kibana | 5601 | `/app/kibana`, `kbn-xsrf` | CVE-2019-7609 proto→RCE |
| Jenkins | 8080 | `X-Jenkins`, `/script` | script console, CVE-2024-23897 |
| GitLab | 80/443 | `/users/sign_in`, `_gitlab_session` | CVE-2021-22205 ExifTool RCE |
| Prometheus | 9090 | `/graph`, `/api/v1/query` | открытые метрики |
| ArgoCD | 443 | `/api/version`, `argocd` | CVE-2022-... auth bypass |

## Как использовать панель для движения дальше

Панель — это узел с высокой связностью. Grafana видит все datasources; Jenkins видит все креды и агентов сборки; GitLab видит код и runner-токены; Kibana видит логи с токенами. Поэтому после входа в панель первым делом ищи **креды других систем**: в Grafana — раздел Datasources (`/api/datasources`), в Jenkins — `/credentials/`, в GitLab — CI/CD-переменные проекта. Часто именно так находят пароль к базе, к облаку или к SSH-хосту, и панель становится мостом вглубь сети.

## Практика: Prometheus и открытые метрики как разведка

Prometheus на `:9090` без аутентификации — это не только графики. Через `/api/v1/targets` виден **полный список целей** мониторинга: имена хостов, порты, пути. Через `/api/v1/query?query=...` можно вытащить метрики с метками, где иногда встречаются версии, имена сервисов и даже пароли (в метках `label`). Начни с `curl -s http://prometheus.target.example:9090/api/v1/targets | head -c 500` — это мгновенно даёт карту инфраструктуры. Затем `/api/v1/label/__name__/values` перечисляет все метрики. Экспортёр Node (`:9100`) через `/metrics` отдаёт список процессов и смонтированных ФС, а `/debug/pprof/` на Go-сервисах может дать heap-дамп. Так DevOps-панель становится картой сети, по которой строится вся дальнейшая атака.

## Квиз

Проверь себя.

```quiz
- question: "Почему DevOps-панель ценна для атакующего?"
  options:
    - "Она красивая"
    - "Она агрегирует доступы (токены/пароли) и даёт исполнение"
    - "Она быстрая"
    - "Она без пароля"
  answer: 1
  explanation: "В конфиге панели — креды ко множеству систем."
- question: "Что делает CVE-2021-43798 в Grafana?"
  options:
    - "Шифрует данные"
    - "Path traversal (LFI) для чтения локальных файлов"
    - "Даёт XSS"
    - "Меняет тему"
  answer: 1
  explanation: "Через traversal читают grafana.ini."
- question: "Через что Kibana получала RCE (CVE-2019-7609)?"
  options:
    - "Через prototype pollution"
    - "Через SQLi"
    - "Через XSS"
    - "Через CSRF"
  answer: 0
  explanation: "Pollution прототипа → выполнение кода."
- question: "Что даёт токен GitLab runner?"
  options:
    - "Ничего"
    - "Возможность запускать пайплайны (код) на инфраструктуре"
    - "Только тему"
    - "Пароль почты"
  answer: 1
  explanation: "Runner исполняет сборки."
- question: "Как в Jenkins добиваются RCE?"
  options:
    - "Через Script Console (Groovy)"
    - "Через cookie"
    - "Через robots.txt"
    - "Через sitemap"
  answer: 0
  explanation: "Groovy-скрипт исполняется сервером."
```

## Куда дальше

Дальше — каждая панель отдельно: Grafana, Kibana, GitLab, Jenkins. А пока запомни: **DevOps-панель — это креды и исполнение; версия → CVE → безопасная проверка.**

## Где пригодится

- Пентест внутренней сети и облачной инфраструктуры.
- Red team: панели как источник кред и путь к CI/CD.
- CTF: задания с конкретными CVE Grafana/GitLab/Jenkins.
