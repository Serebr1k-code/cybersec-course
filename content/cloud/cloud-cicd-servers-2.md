---
id: cloud-cicd-servers-2
title: 'Модуль: CI/CD-плоскости — Buildkite, Travis, Bamboo, Spinnaker, Flux'
category: cloud
parent: cloud-cicd-servers
difficulty: hard
order: 4
tags: [cloud, cicd, buildkite, travis, bamboo, spinnaker, flux, module]
prerequisites: [cloud-cicd-secrets]
useful_for:
  - 'Атаки на CI/CD-инфраструктуру'
  - 'Кража облачных кредов из пайплайнов'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль о CI/CD-платформах второй волны: Buildkite и Travis (агенты + SaaS-контроль), Bamboo/Bitbucket (Atlassian), Spinnaker и Flux (CD-плоскость и GitOps) и self-hosted runners (persistence и кража между репозиториями). У всех одна цель: получить креды, которыми пайплайн ходит в облако.'
---

GitHub Actions, GitLab CI, Jenkins и ArgoCD разобраны в `cloud-cicd-secrets` и `cloud-cicd-servers`. Но в реальных организациях живут и другие платформы: Buildkite с самохостед-агентами, Travis CI, Bamboo и Bitbucket Pipelines от Atlassian, Spinnaker как отдельная CD-плоскость, Flux как GitOps-контроллер и просто self-hosted runners. Логика атаки у всех одна: найти способ исполнить свой код в пайплайне и прочитать секреты.

## Что покрывает подмодуль

1. **Buildkite / Travis** (`cloud-cicd-buildkite-travis`) — самохостед-агенты, pipeline upload, секреты и supply chain шагов.
2. **Bamboo / Bitbucket Pipelines** (`cloud-cicd-bamboo`) — планы, shared credentials, deployment-проекты и агенты Atlassian.
3. **Spinnaker / Flux** (`cloud-cicd-spinnaker-flux`) — CD-плоскость с облачными аккаунтами и GitOps-синхронизация.
4. **Self-hosted runners** (`cloud-cicd-selfhosted-runners`) — persistence на раннере и кража секретов между репозиториями.

## Почему такой порядок

Сначала Buildkite/Travis — модель «агент у тебя, контроль в SaaS». Потом Bamboo — enterprise-стек Atlassian с богатой моделью прав. Затем Spinnaker/Flux — уже не сборка, а доставка в облако (и там креды особенно ценны). Завершаем self-hosted runners — общая проблема для всех платформ, где раннер переиспользуется между задачами и репозиториями.

## Как проходить подмодуль

Один вопрос на все платформы: «какой код исполняется на каком агенте и с какими секретами?». Buildkite даёт `pipeline upload` из кода; Bamboo — планы с shared credentials; Spinnaker — аккаунты облака; Flux — права записи в git; runners — переиспользование окружения. Поняв, где код исполняется и что рядом лежит, ты находишь путь к облачным кредам.

## Квиз

Проверь себя.

```quiz
- question: "Что общего у платформ этого подмодуля?"
  options:
    - "Все исполняют код пайплайна и держат секреты, ведущие в облако"
    - "Они бесплатны"
    - "Они не имеют агентов"
    - "Они не логируются"
  answer: 0
  explanation: "Любой CI/CD — это исполнение кода плюс секреты; захват одного даёт другой."
- question: "Почему self-hosted runners особенно опасны?"
  options:
    - "Окружение раннера переиспользуется между задачами и репозиториями"
    - "Они медленнее"
    - "Они не имеют сети"
    - "Они не хранят секреты"
  answer: 0
  explanation: "Persistent-раннер оставляет следы и доступы от предыдущих сборок."
- question: "Что даёт pipeline upload в Buildkite?"
  options:
    - "Возможность определить шаги пайплайна из кода"
    - "Только логи"
    - "DNS-запись"
    - "Сертификат"
  answer: 0
  explanation: "Пайплайн, определяемый кодом, означает, что изменение кода меняет исполняемые шаги."
- question: "Почему Spinnaker ценен для атакующего?"
  options:
    - "Он хранит аккаунты облака с кредами для деплоя"
    - "Он хранит DNS"
    - "Он не имеет API"
    - "Он только читает"
  answer: 0
  explanation: "Аккаунты Spinnaker содержат креды, которыми CD деплоит в облако."
```

## Куда дальше

Дальше — Buildkite и Travis: агенты у тебя, контроль в SaaS. А пока главное: в CI/CD контроль над исполняемым кодом равен доступу к секретам пайплайна.

## Где пригодится

- Атаки на CI/CD-инфраструктуру.
- Кража облачных кредов из пайплайнов.
- CTF-задачи категории cloud.
