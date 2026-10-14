---
id: cloud-serverless-platforms
title: 'Модуль: serverless-платформы — Knative, framework-и, Function URL, extensions'
category: cloud
parent: cloud-runtime-deep
difficulty: hard
order: 3
tags: [cloud, serverless, knative, lambda, faas, module]
prerequisites: [cloud-serverless]
useful_for:
  - 'Пентест serverless'
  - 'Захват функций и их ролей'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль о serverless-платформах и их поверхностях: Knative/OpenFaaS/Fission в кластере, framework-и деплоя (Serverless Framework/SST/SAM), прямые Function URL, и Lambda extensions/layers как способ исполнять код в песочнице функции. Одна общая цель атаки: код и его роль с правами в облаке.'
---

В уроке `cloud-serverless` ты разобрал базовую модель: функция исполняется по событию в управляемой песочнице, а права даёт роль. Но вокруг этой модели есть целый слой платформ и обвязки: Knative разворачивает serverless в твоём кластере, Serverless Framework и SAM описывают функции конфигом, Function URL открывают функцию напрямую в интернет, а extensions и layers позволяют исполнять свой код внутри песочницы. Каждый из этих слоёв — новая поверхность атаки.

## Что покрывает подмодуль

1. **Knative / OpenFaaS / Fission** (`cloud-knative`) — serverless в кластере: Serving, Eventing, автоскейл и SSRF.
2. **Serverless Framework / SST / SAM** (`cloud-serverless-framework`) — конфиги как код, env-секреты и роли деплоя.
3. **Function URL / API-триггеры** (`cloud-function-url`) — прямые URL, режимы авторизации и SSRF.
4. **Lambda extensions / runtime API / layers** (`cloud-lambda-extensions`) — код внутри песочницы и supply chain слоёв.

## Почему такой порядок

Идём от «платформа внутри кластера» к «обвязке деплоя» и дальше к «прямому доступу» и «внутренностям песочницы». Knative — это serverless, который ты сам ставишь, поэтому там и классические k8s-мисконфиги. Framework-и определяют, что и с какими правами деплоится. Function URL — это то, что видно из интернета. Extensions/layers — то, что исполняется рядом с твоей функцией и часто остаётся незамеченным.

## Как проходить подмодуль

Вопрос один: «какой код исполняется в песочнице и какие у него права?». В Knative код — это контейнер с ServiceAccount кластера. В framework-ах код — твой, но креды деплоя и env-секреты рядом. В Function URL код доступен напрямую. В extensions код исполняется при каждом вызове с теми же правами, что и функция.

## Квиз

Проверь себя.

```quiz
- question: "Чем Knative отличается от Lambda?"
  options:
    - "Knative разворачивается в твоём кластере, Lambda — управляемый сервис облака"
    - "Knative не масштабируется"
    - "Lambda не имеет ролей"
    - "Они идентичны"
  answer: 0
  explanation: "Knative — serverless-платформа на Kubernetes; поэтому к ней применимы и k8s-атаки."
- question: "Где в serverless-платформе живут права?"
  options:
    - "В роли/ServiceAccount, от имени которого исполняется функция"
    - "В DNS"
    - "В логах"
    - "В образе"
  answer: 0
  explanation: "Функция действует от имени роли; захват кода или кредов этой роли даёт облачный доступ."
- question: "Почему Function URL важен для атакующего?"
  options:
    - "Он даёт прямой доступ к функции без шлюза и иногда без авторизации"
    - "Он хранит пароли"
    - "Он заменяет IAM"
    - "Он не имеет настроек"
  answer: 0
  explanation: "Ошибки в режиме авторизации делают функцию публичной."
- question: "Чем опасны Lambda extensions?"
  options:
    - "Они исполняют код в песочнице с правами функции и доступом к env"
    - "Они только логируют"
    - "Они не имеют сети"
    - "Они изолированы от функции"
  answer: 0
  explanation: "Расширение запускается рядом с функцией и видит её окружение и вызовы."
```

## Куда дальше

Дальше — Knative: serverless в кластере, где поверхность включает и Kubernetes. А пока главное: serverless — это код плюс роль, и каждый слой обвязки добавляет точку атаки.

## Где пригодится

- Пентест serverless-платформ.
- Захват функций и их ролей.
- CTF-задачи категории cloud.
