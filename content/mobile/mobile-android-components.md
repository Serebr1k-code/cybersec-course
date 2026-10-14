---
id: mobile-android-components
title: "Компоненты и хранилища Android"
category: mobile
parent: mobile-android-anatomy
difficulty: medium
order: 3
tags: [mobile, android, components, storage, webview]
prerequisites: [mobile-android-anatomy]
useful_for:
  - "CTF: Mobile"
  - "Пентест: Android"
  - "Работа: AppSec"
estimated_minutes: 12
summary: "Этап про хранилища данных, экспортированные компоненты и WebView."
lab:
  kind: shell
  title: 'Практика: поиск экспортированного компонента'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, decoded]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'В `decoded/AndroidManifest.xml` перечислены компоненты приложения.'
    - 'Ищи компоненты, доступные снаружи: атрибут `android:exported="true"`.'
    - 'У экспортированного компонента есть `meta-data` с секретом — найди `nto{` и запиши в `found.txt`.'
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Второй этап про поверхности атаки внутри приложения: небезопасное хранение данных (SharedPreferences, SQLite, Keystore), экспортированные компоненты (Activity, Service, Receiver) и WebView с его JS-мостами.

## Что вы освоите

- Небезопасное хранение данных: SharedPreferences, SQLite
- Экспортированные компоненты: Activity, Service, Receiver
- WebView: XSS, JS-интерфейсы и утечки

## Как проходить

Изучайте по поверхностям: сначала данные, затем межпроцессное взаимодействие, затем WebView. Проверяйте каждую на тестовом приложении.

## Квиз

```quiz
- question: "Чем опасно экспортированное Activity без проверки прав?"
  options:
    - "Любое приложение может его запустить"
    - "Оно медленно работает"
    - "Оно не запускается"
    - "Оно шифрует данные"
  answer: 0
  explanation: "Экспортированный компонент доступен другим приложениям."
- question: "Где Android-приложения часто хранят секреты в открытом виде?"
  options:
    - "В SharedPreferences"
    - "В Keystore"
    - "В Secure Enclave"
    - "В аппаратном TPM"
  answer: 0
  explanation: "SharedPreferences — обычный XML, легко читается при доступе к ФС."
- question: "Чем опасен небезопасный JS-мост в WebView?"
  options:
    - "Веб-контент может вызвать нативные методы"
    - "Он ускоряет рендеринг"
    - "Он блокирует XSS"
    - "Он шифрует трафик"
  answer: 0
  explanation: "Через addJavascriptInterface веб-страница получает доступ к коду приложения."
```

## Где пригодится

- **CTF:** Mobile
- **Пентест:** Android
- **Работа:** AppSec
