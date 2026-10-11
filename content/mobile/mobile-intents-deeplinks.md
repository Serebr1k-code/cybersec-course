---
id: mobile-intents-deeplinks
title: "Deep Links, Intents и URI: как открыть внутренний экран снаружи"
category: mobile
parent: mobile-exported-components
difficulty: medium
order: 1
tags: [android, deep-link, intent, uri, scheme, app-links, redirect]
prerequisites: [mobile-exported-components]
useful_for:
  - "CTF Mobile (запуск скрытых экранов по ссылке)"
  - "Bug bounty (deep link hijacking, обход логики)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как работают Intent, deep links (custom scheme) и Android App Links, почему небезопасный deep link открывает внутренние экраны и как использовать adb/браузер для их вызова и эксплуатации."
---
## Что такое deep links и intents

Deep link — это URI-схема, которая открывает приложение на конкретном экране с параметрами: `myapp://profile?id=42`. Intent — механизм межкомпонентного взаимодействия в Android: он может быть явным (указан конкретный компонент) или неявным (указано действие/данные, а система находит подходящий компонент). Deep links и intents опасны, когда позволяют открыть внутренний экран в обход авторизации, передать данные в неожиданное место или перехватить чужие данные. Цель модуля — научиться находить и эксплуатировать эти векторы.

## Как найти deep links

В манифесте ищите `<intent-filter>` с `<data>`:

```bash
grep -nA5 'intent-filter' AndroidManifest.xml | grep -E 'scheme|host|pathPrefix'
```

Схемы (`scheme`), хосты и пути определяют формат deep link. Например `myapp://secret/*` означает, что `myapp://secret/anything` открывает соответствующий экран.

## Эксплуатация deep link

```bash
adb shell am start -W -a android.intent.action.VIEW -d "myapp://secret/admin"
adb shell am start -W -a android.intent.action.VIEW -d "myapp://profile?id=1"
```

Пробуйте: открыть админские экраны, подставить чужие ID (IDOR), передать вредоносные параметры. Часто «скрытые» экраны доступны через deep link без проверки авторизации.

## WebView и deep links

Если deep link открывает WebView с URL из параметра, возможна инъекция:

```
myapp://web?url=javascript:alert(1)
myapp://web?url=https://evil.com
```

Приложение может загрузить произвольный URL — это открывает путь к XSS, фишингу и утечке токенов через `addJavascriptInterface`.

## Intent redirection

Опасный паттерн — приложение получает Intent и перенаправляет его дальше, не проверяя. Тогда можно заставить его открыть внутренний компонент:

```bash
adb shell am start -n com.example.app/.ProxyActivity -e "redirect" "com.example.app/.SecretActivity"
```

Или передать вложенный Intent (`EXTRA_INTENT`), который выполнится в контексте приложения.

## PendingIntent

`PendingIntent` позволяет другому приложению выполнить действие от имени вашего. Если он создан с `FLAG_MUTABLE` и не проверяет, кто его вызывает, — другой app может подменить его содержимое (Intent redirection, «pending intent hijacking»).

## Перехват intents

Если приложение использует неявные intents для чувствительных действий, вредоносное приложение может зарегистрировать тот же intent-filter и перехватить данные. Признак — передача секретов через неявные intents.

## Инструменты

```bash
drozer console connect
run app.broadcast.info -a com.example.app
run app.activity.info -a com.example.app
run scanner.provider.injection -a com.example.app
```

Drozer автоматически находит уязвимые intent-обработчики.

## Типичные ошибки и подводные камни

- **Забыть про неявные intents** — экспортированы неявно.
- **Не проверить параметры deep link** — IDOR прячется там.
- **Игнорировать WebView** — инъекция URL опасна.
- **Не проверить Intent redirection** — легко пропустить.
- **Путать `am start` и `am startservice`** — разные компоненты.
- **Забыть про Android 12+** — `exported` обязателен.
- **Не использовать drozer** — теряете автоматизацию.

## Справочная таблица

| Вектор | Команда |
|--------|---------|
| Deep link | `am start -a VIEW -d URI` |
| Явный intent | `am start -n pkg/.Act` |
| Broadcast | `am broadcast -a ACTION` |
| Разведка | `drozer app.activity.info` |
| WebView | параметр `url` |

## Что дальше / решение

План: найдите deep links и intent-фильтры в манифесте, проверьте, какие экраны они открывают, передайте параметры (включая чужие ID) и поищите IDOR/обход авторизации. Проверьте WebView на инъекцию URL и Intent redirection. Используйте drozer для автоматизации. Deep links и intents — частый источник уязвимостей, потому что разработчики забывают проверять вызывающую сторону и параметры.

## Практический пример: IDOR через deep link

Разберём сквозной сценарий. Приложение регистрирует deep link `myapp://profile?id=42`, открывающий профиль пользователя. Шаг 1: из манифеста узнаём схему и хост. Шаг 2: запускаем свой профиль: `adb shell am start -a android.intent.action.VIEW -d "myapp://profile?id=1"`. Шаг 3: меняем `id` на чужие значения — `2`, `3`, `admin`. Если приложение не проверяет, что запрошенный профиль принадлежит текущему пользователю, мы видим чужие данные. Это IDOR, реализованный через deep link. Шаг 4: если параметр принимает путь или URL, пробуем инъекцию.

Часто deep links ведут на WebView. Тогда параметр `url` может загрузить произвольный сайт или `javascript:`-пейлоад, что открывает XSS и утечку токенов через JS-интерфейсы. Всегда проверяйте, что происходит с параметрами внутри.

## Практический пример: Intent redirection

Другой сценарий: приложение имеет `ProxyActivity`, которая принимает вложенный Intent и запускает его. Из манифеста видно, что она экспортирована. Шаг 1: пробуем запустить её и передать вложенный Intent, указывающий на приватный экран:

```bash
adb shell am start -n com.example.app/.ProxyActivity \
  -e "android.intent.extra.INTENT" "intent:#Intent;component=com.example.app/.SecretActivity;end"
```

Если приложение не проверяет, какой компонент передан, оно запустит приватный экран от своего имени — обход экспортированности. Это классическая «Intent redirection» уязвимость.

## Частые вопросы

«Не знаю схему deep link?» — смотрите `<data android:scheme>`. «Параметр не принимается?» — попробуйте разные форматы (`?id=`, `/id/`). «WebView не открывается?» — проверьте, что URL-параметр реально используется. «Как автоматизировать?» — drozer `app.activity.info`. «iOS?» — аналогично через URL schemes и universal links.

## Что дальше / решение

Итог: найдите deep links и intent-фильтры, проверьте обработку параметров (IDOR, инъекция URL), проверьте Intent redirection и PendingIntent. Используйте drozer. Deep links и intents — частая точка входа, потому что разработчики фокусируются на UI-навигации, а не на проверке вызывающей стороны и данных.

## Расширенный чек-лист по deep links и intents

Порядок. Первое: `grep -nA5 'intent-filter' AndroidManifest.xml` — соберите схемы, хосты, пути. Второе: сформируйте URI и запустите: `am start -a android.intent.action.VIEW -d "scheme://host/path?params"`. Третье: переберите параметры (ID пользователей, пути, URL) — ищите IDOR и обход авторизации. Четвёртое: если deep link ведёт в WebView, подставьте `javascript:` и внешний URL. Пятое: проверьте Intent redirection (вложенный `EXTRA_INTENT`) и `PendingIntent` с `FLAG_MUTABLE`. Шестое: проверьте неявные intents, которые может перехватить другое приложение. Седьмое: автоматизируйте через drozer.

## Отдельно про WebView

WebView — отдельный большой вектор: `addJavascriptInterface` даёт JS доступ к Java-объектам; загрузка произвольного URL открывает фишинг и утечку; `setAllowFileAccess` позволяет читать файлы. Если deep link или intent передаёт URL в WebView без проверки — это серьёзная уязвимость.

## Частые вопросы

«Как узнать все deep links?» — grep по `<data`. «Параметр игнорируется?» — другой формат URI. «WebView не открывается?» — проверьте, что URL реально используется. «Как найти Intent redirection?» — ищите `getParcelableExtra("...INTENT")`. «Автоматизация?» — drozer.

## Что дальше / решение

Итог: соберите deep links, проверьте обработку параметров (IDOR, инъекция), проверьте WebView, Intent redirection и PendingIntent. Используйте drozer. Deep links и intents — частый источник уязвимостей, потому что разработчики проверяют UI-навигацию, но не данные и вызывающую сторону.

## Итог по deep links и intents

Проверяйте обработку параметров (IDOR, инъекция URL), WebView, Intent redirection и PendingIntent. Используйте drozer для разведки. Помните, что deep links и intents часто открывают внутренние экраны в обход авторизации — это самая частая ошибка.

## Итог по deep links

Ключевое: проверяйте параметры (IDOR), WebView и Intent redirection. Deep links часто открывают внутренние экраны в обход авторизации — это первое, что нужно проверить.

## Квиз

```quiz
- question: "Что такое Intent в Android?"
  options:
    - "Сообщение, описывающее, какой компонент и с какими данными нужно запустить"
    - "Файл конфигурации приложения"
    - "Тип сертификата"
    - "Формат APK"
  answer: 0
- question: "Почему custom scheme deep links (`myapp://`) опаснее App Links (`https://`)?"
  options:
    - "Любое приложение может объявить тот же scheme и перехватить ссылки"
    - "Они не работают в браузере"
    - "Они требуют root"
    - "Они медленнее"
  answer: 0
- question: "Как вызвать deep link через adb?"
  options:
    - "`adb deep open myapp://...`"
    - "`adb shell am start -a android.intent.action.VIEW -d "myapp://..."`"
    - "`adb shell content query`"
    - "`adb logcat`"
  answer: 1
- question: "Чем опасен deep link, передающий `url` в WebView?"
  options:
    - "Можно подсунуть произвольный URL/`javascript:` и получить XSS/утечку токена"
    - "Он замедляет приложение"
    - "Он ломает pinning"
    - "Он стирает данные"
  answer: 0
- question: "Как App Links защищают от перехвата scheme?"
  options:
    - "Привязывают домен к приложению через `/.well-known/assetlinks.json`"
    - "Шифруют ссылки"
    - "Требуют Magisk"
    - "Запрещают deep links"
  answer: 0
```

## Где пригодится

- **CTF Mobile:** запуск скрытых экранов по ссылке, передача «секретного» параметра.
- **Bug bounty:** deep link hijacking, open redirect, обход логики, утечка токенов через WebView.
- **Пентест:** проверка OWASP MASVS-PLATFORM (deep links, IPC).
- **Работа:** аудит регистрации deep links и их обработки на безопасность.
