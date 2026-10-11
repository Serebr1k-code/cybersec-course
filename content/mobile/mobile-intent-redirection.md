---
id: mobile-intent-redirection
title: "Intent redirection: вложенные Intent-ы и захват привилегий"
category: mobile
parent: mobile-android-ipc-deep
difficulty: hard
order: 3
tags: [android, intent, redirection, nested, parcelable, exported, ipc, ato]
prerequisites: [mobile-exported-components, mobile-intents-deeplinks]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Intent redirection: как приложение переиспользует вложенный Intent и это позволяет атакующему запустить приватный компонент, украсть данные или выполнить операцию от имени жертвы."
---
## Введение

Intent redirection — уязвимость, при которой экспортированный компонент принимает от атакующего `Intent` (обычно как `Parcelable` extra) и затем запускает его внутри себя (`startActivity`, `startService`, `sendBroadcast`) **от имени своего процесса**. Поскольку у целевого приложения могут быть привилегии (собственные разрешения, доступ к провайдерам, доверенные учётные данные), атакующий «одалживает» эти привилегии, чтобы дотянуться до компонентов, которые сам напрямую вызвать не может.

Классический паттерн: приложение-«прокси» с экспортированной activity, которая читает `Intent next = getIntent().getParcelableExtra("next")` и вызывает `startActivity(next)`. Атакующий кладёт в `next` явный Intent на **приватный** (`exported=false`) компонент жертвы — и он запускается, потому что вызов идёт из процесса жертвы.

## Механика

```java
// УЯЗВИМЫЙ код в экспортированной Activity
Intent next = getIntent().getParcelableExtra("next");
if (next != null) {
    startActivity(next);          // запускает что угодно от имени жертвы
}
// ещё опаснее — с флагами, поднимающими привилегии
next.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
```

Дополнительные векторы:
- `startService(nested)` — запуск приватного сервиса.
- `sendBroadcast(nested)` — отправка приватного broadcast.
- `setResult`/`startActivityForResult` — редирект результата.
- `PendingIntent` — переиспользование чужого PendingIntent (отдельный класс).

## Разведка

```bash
# ищем getParcelableExtra и запуск Intent
grep -rn "getParcelableExtra\|getIntent().*Extra\|startActivity(" src/ | grep -i "extra\|next\|intent"
# jadx: искать по строкам
jadx -d out app.apk && grep -rn "getParcelableExtra" out/sources/ | head
# drozer: перечислить activity
dz> run app.activity.info -a com.target.app
```

## Полный сквозной пример: запуск приватной Activity

Дано: `com.target.app/.ProxyActivity` экспортирована и редиректит `next`. Приватная `com.target.app/.SecretActivity` (exported=false) показывает токен.

```bash
# 1. Прямой запуск приватной activity — запрещён
adb shell am start -n com.target.app/.SecretActivity
# SecurityException: not exported

# 2. Запуск через прокси с вложенным Intent
adb shell am start -n com.target.app/.ProxyActivity \
  --es next 'intent:#Intent;component=com.target.app/.SecretActivity;end'
# -> SecretActivity запускается от имени жертвы
```

`am` умеет парсить строковую сериализацию Intent (`intent:#Intent;...;end`) и положить её как Parcelable-extra. Альтернатива — написать маленькое PoC-приложение:

```java
Intent nested = new Intent();
nested.setComponent(new ComponentName("com.target.app", "com.target.app.SecretActivity"));
Intent wrapper = new Intent();
wrapper.setComponent(new ComponentName("com.target.app", "com.target.app.ProxyActivity"));
wrapper.putExtra("next", nested);
startActivity(wrapper);
```

Если `SecretActivity` появилась на экране — redirection подтверждён.

## Цепочка до кражи данных / ATO

Redirection становится критичным, когда приватный компонент возвращает данные или выполняет действие:

- Приватный provider: `next` с `content://com.target.app.private/...` + `FLAG_GRANT_READ_URI_PERMISSION` → атакующий получает доступ к данным.
- Приватная activity логина с авто-входом (trusted device) → захват сессии.
- Приватный сервис с операцией записи → изменение данных.

Иногда redirection комбинируют с **PendingIntent hijacking**: если приложение кладёт в extra чужой `PendingIntent` и вызывает `send`, атакующий подменяет его содержимое.

## Связанный класс: unsafe getIntent data

Не только `next`: любое доверенное использование данных из Intent от недоверенного источника опасно — `getStringExtra("url")` → `loadUrl` (WebView), `getStringExtra("file")` → открытие файла (path traversal), `getSerializableExtra` → deserialization (см. ниже). Правило: **данные из внешнего Intent — недоверенные**.

## Частые ошибки

- **Считать, что `exported=false` защищает**: при redirection вызов идёт из процесса жертвы, где компонент доступен.
- **Забыть про `FLAG_GRANT_*_URI_PERMISSION`**: без флага доступ к provider не дадут.
- **Тест только прямым `am start`**: нужен вложенный Intent через `--es next 'intent:#Intent;...'`.
- **Не проверить `sendBroadcast`/`startService`**: redirection не только про activity.
- **Игнорировать PendingIntent**: переиспользование — отдельный вектор.
- **Путать с deep link**: deep link — вход снаружи, redirection — переиспользование внутри.

## Что дальше / решение

Найдя `getParcelableExtra` + `startActivity/startService/sendBroadcast`, проверьте достижимость приватных компонентов. Свяжите с `mobile-deeplink-deep` (цепочки ATO), `mobile-exported-provider` (grant URI), `mobile-android-binder`. Дальше: `mobile-ipc-fuzzing`. Рекомендация: валидировать вложенный Intent (проверять пакет/компонент), запрещать внешние `Parcelable`, не давать `FLAG_GRANT_*`.

## Справочная таблица

| Sink | Опасность |
|------|-----------|
| startActivity(nested) | запуск приватной activity |
| startService(nested) | запуск приватного сервиса |
| sendBroadcast(nested) | подделка события |
| startActivityForResult(nested) | редирект результата |
| getSerializableExtra | deserialization |
| getStringExtra("url") | WebView/SSRF |

| adb-строка Intent | Синтаксис |
|-------------------|-----------|
| Явный компонент | `intent:#Intent;component=pkg/.Cls;end` |
| Action | `intent:#Intent;action=android.intent.action.VIEW;end` |
| Extra | `...;S.key=value;end` |

## Сквозной кейс: цепочка redirection до приватного провайдера

Рассмотрим полный сценарий. Приложение имеет экспортированную activity `ProxyActivity`, которая берёт вложенный Intent из extra и запускает его. Цель — добраться до приватного Content Provider, читающего токены.

Сначала разведка. В декомпилированном коде находим обработку extra: `Intent next = getIntent().getParcelableExtra("next")`, затем `startActivity(next)`. Значит, мы контролируем запускаемый компонент. Дальше смотрим манифест: есть приватный provider `TokenProvider` с `android:exported="false"` — напрямую недоступен.

Идея атаки: запустить из процесса жертвы activity, которая читает provider. Но нам нужна не activity, а сам provider. Здесь помогает `FLAG_GRANT_READ_URI_PERMISSION` в переданном Intent: если жертва запускает activity, которой мы дали URI, и та запрашивает grant, мы получаем доступ. Либо используем redirection в activity, которая отображает данные provider.

Собираем PoC-приложение: создаём Intent на приватный компонент, оборачиваем его во внешний Intent на `ProxyActivity`, запускаем. Наблюдаем запуск приватного компонента — это подтверждение. Если приватная activity возвращает данные (например, через `setResult`), мы их получаем.

Другой вариант: redirection в `startService`. Если жертва имеет приватный сервис с операцией чтения/записи, запускаем его через прокси. Ещё вариант — `sendBroadcast`: приватный receiver принимает наши данные.

## Обработка результата и PendingIntent

Продвинутый сценарий — PendingIntent hijacking. Если приложение кладёт в extra чужой PendingIntent и вызывает `send`, атакующий может подменить его содержимое, если PendingIntent не immutable и создан с `FLAG_MUTABLE`. Проверяйте флаги: `FLAG_IMMUTABLE` обязателен с Android 12. Отсутствие флага — находка.

## Защита: как должен выглядеть безопасный код

Безопасная реализация проверяет источник вложенного Intent: сверяет package/component с whitelist, запрещает внешние Parcelable, не добавляет `FLAG_GRANT_*`. Также приложение не должно запускать компоненты, переданные извне, без валидации. Если нужен редирект, используйте явный список разрешённых целей.

## Чек-лист тестирования

Найти все места `getParcelableExtra` + `startActivity/startService/sendBroadcast`. Для каждого проверить достижимость приватных компонентов. Проверить флаги PendingIntent. Построить PoC с вложенным Intent. Оформить находку с указанием достигнутого компонента и влияния.

## Рекомендации в отчёте

Не доверять вложенным Intent из внешних источников, валидировать компонент, не давать grant-флаги, использовать `FLAG_IMMUTABLE` для PendingIntent. Redirection — типичная находка на стыке компонентов, часто недооценённая, но ведущая к утечке или эскалации.

## Практические советы по redirection

Начинайте с поиска `getParcelableExtra` и вызовов `startActivity`/`startService`/`sendBroadcast` с полученным Intent. Каждое такое место — кандидат. Проверяйте, есть ли валидация компонента (проверка package/component по whitelist). Если нет — строьте PoC.

Для adb-демонстрации используйте строковую сериализацию Intent (`intent:#Intent;component=...;end`), переданную как extra. Для более сложных сценариев (grant URI, результат) пишите маленькое PoC-приложение.

## Связь с другими векторами

Redirection часто комбинируется с захватом provider (`FLAG_GRANT_READ_URI_PERMISSION`), с WebView (загрузка приватного контента) и с PendingIntent hijacking. Проверяйте флаги PendingIntent: отсутствие `FLAG_IMMUTABLE` — отдельная находка.

## Итог

Intent redirection — недооценённый, но частый вектор на стыке компонентов. Ключ — найти пару «вложенный Intent + sink» и доказать достижимость приватного компонента. Рекомендация: валидировать компонент, не доверять внешним Parcelable, не давать grant-флаги.

## Разбор через Frida и логирование

Статический поиск `getParcelableExtra` полезен, но динамика надёжнее. Хук на `Intent.getParcelableExtra` покажет, какие вложенные Intent-ы реально принимаются:

```javascript
Java.perform(function() {
  var Intent = Java.use("android.content.Intent");
  Intent.getParcelableExtra.overload("java.lang.String").implementation = function(k) {
    var v = this.getParcelableExtra(k);
    console.log("[extra] " + k + " = " + v);
    return v;
  };
});
```

Запустите приложение под этим скриптом, выполните действия, и увидите поток вложенных Intent-ов. Дополнительно хукайте `startActivity`/`startService`/`sendBroadcast`, чтобы видеть, что именно запускается.

## Автоматический поиск

Скрипт обходит все activity из drozer-списка и пытается передать вложенный Intent на приватный компонент. Результат (запустился/не запустился) фиксируется. Это системный способ найти redirection. Для каждой находки стройте PoC с реальным приватным компонентом и показывайте влияние.

## Итог

Redirection — цепочка «вход → вложенный Intent → sink». Динамика (Frida) даёт точную картину, статика — карту кандидатов. Комбинируйте. В отчёте указывайте полный путь и рекомендации по валидации.

## Итоговый чек-лист intent redirection

1. Найдите все места `getParcelableExtra` + `startActivity`/`startService`/`sendBroadcast`.
2. Проверьте, валидируется ли компонент вложенного Intent.
3. Определите достижимые приватные компоненты (activity/provider/service).
4. Проверьте флаги `FLAG_GRANT_*` и PendingIntent (`FLAG_IMMUTABLE`).
5. Постройте PoC с вложенным Intent (adb-строка или PoC-приложение).
6. Оформите с указанием достигнутого компонента и влияния.

Ключ: redirection обходит `exported=false`, потому что вызов идёт из процесса жертвы. Рекомендация — валидировать компонент, не доверять внешним Parcelable, не давать grant-флаги, использовать immutable PendingIntent.

## Квиз

```quiz
- question: "Почему redirection обходит `exported=false`?"
  options:
    - "Вызов идёт из процесса жертвы, где компонент доступен"
    - "Android игнорирует exported"
    - "Redirection меняет манифест"
    - "Он использует root"
  answer: 0
- question: "Какая строка Intent запускает приватную activity через adb?"
  options:
    - "--ez next true"
    - "--es next 'intent:#Intent;component=pkg/.Secret;end'"
    - "--activity-clear-top"
    - "--user 0"
  answer: 1
- question: "Какой флаг нужен для доступа к provider через redirection?"
  options:
    - "FLAG_GRANT_READ_URI_PERMISSION"
    - "FLAG_ACTIVITY_NEW_TASK"
    - "FLAG_DEBUGGABLE"
    - "FLAG_KEEP_SCREEN_ON"
  answer: 0
- question: "Какой sink опасен помимо startActivity?"
  options:
    - "sendBroadcast/startService"
    - "setContentView"
    - "findViewById"
    - "getSystemService"
  answer: 0
- question: "Какой принцип защиты от redirection?"
  options:
    - "Считать данные внешнего Intent недоверенными и валидировать компонент"
    - "Обфусцировать строки"
    - "Отключить R8"
    - "Включить ProGuard"
  answer: 0
```

## Где пригодится

- **Пентест Android:** серьёзные находки на стыке компонентов.
- **Bug bounty:** redirection → кража данных/ATO.
- **Анализ малвари:** понимание межпакетных атак.
- **CTF:** Mobile-задачи с вложенными Intent-ами.
