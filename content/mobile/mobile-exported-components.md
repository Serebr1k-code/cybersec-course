---
id: mobile-exported-components
title: "Экспортированные компоненты: Activity, Service, Receiver, Provider"
category: mobile
parent: mobile-android-components
difficulty: medium
order: 2
tags: [android, exported, activity, service, receiver, content-provider, ipc]
prerequisites: [mobile-android-anatomy]
useful_for:
  - "CTF Mobile (доступ к скрытой функциональности)"
  - "Bug bounty (неавторизованный доступ через IPC)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как компоненты Android становятся доступны другим приложениям через android:exported, чем это опасно (неавторизованный доступ, обход экранов, утечки через ContentProvider) и как их перечислять и вызывать через adb."
---

## Вопрос, с которого всё начинается

Android-приложение — это не один монолит, а набор **компонентов**: Activity (экран), Service (фоновая работа), Broadcast Receiver (обработчик событий), Content Provider (доступ к данным). По умолчанию они приватны, но разработчик может пометить компонент `android:exported="true"` — и тогда к нему сможет обратиться любое другое приложение на устройстве.

Что именно открывается наружу и как этим воспользоваться?

## Наш пример: fdroid.apk

Возьмём реальный APK `fdroid.apk`. Декодируем манифест и вытащим все экспортированные компоненты:

```
$ apktool d -f -o fdroid_dec fdroid.apk
$ grep -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*' \
    fdroid_dec/AndroidManifest.xml | sed -E 's/.*android:name="([^"]*)".*/\1/' | sort -u
androidx.profileinstaller.ProfileInstallReceiver
androidx.work.impl.background.systemjob.SystemJobService
androidx.work.impl.diagnostics.DiagnosticsReceiver
org.fdroid.IconActivity
org.fdroid.IconCalculatorActivity
org.fdroid.MainActivity
org.fdroid.fdroid.panic.CalculatorActivity
org.fdroid.ui.panic.PanicActivity
org.fdroid.ui.panic.PanicResponderActivity
org.fdroid.ui.repositories.UpdateRepoActivity
```

Вот он — список «входов» в приложение. Разберём, что каждый тип компонента означает и как его проверять.

## Шаг 1: что такое exported

Атрибут `exported` отвечает на вопрос «может ли другое приложение обратиться к этому компоненту?». Три состояния:

- `exported="true"` — доступен всем приложениям.
- `exported="false"` — только своему приложению.
- **не указан** — система решает сама: если у компонента есть `intent-filter`, он считается экспортированным (историческое поведение, источник многих уязвимостей).

Отсюда первое правило аудита: **найти все `exported="true"` и все компоненты с `intent-filter` без явного `exported`**.

## Шаг 2: Activity — экраны

`Activity` — это экран. Экспортированная Activity может быть запущена другим приложением:

```
$ adb shell am start -n org.fdroid.fdroid/.ui.panic.PanicResponderActivity
Starting: Intent { cmp=org.fdroid.fdroid/.ui.panic.PanicResponderActivity }
```

`PanicResponderActivity` — экран «паники» (F-Droid умеет стирать данные по сигналу). Если он открывается снаружи без проверки, это может быть проблемой. Проверяем: требует ли Activity прав, аутентификации или проверки вызывающего.

## Шаг 3: Service — фоновые задачи

`Service` выполняет работу в фоне. Экспортированный сервис можно запустить или привязаться к нему (`startService`/`bindService`):

```
$ adb shell am startservice -n org.fdroid.fdroid/.nearby.LocalRepoService
```

Если сервис выполняет привилегированное действие (обновление, удаление) и не проверяет, кто его вызвал, — это находка. Обратите внимание: в нашем списке `SystemJobService` экспортирован, **но** защищён `android:permission="android.permission.BIND_JOB_SERVICE"` — без этого разрешения к нему не привязаться. Разрешение-защита — правильная практика.

## Шаг 4: Broadcast Receiver — обработчики событий

Receiver реагирует на broadcast-сообщения. Экспортированный receiver можно «пнуть» извне:

```
$ adb shell am broadcast -n org.fdroid.fdroid/androidx.work.impl.diagnostics.DiagnosticsReceiver
```

Здесь тоже есть защита: `android:permission="android.permission.DUMP"` — только системные/привилегированные вызовы. Если бы разрешения не было, любое приложение могло бы дёргать диагностику.

## Шаг 5: Content Provider — доступ к данным

Provider отдаёт данные по URI (`content://authority/path`). У F-Droid все провайдеры приватны:

```
$ grep -oE '<provider[^>]*authorities="[^"]*"[^>]*android:exported="[^"]*"' fdroid_dec/AndroidManifest.xml | head
<provider ... authorities="org.fdroid.fdroid.install.ApkFileProvider" android:exported="false" .../>
<provider ... authorities="org.fdroid.fdroid.fileprovider" android:exported="false" .../>
```

`exported="false"` — правильная настройка: файлы приложения не отдаются другим. Если бы провайдер был экспортирован и поддерживал path traversal — это была бы утечка данных (отдельный урок).

## Шаг 6: автоматизация — drozer

Вручную перебирать компоненты утомительно. `drozer` подключается к агенту на устройстве и перечисляет атакуемую поверхность:

```
$ drozer console connect
dz> run app.package.attacksurface org.fdroid.fdroid
Attack Surface:
  6 activities exported
  2 broadcast receivers exported
  2 services exported
  0 content providers exported
```

Дальше `app.activity.info`, `app.broadcast.info` показывают детали. Инструмент не находит уязвимости сам, но быстро рисует карту.

## Полный прогон от начала до конца

Соберём аудит поверхности в один сценарий для `fdroid.apk`:

1. **`apktool d`** — декодируем манифест.
2. **Собираем `exported="true"`** — получаем список из десяти компонентов.
3. **Классифицируем** по типам: activities, services, receivers, providers.
4. **Проверяем защиту** каждого: `android:permission`, `getCallingUid`.
5. **Пробуем вызвать** безопасный компонент (`am start`, `am broadcast`).
6. **Фиксируем**, что доступно без проверки, а что защищено разрешением.

В случае F-Droid большинство входов защищены — но список всё равно показывает, что именно стоит проверять дальше.

## Если не сработало

- **Компонент не отвечает на `am start`.** Возможно, требуется `action` или категория — смотрите `intent-filter`.
- **`Permission Denial`.** Компонент защищён `android:permission`; проверьте, есть ли у вас это разрешение (обычно нет — и это правильно).
- **Компонент падает.** Может требоваться предварительная авторизация или данные; пробуйте через само приложение.
- **`exported` не указан, но есть `intent-filter`.** Значит, компонент всё равно экспортирован — не пропустите его.
- **drozer не подключается.** Нужен агент на устройстве и проброс порта (`adb forward`).

## Что фиксировать в отчёте

- **Полный список экспортированных компонентов** с типами.
- **Какие из них без защиты** и что выполняют.
- **Доказательство вызова** (команда и результат).
- **Рекомендации:** явный `exported`, `android:permission`, проверка вызывающего.

## Частые вопросы

**«Все экспортированные компоненты — уязвимость?»** — нет, только те, что выполняют действие без проверки. **«Обязательно ли root?»** — нет, вызов через adb/другое приложение работает и без него. **«Что важнее: Activity или Provider?»** — Provider обычно опаснее (данные), но и Activity может обходить авторизацию. **«Как быстро собрать список?»** — grep по манифесту или drozer. **«Что если компонент защищён разрешением?»** — это правильная практика, не находка.

## Практический совет

Не гонитесь за количеством экспортированных компонентов — гонитесь за теми, что **делают что-то значимое** без проверки вызывающего. Откройте код каждого кандидата и прочитайте, что он выполняет. Десять открытых, но безобидных экранов — не находка; один сервис, стирающий данные, — critical.

## Экспортированность и intent-filter: тонкость

Многие считают, что если `exported` не написан, компонент приватный. Это не так. Если у компонента есть хотя бы один `intent-filter`, система считает его экспортированным по умолчанию — таково историческое поведение Android. Разработчик обязан явно написать `exported="false"`, чтобы закрыть такой компонент. Поэтому при аудите нельзя ограничиваться поиском строки `exported="true"`: надо отдельно собрать все компоненты с `intent-filter` и проверить, стоит ли у них явный `exported`.

Это правило — источник большого числа находок. Компонент с фильтром для deep link, у которого забыли поставить `exported="false"`, открыт всему устройству, хотя разработчик этого не планировал.

## Как отличать опасный компонент от безобидного

Экспортированный компонент сам по себе — не уязвимость. Уязвимость появляется, когда он **делает что-то значимое без проверки вызывающего**. Поэтому для каждого кандидата задайте три вопроса:

- **Что он делает?** Открывает экран, отдаёт данные, меняет состояние?
- **Кого проверяет?** Есть `android:permission`, проверка `getCallingUid`, требование авторизации?
- **Что можно передать?** Принимает ли он параметры, влияющие на поведение?

Компонент, который просто показывает статичный экран, — не находка. Компонент, который удаляет данные по команде извне, — critical. Разница не в слове `exported`, а в последствиях.

## Что мы теперь знаем

По-простому:

1. `exported="true"` открывает компонент другим приложениям.
2. Компонент с `intent-filter` без явного `exported` тоже считается экспортированным.
3. Activity запускается через `am start`, Service — `am startservice`/`bindservice`, Receiver — `am broadcast`.
4. Provider отдаёт данные по `content://`.
5. Разрешение (`android:permission`) или проверка вызывающего — правильная защита.

## На что смотреть дальше

- **Сначала список:** все `exported="true"` и все `intent-filter` без `exported`.
- **Проверяйте защиту:** есть ли `android:permission` или проверка `getCallingUid`.
- **Экспортированный ≠ уязвимый:** ищите компонент, выполняющий действие без проверки.
- **Используйте drozer** для карты поверхности, но подтверждайте руками.

## Квиз

Проверь себя.

```quiz
- question: "Что означает `android:exported='true'` у компонента?"
  options:
    - "Компонент доступен другим приложениям"
    - "Компонент экспортирует данные в сеть"
    - "Компонент зашифрован"
    - "Компонент только для отладки"
  answer: 0
- question: "Какой компонент отвечает за экран?"
  options:
    - "Activity"
    - "Service"
    - "Receiver"
    - "Provider"
  answer: 0
- question: "Как запустить экспортированную Activity из adb?"
  options:
    - "adb shell am start -n pkg/.Activity"
    - "adb shell pm list packages"
    - "adb push app.apk"
    - "adb shell logcat"
  answer: 0
- question: "Какая защита делает экспортированный сервис безопасным?"
  options:
    - "Атрибут android:permission или проверка вызывающего"
    - "Длинное имя класса"
    - "Отсутствие intent-filter"
    - "Использование HTTPS"
  answer: 0
- question: "Что делает drozer?"
  options:
    - "Перечисляет атакуемую поверхность приложения"
    - "Расшифровывает трафик"
    - "Собирает APK заново"
    - "Хукает функции"
  answer: 0
```

## Куда дальше

Мы научились находить экспортированные компоненты и понимать их типы. В следующем уроке углубимся в **deep links и Intent**: как внешняя ссылка открывает внутренний экран и почему это приводит к утечкам и захвату аккаунта. А пока запомни главное: `exported="true"` — это приглашение, и аудит начинается с полного списка таких компонентов.

## Где пригодится

- **CTF Mobile:** обход авторизации через экспортированную Activity.
- **Bug bounty:** экспортированные компоненты — классический источник находок.
- **Пентест:** проверка OWASP MASVS-PLATFORM.
- **Работа:** ревью манифеста и атакуемой поверхности приложения.
