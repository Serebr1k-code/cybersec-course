---
id: mobile-task-hijacking
title: "Task hijacking: StrandHogg и UI-redress на Android"
category: mobile
parent: mobile-android-ipc-deep
difficulty: hard
order: 2
tags: [android, task-hijacking, strandhogg, taskaffinity, launchmode, ui-redress, phishing]
prerequisites: [mobile-exported-components, mobile-tapjacking]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "Анализ малвари (банковские трояны)"
estimated_minutes: 50
summary: "Task hijacking и StrandHogg 1.0/2.0: как через taskAffinity, launchMode и allowTaskReparenting перехватить задачу жертвы, показать свой UI поверх и украсть данные."
---
## Введение

Task hijacking — класс атак, при которых вредоносное приложение «вклинивается» в задачу (task/back stack) легитимного приложения и показывает свой экран вместо него. Самая известная реализация — **StrandHogg** (1.0 — task hijacking через `taskAffinity`/`allowTaskReparenting`; 2.0 — перехват при возврате из фона). Цель: UI-redress, фишинг (поддельный экран логина поверх реального приложения), кража вводимых данных и токенов. Это один из самых серьёзных классов Android-уязвимостей, активно используемый банковскими троянами.

Механика опирается на то, как Android управляет задачами: `taskAffinity`, `launchMode`, `allowTaskReparenting`, `documentLaunchMode`, `excludeFromRecents`. Некорректные значения позволяют чужому activity «присвоить» задачу жертвы.

## Как устроены задачи Android

Задача (task) — стек activity, объединённых общим `taskAffinity` (по умолчанию = package name). Когда приложение выходит в фон и возвращается, система восстанавливает верхнюю activity задачи. Если атакующее приложение объявляет тот же `taskAffinity`, оно может подменить верхнюю activity.

```xml
<!-- УЯЗВИМО: allowTaskReparenting=true позволяет перепривязать activity -->
<activity android:name=".MainActivity"
          android:allowTaskReparenting="true"
          android:taskAffinity="" />   <!-- пустой affinity -> дефолт, конфликтует -->
```

Уязвимость на стороне **жертвы**: если её activity имеет `allowTaskReparenting="true"` или `taskAffinity=""` (пустой), её можно «утащить» в чужую задачу.

## StrandHogg 1.0

Атакующий объявляет activity с тем же `taskAffinity`, что у цели, и `launchMode`, позволяющим перехват:

```xml
<activity android:name=".EvilActivity"
          android:taskAffinity="com.target.app"
          android:excludeFromRecents="true"
          android:launchMode="singleTask"/>
```

Сценарий: пользователь запускает жертву → жертва уходит в фон → атакующий (через свой триггер) подставляет свой activity на верх задачи → пользователь видит фейковый экран ввода пароля. Ввод утекает атакующему.

## StrandHogg 2.0 (CVE-2020-0096)

StrandHogg 2.0 использует `TaskAffinity` + `allowTaskReparenting` + `singleTask` и перехватывает activity при возврате из фона, не требуя, чтобы жертва была запущена первой. Эксплуатация сложнее, но эффективнее; устранена в патчах 2020 года.

Проверка уязвимости на устройстве:

```bash
# список задач и их affinity
adb shell dumpsys activity activities | grep -iE 'task|affinity|realActivity'
# посмотреть, какую activity видит пользователь
adb shell dumpsys activity top | grep ACTIVITY
```

## Полный сквозной пример: проверка hijackable-задачи

Цель: определить, можно ли перехватить задачу тестового приложения.

```bash
# 1. Смотрим манифест цели на опасные флаги
grep -nE 'taskAffinity|allowTaskReparenting|launchMode|documentLaunchMode' target_src/AndroidManifest.xml
# -> android:taskAffinity=""  <-- опасно
# 2. Смотрим задачи во время работы приложения
adb shell dumpsys activity activities | grep -A2 "com.target.app"
# 3. Собираем PoC-приложение с EvilActivity taskAffinity="com.target.app"
#    и excludeFromRecents, launchMode=singleTask
# 4. Запускаем жертву, уводим в фон, триггерим EvilActivity
adb shell am start -n com.evil.app/.EvilActivity
adb shell dumpsys activity top | grep ACTIVITY
# -> ACTIVITY com.evil.app/.EvilActivity   <-- перехват подтверждён
```

Если наверху задачи `com.target.app` оказался `com.evil.app`, приложение уязвимо к task hijacking.

## Связь с tapjacking

Task hijacking часто комбинируют с **tapjacking** (наложение прозрачного окна поверх UI, `SYSTEM_ALERT_WINDOW`/`TYPE_APPLICATION_OVERLAY`) — см. `mobile-tapjacking`. Если жертва не защищает свои activity от overlay, можно «подсматривать» нажатия и перенаправлять их. Защита — `setFilterTouchesWhenObscured(true)` и `HIDE_OVERLAY_WINDOWS`.

## Защита (что искать в отчёте)

- `android:taskAffinity=""` — опасно.
- `allowTaskReparenting="true"` — опасно.
- Отсутствие проверки «сверху ли наша activity» (`onResume`/`onNewIntent`).
- Отсутствие `excludeFromRecents` у чувствительных activity.
- Отсутствие защиты от overlay (`setFilterTouchesWhenObscured`).

Приложение считается защищённым, если не позволяет репарентить/подменять свои задачи и проверяет целостность при возврате.

## Частые ошибки

- **Тест только вручную**: StrandHogg требует аккуратной последовательности (запуск, фон, возврат) — используйте PoC-приложение.
- **Считать фикс по версии Android достаточным**: кастомные прошивки могут быть не пропатчены.
- **Игнорировать `documentLaunchMode`**: он тоже влияет на задачи.
- **Путать с tapjacking**: это разные механизмы, но комбинируются.
- **Не проверять `dumpsys activity top`**: без него не увидеть, кто реально наверху.
- **Забыть про `excludeFromRecents`**: иначе атака заметна в переключателе задач.

## Что дальше / решение

Task hijacking — находка уровня High для финансовых/чувствительных приложений. Свяжите с `mobile-tapjacking`, `mobile-deeplink-deep`. Дальше: `mobile-intent-redirection`, `mobile-ipc-fuzzing`. Рекомендация: убрать `taskAffinity=""`/`allowTaskReparenting`, добавить overlay-защиту и проверку стека.

## Справочная таблица

| Флаг | Опасное значение | Почему |
|------|------------------|--------|
| taskAffinity | "" | конфликт с дефолтом |
| allowTaskReparenting | true | перепривязка activity |
| launchMode | singleTask | захват вершины задачи |
| excludeFromRecents | false | заметность |
| documentLaunchMode | intoExisting | смешение документов |

| Проверка | Команда |
|----------|---------|
| Задачи | `dumpsys activity activities` |
| Верхняя activity | `dumpsys activity top` |
| Флаги | grep манифеста |

## Сквозной кейс: воспроизведение StrandHogg в лаборатории

Разберём, как подтвердить task hijacking на тестовом приложении.

Первый этап — анализ цели. В манифесте ищем опасные значения: `android:taskAffinity=""`, `android:allowTaskReparenting="true"`, `android:launchMode="singleTask"` у чувствительных activity. Если `taskAffinity` пустой — activity может быть перепривязана к чужой задаче. Фиксируем список уязвимых activity.

Второй этап — сборка PoC. Создаём приложение с `EvilActivity`, у которой `taskAffinity` совпадает с package-ом жертвы, `launchMode="singleTask"`, `excludeFromRecents="true"`. Также добавляем триггер (например, broadcast receiver), который запускает EvilActivity.

Третий этап — сценарий. Запускаем жертву, уводим в фон (Home), затем триггерим EvilActivity. Проверяем, кто наверху задачи:

```bash
adb shell dumpsys activity activities | grep -A2 "com.target.app"
adb shell dumpsys activity top | grep ACTIVITY
```

Если наверху `com.evil.app/.EvilActivity` в задаче `com.target.app` — перехват подтверждён. Пользователь, вернувшись к приложению, видит наш экран.

Четвёртый этап — демонстрация влияния. Заменяем EvilActivity на фейковый экран логина, идентичный банковскому. Пользователь вводит пароль — он утекает. Это UI-redress/фишинг. Severity — High для финансовых приложений.

## StrandHogg 2.0

Версия 2.0 перехватывает при возврате из фона, используя комбинацию `allowTaskReparenting` и `singleTask`. Эксплуатация сложнее, но не требует, чтобы жертва была запущена первой. Проверка аналогична, но триггер срабатывает при возврате.

## Комбинация с overlay

Task hijacking часто усиливают overlay-окном (`SYSTEM_ALERT_WINDOW`), которое перекрывает интерфейс. Если жертва не защищена `setFilterTouchesWhenObscured`, нажатия перенаправляются. Это отдельный вектор (см. `mobile-tapjacking`), но комбинируется с захватом задачи.

## Защита

Безопасное приложение: не использует `taskAffinity=""`, не включает `allowTaskReparenting`, проверяет при возврате, что наверху его activity (`onResume`/`onNewIntent`), использует `excludeFromRecents` для чувствительных экранов, защищается от overlay. На уровне платформы — свежие патчи Android.

## Чек-лист

Найти опасные флаги манифеста, собрать PoC с EvilActivity, воспроизвести сценарий, проверить `dumpsys activity top`, показать влияние, оформить.

## Рекомендации в отчёте

Убрать `taskAffinity=""` и `allowTaskReparenting`, добавить overlay-защиту, проверять стек задач при возврате. Task hijacking — серьёзный класс, особенно для банков, и должен тестироваться в каждом пентесте финансового приложения.

## Практические советы по task hijacking

Начните с манифеста: ищите `taskAffinity=""`, `allowTaskReparenting="true"`, `launchMode="singleTask"`, `documentLaunchMode`. Каждый — потенциальная уязвимость. Для подтверждения соберите PoC-приложение с EvilActivity, повторите сценарий (запуск, фон, триггер) и проверьте `dumpsys activity top`.

Не забывайте про `excludeFromRecents`: без него захват заметен в переключателе задач, но уязвимость остаётся. Для финансовых приложений фиксируйте severity как High.

## Комбинации

Task hijacking усиливается overlay (tapjacking) и фейковым экраном логина. Проверяйте также защиту от overlay (`setFilterTouchesWhenObscured`). Комбинируйте с `mobile-tapjacking` при оценке влияния.

## Итог

Task hijacking — серьёзный класс UI-redress, особенно для банков. Ключ — опасные флаги манифеста и воспроизводимый PoC. Рекомендация: убрать `taskAffinity=""`/`allowTaskReparenting`, добавить overlay-защиту, проверять стек задач при возврате.

## Детальный разбор StrandHogg 2.0

StrandHogg 2.0 (CVE-2020-0096) — усовершенствованная версия task hijacking. Она использует `allowTaskReparenting` вместе с `singleTask`/`singleInstance` и перехватывает activity при возврате приложения из фона, не требуя, чтобы жертва была запущена первой. Механика: атакующий регистрирует activity с `taskAffinity` цели и `allowTaskReparenting=true`, затем, когда пользователь возвращается к приложению, система «перепривязывает» и показывает activity атакующего.

Проверка уязвимости требует аккуратного воспроизведения: запустить жертву, увести в фон, дождаться возврата, проверить `dumpsys activity top`. Если наверху activity атакующего в задаче жертвы — уязвимо. Патчи Android 2020 года закрывают эту версию, но кастомные прошивки могут быть не пропатчены.

## Комбинация с фишингом

Классический сценарий: фейковый экран логина поверх банковского приложения. Пользователь вводит данные — они утекают. Для убедительности атакующий копирует дизайн жертвы. Это делает task hijacking критичным для финансовых приложений (severity High/Critical).

## Защита и проверка

Безопасное приложение: не использует `taskAffinity=""`, не включает `allowTaskReparenting`, задаёт `excludeFromRecents` для чувствительных activity, проверяет при возврате, что наверху его activity (`onResume`/`onNewIntent`), защищается от overlay (`setFilterTouchesWhenObscured`). Проверяйте все чувствительные activity на эти флаги.

## Итог

Task hijacking — UI-redress-класс, требующий PoC-приложения для подтверждения. Находите опасные флаги манифеста, воспроизводите, показывайте влияние. В отчёте — High для банков, с рекомендациями по флагам и overlay-защите.

## Квиз

```quiz
- question: "На каком флаге манифеста основан StrandHogg 1.0?"
  options:
    - "taskAffinity"
    - "debuggable"
    - "allowBackup"
    - "networkSecurityConfig"
  answer: 0
- question: "Чем опасно пустое значение taskAffinity у activity?"
  options:
    - "Конфликтует с дефолтной affinity и позволяет захватить задачу"
    - "Ускоряет запуск"
    - "Снимает подпись"
    - "Включает root"
  answer: 0
- question: "Как увидеть, какая activity сейчас наверху задачи?"
  options:
    - "adb logcat"
    - "adb shell dumpsys activity top"
    - "adb backup"
    - "fastboot getvar"
  answer: 1
- question: "С каким классом атак task hijacking часто комбинируют?"
  options:
    - "SQL-инъекции"
    - "Tapjacking/overlay"
    - "SSRF"
    - "XXE"
  answer: 1
- question: "Какой флаг позволяет перепривязать activity к другой задаче?"
  options:
    - "allowTaskReparenting"
    - "excludeFromRecents"
    - "configChanges"
    - "hardwareAccelerated"
  answer: 0
```

## Где пригодится

- **Пентест Android:** критичная находка для банков/финансов.
- **Bug bounty:** task hijacking — серьёзный класс багов.
- **Анализ малвари:** банковские трояны используют StrandHogg.
- **CTF:** Mobile-задачи на UI-redress.
