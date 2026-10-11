---
id: mobile-tapjacking
title: "Tapjacking, task hijacking и UI-redressing"
category: mobile
parent: mobile-webview
difficulty: medium
order: 1
tags: [tapjacking, task-hijacking, ui-redressing, overlay, android, strandhogg]
prerequisites: [mobile-webview, mobile-exported-components]
useful_for:
  - "CTF Mobile (перехват UI/логики)"
  - "Bug bounty (UI-redressing, перехват тасков)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как атаки на UI (overlay/tapjacking, task hijacking, StrandHogg) перехватывают нажатия и задачи приложения, и как это находить и тестировать."
---
## Введение

UI-redressing — это семейство атак, где вредоносное приложение или веб-страница накладывается поверх легитимного интерфейса либо перехватывает его «задачу» (task), чтобы пользователь нажал не туда или чтобы злоумышленник получил окно жертвы. На Android это tapjacking, StrandHogg и task hijacking; в веб-контексте — clickjacking. Для пентеста важно находить непокрытые экраны (без `filterTouchesWhenObscured`) и компоненты с опасными `launchMode`/`taskAffinity`.

## Как работает tapjacking

Поверх экрана банка рисуется прозрачное окно злоумышленника. Пользователь думает, что нажимает на своём экране, но касание попадает в скрытый оверлей, который выполняет действие — подтверждает перевод или выдаёт разрешение. Ключевой примитив — разрешение `SYSTEM_ALERT_WINDOW` (draw over other apps) или `TYPE_APPLICATION_OVERLAY`.

С Android 12 (API 31) наложенные окна блокируют касания автоматически, но приложения с настройками прозрачности остаются уязвимы на старых версиях и в комбинации с `FLAG_NOT_TOUCHABLE`.

## Overlay-атака: практика

```java
WindowManager.LayoutParams p = new WindowManager.LayoutParams(
    MATCH_PARENT, MATCH_PARENT,
    Build.VERSION.SDK_INT >= 26
        ? TYPE_APPLICATION_OVERLAY : TYPE_PHONE,
    FLAG_NOT_FOCUSABLE | FLAG_NOT_TOUCH_MODAL | FLAG_WATCH_OUTSIDE_TOUCH,
    PixelFormat.TRANSLUCENT);
p.gravity = Gravity.TOP | Gravity.LEFT;
wm.addView(overlayView, p);   // overlayView прозрачная, но перехватывает касания
```

Если целевое приложение не вызывает `setFilterTouchesWhenObscured(true)`, касания доходят до оверлея.

```bash
apktool d app.apk -o out
grep -rn "filterTouchesWhenObscured\|FLAG_WINDOW_IS_OBSCURED\|isObscured" out/
```

Приложение, которое **не** проверяет `MotionEvent.FLAG_WINDOW_IS_OBSCURED` для критичных действий (платёж, ввод PIN, разрешение), — кандидат на tapjacking.

## StrandHogg и task hijacking

StrandHogg (CVE-2019-2025) эксплуатирует `taskAffinity` и `allowTaskReparenting`: вредоносное Activity с той же `taskAffinity`, что и жертва, «встраивается» в задачу и подменяет экран. StrandHogg 2.0 — обход через `launchMode`.

```xml
<activity android:name=".LoginActivity"
          android:taskAffinity=""
          android:launchMode="singleTask"
          android:exported="true"/>
```

Правила: пустая `taskAffinity` (`android:taskAffinity=""`) или `singleTask`/`singleInstance` без защиты позволяют другому приложению «присосаться» к задаче. `allowTaskReparenting="true"` тоже расширяет поверхность.

## Обнаружение и тестирование

1. Декомпилировать APK и собрать список Activity с `taskAffinity`, `launchMode`, `exported`.
2. Проверить разметки критичных экранов на `filterTouchesWhenObscured`.
3. В динамике: `dumpsys activity activities` и `dumpsys window`.
4. PoC-оверлей на тестовом устройстве.
5. Для веб-части — `X-Frame-Options`/`frame-ancestors`.

```bash
adb shell dumpsys activity activities | grep -i "task\|affinity" | head -40
adb shell am start -n com.target/.SensitiveActivity
```

## Разобранный пример

Приложение кошелька: `TransferConfirmActivity` с `android:taskAffinity=""` и без `filterTouchesWhenObscured`. Пентестер находит Activity, пишет PoC-оверлей с кнопкой «Подтвердить», пользователь жмёт — касание уходит в реальное приложение, перевод уходит. Отчёт: tapjacking возможен на API < 31 и на API ≥ 31 из-за отсутствия защиты.

## Частые ошибки и подводные камни

- Тестировать только современные Android: tapjacking «закрыт» с 12-й версии, но актуален для старых API и `FLAG_NOT_TOUCHABLE`.
- Искать только `SYSTEM_ALERT_WINDOW` у жертвы: защита — `filterTouchesWhenObscured`.
- Путать StrandHogg с обычным exported Activity: StrandHogg — про перехват *задачи*.
- Забывать про веб-часть (WebView) и заголовки защиты от фрейминга.

## Справочная таблица

| Атака | Примитив | Защита |
|-------|----------|--------|
| Tapjacking | overlay | `filterTouchesWhenObscured` |
| StrandHogg | taskAffinity/launchMode | корректная affinity, не exported |
| Clickjacking | iframe/WebView | X-Frame-Options/frame-ancestors |
| Task hijacking | launchMode | явная affinity |

## Что дальше / решение

- Нет `filterTouchesWhenObscured` на критичном экране → находка + PoC-оверлей.
- Пустая `taskAffinity`/`singleTask` → task hijacking, опишите шаги.
- Критичный экран в WebView без `X-Frame-Options` → clickjacking.
- Android 12+ и защита стоит → отметьте зависимость от API.

## WebView и clickjacking

Если критичный экран — это веб-страница внутри WebView, атакующий может попытаться загрузить её в своём фрейме/WebView и наложить UI. Защита — заголовки `X-Frame-Options: DENY/SAMEORIGIN` и CSP `frame-ancestors 'none'`. Проверка:

```bash
curl -sI https://app.example/transfer | grep -iE 'x-frame-options|content-security-policy'
```

Дополнительно проверьте, загружает ли приложение произвольные URL в WebView (deep link → WebView) и есть ли JS-мост — тогда кликджекинг может вести к вызову нативных методов.

## Обнаружение tapjacking автоматически

Соберите список критичных экранов и проверьте, вызывается ли `setFilterTouchesWhenObscured`/`setFilterTouchesWhenObscured(true)` в их коде:

```bash
grep -rn "setFilterTouchesWhenObscured\|filterTouchesWhenObscured" out/smali* | head
grep -rln "TransferConfirm\|PaymentActivity\|PinActivity" out/smali* | head
```

Если критичный экран не устанавливает фильтр и не проверяет `FLAG_WINDOW_IS_OBSCURED` в `onTouchEvent` — зафиксируйте находку и подготовьте PoC-оверлей.

## Нюансы Android 12+ и FLAG_NOT_TOUCHABLE

С Android 12 непрозрачные оверлеи больше не пропускают касания, но:

- полупрозрачные/частичные оверлеи по-прежнему могут создавать проблемы в отдельных сценариях;
- на устройствах старее API 31 защита отсутствует;
- `FLAG_NOT_TOUCHABLE` и кастомные окна могут обходить системные эвристики.

Поэтому находку всегда указывайте с версией API: «воспроизводится на API < 31; на API ≥ 31 требует дополнительных условий».

## Пошаговый PoC

1. Определите критичный экран (подтверждение платежа/разрешение).
2. Убедитесь, что `filterTouchesWhenObscured` не установлен.
3. Соберите тестовое приложение с `SYSTEM_ALERT_WINDOW` и оверлеем, визуально совпадающим с кнопкой.
4. Покажите, что касание попадает в реальное приложение (лог/эффект).
5. Опишите impact и рекомендацию: установить фильтр, проверять `FLAG_WINDOW_IS_OBSCURED`, не полагаться на API-версию.

## Оценка severity

- Подтверждение платежа/выдача разрешения без защиты — High (денежные/приватные последствия).
- Некритичный экран — Low/Medium.
- Task hijacking с подменой экрана входа — High/Critical.

## Что дальше

- Подтвердите PoC на реальном тестовом устройстве.
- Проверьте зависимость от API-версии.
- Оформите рекомендации по защите UI.

## Task hijacking: детали эксплойта

StrandHogg эксплуатирует то, как Android группирует Activity в задачи (tasks). Ключевые атрибуты жертвы:

- `android:taskAffinity` — «семейство» задач; пустая строка означает «без привязки» и позволяет чужому Activity войти.
- `android:launchMode="singleTask"/"singleInstance"` — экземпляр переиспользуется; вредоносный компонент может подменить верх задачи.
- `android:allowTaskReparenting="true"` — Activity может «переехать» в задачу жертвы.
- `android:exported="true"` — доступ извне.

PoC: приложение-атакующий объявляет Activity с той же `taskAffinity`, что и жертва, и `exported`. Когда пользователь возвращается к приложению жертвы, Android может показать Activity атакующего вместо реального экрана — классический фишинг входа.

```xml
<activity android:name=".Evil"
          android:taskAffinity="com.victim.app"
          android:exported="true"
          android:launchMode="singleTask"/>
```

Проверка в манифесте жертвы:

```bash
grep -n "taskAffinity\|launchMode\|allowTaskReparenting\|exported" out/AndroidManifest.xml | head -40
```

## Что дальше

- Найдите критичные Activity и оцените их атрибуты.
- Подтвердите перехват задачи PoC-приложением на тестовом устройстве.
- Опишите шаги и рекомендации: явная `taskAffinity`, отказ от лишнего `exported`, защита экранов входа.

## Итоговый чек-лист tapjacking/task-hijacking

| Проверка | Команда/где смотреть |
|----------|----------------------|
| Фильтр касаний | `grep filterTouchesWhenObscured out/` |
| Флаг перекрытия | `FLAG_WINDOW_IS_OBSCURED` в `onTouchEvent` |
| taskAffinity | `grep taskAffinity out/AndroidManifest.xml` |
| launchMode | `singleTask`/`singleInstance` без защиты |
| exported Activity | `grep exported out/AndroidManifest.xml` |
| Веб-фрейминг | `X-Frame-Options`, CSP `frame-ancestors` |
| Версия API | зависимость от Android 12+ |

Прогоняйте этот чек-лист для каждого критичного экрана (вход, платёж, выдача разрешений) — именно там последствия UI-атак максимальны.

## Квиз

```quiz
- question: "Что защищает Android-приложение от tapjacking на критичных экранах?"
  options:
    - "setFilterTouchesWhenObscured(true)"
    - "android:exported='false'"
    - "Использование HTTPS"
    - "Обфускация ProGuard"
  answer: 0
  explanation: "Фильтр отбрасывает касания, когда окно перекрыто другим (obscured)."
- question: "Какой атрибут манифеста открывает путь к task hijacking?"
  options:
    - "android:taskAffinity='' (пустая)"
    - "android:debuggable='false'"
    - "android:theme"
    - "android:label"
  answer: 0
  explanation: "Пустая affinity позволяет вредоносному Activity встроиться в задачу жертвы."
- question: "Какой флаг MotionEvent сигнализирует о перекрытии окна?"
  options:
    - "FLAG_WINDOW_IS_OBSCURED"
    - "FLAG_ACTIVITY_NEW_TASK"
    - "FLAG_SECURE"
    - "FLAG_KEEP_SCREEN_ON"
  answer: 0
  explanation: "Приложение должно само проверять этот флаг на критичных действиях."
- question: "С какой версии Android наложенные окна блокируют касания по умолчанию?"
  options:
    - "Android 12 (API 31)"
    - "Android 6 (API 23)"
    - "Android 8 (API 26)"
    - "Android 10 (API 29)"
  answer: 0
  explanation: "С Android 12 непрозрачные наложения больше не пропускают касания по умолчанию."
- question: "StrandHogg — это в первую очередь атака на…"
  options:
    - "Перехват задачи (task) приложения"
    - "Шифрование TLS"
    - "SQLite"
    - "Keychain"
  answer: 0
  explanation: "StrandHogg эксплуатирует affinity/launchMode для подмены экрана внутри задачи."
```

## Где пригодится

- **CTF Mobile:** задачи, где нужно перехватить нажатие или подменить экран для получения флага/токена.
- **Bug bounty:** UI-redressing и перехват критичных действий — валидные находки в мобильных программах.
- **Пентест:** проверка защищённости платежных и аутентификационных экранов.
- **Работа:** ревью мобильного кода на предмет UI-защит перед релизом.
