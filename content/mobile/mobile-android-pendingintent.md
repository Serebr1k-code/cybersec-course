---
id: mobile-android-pendingintent
title: 'PendingIntent: mutable-флаги и захват'
category: mobile
parent: mobile-android-ipc-attacks
difficulty: hard
order: 1
tags: [android, pendingintent, ipc, intent, hijacking, android12]
prerequisites: [mobile-exported-components, mobile-intents-deeplinks]
useful_for:
  - 'Пентест мобильных приложений (Android)'
  - 'Bug bounty Android'
  - 'CTF Mobile'
estimated_minutes: 40
summary: 'Что такое PendingIntent, зачем нужны флаги мутабельности, как мутабельный неявный PendingIntent превращается в перехват вызова и как это искать в коде.'
lab:
  kind: shell
  title: 'Практика: найти мутабельный PendingIntent'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, notify_dump.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`notify_dump.txt` — выжимка из `dumpsys activity intents`.'
    - 'Ищи строки с action и флагом в hex; вспомни, что `0x02000000` — это FLAG_MUTABLE.'
    - 'Рядом с одной из записей лежит строка `secret: nto{...}` — запиши её в `found.txt`.'
---

## Вопрос, с которого всё начинается

Приложение показывает уведомление «Ваш заказ №42» — и по тапу открывает экран заказа.
Само приложение при этом не запущено. Кто же открывает Activity, если процесс спит? За это
отвечает **PendingIntent**. И именно вокруг него живёт целый класс уязвимостей. Разберёмся.

## Наш пример: уведомление со ссылкой на заказ

В декомпилированном коде приложения доставки находим создание уведомления:

```java
Intent open = new Intent("com.example.delivery.OPEN_ORDER");
open.putExtra("order_id", orderId);
PendingIntent pi = PendingIntent.getActivity(
        context, 0, open, PendingIntent.FLAG_MUTABLE);
```

Строка `FLAG_MUTABLE` — красный флаг. Но почему? Чтобы понять, надо сначала разобраться,
что такое PendingIntent и что делает этот флаг.

## Шаг 1: что такое PendingIntent

Обычный `Intent` — это описание того, что надо сделать: «открой Activity X» или «отправь
broadcast Y». Но вызвать его можно только от имени того процесса, который это делает.

**PendingIntent** — это *токен*: приложение заранее создаёт Intent и отдаёт его системе
(например, `NotificationManager`). Когда пользователь тапает уведомление, систему просит
выполнить этот Intent **от имени создателя**, даже если само приложение уже не запущено.
Именно поэтому уведомления и виджеты работают без активного процесса.

Другими словами: PendingIntent — это «право выполнить действие моими полномочиями».

## Шаг 2: флаги мутабельности

Исторически у PendingIntent были флаги `FLAG_ONE_SHOT`, `FLAG_NO_CREATE`, `FLAG_UPDATE_CURRENT`.
С Android 12 (API 31) появились два важных:

- `FLAG_IMMUTABLE` — получатель **не может** менять содержимое Intent. Безопасный вариант.
- `FLAG_MUTABLE` — получатель **может** дозаполнить незаданные поля.

`FLAG_MUTABLE` нужен для легитимных сценариев: пузырьки чатов (bubbles), прямые ответы из
уведомления, где система сама вписывает текст ответа в Intent. Но если базовый Intent
**неявный** (задан action, но не задан конкретный component), то «незаданное поле» — это и
есть component. Кто угодно может его вписать.

## Шаг 3: как выглядит уязвимость

В нашем примере базовый Intent неявный: задан только action `com.example.delivery.OPEN_ORDER`
и extra `order_id`, но не указан пакет. Приложение-атакующий объявляет у себя Activity с
таким же intent-filter:

```xml
<activity android:name=".EvilActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.example.delivery.OPEN_ORDER"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

Когда система резолвит PendingIntent, она может выбрать **нашу** Activity — и получить
`order_id` из extra, а также выполнить вызов с правами приложения-жертвы. Это и есть
**PendingIntent hijacking**: перехват вызова и утечка данных, которые создатель считал
безопасными.

## Шаг 4: эксплуатация через adb и логи

В лабораторных условиях поведение проверяют так. Смотрим, какие PendingIntent-и создаёт
приложение, по логам или через Frida-хук на `PendingIntent.getActivity`:

```bash
$ adb shell dumpsys activity intents | grep -i pendingintent
  PendingIntentRecord{... action=com.example.delivery.OPEN_ORDER flags=0x02000000}
```

Здесь `0x02000000` — это `FLAG_MUTABLE`. Дальше атакующее приложение просто регистрирует
совпадающий intent-filter и ждёт, пока жертва тапнет уведомление.

## Шаг 5: что искать в коде и манифесте

При статическом анализе ищем связку из двух условий:

1. `PendingIntent.getActivity/getBroadcast/getService` с `FLAG_MUTABLE`;
2. базовый Intent без `setPackage()` / `setComponent()` (то есть неявный).

Инструментально это делается так:

```bash
$ grep -rn "FLAG_MUTABLE" decompiled/ | head
decompiled/smali/com/example/delivery/Notify.smali: ... FLAG_MUTABLE
```

И проверяем, что рядом нет `setPackage`. Если есть — риск снимается: пакет фиксирует
получателя.

## Шаг 6: как это чинится

- Использовать `FLAG_IMMUTABLE` всегда, когда мутабельность не нужна.
- Если нужна мутабельность — задать явный `setPackage()` или `setComponent()`.
- Не класть в мутабельный PendingIntent чувствительные extra, которые получатель может
  прочитать.

## Что мы теперь знаем

- PendingIntent — токен на выполнение действия от имени создателя.
- `FLAG_MUTABLE` разрешает получателю дозаполнять поля.
- Мутабельный **неявный** PendingIntent = перехват вызова чужой Activity.
- Искать надо пару «FLAG_MUTABLE + нет setPackage/setComponent».

## Шаг 7: как комбинируются флаги

Флаги — это битовая маска, и их часто пишут вместе:

```java
PendingIntent.getActivity(ctx, 0, i,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
```

Разберём каждый:

- `FLAG_UPDATE_CURRENT` — если такой PendingIntent уже существует, обновить его extra. Сам
  по себе он не создаёт уязвимость, но в паре с мутабельностью усложняет предсказание того,
  какие данные там окажутся.
- `FLAG_CANCEL_CURRENT` — отменить старый и создать новый. Полезно, чтобы не переиспользовать
  токен с устаревшими данными.
- `FLAG_ONE_SHOT` — токен сработает один раз. Не защищает от перехвата, но ограничивает
  повторное использование.
- `FLAG_NO_CREATE` — не создавать, вернуть `null`, если токена нет. Используется для проверок.

Важно: `FLAG_MUTABLE` и `FLAG_IMMUTABLE` взаимоисключающи, и если не указать ни один, система
на Android 12+ по умолчанию считает токен **иммутабельным** (с предупреждением в логах). Но
на старых версиях поведение было иным — поэтому в легаси-коде всё ещё встречаются токены без
явного флага, которые фактически мутабельны.

## Шаг 8: почему неявный Intent вообще попадает в систему

Резолвинг Intent — это отдельный механизм. Когда система получает неявный Intent, она
перебирает установленные приложения и их intent-filter'ы, чтобы найти совпадение. Если
совпадений несколько, пользователю показывают выбор (chooser), но для PendingIntent выбор
происходит **без** участия пользователя — по внутренним приоритетам. Атакующий этим
пользуется: он объявляет свой фильтр и, если его приоритет выше, получает вызов.

Есть ещё нюанс с `android:exported`. Даже Activity, не экспортированная для прямого вызова
извне, может быть целью PendingIntent, если у неё есть intent-filter и она помечена
`exported="true"`. Атакующий делает свою Activity экспортированной — это разрешено, — и она
становится кандидатом.

## Шаг 9: как автоматизировать поиск

Вручную просматривать весь smali неэффективно. На практике используют два подхода.

Первый — семантический поиск по коду через semgrep-правило:

```yaml
rules:
  - id: mutable-pendingintent
    languages: [java]
    pattern: PendingIntent.getActivity(..., PendingIntent.FLAG_MUTABLE)
    message: PendingIntent is mutable — check base intent is explicit
    severity: WARNING
```

Второй — статический анализ MobSF: он сам поднимает предупреждение о мутабельных PendingIntent
и показывает, какие Activity их используют. Но MobSF даёт сигнал, а не приговор: обязательно
проверяйте, есть ли `setPackage()`/`setComponent()` рядом.

## Шаг 10: типичные ошибки при анализе

- Считать, что `FLAG_MUTABLE` — всегда баг. Нет: если базовый Intent явный, мутабельность
  безопасна. Опасна именно пара «мутабельный + неявный».
- Игнорировать, что extra тоже утекают. Даже при явном получателе чувствительные данные в
  extra может прочитать тот, кому токен передан.
- Забывать про динамически регистрируемые получатели: `registerReceiver` тоже может принимать
  PendingIntent-подобные конструкции.
- Путать PendingIntent с обычным Intent: обычный Intent нельзя «выполнить от имени» другого
  приложения, а PendingIntent — можно, и именно в этом его сила и его риск.

## Шаг 11: что писать в отчёте

Формулировка находки должна включать: где создаётся токен (класс/метод), какой флаг
мутабельности, неявный ли базовый Intent, какое приложение может его перехватить и какие
данные при этом утекают. Плюс рекомендацию: `FLAG_IMMUTABLE`, а при необходимости
мутабельности — явный `setPackage()`. Для CTF-задач достаточно показать, что перехват
возможен, и извлечь данные — но и там полезно указать первопричину.

## Шаг 12: разбираем реальный пример из bug bounty

Типичная находка выглядит так: приложение музыкального сервиса ставит уведомление о
воспроизведении и вешает на кнопку «Пауза» PendingIntent с action
`com.music.PAUSE` и `FLAG_MUTABLE`. Базовый Intent неявный — пакет не задан. Исследователь
пишет приложение, которое объявляет Activity с тем же action и категорией `DEFAULT`. После
того как жертва тапает «Пауза», система запускает Activity исследователя, и он получает
управление воспроизведением **от имени музыкального приложения**, включая доступ к медиа-
сессии. Если бы в extra лежал токен подписки, он тоже утёк бы.

Вывод для исследователя: ищите не только утечку данных, но и **выполнение действия** —
PendingIntent может стартовать Service, отправлять Broadcast, открывать Activity, и каждое
из этих действий расширяет поверхность.

## Шаг 13: почему «неявный» — ключевое слово

Проверить явность Intent можно по наличию `setComponent`, `setClass`, `setPackage`. Если ни
одного нет — Intent неявный, и система резолвит его по intent-filter'ам. Для иммутабельного
токена это безопасно: получатель предопределён. Для мутабельного — нет.

Есть тонкость: даже явный по component Intent может считаться «частично явным», если у
компонента нет разрешения на запуск извне. Поэтому проверка должна учитывать и `exported` у
целевого компонента. Практический алгоритм: собрать цепочку «PendingIntent → базовый Intent →
целевой компонент → exported/permission» и оценить, может ли стороннее приложение встать в
эту цепочку.

## Шаг 14: как выглядит безопасный вариант

Безопасный код фиксирует получателя:

```java
Intent open = new Intent(ctx, OrderActivity.class);   // явный класс
open.putExtra("order_id", orderId);
PendingIntent pi = PendingIntent.getActivity(
        ctx, 0, open,
        PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
```

Здесь и класс задан явно, и флаг иммутабельный — перехватить нельзя. Именно такой шаблон
стоит искать как «правильный» при написании рекомендаций.

## Шаг 15: чек-лист анализа за минуту

Когда видите PendingIntent в коде, пройдите по короткому списку. Какой метод создания —
`getActivity`, `getService`, `getBroadcast`? Какой флаг мутабельности? Есть ли рядом
`setPackage`, `setComponent`, `setClass`? Куда ведёт базовый Intent — в свой компонент или
наружу? Что лежит в extra и чувствительно ли это? Ответив на пять вопросов, вы почти всегда
сразу понимаете, баг перед вами или безопасный код. Этот же список удобно вставлять в
bug-bounty-репорт как обоснование.

## Квиз

Проверь себя.

```quiz
- question: Что такое PendingIntent по сути?
  options:
    - Обычный Intent, лежащий в файле
    - Токен, позволяющий другому процессу выполнить Intent от имени создателя
    - Разрешение на доступ к сети
    - Способ хранения пароля
  answer: 1
  explanation: PendingIntent делегирует право выполнить действие с полномочиями создателя.
- question: Какой флаг делает PendingIntent уязвимым к дозаполнению полей?
  options:
    - FLAG_IMMUTABLE
    - FLAG_MUTABLE
    - FLAG_ONE_SHOT
    - FLAG_CANCEL_CURRENT
  answer: 1
  explanation: FLAG_MUTABLE позволяет получателю заполнить незаданные поля, включая component.
- question: При каком базовом Intent мутабельность особенно опасна?
  options:
    - Явный, с setComponent()
    - Неявный, без setPackage()/setComponent()
    - Пустой Intent без action
    - Intent только с extra
  answer: 1
  explanation: У неявного Intent незаданный component и есть то поле, которое впишет атакующий.
- question: Как нейтрализовать риск при необходимости мутабельности?
  options:
    - Убрать extra
    - Задать явный setPackage()/setComponent()
    - Использовать FLAG_ONE_SHOT
    - Уменьшить размер Intent
  answer: 1
  explanation: Явный получатель фиксирует, кому достанется вызов.
```

## Где пригодится

**CTF:** Mobile — hijack PendingIntent.
**Пентест:** перехват отложенных операций.
**Работа:** анализ флагов PendingIntent и прав.
