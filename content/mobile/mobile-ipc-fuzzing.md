---
id: mobile-ipc-fuzzing
title: "Fuzzing Android IPC: Drozer, Intent-фаззинг и автоматизация"
category: mobile
parent: mobile-android-ipc-deep
difficulty: hard
order: 4
tags: [android, fuzzing, drozer, intent-fuzzing, ipc, automation, crash, marm]
prerequisites: [mobile-exported-components, mobile-android-ipc-deep]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "Анализ малвари"
estimated_minutes: 50
summary: "Автоматический поиск уязвимостей IPC: Drozer-модули, фаззинг Intent-ов, Marm/objection, анализ крашей logcat и приоритизация находок."
---
## Введение

Ручная проверка десятков экспортированных компонентов быстро утомляет. Fuzzing автоматизирует поиск: инструмент перебирает action/extras/data для каждого компонента, ловит краши (DoS), аномальные возвраты и обходы проверок. Drozer даёт готовые модули, Intent-фаззеры (marm, intent-fuzzer) — массовые вариации. Результат — список потенциально уязвимых компонентов, которые затем проверяют вручную.

Важно: фаззинг ищет **сигналы** (краши, исключения), а не доказательства уязвимости. Краш может быть DoS (находка), а может лишь указать на небезопасную обработку входных данных, которую нужно развить в утечку/редирект.

## Разведка перед фаззингом

```bash
# полная карта компонентов
dz> run app.package.attacksurface com.target.app
dz> run app.activity.info -a com.target.app
dz> run app.service.info -a com.target.app
dz> run app.broadcast.info -a com.target.app
dz> run app.provider.info -a com.target.app
# или из манифеста
aapt dump xmltree app.apk AndroidManifest.xml | grep -E 'activity|service|receiver|provider|exported'
```

Приоритет: экспортированные компоненты без permission или с `normal`-permission; компоненты, обрабатывающие extras/URIs.

## Drozer: сканирование и эксплуатация

```bash
dz> run scanner.provider.finduris -a com.target.app
dz> run scanner.provider.injection -a com.target.app     # SQLi
dz> run scanner.provider.traversal -a com.target.app     # path traversal
dz> run app.provider.query content://com.target.app.provider/users --selection "1=1"
```

`scanner.*` автоматически пробует инъекции и traversal по всем provider-ам — это уже готовый «фаззер» для Content Providers.

## Intent-фаззинг

marm (MOBISEC Android Runtime Manipulation) умеет фаззить компоненты:

```bash
# marm: фаззинг activity/service extras
marm --target com.target.app --activities
marm --target com.target.app --services
```

Собственный фаззер на bash для activity (перебор extras):

```bash
for key in next url path file redirect target; do
  for val in "content://com.target.app.private/x" "../../../../etc/hosts" "http://attacker/"; do
    adb shell am start -n com.target.app/.ProxyActivity --es "$key" "$val" >/dev/null 2>&1
  done
done
adb logcat -d | grep -iE 'FATAL|Exception|com.target.app' | tail -50
```

Смотрите logcat: `FATAL EXCEPTION`, `SecurityException`, `NullPointerException`, `FileNotFoundException` — маркеры небезопасной обработки.

## Полный сквозной пример: фаззинг provider + intent

```bash
# 1. Surface
dz> run app.package.attacksurface com.target.app
# 2. Сканер провайдеров
dz> run scanner.provider.traversal -a com.target.app
#   -> content://com.target.app.provider/files/../../../data/data/com.target.app/... VULNERABLE
# 3. Подтверждаем вручную
adb shell content read --uri "content://com.target.app.provider/files/../../../../data/data/com.target.app/shared_prefs/auth.xml"
# 4. Фаззим activity
for v in $(cat payloads.txt); do
  adb shell am start -n com.target.app/.ProxyActivity --es next "$v" 2>/dev/null
done
adb logcat -d | grep -A5 FATAL | head -40
# 5. Фиксируем находки и краши
```

Результат: подтверждён path traversal (критично) и несколько крашей (DoS/кандидаты).

## Автоматизация и приоритизация

- Прогоняйте фаззер в цикле с `timeout`, собирайте уникальные стектрейсы.
- Дедуплицируйте краши по сигнатуре (класс исключения + верхний фрейм).
- Помечайте компоненты с `permission` как низкий приоритет.
- Для каждого краша пытайтесь перейти к утечке/редиректу (эскалация сигнала в находку).
- Логируйте всё в файл (`tee`) и парсите, не засоряя контекст.

```bash
adb logcat -c
# ... фаззинг ...
adb logcat -d > /tmp/fuzz.log
grep -c "FATAL EXCEPTION" /tmp/fuzz.log
grep "FATAL EXCEPTION" -A3 /tmp/fuzz.log | grep "at com.target" | sort -u | head
```

## Частые ошибки

- **Игнорировать logcat**: без него фаззинг слепой — краши не видны.
- **Считать любой краш уязвимостью**: многие — просто плохая обработка, DoS уровня Low/Medium.
- **Фаззить не-экспортированные компоненты**: недостижимо снаружи.
- **Один payload на компонент**: нужен набор (path traversal, intent-строка, null, длинные строки).
- **Не дедуплицировать**: сотни одинаковых крашей забивают отчёт.
- **Забыть про receiver**: `am broadcast` — тоже поверхность фаззинга.

## Что дальше / решение

Фаззинг даёт карту потенциальных находок. Подтверждайте вручную (traversal → чтение файла, redirection → запуск приватного компонента, SQLi → дамп). Свяжите с `mobile-exported-provider`, `mobile-intent-redirection`, `mobile-service-hijacking`. Дальше — ветвь `mobile-network-security`. Рекомендация: минимизировать exported, валидировать все extras/URIs, не крашиться на неверных данных.

## Справочная таблица

| Drozer-модуль | Что делает |
|---------------|-----------|
| app.package.attacksurface | карта компонентов |
| scanner.provider.injection | SQLi по provider |
| scanner.provider.traversal | path traversal |
| scanner.provider.finduris | поиск URI |
| app.service.send | вызов сервиса |

| Маркер в logcat | Значение |
|-----------------|----------|
| FATAL EXCEPTION | краш (DoS/кандидат) |
| SecurityException | попытка обхода permission |
| FileNotFoundException | traversal/путь |
| SQLiteException | SQLi-кандидат |

## Сквозной кейс: автоматизированный фаззинг компонентов

Разберём полный цикл фаззинга на примере приложения с несколькими экспортированными компонентами.

Первый этап — карта поверхности. Запускаем drozer и получаем список: activity, service, receiver, provider. Для каждого фиксируем, есть ли permission и его уровень. Компоненты без permission или с normal — приоритет. Составляем таблицу целей.

Второй этап — фаззинг provider. Запускаем `scanner.provider.traversal` и `scanner.provider.injection`. Для найденных кандидатов подтверждаем вручную: traversal проверяем чтением системного файла через URI, SQLi — временной задержкой или логическим условием. Это даёт точные находки.

Третий этап — фаззинг activity/service. Готовим набор payload-ов: длинные строки, спецсимволы, path traversal, intent-строки, null, неверные типы. Прогоняем через `adb am start` с разными extra и ловим краши в logcat. Каждый уникальный стектрейс — кандидат. Дедуплицируем по сигнатуре.

Четвёртый этап — эскалация сигналов. Краш сам по себе — DoS уровня Low/Medium. Но он указывает на небезопасную обработку входа. Проверяем, ведёт ли тот же вход к утечке или редиректу. Например, traversal-краш → подтверждение чтения файла (High). Redirection → запуск приватного компонента (High).

## Инструменты и их ограничения

Drozer даёт готовые сканеры, но требует установки агента и соединения. Marm фаззит активности/сервисы. Собственные bash/python-скрипты дают гибкость. Ограничения: не-экспортированные компоненты недостижимы снаружи; часть крашей нестабильна; некоторые компоненты требуют специфичных extras для достижения кода.

## Организация выводов

Ведите таблицу: компонент, вход, payload, результат (краш/утечка/редирект), severity. Для каждого подтверждённого — шаги воспроизведения. Это основа отчёта. Не засоряйте отчёт сотнями одинаковых крашей — дедуплицируйте.

## Чек-лист

Получить карту компонентов, прогнать сканеры provider, подготовить payload-набор, фаззить activity/service/receiver, собрать краши из logcat, дедуплицировать, эскалировать сигналы в находки, оформить.

## Рекомендации в отчёте

Минимизировать exported-компоненты, валидировать все extras/URIs, не крашиться на неверных данных, защищать provider разрешениями signature-уровня. Фаззинг — эффективный способ быстро найти слабые места IPC, но требует ручного подтверждения каждого сигнала.

## Практические советы по фаззингу

Стабильность важнее объёма: нестабильные компоненты (требующие авторизации, специфичных extras) лучше тестировать точечно, а не массово. Для каждого краша сохраняйте точную команду запуска — иначе воспроизвести не удастся. Ведите лог с разделителями между попытками, чтобы отличать краши.

Используйте `adb logcat -c` перед каждой серией, чтобы лог был чистым. Фильтруйте по `com.target.app` и по `FATAL`. Для provider-сканирования доверяйте drozer, но всегда подтверждайте находку вручную — ложные срабатывания бывают.

## Эскалация сигналов

Краш — это сигнал, а не финальная находка. Всегда пытайтесь понять причину: если это unhandled exception на неверном входе, проверьте, можно ли тем же входом вызвать утечку или редирект. Например, `FileNotFoundException` на пути намекает на traversal; `SecurityException` — на попытку обхода permission. Превращайте сигнал в доказанную находку.

## Итог

Фаззинг IPC — быстрый способ покрыть десятки компонентов. Ключ к качеству — карта поверхности (drozer), набор payload-ов, сбор крашей из logcat, дедупликация и ручное подтверждение. Без последнего шага это лишь шум.

## Практикум: фаззинг одного provider

Разберём конкретный провайдер. Пусть `content://com.target.app.notes` экспортирован без permission. Проверяем доступ:

```bash
adb shell content query --uri content://com.target.app.notes
```

Если данные вернулись — провайдер открыт. Проверяем SQLi в selection:

```bash
adb shell content query --uri content://com.target.app.notes --where "1=1)--"
adb shell content query --uri content://com.target.app.notes --where "name='x' OR '1'='1'"
```

Если запрос ведёт себя иначе (ошибка, другой набор строк) — кандидат на SQLi. Подтверждаем через `--projection` с подзапросом или временной задержкой. Проверяем traversal:

```bash
adb shell content read --uri content://com.target.app.notes/files/../../../../data/data/com.target.app/databases/app.db
```

Если прочитался приватный файл — traversal подтверждён. Каждую находку фиксируйте командой и выводом. Это ядро фаззинга провайдеров: open → SQLi → traversal.

## Расширенный набор payload-ов и разбор результатов

Эффективный фаззинг требует осмысленных payload-ов, а не случайных строк. Разобьём их на категории. Для строковых extras: очень длинная строка (переполнение буфера в нативном коде), пустая строка, null-байт (`%00`), спецсимволы форматирования (`%s%n` — если строка попадает в нативный printf), unicode-нормализация, path traversal (`../../`), URL (`file://`, `content://`, `javascript:`), intent-строка (`intent:#Intent;...;end`). Для числовых extras: 0, -1, максимальные значения (`2147483647`, `-2147483648`), значения вне ожидаемого диапазона. Для boolean — неожиданные комбинации флагов.

Разбор результатов начинается с logcat. Очищайте его перед серией (`adb logcat -c`), прогоняйте payload-ы, затем собирайте (`adb logcat -d > f.log`). Ищите `FATAL EXCEPTION`, `SecurityException`, `FileNotFoundException`, `SQLiteException`, `NumberFormatException`, `IllegalArgumentException`. Каждый уникальный стектрейс — сигнал. Дедуплицируйте по сигнатуре: класс исключения плюс верхний фрейм в коде приложения.

Для каждого сигнала оцените достижимость эксплуатации. `FileNotFoundException` на пути с `../` — кандидат на traversal (попробуйте прочитать системный файл). `SecurityException` при передаче `content://` — кандидат на обход permission через grant-флаг. `SQLiteException` — кандидат на SQLi (подтвердите временной задержкой или логическим условием). Числовые исключения чаще всего дают только DoS (Low), но иногда открывают путь к обходу логики.

Ведите таблицу: компонент, вход, payload, исключение, гипотеза, статус подтверждения. Это превращает ворох крашей в структурированные находки. Не засоряйте отчёт сотнями одинаковых DoS — группируйте и приоритизируйте по влиянию.

## Автоматизация и воспроизводимость

Скрипт фаззинга должен логировать точную команду для каждой попытки, чтобы любое срабатывание воспроизводилось одной строкой. Запускайте фаззинг в изолированной среде (эмулятор) и сохраняйте артефакты. Для provider-ов используйте drozer-сканеры как первый проход, затем ручное подтверждение. Для activity/service — собственный генератор команд. Комбинируйте: сканеры находят очевидное, ручной набор — глубокое.

## Что писать в отчёте

Для каждой подтверждённой находки: компонент, вход, payload, результат, severity, шаги воспроизведения, рекомендация. Для крашей без эксплуатации — отдельный раздел с низким приоритетом. Ясно разделяйте «подтверждено» и «кандидат».

## Квиз

```quiz
- question: "Что ищет `scanner.provider.traversal`?"
  options:
    - "Path traversal в Content Provider"
    - "Открытые порты"
    - "Ключи в APK"
    - "Root"
  answer: 0
- question: "Где смотреть краши при intent-фаззинге?"
  options:
    - "adb logcat"
    - "fastboot"
    - "Manifest.db"
    - "Keychain"
  answer: 0
- question: "Почему не-экспортированные компоненты не фаззят снаружи?"
  options:
    - "Они недостижимы из другого приложения напрямую"
    - "Они всегда безопасны"
    - "Они не существуют"
    - "Их нельзя запустить даже изнутри"
  answer: 0
- question: "Что означает FATAL EXCEPTION в logcat?"
  options:
    - "Приложение упало (DoS/кандидат на находку)"
    - "Успешный вход"
    - "Утечка токена"
    - "Смена подписи"
  answer: 0
- question: "Зачем дедуплицировать краши?"
  options:
    - "Чтобы отчёт не забивался одинаковыми сигнатурами"
    - "Чтобы ускорить устройство"
    - "Чтобы снять root"
    - "Чтобы подписать APK"
  answer: 0
```

## Где пригодится

- **Пентест Android:** массовая проверка компонентов.
- **Bug bounty:** краши и обходы как находки.
- **Анализ малвари:** понимание атак на IPC.
- **CTF:** Mobile-задачи на автоматизацию.
