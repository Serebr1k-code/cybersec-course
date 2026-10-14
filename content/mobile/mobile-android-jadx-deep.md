---
id: mobile-android-jadx-deep
title: 'JADX deep: скрипты, плагины и деобфускация'
category: mobile
parent: mobile-android-re-tooling
difficulty: medium
order: 1
tags: [jadx, decompiler, dex, java, scripts, deobf]
prerequisites: [mobile-static-analysis]
useful_for:
  - 'Реверс Android-приложений'
  - 'Пентест мобильных приложений'
  - 'CTF Mobile'
estimated_minutes: 40
summary: 'Как выжать из JADX максимум: CLI против GUI, флаги --deobf/--show-bad-code, поиск по декомпилированному дереву, скрипты на Java API и плагины для автоматизации.'
lab:
  kind: shell
  title: 'Практика: поиск секрета через jadx-вывод'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, jadx_sources.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`jadx_sources.txt` — фрагмент декомпилированного дерева.'
    - 'Найди хардкод-секрет (строку с ключом).'
    - 'В строке рядом с ключом — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

В прошлом уроке вы декомпилировали APK в JADX и вручную искали секреты. Но приложение большое:
тысячи классов, обфусцированные имена `a.a.a`, и глазами такое не пролистать. Как превратить
JADX из «просмотрщика» в инструмент, который сам находит нужное? Разберём продвинутую работу
с JADX.

## Наш пример: приложение app.apk

Берём один APK и ведём его через весь урок. Сначала базовый прогон в командной строке — это
воспроизводимее, чем клики в GUI:

```bash
$ jadx -d out app.apk
INFO - loading ...
INFO - processing ...
INFO - done
```

`jadx` — декомпилятор DEX (формата байткода Android) обратно в читаемый Java. Флаг `-d out`
задаёт папку вывода. Результат — дерево `out/sources/**.java` плюс `out/resources/`.

## Шаг 1: что именно мы получили

```bash
$ find out/sources -name '*.java' | wc -l
1843
```

1843 файла — вручную не пройти. Ключевой вопрос: как быстро сузить область до интересного
кода? Ответ — текстовая индексация: ищем по декомпилированному дереву обычным `grep`.

## Шаг 2: поиск по коду вместо кликов

```bash
$ grep -rn -E 'password|apiKey|secret|Bearer ' out/sources --include='*.java' | head
out/sources/com/example/net/Api.java:41:  private String apiKey = "AKIA-EXAMPLE-PLACEHOLDER";
out/sources/com/example/auth/Login.java:88:  body.put("password", md5(pass));
```

Мы нашли хардкод-ключ и точку, где формируется логин. Такой поиск работает на порядок быстрее
любого GUI. Второй полезный запрос — по URL и доменам:

```bash
$ grep -rhoE 'https?://[a-zA-Z0-9./_-]+' out/sources | sort -u
https://api.example.com/v1
https://cdn.example.com/static
```

## Шаг 3: деобфускация имён

Обфусцированный код читается плохо: `a.b.c(1,2)`. JADX умеет переименовывать сущности обратно
в осмысленные (`--deobf` — от «de-obfuscate»):

```bash
$ jadx --deobf -d out_deobf app.apk
```

Для полей/методов, где восстановление невозможно, JADX даёт синтетические имена вроде
`f1234a`. Часто полезнее не имена, а структура: какие классы вызывают `crypto`-API.

## Шаг 4: битый байткод и --show-bad-code

Иногда декомпилятор не может построить корректный Java-код (сложные `goto`, оптимизации).
Тогда JADX по умолчанию скрывает такой код. Флаг `--show-bad-code` заставляет показать
частично декомпилированный результат — лучше кривой, чем ничего:

```bash
$ jadx --show-bad-code -d out_bad app.apk
```

## Шаг 5: скрипты JADX (автоматизация)

Ручной `grep` хорош, но JADX умеет исполнять скрипты на Java API и ходить по всем классам
программно. Пример скрипта, который печатает все методы с «decrypt» в имени:

```java
import jadx.api.*;
public class FindDecrypt implements IJadxScript {
  public void run(JadxDecompiler jadx) {
    for (JavaClass cls : jadx.getClasses())
      for (JavaMethod m : cls.getMethods())
        if (m.getName().toLowerCase().contains("decrypt"))
          System.out.println(m.getFullName());
  }
}
```

Запуск:

```bash
$ jadx --script FindDecrypt.java app.apk
com.example.crypto.CipherUtil.decrypt(String, byte[])
com.example.net.Payload.unwrap(byte[])
```

Теперь мы знаем точные имена точек расшифровки — дальше их можно хукать Frida или разбирать
вручную. Скрипт можно расширить: обход строковых констант, поиск вызовов `Runtime.exec`,
`socket`, `loadLibrary`.

## Шаг 6: плагины

Кроме скриптов есть плагины, которые встраиваются в GUI и добавляют панели. Полезный приём —
плагин, который показывает кросс-ссылки (кто вызывает метод). При анализе это отвечает на
вопрос «где эта функция реально используется», без ручного поиска.

## Шаг 7: ограничения

JADX декомпилирует Java/DEX, но **не** трогает нативный код (`lib/*.so`) — для него нужен
Ghidra/IDA. Также JADX не исполняет код: строки, расшифрованные в рантайме, он не покажет.
Поэтому статику JADX всегда дополняют динамикой.

## Что мы теперь знаем

- JADX декомпилирует DEX в Java-дерево.
- `--deobf` восстанавливает имена, `--show-bad-code` не прячет кривой код.
- `grep` по дереву быстрее ручного просмотра.
- Скрипты на Java API автоматизируют поиск.
- Нативный код JADX не покрывает.

## Квиз

Проверь себя.

```quiz
- question: Что делает флаг --deobf у jadx?
  options:
    - Удаляет ресурсы
    - Восстанавливает осмысленные имена вместо обфусцированных
    - Ставит root
    - Собирает APK
  answer: 1
  explanation: deobf переименовывает сущности обратно.
- question: Как быстро найти хардкод-секреты в большом приложении?
  options:
    - Открыть каждый файл в GUI
    - grep -rn по декомпилированному дереву sources
    - Запустить игру
    - Разобрать .so
  answer: 1
  explanation: Текстовый поиск по дереву сужает область.
- question: Покрывает ли JADX нативные .so-библиотеки?
  options:
    - Да, полностью
    - Нет, для них нужен Ghidra/IDA
    - Только строки
    - Только экспорты
  answer: 1
  explanation: JADX работает с DEX/Java, не с машинным кодом.
- question: Зачем флаг --show-bad-code?
  options:
    - Ускоряет сборку
    - Показывает частично декомпилированный код вместо его скрытия
    - Ломает подпись
    - Грузит IPA
  answer: 1
  explanation: Лучше кривой код, чем пустой.
```

## Куда дальше

JADX даёт нам Java-код, но пересобрать изменённое приложение он не умеет. Дальше разберём
apktool — инструмент, который разбирает APK до smali и собирает обратно, чтобы патчить
поведение приложения.

## Где пригодится

- Быстрый статический разбор больших Android-приложений.
- Автоматизированный поиск секретов и точек расшифровки.
- CTF по мобильному реверсу.
