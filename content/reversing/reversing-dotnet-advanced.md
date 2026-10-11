---
id: reversing-dotnet-advanced
title: ".NET advanced: ConfuserEx, de4dot и IL-патчинг"
category: reversing
parent: reversing-managed-dotnet-java
difficulty: hard
order: 2
tags: [reversing, dotnet, confuserex, de4dot, il, dnspy, obfuscation]
prerequisites: [reversing-managed-dotnet-java]
useful_for:
  - "CTF Reversing"
  - "Анализ .NET-малвари (Cobalt Strike, stealers)"
  - "Bug bounty / аудит .NET-приложений"
estimated_minutes: 65
summary: "Разбор обфусцированных .NET-сборок: ConfuserEx, de4dot, ручная правка IL, пересборка и отладка."
---
.NET-код компилируется не в машинный код, а в **IL** (Intermediate Language) — высокоуровневый стековый байткод, который почти всегда декомпилируется обратно в читаемый C#. Это делает .NET одновременно и лёгким, и сложным для реверса: без защит вы видите почти исходник, но **обфускаторы** (ConfuserEx, .NET Reactor, SmartAssembly) усложняют анализ control-flow flattening'ом, шифрованием строк, proxy-вызовами и anti-tamper. Инструмент **de4dot** снимает большинство стандартных защит, а **dnSpy** позволяет декомпилировать, отлаживать и править IL. Этот урок — полный разбор обфусцированных .NET-сборок от идентификации обфускатора до пересборки и анализа .NET-малвари.

## Зачем .NET реверсить по-другому

- **Высокоуровневое представление.** IL хранит имена типов/методов/полей (если не переименованы), метаданные и строки — декомпилятор восстанавливает структуру классов.
- **Управляемый рантайм.** Код исполняет CLR (.NET Framework/Core/Mono); это даёт мощные инструменты (декомпиляция в исходник, отладка IL, правка сборки).
- **Метаданные.** Даже обфусцированная сборка несёт таблицы метаданных, которые можно читать (`System.Reflection.Metadata`, `dnlib`).
- **Лёгкая пересборка.** Можно править IL и сохранять обратно — аналог патчинга, но проще.

## Инструменты и их роли

| Инструмент | Назначение |
|------------|------------|
| dnSpy / dnSpyEx | декомпиляция, отладка, правка IL, hex-редактор |
| ILSpy | быстрая декомпиляция C#/IL |
| de4dot / de4dot-cex | деобфускация (ConfuserEx, Reactor, SmartAssembly и др.) |
| dotPeek | декомпилятор JetBrains |
| `ildasm` / `ilasm` | разбор/сборка IL (Microsoft) |
| `dnlib` | библиотека чтения/записи .NET-сборок (для скриптов) |
| Mono | запуск .NET на Linux |
| Frida + CLR-bridge | перехват managed-методов в рантайме |

## Обфускаторы: что делает ConfuserEx и другие

- **Control-flow flattening.** Линейный код превращается в `while(true) switch(state)` — поток управления «сплющивается», читать становится тяжело.
- **String encryption.** Все строки шифруются; в рантайме вызывается декодер (часто с ключом из параметра).
- **Proxy calls.** Вызовы методов идут через делегаты/proxy-методы (`call` → `callvirt` на прокси), скрывая реальные цели.
- **Constants encryption.** Числовые константы тоже шифруются.
- **Anti-debug / anti-tamper.** Проверки `Debugger.IsAttached`, контрольные суммы IL, детект патчей.
- **Reference proxy / resource encryption.** Скрытие ссылок и шифрование ресурсов (payload).

.NET Reactor и SmartAssembly добавляют native-стаб (mixed-mode), который расшифровывает сборку в памяти перед загрузкой — это уже гибрид managed/native.

## de4dot: деобфускация

```bash
# Базовая деобфускация (авто-детект обфускатора)
de4dot sample.exe -o sample_clean.exe

# Указать конкретные опции
de4dot --cflow-deob --strtok-deob sample.exe -o clean.exe   # control-flow + строки
de4dot -d sample.exe          # только определить обфускатор (без записи)
de4dot --dont-rename sample.exe   # не переименовывать символы

# .NET Reactor / SmartAssembly
de4dot --native-deob sample.exe
```

`de4dot` переименовывает символы обратно в осмысленные (`method_0` → `Decrypt`), снимает control-flow flattening и расшифровывает строки, если знает схему. Если обфускатор кастомный — de4dot не распознает его, и анализ идёт вручную.

## Ручной анализ: dnSpy/dnSpyEx

```bash
# Открыть сборку
dnSpyEx sample_clean.exe
```

В dnSpy:

- Дерево сборки слева: `Namespaces` -> типы -> методы.
- `Ctrl+Shift+K` — поиск по строке (ищет в IL/строках/методах).
- Правый клик на методе -> `Edit Method (C#)` или `Edit Method (IL)`.
- `Debug` -> `Start` — отладка managed-кода с точками останова.

Если осталась обфускация (switch-диспетчер), анализируйте диспетчер: найдите переменную состояния и таблицу переходов. Часто помогает отладка: поставить breakpoint на точку входа и идти по шагам, наблюдая состояние.

## Правка IL и пересборка

Типичная задача — обойти проверку. В dnSpy:

```text
1) Открыть сборку в dnSpy.
2) Найти метод проверки (по строкам/логике).
3) Edit Method (IL) -> заменить тело.
4) File -> Save Module (пересобрать).
```

Пример: превратить проверку в «всегда истина»:

```il
// было: вызов check() и ветвление
// стало:
ldc.i4.1      // push 1 (true)
ret
```

Для сборки из командной строки:

```bash
ildasm sample.exe /out=sample.il
# правим sample.il
ilasm sample.il /output=patched.exe
```

## Отладка managed-кода

- **dnSpy-отладчик** — пошаговое исполнение IL/C#, точки останова, просмотр стека и локальных переменных. Лучший инструмент для обфусцированного managed-кода.
- **Frida** — перехват managed-методов через CLR-bridge (`frida-clr`/`frida-dotnet`): можно логировать аргументы методов без пересборки.
- **x64dbg** — если в сборке есть native-часть (mixed-mode, Reactor-стаб).

## .NET-малварь: Cobalt Strike, stealers, droppers

- **Cobalt Strike beacon** — .NET/native гибрид; анализ: de4dot → dnSpy → конфиг (строки, ресурсы).
- **Stealers** — .NET-обфускация (Reactor/Confuser); цель — извлечь C2, что собирается, куда отправляется.
- **Droppers** — `Assembly.Load` из ресурсов: второй этап зашифрован в ресурсе и загружается в память.
- **Workflow:** de4dot → dnSpy → строки/конфиг → C2 → (при native-части) x64dbg/Frida.

```text
1) de4dot -> снять обфускацию.
2) dnSpy -> найти конфиг/C2 (строки, ресурсы).
3) Проверить Assembly.Load из ресурсов (dropper) -> извлечь payload.
4) Frida/x64dbg для native-части.
```

## Разобранный пример: ConfuserEx crackme end-to-end

**Шаг 1. Идентифицировать обфускатор.**

```bash
strings -a sample.exe | grep -iE "Confuser|Reactor|SmartAssembly"
# или проверить наличие характерных ресурсов/методов
```

**Шаг 2. Прогнать de4dot.**

```bash
de4dot sample.exe -o sample_clean.exe
de4dot --cflow-deob --strtok-deob sample.exe -o sample_clean.exe
```

**Шаг 3. Декомпилировать.**

```bash
dnSpyEx sample_clean.exe
# найти check-метод по строкам/логике (Ctrl+Shift+K)
```

**Шаг 4. Правка IL.** В dnSpy: Edit Method (IL) → заменить тело на `return true` → File → Save Module.

```il
ldc.i4.1
ret
```

**Шаг 5. Отладка.** Поставьте breakpoint в dnSpy на проверку и пройдите по шагам — проясняет остаточную обфускацию.

```bash
# Проверить, что обфускация снята
de4dot -d sample.exe
dnSpy sample_clean.exe
```

## Скрипты с dnlib и шпаргалка IL

Для массовых операций (расшифровать строки, переименовать методы) удобен **dnlib** — библиотека чтения/записи .NET-сборок из C#/PowerShell:

```csharp
// Псевдокод: загрузка модуля, обход методов, правка IL
var mod = ModuleDefMD.Load("sample.exe");
foreach (var type in mod.GetTypes())
    foreach (var m in type.Methods)
        if (m.HasBody) { /* инспекция инструкций */ }
mod.Write("patched.exe");
```

Полезные опкоды IL (стековая машина):

| Опкод | Действие |
|-------|----------|
| `ldc.i4.1` / `ldc.i4.0` | положить 1/0 |
| `ldstr "..."` | положить строку |
| `call` / `callvirt` | вызов метода (static/virtual) |
| `ret` | возврат |
| `brtrue` / `brfalse` | условный переход |
| `newobj` | создание объекта |
| `ldfld` / `stfld` | чтение/запись поля |

Частый патч — заменить тело метода на `ldc.i4.1; ret` (вернуть true). Для строк: найти декодер, вызвать его на константах через скрипт или вручную в dnSpy. Если сборка переименована (symrenamer), `de4dot` восстановит осмысленные имена по сигнатурам BCL-методов.

## Частые ошибки

- **Правка подписанной сборки.** Может ломать strong-name; отключите проверку (`sn -Vr`/`ilasm` без ключа) или снимите подпись.
- **de4dot не снял всё.** Остатки (native-часть, кастомный обфускатор) требуют ручного анализа.
- **Игнорирование ресурсов.** Payload/конфиг часто в ресурсах (`Assembly.Load`).
- **Нет отладки.** Динамика в dnSpy проясняет обфускацию лучше статики.
- **Неверная версия обфускатора.** de4dot может не распознать кастом — тогда вручную.
- **Забыть про native.** Mixed-mode сборки (Reactor) имеют нативную часть — нужен x64dbg.
- **Путать IL и C#.** Правьте именно IL, если декомпилятор не может восстановить C#.

## Извлечение конфигурации малвари

Большинство .NET-стеллеров/бэкдоров хранят конфиг (C2, ключи, флаги) внутри сборки:

```text
1) de4dot -> снять обфускацию.
2) dnSpy -> поиск по строкам: "http", "https", "Bot", "token", "gate".
3) Если строки зашифрованы -> найти декодер (метод с Cipher/XOR) и вызвать его.
4) Проверить ресурсы: Assembly.Load / GetManifestResourceStream -> извлечь payload.
5) Прочитать настройки из статических полей (Init/Config-класс).
```

Часто конфиг — это строка Base64/AES в статическом конструкторе; её можно расшифровать скриптом на Python или прямым вызовом метода в dnSpy (Immediate Window). Для Cobalt Strike-подобных загрузчиков второй этап лежит в ресурсе и загружается `Assembly.Load` — извлеките его и повторите цикл.

## Anti-tamper и защита от патчей

ConfuserEx/.NET Reactor включают **anti-tamper**: контрольная сумма IL проверяется в рантайме, и патч тела метода приводит к исключению/падению. Обход:

- **Патчить проверку контрольной суммы**, а не только целевую логику.
- **Отключить проверку** (найти метод-валидатор и заменить на `return true`).
- **Пересобрать с de4dot** (он снимает многие anti-tamper-схемы).
- **Динамика:** патчить в памяти (dnSpy) вместо пересборки файла, чтобы обойти проверку файла на диске.

Помните: anti-tamper может проверять и подпись strong-name — снимите/отключите проверку подписи перед патчем.

## Что делать дальше / решение

1. Определите обфускатор (`de4dot -d`, строки, ресурсы).
2. Снимите защиты (`de4dot` с нужными опциями).
3. Декомпилируйте в dnSpy, найдите целевую логику (строки, `Assembly.Load`).
4. При остаточной обфускации — отлаживайте и/или анализируйте switch-диспетчер.
5. Патчите IL и пересобирайте (`Save Module` или `ildasm`/`ilasm`).
6. Для малвари — извлеките конфиг/C2 и проверьте native-часть (x64dbg/Frida).

## Квиз

```quiz
- question: "Какой инструмент деобфусцирует .NET?"
  options:
    - "de4dot"
    - "nm"
    - "ldd"
    - "objdump"
  answer: 0
  explanation: "de4dot снимает ConfuserEx/Reactor и др."
- question: "Что делает dnSpy?"
  options:
    - "Декомпилирует, отлаживает и правит IL"
    - "Сканирует порты"
    - "Шифрует диск"
    - "Собирает ELF"
  answer: 0
  explanation: "dnSpy — декомпилятор/отладчик/редактор IL для .NET."
- question: "Что такое control-flow flattening?"
  options:
    - "Обфускация через switch-диспетчер"
    - "Формат файла"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "ConfuserEx преобразует поток управления в switch."
- question: "Где часто хранится payload .NET-дроппера?"
  options:
    - "В ресурсах сборки"
    - "В GOT"
    - "В ASLR"
    - "В canary"
  answer: 0
  explanation: "Дропперы грузят второй этап из ресурсов через Assembly.Load."
- question: "Почему правка сборки может сломать запуск?"
  options:
    - "Ломается strong-name/подпись"
    - "Меняется ASLR"
    - "Теряется canary"
    - "Меняется NX"
  answer: 0
  explanation: "Strong-name проверка отвергает изменённую сборку."
```

## Где пригодится

- **CTF:** Reversing — .NET-задачи.
- **Анализ .NET-малвари:** Cobalt Strike/stealers.
- **Bug bounty:** аудит .NET-приложений.
- **Работа:** malware analysis.
