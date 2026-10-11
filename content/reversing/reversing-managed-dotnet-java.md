---
id: reversing-managed-dotnet-java
title: "Реверс managed-кода: .NET и Java"
category: reversing
parent: reversing-decompiler-languages
difficulty: medium
order: 2
tags: [reversing, dotnet, java, dnspy, ilspy, bytecode, decompilation]
prerequisites: [reversing-decompiler]
useful_for:
  - "CTF Reversing"
  - "Анализ .NET/Java malware"
  - "Аудит enterprise-приложений"
estimated_minutes: 50
summary: "Декомпиляция .NET (ILSpy/dnSpy) и Java (CFR/procyon/jadx), работа с байткодом и обфускаторами."
---
Бинарники, скомпилированные в байткод управляемых платформ, реверсить **легче** и **сложнее**
одновременно. Легче — потому что байткод .NET (CIL/MSIL) и Java (JVM bytecode) сохраняет структуру
классов, методов, имён и типов: из него восстанавливается почти исходный код. Сложнее — потому что
код часто обфусцирован (ConfuserEx, Dotfuscator, ProGuard), а иногда и скомпилирован AOT
(.NET Native, ReadyToRun, GraalVM native-image). Этот урок — про полный цикл: от декомпиляции
до снятия обфускации.

## Управляемый код: почему он «открыт»

.NET и Java компилируются не в машинный код, а в **промежуточное представление**:

- .NET → **CIL** (Common Intermediate Language), хранится в PE-секции с метаданными.
- Java → **bytecode**, хранится в `.class`-файлах внутри JAR/APK.

Метаданные содержат имена классов, методов, полей, сигнатуры, строки. Пока нет обфускации,
декомпилятор восстанавливает код, почти неотличимый от оригинала. Ключевая точка входа —
**точка входа** (`Main` в .NET, `public static void main` в Java) и **нативные зависимости**.

## Инструменты .NET: что и когда

| Инструмент | Назначение | Заметки |
|---|---|---|
| **dnSpy / dnSpyEx** | декомпиляция + отладка + редактирование | золотой стандарт, умеет патчить и пересобирать |
| **ILSpy** | декомпиляция | кроссплатформенный, плагины |
| **dotPeek** | декомпиляция | от JetBrains |
| **de4dot** | деобфускация | снимает ConfuserEx, Dotfuscator, SmartAssembly |
| **ConfuserEx-Unpacker** | распаковка | современные версии ConfuserEx |
| **dnlib** | библиотека | для написания своих патчей метаданных |
| **Mono.Cecil** | библиотека | чтение/запись сборок |

Быстрый старт:
```bash
# проверить, что это .NET
file target.exe                 # "PE32 executable ... .NET"
rabin2 -I target.exe | grep -i clr

# декомпиляция без GUI
ilspycmd target.exe -o ./out -p          # ILSpy CLI (dotnet tool)
```

## Инструменты Java: что и когда

| Инструмент | Назначение | Заметки |
|---|---|---|
| **jd-gui** | GUI-декомпилятор | быстрый, но иногда ломает generics |
| **CFR** | CLI | лучший на современном Java (records, switch) |
| **Procyon** | CLI | хорош на лямбдах/стримах |
| **Fernflower** | в IDEA | декомпилятор IntelliJ |
| **JADX** | APK/DEX | Android-специфика |
| **javap** | JDK | дизассемблер байткода, всегда доступен |
| **Krakatau** | байткод | продвинутый, читает/пишет |

```bash
# извлечь jar и декомпилировать
unzip -o target.jar -d target_extracted
find target_extracted -name '*.class' | head
# CFR
java -jar cfr.jar target.jar --outputdir ./cfr_out
# javap: дизассемблировать конкретный класс
javap -c -p -constants target_extracted/com/example/Check.class
```

## Разобранный пример: .NET crackme с проверкой пароля

Дано: `crackme.exe`, .NET. Открываем в dnSpy (`dnSpy.exe crackme.exe`).

**Шаг 1. Находим точку входа.** В дереве слева — `crackme`, узел `Program`. Метод `Main` вызывает
`CheckPassword`. Двойной клик → декомпилированный C#:

```csharp
public static bool CheckPassword(string input) {
    string text = "";
    for (int i = 0; i < input.Length; i++)
        text += (char)(input[i] ^ 0x41);
    return text == "Bqqf!Tfdsfu";
}
```

**Шаг 2. Решаем.** XOR `0x41` обратим: `"Bqqf!Tfdsfu"` XOR `0x41` = `"Admin Secret"`.
Вводим — «Correct!».

**Шаг 3. Если код обфусцирован.** Запускаем `de4dot`:
```bash
de4dot crackme.exe -o crackme_clean.exe
```
Лог покажет определённый протектор (`Detected ConfuserEx v1.0.0`). После очистки открываем
`crackme_clean.exe` в dnSpy — имена методов вернулись (`CheckPassword` вместо `method_7`).

**Шаг 4. Динамический обход.** Если обфускация сложная (control-flow flattening, string encryption),
в dnSpy ставим breakpoint (`F9`) на подозрительный метод, запускаем (`F5`), смотрим значения
локальных переменных в окне Locals — расшифрованные строки видны в рантайме.

## Разобранный пример: Java-приложение и `javap`

Дано: `app.jar`, проверяет лицензию. Декомпилируем CFR:
```bash
java -jar cfr.jar app.jar --outputdir ./out
```
Открываем `out/com/example/License.java`:
```java
public static boolean verify(String s) {
    int h = 0;
    for (char c : s.toCharArray()) h = h * 31 + c;
    return h == 0x2f4a91;
}
```
Решаем обратной задачей (или брутом по алфавиту). Если CFR «спотыкается», сверяемся с байткодом:
```bash
javap -c -p -constants out_classes/com/example/License.class
```
`javap` покажет точные инструкции (`imul`, `iadd`, `ldc`) — незаменимо, когда декомпилятор врёт.

## Строковое шифрование и его снятие

Самый частый вид обфускации managed-кода — **encrypted strings**. Плюсы для атакующего: строки
расшифровываются в рантайме, значит их можно вытащить.

Приёмы:
- **de4dot** умеет снимать string encryption многих протекторов автоматически
  (`de4dot --dont-rename crackme.exe`).
- **Динамически**: breakpoint на методе-декрипторе, сдампить возвращаемые строки. В dnSpy —
  правый клик на методе → `Analyze` → трассировка вызовов.
- **Скриптом**: в Java — агент/`java -javaagent`; в .NET — `dnlib` для прохода по IL и вызова
  декриптора.

## AOT и нативный код

Современные защитные компиляторы превращают managed-код в нативный, и декомпиляция «в лоб» не работает:

- **.NET Native / NativeAOT** — компилирует CIL в нативный x64/ARM. Реверсим как обычный бинарник
  (Ghidra/IDA), но метаданные и часть reflection сохраняются. Помогает поиск сигнатур рантайма
  (`System.Private.CoreLib`).
- **ReadyToRun (R2R)** — гибрид: нативный код + сохранённые метаданные. Часть методов декомпилируется.
- **GraalVM native-image** — Java в нативный ELF. Ищите строки и структуру встроенного рантайма;
  для отладки полезен `-g` при сборке (если есть).
- **Xamarin / MAUI** — managed-сборки упакованы внутрь нативного лаунчера; распаковка: найти
  embedded assemblies в ресурсах (`Extract MSBuild`), либо `monodis`.

## Крайние случаи и подводные камни

- **de4dot на новых протекторах** может не сработать — тогда ручной разбор через dnSpy + патч IL.
- **Декомпилятор врёт.** Всегда сверяйте критичные проверки с `javap`/IL-листингом (в dnSpy —
  `View → IL`). Особенно на `switch`, `try/finally`, generics.
- **Reflection и dynamic.** В Java `Method.invoke`, в .NET `System.Reflection` скрывают вызовы —
  статический анализ не видит цель; нужен рантайм-трейс.
- **JAR может содержать несколько версий класса** (`META-INF/versions/`) — декомпилируйте нужную.
- **Native-библиотеки (JNI/P-Invoke).** Логика может быть вынесена в `.dll`/`.so` — их реверсят отдельно.
- **Анти-дебаг.** dnSpy может падать/детектиться; используйте `--no-detect` в de4dot, патчите
  `Debugger.IsAttached`.
- **Осторожно с запуском malware.** Managed-код исполняется; изолируйте VM/песочницу.

## Что дальше / решение

1. Определить платформу: `file`, `rabin2 -I`, проверка CLR-заголовка.
2. Для .NET — dnSpy; для Java — CFR/jd-gui; сразу смотреть точку входа.
3. При обфускации — de4dot/ConfuserEx-Unpacker, затем повторная декомпиляция.
4. Если статически не выходит — динамика (breakpoint в dnSpy, java-agent/`-agentlib:jdwp`).
5. AOT/native — переходим к классическому реверсу (Ghidra/IDA, см. уроки по ELF/PE).

Практическое правило: **managed-код сначала декомпилируется, потом обфусцируется, потом снова
декомпилируется**. В 90% задач достаточно dnSpy + de4dot (или CFR + ручной патч).

## Справочная таблица: платформа → инструмент

| Платформа | Декомпилятор | Деобфускатор | Отладчик |
|---|---|---|---|
| .NET (CIL) | dnSpy, ILSpy | de4dot, ConfuserEx-Unpacker | dnSpy |
| Java (JVM) | CFR, jd-gui, Procyon | SpecialSource, ручной | JDWP / IDEA |
| Android (DEX) | JADX | jadx, dex-oracle | Frida |
| .NET AOT | Ghidra/IDA | — | x64dbg |
| Java native | Ghidra/IDA | — | gdb |

## Android: DEX, APK и JADX

Android-приложения — это Java/Kotlin, скомпилированные в DEX и упакованные в APK. Рабочий процесс:

```bash
apktool d app.apk -o app_decoded        # ресурсы + smali
jadx -d app_jadx app.apk                # декомпиляция в Java
jadx-gui app.apk                        # GUI
```

- **smali** — человекочитаемое представление DEX; в нём видно точные инструкции
  (`invoke-virtual`, `const-string`, `if-eqz`).
- **Kotlin** часто содержит `synthetic`-методы и `null`-проверки — не пугайтесь лишнего кода.
- **Native-часть** (`lib/*.so`) — реверсится Ghidra/IDA отдельно; JNI-функции имеют имена
  `Java_com_example_Class_method`.
- **Обфускация** (ProGuard/R8) переименовывает классы в `a`, `b`, `c`; строки могут шифроваться
  (строковый dex-обфускатор) — снимается рантайм-дампом или `dex-oracle`.

Для динамики Android — Frida (`frida -U -f com.example -l hook.js`) и Objection. Они позволяют
хукать методы по имени/сигнатуре и видеть аргументы/возвраты без пересборки APK.

## JNI и native-мост

Ключевая ловушка: логика проверки часто вынесена в нативную библиотеку. Признаки:
```bash
grep -r "native " app_jadx/ | head
# public static native boolean check(String s);
```
Тогда `System.loadLibrary("native-lib")` подгружает `.so`, и Java лишь передаёт строку в C.
Реверс: найти экспорт `Java_..._check` в `.so` (Ghidra), разобрать алгоритм, при необходимости
эмулировать (Unicorn) или реализовать на Python.

## Динамика .NET: dnSpy-отладка по шагам

```text
1. dnSpy → File → Open → crackme.exe
2. Найти метод (по строкам: Debug → Windows → Search Assemblies, либо Ctrl+Shift+K)
3. F9 на первой строке метода — breakpoint
4. F5 — Start (или Debug → Start)
5. Ввести данные во всплывшем консольном окне
6. Останов на breakpoint → Locals / Watch: видим локальные переменные и поля
7. F10/F11 — шаг; правый клик → Edit Method для патча IL "на лету"
```

Редактирование метода прямо в dnSpy позволяет **изменить проверку без пересборки**: убрать
`return false`, инвертировать условие, вывести ключ в консоль. Затем `File → Save Module` — и
патченная сборка готова.

## Криптография в managed-коде

В .NET и Java крипто вызывается из стандартной библиотеки, поэтому опознаётся по именам:

- .NET: `System.Security.Cryptography.Aes`, `RijndaelManaged`, `MD5.Create`, `SHA256Managed`,
  `Rfc2898DeriveBytes` (PBKDF2), `CryptoStream`.
- Java: `javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")`, `MessageDigest.getInstance("SHA-256")`,
  `SecretKeySpec`, `IvParameterSpec`.

Практический приём: даже если строки зашифрованы, **имена типов и методов в метаданных часто
остаются** (обфускатор может не трогать BCL-вызовы). Тогда `grep -r "Cipher.getInstance"` по
декомпилированному коду мгновенно находит крипту. Ключ/IV ищутся рядом (хардкод, вывод из пароля,
`Rfc2898DeriveBytes` с солью-константой).

## Метрики и отчётность

При разборе managed-образцов фиксируйте:

- Платформу и рантайм (`.NET Framework 4.x`, `.NET 6`, `Java 8/11/17`).
- Протектор и версию (`de4dot` в логе печатает `Detected <name> v<ver>`).
- Точку входа и ключевые методы (имена, адреса).
- Тип защиты (string encryption, control-flow, anti-tamper, anti-debug).
- Итоговый артефакт (деобфусцированная сборка, скрипт дешифровки).

Эти данные удобно складывать в JSON-отчёт — они повторяются от образца к образцу и ускоряют
триаж целой партии.

## Квиз

```quiz
- question: "Какой инструмент — стандарт для декомпиляции .NET?"
  options:
    - "Ghidra"
    - "dnSpy / ILSpy"
    - "radare2"
    - "upx"
  answer: 1
  explanation: "dnSpy и ILSpy дают читаемый C# из IL."
- question: "Что такое IL?"
  options:
    - "Intermediate Language — байткод .NET"
    - "Intel Library"
    - "Inline Loader"
    - "Internal Linker"
  answer: 0
  explanation: "IL — промежуточный язык .NET."
- question: "Чем .jar отличается от .class?"
  options:
    - "Ничем"
    - ".jar — это zip-архив с .class и ресурсами"
    - ".class — это zip"
    - ".jar — нативный бинарник"
  answer: 1
  explanation: "JAR упаковывает классы и метаданные."
- question: "Какая особенность managed-кода упрощает реверс?"
  options:
    - "Отсутствие байткода"
    - "Сохранение имён классов/методов в метаданных"
    - "Отсутствие защиты"
    - "Машинный код"
  answer: 1
  explanation: "Метаданные содержат имена — навигация проще."
- question: "Что использовать против обфускатора ConfuserEx (.NET)?"
  options:
    - "upx -d"
    - "de4dot"
    - "strings"
    - "readelf"
  answer: 1
  explanation: "de4dot снимает многие .NET-обфускаторы."
```

## Где пригодится

- **CTF Reversing:** .NET/Java задачи решаются за минуты в dnSpy/CFR/jadx.
- **Malware analysis:** значительная доля malware — .NET (Cobalt Strike, stealers).
- **Android:** jadx для APK — обязательный инструмент мобильного RE.
- **Аудит enterprise:** Java-приложения банков/CRM часто реверсят для оценки безопасности.
- **Собес:** вопросы про dnSpy, de4dot, javap, jadx — стандарт для .NET/Java RE-ролей.
