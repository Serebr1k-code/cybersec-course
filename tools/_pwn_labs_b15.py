#!/usr/bin/env python3
"""Authoring helper: write the 9 lab bundles for the pwn §3/§8 gap lessons."""
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'

def bundle(id, title, files, answer, hints, toolset=None):
    fs = [{'path': WD, 'type': 'dir'}]
    for name, text in files.items():
        fs.append({'path': f'{WD}/{name}', 'text': text})
    return {
        'id': id, 'category': 'pwn', 'title': title,
        'toolset': toolset or ['core'],
        'workdir': WD, 'files': list(files.keys()),
        'check': "grep -q '" + answer + "' answer.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/answer.txt', 'contains': answer},
        'fs': fs,
    }

BUNDLES = []

BUNDLES.append(bundle(
    'pwn-msg-msg', 'Практика: структура msg_msg',
    {'task.md': (
        "# Задача: структура msg_msg\n\n"
        "`msg_msg.h` — фрагмент определения объекта System V IPC, который используют\n"
        "для спрея кучи ядра и утечек.\n\n"
        "1. Открой `msg_msg.h` (`cat msg_msg.h`).\n"
        "2. Найди, как называется второе поле структуры (после `m_list`).\n"
        "3. Запиши `m_type=msg_msg` в `answer.txt` и выполни `check`.\n"),
     'msg_msg.h': (
        "struct msg_msg {\n"
        "    struct list_head m_list;   // 16 bytes: prev/next in queue\n"
        "    long m_type;               // type of message\n"
        "    size_t m_ts;               // message text size\n"
        "    struct msg_msgseg *next;   // next segment (large messages)\n"
        "    void *security;            // LSM label\n"
        "};\n")},
    'm_type=msg_msg',
    ["msg_msg — объект System V IPC.",
     "Первое поле — `m_list` (двусвязный список).",
     "Второе поле — `m_type`.",
     "Запиши `m_type=msg_msg`."]))

BUNDLES.append(bundle(
    'pwn-kernel-heap-spray', 'Практика: выбор объекта для спрея',
    {'task.md': (
        "# Задача: объект для heap spray\n\n"
        "`spray.c` — заготовка эксплойта, который спреит кучу ядра после UAF.\n\n"
        "1. Открой `spray.c` (`cat spray.c`).\n"
        "2. Определи, какой объект используется для спрея.\n"
        "3. Запиши `spray=msg_msg` в `answer.txt` и выполни `check`.\n"),
     'spray.c': (
        "#include <sys/msg.h>\n"
        "struct msgbuf { long mtype; char mtext[16]; };\n"
        "void spray(int qid, int n) {\n"
        "    struct msgbuf m = {.mtype = 1};\n"
        "    memset(m.mtext, 'A', sizeof(m.mtext));\n"
        "    for (int i = 0; i < n; i++)\n"
        "        msgsnd(qid, &m, sizeof(m.mtext), 0);  // <-- spray object\n"
        "}\n")},
    'spray=msg_msg',
    ["Спрей занимает освобождённый слот подконтрольным объектом.",
     "Ищи в коде вызов, создающий объект ядра.",
     "`msgsnd` создаёт `msg_msg`.",
     "Запиши `spray=msg_msg`."]))

BUNDLES.append(bundle(
    'pwn-kernel-info-leak', 'Практика: что утекает первым',
    {'task.md': (
        "# Задача: тип утечки\n\n"
        "`leak.txt` — дамп памяти ядра, полученный через OOB-чтение.\n\n"
        "1. Открой `leak.txt` (`cat leak.txt`).\n"
        "2. Посмотри на адрес `ffff8880...` — это куча ядра или база?\n"
        "3. Запиши `leak=heap-ptr` в `answer.txt` и выполни `check`.\n"),
     'leak.txt': (
        "00000000: 0000 0000 0000 0000 ffff 8880 1234 ab00\n"
        "00000010: ffff 8880 1234 ab80 0000 0000 0000 0001\n"
        "00000020: 0000 0000 0000 0040 ffff ffff 8a2b 1000\n")},
    'leak=heap-ptr',
    ["`ffff8880...` — диапазон кучи ядра, не база `.text`.",
     "База ядра выглядит как `ffffffff8...`.",
     "Первая утечка обычно даёт адрес в куче.",
     "Запиши `leak=heap-ptr`."]))

BUNDLES.append(bundle(
    'pwn-kernel-data-only', 'Практика: цель data-only атаки',
    {'task.md': (
        "# Задача: цель data-only атаки\n\n"
        "`cred.h` — фрагмент структуры ядра, описывающей права процесса.\n\n"
        "1. Открой `cred.h` (`cat cred.h`).\n"
        "2. Определи, как называется эта структура.\n"
        "3. Запиши `target=cred` в `answer.txt` и выполни `check`.\n"),
     'cred.h': (
        "struct cred {\n"
        "    atomic_t usage;\n"
        "    kuid_t   uid, gid, suid, sgid, euid, egid, fsuid, fsgid;\n"
        "    kernel_cap_t cap_permitted, cap_effective, ...;\n"
        "};\n")},
    'target=cred',
    ["Data-only не трогает поток управления.",
     "Цель — структура, описывающая права процесса.",
     "Она называется `cred`.",
     "Запиши `target=cred`."]))

BUNDLES.append(bundle(
    'pwn-kpti-bypass', 'Практика: чем завершают kernel ROP',
    {'task.md': (
        "# Задача: финиш kernel ROP\n\n"
        "`vmlinux.gadgets.txt` — фрагмент символов ядра.\n\n"
        "1. Открой `vmlinux.gadgets.txt` (`cat vmlinux.gadgets.txt`).\n"
        "2. Найди символ, который переключает таблицу страниц и возвращает в userland.\n"
        "3. Запиши `finish=trampoline` в `answer.txt` и выполни `check`.\n"),
     'vmlinux.gadgets.txt': (
        "ffffffff81e00e10 T swapgs_restore_regs_and_return_to_usermode\n"
        "ffffffff810a1230 T commit_creds\n"
        "ffffffff810a11e0 T prepare_kernel_cred\n"
        "ffffffff81002000 T native_write_cr4\n")},
    'finish=trampoline',
    ["Прямой возврат в userland на KPTI-ядре ломается.",
     "Нужна функция, переключающая таблицы страниц.",
     "Это `swapgs_restore_regs_and_return_to_usermode` (trampoline).",
     "Запиши `finish=trampoline`."]))

BUNDLES.append(bundle(
    'pwn-jop', 'Практика: ищем jmp-гаджеты',
    {'task.md': (
        "# Задача: JOP-гаджеты\n\n"
        "`libc.jop.txt` — список гаджетов.\n\n"
        "1. Открой `libc.jop.txt` (`cat libc.jop.txt`).\n"
        "2. Определи, какой тип завершения используют JOP-гаджеты.\n"
        "3. Запиши `gadget=jmp` в `answer.txt` и выполни `check`.\n"),
     'libc.jop.txt': (
        "0x00123456 : jmp rax\n"
        "0x00123980 : jmp rdx\n"
        "0x00124010 : jmp qword ptr [rsi + 0x10]\n")},
    'gadget=jmp',
    ["JOP использует гаджеты, заканчивающиеся косвенным переходом.",
     "Это `jmp [reg]`, а не `ret`.",
     "Запиши `gadget=jmp`."]))

BUNDLES.append(bundle(
    'pwn-cop', 'Практика: ищем call-гаджеты',
    {'task.md': (
        "# Задача: COP-гаджеты\n\n"
        "`libc.cop.txt` — список гаджетов.\n\n"
        "1. Открой `libc.cop.txt` (`cat libc.cop.txt`).\n"
        "2. Определи, какой тип завершения используют COP-гаджеты.\n"
        "3. Запиши `gadget=call` в `answer.txt` и выполни `check`.\n"),
     'libc.cop.txt': (
        "0x00110020 : call rax\n"
        "0x001100a0 : call qword ptr [rdx + 0x18]\n"
        "0x00110140 : call rsi\n")},
    'gadget=call',
    ["COP использует косвенные вызовы.",
     "Это `call [reg]`, а не `ret` и не `jmp`.",
     "Запиши `gadget=call`."]))

BUNDLES.append(bundle(
    'pwn-dop', 'Практика: чем управляет DOP',
    {'task.md': (
        "# Задача: что контролирует DOP\n\n"
        "`data.txt` — описание атаки.\n\n"
        "1. Открой `data.txt` (`cat data.txt`).\n"
        "2. Определи, чем управляет DOP.\n"
        "3. Запиши `control=data` в `answer.txt` и выполни `check`.\n"),
     'data.txt': (
        "DOP (Data-Oriented Programming):\n"
        "  - поток управления НЕ перехватывается;\n"
        "  - штатный код программы исполняется как есть;\n"
        "  - атакующий управляет только данными (поля структур, флаги).\n")},
    'control=data',
    ["DOP не перехватывает поток управления.",
     "Он управляет данными, а код исполняется штатный.",
     "Запиши `control=data`."]))

BUNDLES.append(bundle(
    'pwn-coop', 'Практика: цель COOP',
    {'task.md': (
        "# Задача: цель COOP\n\n"
        "`cpp.txt` — фрагмент дизассемблера виртуального вызова.\n\n"
        "1. Открой `cpp.txt` (`cat cpp.txt`).\n"
        "2. Определи, что подменяет COOP.\n"
        "3. Запиши `hijack=vtable` в `answer.txt` и выполни `check`.\n"),
     'cpp.txt': (
        "mov  rax, [rdi]       ; rax = vptr (pointer to vtable)\n"
        "call [rax + 0]        ; virtual call to first method\n")},
    'hijack=vtable',
    ["COOP подменяет таблицу виртуальных методов.",
     "Она называется vtable.",
     "Запиши `hijack=vtable`."]))

for b in BUNDLES:
    path = os.path.join(LABS, b['id'] + '.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(b, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print('wrote', path)
