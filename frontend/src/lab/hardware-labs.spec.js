import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the hardware gB gap lab batch
// (cellular / silicon / OT fieldbus / MCU). Each entry loads the REAL fixture
// bundle from content/labs, replays the intended solution through the emulated
// engine builtins (grep/cut/base64/cat), and asserts the lab's own `check`
// passes and the hidden `expect` is satisfied.
const dir = path.resolve(process.cwd(), '../content/labs')

const LABS = [
  { id: 'hardware-gsm-2g', wd: '/home/student/gsm',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep payload grgsm.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-umts-3g', wd: '/home/student/umts',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep payload umts.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-lte-4g', wd: '/home/student/lte',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep token lte-nas.log | cut -d= -f2 | base64 -d > found.txt'] },
  { id: 'hardware-5g-nr', wd: '/home/student/5g',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep payload nr-signal.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-sim-esim', wd: '/home/student/sim',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep data apdu.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-baseband', wd: '/home/student/baseband',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep nto firmware-strings.txt | cut -d: -f2 > found.txt'] },
  { id: 'hardware-decapping', wd: '/home/student/decap',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep marker decap-log.txt | cut -d= -f2 > found.txt'] },
  { id: 'hardware-microprobing', wd: '/home/student/probe',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep target probe-plan.txt | cut -d= -f2 > found.txt'] },
  { id: 'hardware-fib-edit', wd: '/home/student/fib',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep result fib-log.txt | cut -d= -f2 > found.txt'] },
  { id: 'hardware-emfi', wd: '/home/student/emfi',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep flag emfi-run.txt | cut -d= -f2 > found.txt'] },
  { id: 'hardware-ethercat', wd: '/home/student/ethercat',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep data ethercat.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-iec-61850', wd: '/home/student/iec61850',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep stNum goose.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-iec-104', wd: '/home/student/iec104',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep IOA iec104.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-dnp3-sav5', wd: '/home/student/dnp3sav5',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep key sav5.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-arm-cortex-m', wd: '/home/student/cortexm',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep symbol vectors.txt | cut -d= -f2 > found.txt'] },
  { id: 'hardware-arm-cortex-a', wd: '/home/student/cortexa',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep world tz-log.txt | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-riscv', wd: '/home/student/riscv',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep nto disasm.txt | cut -d# -f2 > found.txt'] },
  { id: 'hardware-xtensa-esp', wd: '/home/student/esp32',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep app_desc esptool.log | grep nto | cut -d= -f2 > found.txt'] },
  { id: 'hardware-avr-pic', wd: '/home/student/avr',
    check: "grep -q 'nto{' found.txt",
    solution: ['grep lockbits avrdude.log | cut -d= -f2 > found.txt'] },
]

describe('hardware gB gap labs solve end-to-end', () => {
  for (const { id, wd, check, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: wd, check, hints: ['a', 'b', 'c', 'd'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of solution) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
