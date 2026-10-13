// xterm glue for the lab. This is the ONLY module that imports @xterm, so the
// terminal engine lands in its own chunk and is fetched only for lessons that
// actually carry a lab.
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { complete, commonPrefix } from './complete'

const THEME = {
  background: '#0b111a',
  foreground: '#e6edf3',
  cursor: '#38bdf8',
  cursorAccent: '#0b111a',
  selectionBackground: 'rgba(56,189,248,0.3)',
  black: '#0b111a', red: '#ef4444', green: '#22c55e', yellow: '#eab308',
  blue: '#38bdf8', magenta: '#f472b6', cyan: '#22d3ee', white: '#e6edf3',
  brightBlack: '#4a5766', brightRed: '#f87171', brightGreen: '#4ade80',
  brightYellow: '#facc15', brightBlue: '#7dd3fc', brightMagenta: '#f9a8d4',
  brightCyan: '#67e8f9', brightWhite: '#ffffff',
}

export class LabShell {
  constructor(el, session, opts = {}) {
    this.session = session
    this.opts = opts
    this.line = ''
    this.cursor = 0
    this.histIdx = -1
    this.busy = false
    this.disposed = false

    this.term = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: "var(--mono), 'JetBrains Mono', Menlo, Consolas, monospace",
      fontSize: opts.fontSize || 13.5,
      lineHeight: 1.25,
      scrollback: 2000,
      theme: THEME,
    })
    this.fit = new FitAddon()
    this.term.loadAddon(this.fit)
    this.term.open(el)
    try { this.fit.fit() } catch (e) { /* element not sized yet */ }
    this.term.onData((d) => this.onData(d))
    this.term.onResize(() => { try { this.fit.fit() } catch (e) { /* ignore */ } })
    this._onResize = () => { try { this.fit.fit() } catch (e) { /* ignore */ } }
    window.addEventListener('resize', this._onResize)
    if (typeof ResizeObserver !== 'undefined') {
      this._ro = new ResizeObserver(() => this._onResize())
      this._ro.observe(el)
    }
  }

  banner() {
    const t = this.term
    t.writeln('\x1b[1;36mЛаборатория\x1b[0m \x1b[2m— встроенный шелл. Набери \x1b[0mhelp\x1b[2m, чтобы увидеть инструменты.\x1b[0m')
    const st = this.session.getState()
    t.writeln(`\x1b[2mРабочий каталог: ${st.cwd}\x1b[0m`)
    t.writeln('')
    this.prompt()
  }

  prompt() {
    const st = this.session.getState()
    const home = st.env.HOME || '/home/student'
    let cwd = st.cwd
    if (cwd === home) cwd = '~'
    else if (cwd.startsWith(home + '/')) cwd = '~' + cwd.slice(home.length)
    const user = st.env.USER || 'student'
    const host = st.env.HOSTNAME || 'lab'
    this.term.write(`\x1b[1;32m${user}@${host}\x1b[0m:\x1b[1;34m${cwd}\x1b[0m$ `)
  }

  async onData(data) {
    if (this.disposed) return
    const t = this.term
    // Ctrl-C
    if (data === '\x03') { t.write('^C\r\n'); this.line = ''; this.cursor = 0; this.prompt(); return }
    // Ctrl-L
    if (data === '\x0c') { t.clear(); this.prompt(); return }
    // Enter
    if (data === '\r') { await this.submit(); return }
    // Backspace
    if (data === '\x7f') { if (this.cursor > 0) { this.line = this.line.slice(0, this.cursor - 1) + this.line.slice(this.cursor); this.cursor--; this.redraw() } return }
    // Tab
    if (data === '\t') { this.tabComplete(); return }
    // Arrow keys
    if (data === '\x1b[A') { this.historyPrev(); return }
    if (data === '\x1b[B') { this.historyNext(); return }
    if (data === '\x1b[D') { if (this.cursor > 0) { this.cursor--; t.write('\b') } return }
    if (data === '\x1b[C') { if (this.cursor < this.line.length) { t.write(this.line[this.cursor]); this.cursor++ } return }
    if (data.startsWith('\x1b')) return
    // Printable (ignore other control chars)
    if (data >= ' ') {
      this.line = this.line.slice(0, this.cursor) + data + this.line.slice(this.cursor)
      this.cursor += data.length
      this.redraw()
    }
  }

  redraw() {
    // Rewrite the current input line in place.
    this.term.write('\x1b[2K\r')
    const st = this.session.getState()
    const home = st.env.HOME || '/home/student'
    let cwd = st.cwd
    if (cwd === home) cwd = '~'
    else if (cwd.startsWith(home + '/')) cwd = '~' + cwd.slice(home.length)
    const user = st.env.USER || 'student'
    const host = st.env.HOSTNAME || 'lab'
    this.term.write(`\x1b[1;32m${user}@${host}\x1b[0m:\x1b[1;34m${cwd}\x1b[0m$ ${this.line}`)
    const back = this.line.length - this.cursor
    if (back > 0) this.term.write(`\x1b[${back}D`)
  }

  historyPrev() {
    const h = this.session.getState().history
    if (!h.length) return
    if (this.histIdx === -1) this.histIdx = h.length
    if (this.histIdx > 0) this.histIdx--
    this.line = h[this.histIdx] || ''
    this.cursor = this.line.length
    this.redraw()
  }

  historyNext() {
    const h = this.session.getState().history
    if (this.histIdx === -1) return
    if (this.histIdx < h.length - 1) { this.histIdx++; this.line = h[this.histIdx] } else { this.histIdx = -1; this.line = '' }
    this.cursor = this.line.length
    this.redraw()
  }

  tabComplete() {
    const st = this.session.getState()
    const cands = complete(this.line, { cwd: st.cwd, vfs: this.session.vfs, toolNames: this.session.toolNames })
    if (!cands.length) return
    const cp = commonPrefix(cands)
    if (cands.length === 1) {
      const c = cands[0]
      this.line = this.line.slice(0, this.line.length - (this.line.match(/(\S*)$/) || [''])[1].length) + c + (c.endsWith('/') ? '' : ' ')
    } else if (cp.length > (this.line.match(/(\S*)$/) || [''])[1].length) {
      this.line = this.line.slice(0, this.line.length - (this.line.match(/(\S*)$/) || [''])[1].length) + cp
    } else {
      this.term.write('\r\n' + cands.join('  ') + '\r\n')
    }
    this.cursor = this.line.length
    this.redraw()
  }

  async submit() {
    const line = this.line
    this.term.write('\r\n')
    this.line = ''
    this.cursor = 0
    this.histIdx = -1
    if (this.busy) return
    this.busy = true
    try {
      const r = await this.session.run(line)
      if (r.clear) this.term.clear()
      if (r.parts && r.parts.length) {
        for (const p of r.parts) {
          if (p.s === 'err') this.writeErr(p.t)
          else this.writeOut(p.t)
        }
      } else {
        if (r.stdout) this.writeOut(r.stdout)
        if (r.stderr) this.writeErr(r.stderr)
      }
    } catch (e) {
      this.writeErr(`ошибка: ${e.message}\r\n`)
    } finally {
      this.busy = false
      this.prompt()
    }
  }

  writeOut(s) { this.term.write(s.replace(/\n/g, '\r\n')) }
  writeErr(s) { this.term.write('\x1b[31m' + s.replace(/\n/g, '\r\n') + '\x1b[0m') }

  /** Run a command from outside (e.g. the hint button). */
  async runExternal(cmd) {
    this.term.write(`\x1b[2m> ${cmd}\x1b[0m\r\n`)
    const r = await this.session.run(cmd)
    if (r.stdout) this.writeOut(r.stdout)
    if (r.stderr) this.writeErr(r.stderr)
    this.prompt()
  }

  focus() { try { this.term.focus() } catch (e) { /* ignore */ } }

  dispose() {
    this.disposed = true
    window.removeEventListener('resize', this._onResize)
    if (this._ro) this._ro.disconnect()
    try { this.term.dispose() } catch (e) { /* ignore */ }
  }
}
