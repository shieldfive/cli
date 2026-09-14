// ShieldFive CLI — terminal prompts.
//
// The password prompt reads in raw mode and echoes nothing, not even asterisks:
// a count of characters is a fact about the password. There is deliberately no
// way to pass a password on the command line, where it would sit in shell
// history and in every process listing on the machine.

import { createInterface } from 'node:readline'

// Written as escapes on purpose. Literal control characters in source are
// invisible in review and easy to lose in an editor; a prompt that silently
// stopped matching Ctrl-C would trap the user in raw mode.
const CTRL_C = '\u0003'
const CTRL_D = '\u0004'
const BACKSPACE = '\u007f'
const CTRL_H = '\b'

/** Prompt for a single visible line (an email address, a TOTP code). */
export function promptLine(question, { input = process.stdin, output = process.stderr } = {}) {
  return new Promise((resolve, reject) => {
    const rl = createInterface({ input, output })
    rl.question(question, (answer) => {
      rl.close()
      resolve(answer)
    })
    rl.on('error', reject)
  })
}

/** Prompt for a secret without echoing it. Needs a terminal. */
export function promptHidden(question, { input = process.stdin, output = process.stderr } = {}) {
  if (!input.isTTY || typeof input.setRawMode !== 'function') {
    return Promise.reject(
      new Error(
        'A password prompt needs a terminal. Run sf login in an interactive ' +
          'shell; it cannot read a password from a pipe.',
      ),
    )
  }

  return new Promise((resolve, reject) => {
    const wasRaw = Boolean(input.isRaw)
    let value = ''

    const finish = (err) => {
      input.off('data', onData)
      input.setRawMode(wasRaw)
      input.pause()
      output.write('\n')
      if (err) reject(err)
      else resolve(value)
    }

    const onData = (chunk) => {
      for (const ch of String(chunk)) {
        if (ch === '\r' || ch === '\n') return finish()
        if (ch === CTRL_C) return finish(new Error('Cancelled.'))
        if (ch === CTRL_D) {
          if (!value) return finish(new Error('Cancelled.'))
          continue
        }
        if (ch === BACKSPACE || ch === CTRL_H) {
          value = value.slice(0, -1)
          continue
        }
        // Other control characters, including the escape sequences arrow keys
        // send, are not part of a password.
        if (ch < ' ') continue
        value += ch
      }
    }

    output.write(question)
    input.setEncoding('utf8')
    input.setRawMode(true)
    input.resume()
    input.on('data', onData)
  })
}
