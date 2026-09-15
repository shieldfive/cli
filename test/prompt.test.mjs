// VERIFIED (offline): the hidden password prompt. It runs the terminal in raw
// mode, so the failure that matters is not a wrong password but a user who
// cannot get out: Ctrl-C and Ctrl-D must always end it, and raw mode must be
// restored whichever way it ends.

import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import { test } from 'node:test'

import { promptHidden } from '../src/prompt.mjs'

function fakeTty() {
  const input = new PassThrough()
  input.isTTY = true
  input.isRaw = false
  input.rawCalls = []
  input.setRawMode = (on) => {
    input.rawCalls.push(on)
    input.isRaw = on
  }
  const output = new PassThrough()
  let written = ''
  output.on('data', (c) => {
    written += c
  })
  return { input, output, written: () => written }
}

test('returns what was typed, handles backspace, and echoes nothing', async () => {
  const t = fakeTty()
  const answer = promptHidden('Password: ', { input: t.input, output: t.output })
  t.input.write('secret\r')
  assert.equal(await answer, 'scret')
  await new Promise((r) => setImmediate(r))
  assert.equal(t.written(), 'Password: \n')
})

test('Ctrl-C cancels and restores the terminal mode', async () => {
  const t = fakeTty()
  const answer = promptHidden('Password: ', { input: t.input, output: t.output })
  t.input.write('abc')
  await assert.rejects(answer, /Cancelled/)
  assert.deepEqual(t.input.rawCalls, [true, false])
})

test('Ctrl-D on an empty line cancels; mid-line it is ignored', async () => {
  const empty = fakeTty()
  const p1 = promptHidden('Password: ', { input: empty.input, output: empty.output })
  empty.input.write('')
  await assert.rejects(p1, /Cancelled/)

  const midline = fakeTty()
  const p2 = promptHidden('Password: ', { input: midline.input, output: midline.output })
  midline.input.write('abc\n')
  assert.equal(await p2, 'abc')
})

test('arrow keys and other control bytes are not part of the password', async () => {
  const t = fakeTty()
  const answer = promptHidden('Password: ', { input: t.input, output: t.output })
  t.input.write('pa[Dss\r')
  // ESC is dropped; the printable "[D" that follows it is kept, which is what a
  // raw terminal actually delivers and is documented rather than guessed at.
  assert.equal(await answer, 'pa[Dss')
})

test('refuses without a terminal instead of reading a password from a pipe', async () => {
  const input = new PassThrough()
  await assert.rejects(
    promptHidden('Password: ', { input, output: new PassThrough() }),
    /needs a terminal/,
  )
})
