// ShieldFive CLI — talk to a running agent.

import { connect } from 'node:net'

import { socketPath } from './paths.mjs'
import { encode, lineSplitter } from './protocol.mjs'

export class AgentUnavailableError extends Error {
  constructor(message) {
    super(message)
    this.name = 'AgentUnavailableError'
    this.code = 'agent_unavailable'
  }
}

export class AgentRequestError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'AgentRequestError'
    this.code = code
  }
}

/**
 * Send one request and resolve with the result.
 *
 * `timeoutMs: 0` disables the timeout, which uploads and syncs need: a large
 * file can take longer than any fixed number.
 */
export function request(op, args = {}, { path = socketPath(), timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    const socket = connect({ path })

    const settle = (fn, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      fn(value)
    }

    const timer = timeoutMs
      ? setTimeout(
          () => settle(reject, new AgentRequestError('timeout', `Agent did not answer within ${timeoutMs} ms.`)),
          timeoutMs,
        )
      : null

    socket.on('error', (err) => {
      if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
        settle(reject, new AgentUnavailableError('The ShieldFive agent is not running. Run sf login.'))
      } else {
        settle(reject, err)
      }
    })

    socket.setEncoding('utf8')
    socket.on(
      'data',
      lineSplitter((line) => {
        let message
        try {
          message = JSON.parse(line)
        } catch {
          return settle(reject, new AgentRequestError('bad_response', 'Agent sent something that is not JSON.'))
        }
        if (message.ok) settle(resolve, message.result)
        else settle(reject, new AgentRequestError(message.error?.code ?? 'error', message.error?.message ?? 'Agent refused.'))
      }),
    )
    socket.on('close', () =>
      settle(reject, new AgentRequestError('closed', 'Agent closed the connection without answering.')),
    )

    socket.on('connect', () => socket.write(encode({ id: 1, op, args })))
  })
}

/** The agent's status, or null when no agent is listening. */
export async function agentStatus(options = {}) {
  try {
    return await request('status', {}, { timeoutMs: 2_000, ...options })
  } catch (err) {
    if (err instanceof AgentUnavailableError) return null
    throw err
  }
}
