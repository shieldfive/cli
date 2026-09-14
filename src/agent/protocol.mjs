// ShieldFive CLI — the agent's wire protocol.
//
// Newline-delimited JSON over a Unix domain socket: one request line, one
// response line.
//
// The operation list is an allowlist and it is deliberately short. There is no
// operation that lists vault contents, downloads, decrypts, or returns key
// material, and adding one would change what a process that can reach the
// socket is able to do. A test pins the list so that change cannot happen by
// accident.

import { isAbsolute } from 'node:path'

export const OPS = Object.freeze(['status', 'upload', 'sync', 'verify', 'lock', 'logout'])
const OP_SET = new Set(OPS)

export const MAX_LINE_BYTES = 1_000_000
export const MAX_VERIFY_PATHS = 500
const MAX_PATH_LENGTH = 4096

export class ProtocolError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'ProtocolError'
    this.code = code
  }
}

export function encode(message) {
  return JSON.stringify(message) + '\n'
}

export function ok(id, result) {
  return { id, ok: true, result }
}

export function fail(id, code, message) {
  return { id, ok: false, error: { code, message } }
}

/**
 * Split an incoming UTF-8 text stream into lines.
 *
 * The socket must be set to 'utf8' encoding first so a multi-byte character
 * split across two chunks is reassembled before it gets here. A line longer
 * than MAX_LINE_BYTES is an error rather than an unbounded buffer.
 */
export function lineSplitter(onLine, { maxBytes = MAX_LINE_BYTES } = {}) {
  let buffer = ''
  return (chunk) => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      if (line.trim()) onLine(line)
    }
    if (Buffer.byteLength(buffer) > maxBytes) {
      buffer = ''
      throw new ProtocolError('line_too_long', `A request line exceeded ${maxBytes} bytes.`)
    }
  }
}

function absolutePath(value, name) {
  if (typeof value !== 'string' || !value || value.length > MAX_PATH_LENGTH) {
    throw new ProtocolError('bad_request', `${name} must be a path of at most ${MAX_PATH_LENGTH} characters.`)
  }
  if (!isAbsolute(value) || value.includes('\0')) {
    throw new ProtocolError('bad_request', `${name} must be an absolute path.`)
  }
  return value
}

/** Parse and validate one request line. Throws ProtocolError. */
export function parseRequest(line) {
  let message
  try {
    message = JSON.parse(line)
  } catch {
    throw new ProtocolError('bad_json', 'Request is not valid JSON.')
  }
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    throw new ProtocolError('bad_request', 'Request must be a JSON object.')
  }

  const { id, op } = message
  if (!(typeof id === 'string' || Number.isInteger(id)) || String(id).length > 64) {
    throw new ProtocolError('bad_request', 'Request id must be a string or integer.')
  }
  if (typeof op !== 'string' || !OP_SET.has(op)) {
    throw new ProtocolError(
      'unknown_op',
      `Unknown operation ${JSON.stringify(op)}. The agent performs only: ${OPS.join(', ')}.`,
    )
  }

  const args = message.args ?? {}
  if (typeof args !== 'object' || Array.isArray(args)) {
    throw new ProtocolError('bad_request', 'args must be an object.')
  }

  switch (op) {
    case 'upload':
      return { id, op, args: { path: absolutePath(args.path, 'path') } }
    case 'sync':
      return { id, op, args: { folder: absolutePath(args.folder, 'folder') } }
    case 'verify': {
      if (!Array.isArray(args.paths) || args.paths.length === 0) {
        throw new ProtocolError('bad_request', 'paths must be a non-empty array.')
      }
      if (args.paths.length > MAX_VERIFY_PATHS) {
        throw new ProtocolError('bad_request', `At most ${MAX_VERIFY_PATHS} paths per verify.`)
      }
      return { id, op, args: { paths: args.paths.map((p, i) => absolutePath(p, `paths[${i}]`)) } }
    }
    default:
      return { id, op, args: {} }
  }
}
