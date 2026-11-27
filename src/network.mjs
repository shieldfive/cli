export const API_REQUEST_TIMEOUT_MS = 30_000
export const STORAGE_REQUEST_TIMEOUT_MS = 120_000
export const MAX_RETRY_DELAY_MS = 60_000

export function networkCode(cause) {
  const err = cause?.cause ?? cause
  if (err?.name === 'TimeoutError' || err?.name === 'AbortError' || /TIMEOUT/.test(err?.code ?? '')) return 'ETIMEDOUT'
  const code = err?.code
  if (code === 'UND_ERR_SOCKET') return 'ECONNRESET'
  if (/TLS|SSL|CERT|SELF_SIGNED|ISSUER/.test(code ?? '')) {
    return /^[A-Z0-9_]{1,64}$/.test(code) ? `TLS ${code}` : 'TLS'
  }
  return /^(E[A-Z0-9_]{1,24}|UND_ERR_[A-Z_]{1,32})$/.test(code ?? '') ? code : 'NETWORK_ERROR'
}

export function networkError(operation, cause, host) {
  const code = networkCode(cause)
  return Object.assign(new Error(`${operation} failed (${code})${host ? ` at ${host}` : ''}`, { cause }), {
    uploadNetworkError: true, networkCode: code, host,
  })
}

export async function networkRequest(url, init, operation, timeoutMs = API_REQUEST_TIMEOUT_MS, fetchImpl = fetch) {
  try {
    return await fetchImpl(url, {
      ...init, signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (cause) {
    throw networkError(operation, cause, new URL(url).host)
  }
}

export async function readJson(res, operation) {
  try {
    return await res.json()
  } catch (cause) {
    if (!res.ok) return {}
    throw networkError(`${operation} reply`, cause, res.url ? new URL(res.url).host : undefined)
  }
}

// Token sources can share an in-flight refresh. Bound the caller's wait
// without starting another refresh or interrupting the other callers.
export async function resolveToken(accessToken, options) {
  if (typeof accessToken !== 'function') return accessToken
  let timer
  try {
    return await Promise.race([
      accessToken(options),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(networkError('Get access token', { code: 'ETIMEDOUT' })), API_REQUEST_TIMEOUT_MS)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}
