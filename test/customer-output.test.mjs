import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { readFile, readdir } from 'node:fs/promises'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const supplier = /\b(?:Backblaze|B2|Amazon(?: Web Services)?|AWS|Cloudflare|Supabase|MinIO)\b/i

test('CLI help and non-comment source lines do not mention suppliers', async () => {
  const src = new URL('../src/', import.meta.url)
  const help = execFileSync(process.execPath, [fileURLToPath(new URL('cli.mjs', src)), '--help'], { encoding: 'utf8' })
  assert.doesNotMatch(help, supplier)
  for (const doc of ['README.md', 'CHANGELOG.md', 'docs/agent-design.md']) {
    assert.doesNotMatch(await readFile(new URL(`../${doc}`, import.meta.url), 'utf8'), supplier, doc)
  }
  for (const entry of await readdir(src, { recursive: true })) {
    if (!entry.endsWith('.mjs')) continue
    const lines = (await readFile(new URL(entry.replaceAll('\\', '/'), src), 'utf8')).split('\n')
    for (const [index, line] of lines.entries()) {
      // Source comments and imports describe implementation dependencies.
      if (/^\s*(?:\/\/|\/\*|\*|import\b)/.test(line)) continue
      // The service endpoint is used internally to configure authentication.
      if (/^\s*supabaseUrl: /.test(line)) continue
      // Import specifiers describe implementation dependencies.
      const literals = line.trim().replace(/^.*?from ['"][^'"]+['"]$/, '')
      const strings = literals.match(/(['"`])(?:\\.|(?!\1).)*\1/g) ?? []
      for (const str of strings) assert.doesNotMatch(str, supplier, `${entry}:${index + 1}`)
    }
  }
})

test('Windows login points to environment credentials before prompting', () => {
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url))
  const windows = "data:text/javascript,Object.defineProperty(process,'platform',{value:'win32'})"
  const result = spawnSync(process.execPath, ['--import', windows, cli, 'login', '--idle'], { encoding: 'utf8' })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /Windows.*SF_EMAIL and SF_PASSWORD.*sf push/)
  assert.doesNotMatch(result.stderr, supplier)
})
