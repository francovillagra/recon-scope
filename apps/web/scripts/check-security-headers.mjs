// Prueba de humo de las cabeceras de la web contra el servidor de producción ya construido (`pnpm build`).
//   node apps/web/scripts/check-security-headers.mjs
// Falla si las páginas dejan de llevar la Content-Security-Policy con nonce, si algún <script> no lo tiene (la
// página quedaría en blanco en producción) o si falta alguna cabecera de seguridad.
import { spawn } from 'node:child_process'
import path from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const webDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const port = process.env.CHECK_PORT ?? '3987'
const base = `http://127.0.0.1:${port}`
const failures = []
const check = (ok, message) => {
  if (!ok) failures.push(message)
}

const server = spawn(process.execPath, [path.join(webDir, '.next/standalone/apps/web/server.js')], {
  env: { ...process.env, PORT: port, HOSTNAME: '127.0.0.1', NODE_ENV: 'production' },
  stdio: ['ignore', 'pipe', 'pipe'],
})
let serverOutput = ''
server.stdout.on('data', (d) => (serverOutput += d))
server.stderr.on('data', (d) => (serverOutput += d))

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      await fetch(`${base}/login`)
      return
    } catch {
      await sleep(500)
    }
  }
  throw new Error(`el servidor no arrancó:\n${serverOutput}`)
}

async function page(route) {
  const res = await fetch(base + route)
  return { res, html: await res.text(), csp: res.headers.get('content-security-policy') ?? '' }
}

try {
  await waitForServer()
  const nonces = new Set()
  for (const route of ['/', '/login', '/register', '/dashboard']) {
    const { res, html, csp } = await page(route)
    check(res.status === 200, `${route}: devolvió ${res.status}`)
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1]
    check(Boolean(nonce), `${route}: la Content-Security-Policy no trae nonce (${csp || 'sin cabecera'})`)
    if (!nonce) continue
    nonces.add(nonce)
    check(csp.includes("'strict-dynamic'"), `${route}: falta 'strict-dynamic'`)
    check(!csp.includes("'unsafe-eval'"), `${route}: 'unsafe-eval' en producción`)
    check(!/script-src[^;]*'unsafe-inline'/.test(csp), `${route}: 'unsafe-inline' en script-src`)
    check(/object-src 'none'/.test(csp) && /frame-ancestors 'none'/.test(csp), `${route}: faltan object-src/frame-ancestors`)
    const scripts = html.match(/<script\b[^>]*>/g) ?? []
    check(scripts.length > 0, `${route}: la página no tiene scripts`)
    const unmarked = scripts.filter((tag) => !tag.includes(`nonce="${nonce}"`))
    check(
      unmarked.length === 0,
      `${route}: ${unmarked.length} de ${scripts.length} scripts sin el nonce de la respuesta (el navegador los bloquearía; ` +
        `¿la página se generó de antemano?). Ejemplo: ${unmarked[0]?.slice(0, 100)}`,
    )
    const want = {
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
    }
    for (const [name, value] of Object.entries(want)) {
      check(res.headers.get(name) === value, `${route}: ${name} = ${res.headers.get(name)}`)
    }
    for (const name of ['permissions-policy', 'strict-transport-security', 'cross-origin-opener-policy']) {
      check(res.headers.has(name), `${route}: falta ${name}`)
    }
    check(!res.headers.has('x-powered-by'), `${route}: anuncia x-powered-by`)
  }
  check(nonces.size === 4, `el nonce se repitió entre respuestas (${nonces.size} distintos de 4)`)
} catch (err) {
  failures.push(String(err))
} finally {
  server.kill('SIGTERM')
}

if (failures.length) {
  console.error('FALLÓ la comprobación de cabeceras:\n - ' + failures.join('\n - '))
  process.exit(1)
}
console.log('Cabeceras de seguridad de la web: OK')
