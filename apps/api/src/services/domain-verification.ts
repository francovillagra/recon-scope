import dns from 'dns/promises'

const FETCH_TIMEOUT_MS = 8_000

export async function verifyDnsTxt(
  domain: string,
  token: string,
): Promise<boolean> {
  const recordName = `_recon-verify.${domain}`
  try {
    const records = await dns.resolveTxt(recordName)
    // resolveTxt returns string[][] — flatten to string[]
    return records.flat().some((v) => v.trim() === token)
  } catch {
    return false
  }
}

export async function verifyWellKnownFile(
  domain: string,
  token: string,
): Promise<boolean> {
  const url = `https://${domain}/.well-known/recon-verification.txt`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
    })
    clearTimeout(timer)
    if (!res.ok) return false
    const text = await res.text()
    return text.trim() === token
  } catch {
    clearTimeout(timer)
    return false
  }
}
