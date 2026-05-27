import { randomUUID } from 'crypto'
import type { FastifyInstance } from 'fastify'
import type {
  CreateDomainInput,
  VerifyDomainInput,
  Domain,
  DomainVerificationInstructions,
} from '@recon/core'
import { query, queryOne, transaction } from '../lib/db.js'
import { authenticate } from '../middleware/authenticate.js'
import { verifyDnsTxt, verifyWellKnownFile } from '../services/domain-verification.js'

// Accepts apex domains and subdomains: example.com, api.example.com, etc.
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i

function buildInstructions(
  domain: string,
  token: string,
): DomainVerificationInstructions {
  return {
    domain,
    token,
    dns_txt: {
      record_name: `_recon-verify.${domain}`,
      record_type: 'TXT',
      record_value: token,
    },
    well_known_file: {
      url: `https://${domain}/.well-known/recon-verification.txt`,
      file_path: '.well-known/recon-verification.txt',
      content: token,
    },
  }
}

export async function domainRoutes(app: FastifyInstance) {
  // All domain routes require auth
  app.addHook('preHandler', authenticate)

  // GET /api/v1/domains
  app.get('/domains', async (req, reply) => {
    const domains = await query<Domain>(
      `SELECT id, user_id, domain, verification_status, verification_method,
              verification_token, verified_at, created_at, updated_at
       FROM domains
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.sub],
    )
    return reply.send({ domains })
  })

  // POST /api/v1/domains
  app.post<{ Body: CreateDomainInput }>('/domains', async (req, reply) => {
    const { domain } = req.body ?? {}

    if (!domain || !DOMAIN_RE.test(domain)) {
      return reply.status(400).send({ error: 'Valid domain name required (e.g. example.com)' })
    }

    const normalized = domain.toLowerCase().trim()

    const existing = await queryOne(
      'SELECT id FROM domains WHERE user_id = $1 AND domain = $2',
      [req.user.sub, normalized],
    )
    if (existing) {
      return reply.status(409).send({ error: 'Domain already registered for your account' })
    }

    const token = `recon-verify-${randomUUID()}`

    const row = await queryOne<Domain>(
      `INSERT INTO domains (user_id, domain, verification_token)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [req.user.sub, normalized, token],
    )
    if (!row) throw new Error('Domain insert failed')

    // Audit
    await query(
      `INSERT INTO audit_log (user_id, action, target, ip_address, metadata)
       VALUES ($1, 'domain_registered', $2, $3::inet, $4)`,
      [
        req.user.sub,
        normalized,
        req.ip || null,
        JSON.stringify({ domain_id: row.id }),
      ],
    )

    return reply.status(201).send({
      domain: row,
      instructions: buildInstructions(normalized, token),
    })
  })

  // GET /api/v1/domains/:id
  app.get<{ Params: { id: string } }>('/domains/:id', async (req, reply) => {
    const row = await queryOne<Domain>(
      'SELECT * FROM domains WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.sub],
    )
    if (!row) return reply.status(404).send({ error: 'Domain not found' })

    return reply.send({
      domain: row,
      instructions: buildInstructions(row.domain, row.verification_token),
    })
  })

  // POST /api/v1/domains/:id/verify
  app.post<{ Params: { id: string }; Body: VerifyDomainInput }>(
    '/domains/:id/verify',
    async (req, reply) => {
      const method = req.body?.method ?? 'dns_txt'
      if (method !== 'dns_txt' && method !== 'well_known_file') {
        return reply
          .status(400)
          .send({ error: 'method must be "dns_txt" or "well_known_file"' })
      }

      const row = await queryOne<Domain>(
        'SELECT * FROM domains WHERE id = $1 AND user_id = $2',
        [req.params.id, req.user.sub],
      )
      if (!row) return reply.status(404).send({ error: 'Domain not found' })

      if (row.verification_status === 'verified') {
        return reply.send({ domain: row, already_verified: true })
      }

      const success =
        method === 'dns_txt'
          ? await verifyDnsTxt(row.domain, row.verification_token)
          : await verifyWellKnownFile(row.domain, row.verification_token)

      const updated = await transaction(async (client) => {
        const newStatus = success ? 'verified' : 'failed'
        const { rows } = await client.query<Domain>(
          `UPDATE domains
           SET verification_status = $1,
               verification_method = $2,
               verified_at = $3
           WHERE id = $4
           RETURNING *`,
          [newStatus, method, success ? new Date() : null, row.id],
        )

        const auditAction = success ? 'domain_verified' : 'domain_verification_failed'
        await client.query(
          `INSERT INTO audit_log (user_id, action, target, ip_address, metadata)
           VALUES ($1, $2, $3, $4::inet, $5)`,
          [
            req.user.sub,
            auditAction,
            row.domain,
            req.ip || null,
            JSON.stringify({ domain_id: row.id, method }),
          ],
        )

        return rows[0]
      })

      if (!success) {
        return reply.status(422).send({
          domain: updated,
          error: `Verification failed via ${method}. Ensure the record/file is published and try again.`,
          instructions: buildInstructions(row.domain, row.verification_token),
        })
      }

      return reply.send({ domain: updated })
    },
  )

  // DELETE /api/v1/domains/:id
  app.delete<{ Params: { id: string } }>('/domains/:id', async (req, reply) => {
    const row = await queryOne<Domain>(
      'SELECT id FROM domains WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.sub],
    )
    if (!row) return reply.status(404).send({ error: 'Domain not found' })

    await query('DELETE FROM domains WHERE id = $1', [req.params.id])
    return reply.status(204).send()
  })
}
