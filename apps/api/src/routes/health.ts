import type { FastifyInstance } from 'fastify'
import { getPool } from '../lib/db.js'

export async function healthRoutes(app: FastifyInstance) {
  app.get('/health', async (_req, reply) => {
    try {
      await getPool().query('SELECT 1')
      return reply.send({ status: 'ok', db: 'connected' })
    } catch {
      return reply.status(503).send({ status: 'error', db: 'unavailable' })
    }
  })
}
