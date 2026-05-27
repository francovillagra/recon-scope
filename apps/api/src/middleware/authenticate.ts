import type { FastifyRequest, FastifyReply } from 'fastify'
import jwt from 'jsonwebtoken'
import type { JWTPayload } from '@recon/core'

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const auth = request.headers.authorization
  if (!auth?.startsWith('Bearer ')) {
    reply.status(401).send({ error: 'Authorization header required' })
    return
  }

  const token = auth.slice(7)
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload
    request.user = payload
  } catch {
    reply.status(401).send({ error: 'Invalid or expired token' })
  }
}
