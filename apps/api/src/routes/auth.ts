import type { FastifyInstance } from 'fastify'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import type { RegisterInput, LoginInput } from '@recon/core'
import { queryOne } from '../lib/db.js'

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function signToken(payload: { sub: string; email: string; role: string }) {
  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: (process.env.JWT_EXPIRES_IN ?? '7d') as jwt.SignOptions['expiresIn'],
  })
}

export async function authRoutes(app: FastifyInstance) {
  // POST /api/v1/auth/register
  app.post<{ Body: RegisterInput }>('/auth/register', async (req, reply) => {
    const { email, password, tos_accepted } = req.body ?? {}

    if (!email || !EMAIL_RE.test(email)) {
      return reply.status(400).send({ error: 'Valid email required' })
    }
    if (!password || password.length < 8) {
      return reply.status(400).send({ error: 'Password must be at least 8 characters' })
    }
    if (tos_accepted !== true) {
      return reply
        .status(400)
        .send({ error: 'You must accept the Terms of Service to register' })
    }

    const existing = await queryOne(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()],
    )
    if (existing) {
      return reply.status(409).send({ error: 'Email already registered' })
    }

    const rounds = parseInt(process.env.BCRYPT_ROUNDS ?? '12', 10)
    const password_hash = await bcrypt.hash(password, rounds)

    const user = await queryOne<{
      id: string
      email: string
      role: string
      tos_accepted_at: string | null
      created_at: string
    }>(
      `INSERT INTO users (email, password_hash, tos_accepted_at)
       VALUES ($1, $2, now())
       RETURNING id, email, role, tos_accepted_at, created_at`,
      [email.toLowerCase(), password_hash],
    )

    if (!user) throw new Error('User insert failed')

    const token = signToken({ sub: user.id, email: user.email, role: user.role })
    return reply.status(201).send({ token, user })
  })

  // POST /api/v1/auth/login
  app.post<{ Body: LoginInput }>('/auth/login', async (req, reply) => {
    const { email, password } = req.body ?? {}

    if (!email || !password) {
      return reply.status(400).send({ error: 'Email and password required' })
    }

    const user = await queryOne<{
      id: string
      email: string
      role: string
      password_hash: string
      tos_accepted_at: string | null
      created_at: string
    }>(
      `SELECT id, email, role, password_hash, tos_accepted_at, created_at
       FROM users WHERE email = $1`,
      [email.toLowerCase()],
    )

    // Constant-time comparison regardless of whether the user exists
    const dummyHash = '$2a$12$invaliddummyhashfortimingprotection00000000000000000'
    const hashToCheck = user?.password_hash ?? dummyHash
    const match = await bcrypt.compare(password, hashToCheck)

    if (!user || !match) {
      return reply.status(401).send({ error: 'Invalid credentials' })
    }

    const token = signToken({ sub: user.id, email: user.email, role: user.role })

    const { password_hash: _, ...publicUser } = user
    return reply.send({ token, user: publicUser })
  })
}
