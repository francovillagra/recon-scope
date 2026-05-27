export type UserRole = 'user' | 'admin'

export interface User {
  id: string
  email: string
  password_hash: string
  role: UserRole
  tos_accepted_at: string | null
  created_at: string
  updated_at: string
}

export type PublicUser = Omit<User, 'password_hash'>

export interface JWTPayload {
  sub: string
  email: string
  role: UserRole
  iat: number
  exp: number
}

export interface RegisterInput {
  email: string
  password: string
  tos_accepted: boolean
}

export interface LoginInput {
  email: string
  password: string
}

export interface AuthResponse {
  token: string
  user: PublicUser
}
