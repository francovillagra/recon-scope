'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'

const navItems = [
  { href: '/dashboard', label: 'Overview', icon: '◈' },
  { href: '/dashboard/domains', label: 'Domains', icon: '◎' },
  // Scans and Reports are unlocked in later phases
]

export function Sidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const { user, logout } = useAuth()

  function handleLogout() {
    logout()
    router.push('/login')
  }

  return (
    <aside className="flex h-screen w-56 flex-col border-r border-slate-200 bg-slate-900 text-slate-200">
      {/* Logo */}
      <div className="flex items-center gap-2 px-5 py-5 border-b border-slate-700">
        <span className="text-brand-500 text-xl font-mono font-bold">⬡</span>
        <span className="font-semibold tracking-wide text-sm uppercase text-white">
          Recon Platform
        </span>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const active = pathname.startsWith(item.href)
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors
                ${
                  active
                    ? 'bg-brand-600 text-white'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                }`}
            >
              <span className="font-mono text-xs">{item.icon}</span>
              {item.label}
            </Link>
          )
        })}

        <div className="pt-4 mt-4 border-t border-slate-700 space-y-1">
          <Link
            href="/dashboard/domains/new"
            className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <span className="font-mono text-xs">+</span>
            Add Domain
          </Link>
        </div>
      </nav>

      {/* User + Logout */}
      <div className="border-t border-slate-700 px-3 py-4">
        <p className="truncate px-3 text-xs text-slate-400 mb-2">{user?.email}</p>
        <button
          onClick={handleLogout}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-red-400 transition-colors"
        >
          <span className="font-mono text-xs">→</span>
          Sign out
        </button>
      </div>
    </aside>
  )
}
