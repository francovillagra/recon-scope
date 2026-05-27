import Link from 'next/link'

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: string
  title: string
  description: string
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 px-6 py-6">
      <div className="mb-3 text-2xl">{icon}</div>
      <h3 className="text-base font-semibold text-white mb-1">{title}</h3>
      <p className="text-sm text-slate-400 leading-relaxed">{description}</p>
    </div>
  )
}

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-white">
      {/* Nav */}
      <nav className="mx-auto flex max-w-5xl items-center justify-between px-6 py-5">
        <span className="font-mono text-lg font-bold tracking-tight text-white">
          recon-scope
        </span>
        <div className="flex items-center gap-4">
          <Link
            href="/login"
            className="text-sm text-slate-400 hover:text-white transition-colors"
          >
            Log in
          </Link>
          <Link
            href="/register"
            className="rounded-md bg-brand-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-brand-700 transition-colors"
          >
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="mx-auto max-w-5xl px-6 pb-24 pt-20 text-center">
        <div className="mb-4 inline-block rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-medium text-slate-400 tracking-wide">
          Authorized targets only
        </div>
        <h1 className="text-5xl font-extrabold tracking-tight text-white sm:text-6xl">
          recon-scope
        </h1>
        <p className="mx-auto mt-5 max-w-xl text-lg text-slate-400">
          Automated reconnaissance platform for authorized security assessments.
          Enumerate subdomains, scan ports, fingerprint services — all from a
          single dashboard.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
          <Link
            href="/register"
            className="rounded-lg bg-brand-600 px-6 py-3 text-sm font-semibold text-white hover:bg-brand-700 transition-colors"
          >
            Get Started
          </Link>
          <a
            href="https://github.com/francovillagra/recon-scope"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-slate-700 bg-slate-900 px-6 py-3 text-sm font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
          >
            View on GitHub
          </a>
        </div>
      </section>

      {/* Feature cards */}
      <section className="mx-auto max-w-5xl px-6 pb-24">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <FeatureCard
            icon="◎"
            title="Subdomain Enumeration"
            description="Passive discovery via crt.sh with async DNS resolution. No brute-force — only authorized, low-noise enumeration."
          />
          <FeatureCard
            icon="⬡"
            title="Port Scanning"
            description="Asyncio TCP connect scan across top-100, top-1000, or full port ranges. Banner grabbing and service identification included."
          />
          <FeatureCard
            icon="⟨/⟩"
            title="Fingerprinting"
            description="HTTP header analysis, tech stack detection, TLS certificate capture, and a findings engine with critical-to-info severity levels."
          />
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8 text-center text-xs text-slate-600">
        recon-scope — authorized targets only
      </footer>
    </main>
  )
}
