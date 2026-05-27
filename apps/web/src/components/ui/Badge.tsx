type Variant = 'verified' | 'pending' | 'failed' | 'neutral'

const styles: Record<Variant, string> = {
  verified: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  pending: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  failed: 'bg-red-50 text-red-700 ring-red-600/20',
  neutral: 'bg-slate-50 text-slate-700 ring-slate-600/20',
}

const labels: Record<Variant, string> = {
  verified: 'Verified',
  pending: 'Pending',
  failed: 'Failed',
  neutral: 'Unknown',
}

interface BadgeProps {
  variant: Variant
  label?: string
  className?: string
}

export function Badge({ variant, label, className = '' }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${styles[variant]} ${className}`}
    >
      {label ?? labels[variant]}
    </span>
  )
}
