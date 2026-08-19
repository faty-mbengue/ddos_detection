import type { LucideIcon } from 'lucide-react';

import { cn } from '@/lib/utils';

interface KpiCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: LucideIcon;
  /** Accentue la valeur : neutre par defaut, "danger" en cas d'attaque. */
  tone?: 'default' | 'danger' | 'success';
  className?: string;
}

const TONES = {
  default: 'text-primary',
  danger: 'text-red-600 dark:text-red-400',
  success: 'text-emerald-600 dark:text-emerald-400',
} as const;

export function KpiCard({ label, value, sub, icon: Icon, tone = 'default', className }: KpiCardProps) {
  return (
    <div className={cn('p-4 rounded-xl border bg-card space-y-2', className)}>
      <div className="flex items-center gap-2">
        <Icon className={cn('w-4 h-4 shrink-0', TONES[tone])} aria-hidden />
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <div className={cn('text-2xl font-bold', TONES[tone])}>{value}</div>
      {sub && <p className="text-[11px] text-muted-foreground leading-tight">{sub}</p>}
    </div>
  );
}
