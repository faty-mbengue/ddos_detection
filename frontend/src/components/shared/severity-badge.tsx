import { AlertOctagon, AlertTriangle, Info, ShieldAlert, ShieldCheck } from 'lucide-react';

import { cn } from '@/lib/utils';
import { SEVERITY_STYLES } from '@/lib/viz';
import type { AttackStatus, Severity } from '@/types';

const SEVERITY_ICONS = {
  LOW: Info,
  MEDIUM: AlertTriangle,
  HIGH: ShieldAlert,
  CRITICAL: AlertOctagon,
} as const;

const SEVERITY_LABELS = {
  LOW: 'Faible',
  MEDIUM: 'Moyenne',
  HIGH: 'Elevee',
  CRITICAL: 'Critique',
} as const;

/** Criticite : couleur + icone + libelle — jamais la couleur seule. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const Icon = SEVERITY_ICONS[severity] ?? Info;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium',
        SEVERITY_STYLES[severity],
        className
      )}
    >
      <Icon className="w-3 h-3 shrink-0" aria-hidden />
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  );
}

/** Etat de l'alerte : ACTIVE (en cours) ou MITIGATED (traitee). */
export function StatusBadge({ status }: { status: AttackStatus }) {
  const active = status === 'ACTIVE';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium',
        active
          ? 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30'
          : 'bg-muted text-muted-foreground border-border'
      )}
    >
      {active ? (
        <ShieldAlert className="w-3 h-3 shrink-0" aria-hidden />
      ) : (
        <ShieldCheck className="w-3 h-3 shrink-0" aria-hidden />
      )}
      {active ? 'Active' : 'Mitigee'}
    </span>
  );
}

/** Classe predite : le libelle porte l'identite, la couleur le caractere benin/malveillant. */
export function ClassBadge({ name, className }: { name: string; className?: string }) {
  const benign = name === 'BENIGN';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px] font-medium',
        benign
          ? 'bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/30'
          : 'bg-red-500/10 text-red-700 dark:text-red-300 border-red-500/30',
        className
      )}
    >
      {benign ? (
        <ShieldCheck className="w-3 h-3 shrink-0" aria-hidden />
      ) : (
        <ShieldAlert className="w-3 h-3 shrink-0" aria-hidden />
      )}
      {name}
    </span>
  );
}
