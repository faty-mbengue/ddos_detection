import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  BarChart2,
  Brain,
  FileSearch,
  Gauge,
  History,
  LogOut,
  Settings,
  ShieldCheck,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { NavLink } from 'react-router-dom';

import { ModeToggle } from '@/components/shared/theme-toogle';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/use-auth';
import { cn } from '@/lib/utils';
import { fetchSystemStatus } from '@/service/monitoring.service';

/** Une entree de navigation de la barre laterale. */
export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  hint: string;
  /** Entree reservee aux administrateurs : masquee pour les autres roles. */
  adminOnly?: boolean;
}

/** Les 6 sections principales de la barre laterale (cf. Description systeme, 3.2). */
export const NAV_ITEMS: NavItem[] = [
  { to: '/live', label: 'Flux Live', icon: Activity, hint: 'Paquets en temps reel' },
  { to: '/dashboard', label: 'Tableau de bord', icon: Gauge, hint: 'Indicateurs cles' },
  { to: '/history', label: 'Historique', icon: History, hint: 'Journal des alertes' },
  { to: '/predictions', label: 'Predictions', icon: Brain, hint: 'Classification des flux' },
  { to: '/metrics', label: 'Metriques', icon: BarChart2, hint: 'Performances du modele' },
  { to: '/analyze', label: 'Analyse fichier', icon: FileSearch, hint: 'Rejouer un PCAP ou un CSV' },
  {
    to: '/admin',
    label: 'Administration',
    icon: Settings,
    hint: 'Utilisateurs & config',
    adminOnly: true,
  },
];

const ROLE_LABELS: Record<string, string> = {
  admin: 'Administrateur',
  analyst: 'Analyste',
  viewer: 'Lecture seule',
};

export function AppSidebar() {
  const { user, logout, isAdmin } = useAuth();

  // Indicateur LED : etat reel du pipeline, rafraichi toutes les 10 s
  const { data: status } = useQuery({
    queryKey: ['system-status'],
    queryFn: fetchSystemStatus,
    refetchInterval: 10000,
  });

  // Les entrees reservees aux administrateurs sont retirees, pas desactivees.
  const visibleItems = NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin);

  const running = status?.pipeline_running ?? false;
  const captureBackend = status?.capture.backend;

  return (
    // Barre laterale permanente : collee au viewport pour que la navigation, la LED
    // d'etat et les actions utilisateur restent accessibles sur les pages longues.
    <aside className="hidden md:flex sticky top-0 h-screen w-60 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground">
      {/* En-tete */}
      <div className="flex items-center gap-2.5 px-4 h-14 border-b">
        <div className="p-1.5 rounded-lg bg-primary/10 shrink-0">
          <ShieldCheck className="w-5 h-5 text-primary" aria-hidden />
        </div>
        <div className="min-w-0">
          <p className="font-bold text-sm leading-tight">DDoS Monitor</p>
          <p className="text-[10px] text-muted-foreground">Detection temps reel</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-2 space-y-0.5">
        {/* Une entree inaccessible n'a pas a etre affichee : un analyste ne voit
            donc pas du tout Administration, plutot qu'un lien grise. */}
        {visibleItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              title={item.hint}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                    : 'text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground'
                )
              }
            >
              <Icon className="w-4 h-4 shrink-0" aria-hidden />
              {item.label}
            </NavLink>
          );
        })}
      </nav>

      {/* Pied : etat du systeme + utilisateur */}
      <div className="border-t p-3 space-y-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5 shrink-0" aria-hidden>
            {running && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-60" />
            )}
            <span
              className={cn(
                'relative inline-flex h-2.5 w-2.5 rounded-full',
                running ? 'bg-emerald-500' : 'bg-red-500'
              )}
            />
          </span>
          <div className="min-w-0">
            <p className="text-xs font-medium">{running ? 'Systeme actif' : 'Systeme arrete'}</p>
            <p className="text-[10px] text-muted-foreground truncate">
              {captureBackend
                ? `Capture : ${captureBackend} · ${status?.cycles ?? 0} cycles`
                : 'Etat indisponible'}
            </p>
          </div>
        </div>

        <div className="flex items-center justify-between gap-2 pt-1 border-t">
          <div className="min-w-0 pt-2">
            <p className="text-xs font-medium truncate">{user?.username}</p>
            <p className="text-[10px] text-muted-foreground">
              {ROLE_LABELS[user?.role ?? ''] ?? user?.role}
            </p>
          </div>
          <div className="flex items-center gap-1 pt-2">
            <ModeToggle />
            <Button
              variant="ghost"
              size="icon"
              className="h-9 w-9"
              onClick={logout}
              title="Se deconnecter"
            >
              <LogOut className="size-4" />
              <span className="sr-only">Se deconnecter</span>
            </Button>
          </div>
        </div>
      </div>
    </aside>
  );
}
