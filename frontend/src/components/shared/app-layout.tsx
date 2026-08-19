import { useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Menu, ShieldAlert, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { toast } from 'sonner';

import { AppSidebar, NAV_ITEMS } from '@/components/shared/app-sidebar';
import { ModeToggle } from '@/components/shared/theme-toogle';
import { SeverityBadge } from '@/components/shared/severity-badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/use-auth';
import { useWebSocket } from '@/hooks/use-websocket';
import { cn } from '@/lib/utils';
import type { Attack } from '@/types';

interface AlertEvent {
  type: string;
  data: Attack;
}

/**
 * Coquille de l'application : barre laterale permanente, banniere d'alerte
 * temps reel et memorisation de la derniere page visitee.
 */
export function AppLayout() {
  const location = useLocation();
  const queryClient = useQueryClient();
  const [banner, setBanner] = useState<Attack | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const { isAdmin } = useAuth();

  // Memorise la derniere page visitee (cf. Description systeme, 3.2)
  useEffect(() => {
    localStorage.setItem('ddos-monitor-last-page', location.pathname);
  }, [location.pathname]);

  // Canal d'alertes : banniere + notification, et invalidation des caches
  useWebSocket<AlertEvent>({
    channel: 'alerts',
    onMessage: (message) => {
      if (message.type !== 'attack') return;
      setBanner(message.data);
      toast.error(`Attaque ${message.data.attack_type} detectee`, {
        description: `${message.data.source_ip} → ${message.data.destination_ip} · ${message.data.flows_count} flux · confiance ${message.data.avg_confidence.toFixed(1)} %`,
      });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['attacks'] });
      queryClient.invalidateQueries({ queryKey: ['live-stats'] });
    },
  });

  return (
    <div className="min-h-screen flex bg-background">
      <AppSidebar />

      <div className="flex-1 min-w-0 flex flex-col">
        {/* Barre superieure mobile */}
        <header className="md:hidden flex items-center justify-between border-b px-3 h-14 sticky top-0 bg-background/95 backdrop-blur z-20">
          <Button variant="ghost" size="icon" onClick={() => setMobileOpen((open) => !open)}>
            {mobileOpen ? <X className="size-5" /> : <Menu className="size-5" />}
            <span className="sr-only">Menu</span>
          </Button>
          <span className="font-bold text-sm">DDoS Monitor</span>
          <ModeToggle />
        </header>

        {mobileOpen && (
          <nav className="md:hidden border-b p-2 space-y-0.5 bg-sidebar">
            {NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin).map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium',
                      isActive
                        ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                        : 'text-muted-foreground'
                    )
                  }
                >
                  <Icon className="w-4 h-4" aria-hidden />
                  {item.label}
                </NavLink>
              );
            })}
          </nav>
        )}

        {/* Banniere d'alerte (code couleur rouge + animation) */}
        {banner && (
          <div
            role="alert"
            className="flex items-start gap-3 border-b border-red-500/40 bg-red-500/10 px-4 py-3 animate-in slide-in-from-top-2"
          >
            <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5 animate-pulse" aria-hidden />
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-red-700 dark:text-red-300">
                  Attaque {banner.attack_type} en cours
                </p>
                <SeverityBadge severity={banner.severity} />
              </div>
              <p className="text-xs text-muted-foreground">
                Source <span className="font-mono">{banner.source_ip}</span> → cible{' '}
                <span className="font-mono">{banner.destination_ip}</span> · {banner.flows_count}{' '}
                flux · confiance moyenne {banner.avg_confidence.toFixed(1)} %
              </p>
            </div>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setBanner(null)}>
              <X className="size-4" />
              <span className="sr-only">Fermer l’alerte</span>
            </Button>
          </div>
        )}

        <main className="flex-1 min-w-0">
          <Outlet />
        </main>

        <footer className="border-t px-4 py-3">
          <p className="text-center text-[11px] text-muted-foreground">
            DDoS Monitor · detection Random Forest sur CICDDoS2019 · 12 classes de trafic
          </p>
        </footer>
      </div>
    </div>
  );
}

/** Bandeau d'information affiche en tete de page. */
export function PageHeader({
  title,
  subtitle,
  icon: Icon,
  actions,
}: {
  title: string;
  subtitle: string;
  icon: React.ElementType;
  actions?: React.ReactNode;
}) {
  return (
    <div className="border-b sticky top-0 bg-background/95 backdrop-blur z-10">
      <div className="px-4 md:px-6 py-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-1.5 rounded-lg bg-primary/10 shrink-0">
            <Icon className="w-5 h-5 text-primary" aria-hidden />
          </div>
          <div className="min-w-0">
            <h1 className="font-bold leading-tight truncate">{title}</h1>
            <p className="text-xs text-muted-foreground truncate">{subtitle}</p>
          </div>
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
      </div>
    </div>
  );
}

/** Etat vide reutilisable. */
export function EmptyState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-16 text-center">
      <AlertTriangle className="w-7 h-7 text-muted-foreground" aria-hidden />
      <p className="text-sm font-medium">{message}</p>
      {hint && <p className="text-xs text-muted-foreground max-w-sm">{hint}</p>}
    </div>
  );
}
