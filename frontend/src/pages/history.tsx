import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Ban,
  ChevronLeft,
  ChevronRight,
  Download,
  History as HistoryIcon,
  Loader2,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';

import { EmptyState, PageHeader } from '@/components/shared/app-layout';
import { SeverityBadge, StatusBadge } from '@/components/shared/severity-badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useAuth } from '@/hooks/use-auth';
import { errorMessage } from '@/service/api.service';
import {
  blockIp,
  downloadCsv,
  fetchAttackSummary,
  fetchAttackTypes,
  fetchAttacks,
  mitigateAttack,
} from '@/service/monitoring.service';
import { formatBytes, formatDateTime, formatNumber } from '@/lib/viz';

const PAGE_SIZE = 20;

const PERIODS = [
  { value: 'all', label: 'Toute la periode', hours: null },
  { value: '1', label: 'Derniere heure', hours: 1 },
  { value: '24', label: 'Dernieres 24 h', hours: 24 },
  { value: '168', label: 'Derniers 7 jours', hours: 168 },
];

/** Page Historique : journal des alertes, filtres, export CSV, mitigation
 * et blocage des IP sources. */
export default function HistoryPage() {
  const { canWrite } = useAuth();
  const queryClient = useQueryClient();

  const [page, setPage] = useState(0);
  const [type, setType] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [period, setPeriod] = useState('all');
  const [since, setSince] = useState<string | undefined>(undefined);
  const [ipInput, setIpInput] = useState('');
  const [ip, setIp] = useState('');
  const [sort, setSort] = useState<'recent' | 'severity'>('recent');

  // La borne temporelle est figee au moment du choix : la requete reste stable
  const changePeriod = (value: string) => {
    const hours = PERIODS.find((row) => row.value === value)?.hours;
    setPeriod(value);
    setSince(hours ? new Date(Date.now() - hours * 3600_000).toISOString() : undefined);
    setPage(0);
  };

  const filters = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    attack_type: type === 'all' ? undefined : type,
    severity: severity === 'all' ? undefined : severity,
    attack_status: status === 'all' ? undefined : status,
    ip: ip || undefined,
    since,
    sort,
  };

  const { data, isLoading } = useQuery({
    queryKey: ['attacks', filters],
    queryFn: () => fetchAttacks(filters),
    refetchInterval: 30000,
  });

  const { data: types } = useQuery({ queryKey: ['attack-types'], queryFn: fetchAttackTypes });
  const { data: summary } = useQuery({
    queryKey: ['attack-summary'],
    queryFn: () => fetchAttackSummary(24),
    refetchInterval: 60000,
  });

  const mitigate = useMutation({
    mutationFn: mitigateAttack,
    onSuccess: (attack) => {
      toast.success(`Alerte ${attack.attack_type} marquee comme mitigee`);
      queryClient.invalidateQueries({ queryKey: ['attacks'] });
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const block = useMutation({
    mutationFn: ({ address, reason }: { address: string; reason: string }) =>
      blockIp(address, reason),
    onSuccess: (entry) => toast.success(`IP ${entry.ip_address} bloquee`),
    onError: (error) => toast.error(errorMessage(error)),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const applySearch = (event: React.FormEvent) => {
    event.preventDefault();
    setIp(ipInput.trim());
    setPage(0);
  };

  const resetFilters = () => {
    setType('all');
    setSeverity('all');
    setStatus('all');
    setPeriod('all');
    setSince(undefined);
    setIp('');
    setIpInput('');
    setPage(0);
  };

  return (
    <div className="min-w-0">
      <PageHeader
        title="Historique"
        subtitle="Journal chronologique de toutes les alertes"
        icon={HistoryIcon}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              downloadCsv('/attacks/export/csv', 'historique_alertes.csv', {
                attack_type: type === 'all' ? undefined : type,
                severity: severity === 'all' ? undefined : severity,
                ip: ip || undefined,
                since,
              }).catch((error) => toast.error(errorMessage(error)))
            }
          >
            <Download className="size-3.5" />
            Exporter en CSV
          </Button>
        }
      />

      <div className="p-4 md:p-6 space-y-5 max-w-[1600px]">
        {/* Synthese 24 h par criticite */}
        {summary && summary.by_severity.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((level) => {
              const row = summary.by_severity.find((s) => s.severity === level);
              return (
                <div key={level} className="rounded-xl border bg-card p-4 space-y-2">
                  <SeverityBadge severity={level as never} />
                  <p className="text-2xl font-bold">{row?.count ?? 0}</p>
                  <p className="text-[11px] text-muted-foreground">alertes sur 24 h</p>
                </div>
              );
            })}
          </div>
        )}

        {/* Filtres — une seule rangee au-dessus du tableau */}
        <div className="rounded-xl border bg-card p-4 space-y-3">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div className="space-y-1.5">
              <Label className="text-xs">Type d’attaque</Label>
              <Select
                value={type}
                onValueChange={(value) => {
                  setType(value);
                  setPage(0);
                }}
              >
                <SelectTrigger className="h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les types</SelectItem>
                  {(types ?? []).map((row) => (
                    <SelectItem key={row.attack_type} value={row.attack_type}>
                      {row.attack_type} ({row.count})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Criticite</Label>
              <Select
                value={severity}
                onValueChange={(value) => {
                  setSeverity(value);
                  setPage(0);
                }}
              >
                <SelectTrigger className="h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Toutes</SelectItem>
                  <SelectItem value="CRITICAL">Critique</SelectItem>
                  <SelectItem value="HIGH">Elevee</SelectItem>
                  <SelectItem value="MEDIUM">Moyenne</SelectItem>
                  <SelectItem value="LOW">Faible</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Etat</Label>
              <Select
                value={status}
                onValueChange={(value) => {
                  setStatus(value);
                  setPage(0);
                }}
              >
                <SelectTrigger className="h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous</SelectItem>
                  <SelectItem value="ACTIVE">Active</SelectItem>
                  <SelectItem value="MITIGATED">Mitigee</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Periode</Label>
              <Select value={period} onValueChange={changePeriod}>
                <SelectTrigger className="h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PERIODS.map((row) => (
                    <SelectItem key={row.value} value={row.value}>
                      {row.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <form onSubmit={applySearch} className="space-y-1.5">
              <Label className="text-xs" htmlFor="ip-search">
                Adresse IP
              </Label>
              <div className="flex gap-1.5">
                <Input
                  id="ip-search"
                  className="h-9 text-xs"
                  placeholder="192.168.1.10"
                  value={ipInput}
                  onChange={(event) => setIpInput(event.target.value)}
                />
                <Button type="submit" variant="secondary" size="icon" className="h-9 w-9 shrink-0">
                  <Search className="size-4" />
                  <span className="sr-only">Rechercher</span>
                </Button>
              </div>
            </form>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t">
            <p className="text-xs text-muted-foreground pt-2">
              {formatNumber(total)} alerte(s) correspondante(s)
            </p>
            <div className="flex items-center gap-2 pt-2">
              <Select value={sort} onValueChange={(value) => setSort(value as 'recent' | 'severity')}>
                <SelectTrigger className="h-8 w-[170px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="recent">Trier par date</SelectItem>
                  <SelectItem value="severity">Trier par criticite</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={resetFilters}>
                Reinitialiser
              </Button>
            </div>
          </div>
        </div>

        {/* Journal */}
        <div className="rounded-xl border bg-card overflow-hidden">
          {isLoading ? (
            <div className="flex justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin text-primary" />
            </div>
          ) : items.length === 0 ? (
            <EmptyState
              message="Aucune alerte pour ces criteres"
              hint="Elargissez la periode ou reinitialisez les filtres."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date et heure</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Cible</TableHead>
                  <TableHead className="text-right">Flux</TableHead>
                  <TableHead className="text-right">Paquets</TableHead>
                  <TableHead className="text-right">Volume</TableHead>
                  <TableHead className="text-right">Confiance</TableHead>
                  <TableHead>Criticite</TableHead>
                  <TableHead>Etat</TableHead>
                  {canWrite && <TableHead className="text-right">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((attack) => (
                  <TableRow key={attack.id} className="text-xs">
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      {formatDateTime(attack.timestamp)}
                    </TableCell>
                    <TableCell className="font-mono font-medium">{attack.attack_type}</TableCell>
                    <TableCell className="font-mono">{attack.source_ip}</TableCell>
                    <TableCell className="font-mono">{attack.destination_ip}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {formatNumber(attack.flows_count)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {formatNumber(attack.total_packets)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {formatBytes(attack.total_bytes)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {attack.avg_confidence.toFixed(1)} %
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={attack.severity} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={attack.status} />
                    </TableCell>
                    {canWrite && (
                      <TableCell className="text-right whitespace-nowrap">
                        {attack.status === 'ACTIVE' && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => mitigate.mutate(attack.id)}
                            title="Marquer comme mitigee"
                          >
                            <ShieldCheck className="size-3.5" />
                            Mitiger
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-red-600 dark:text-red-400"
                          onClick={() =>
                            block.mutate({
                              address: attack.source_ip,
                              reason: `Attaque ${attack.attack_type} (alerte #${attack.id})`,
                            })
                          }
                          title="Bloquer l’IP source"
                        >
                          <Ban className="size-3.5" />
                          Bloquer
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {/* Pagination */}
          {total > PAGE_SIZE && (
            <div className="flex items-center justify-between gap-3 px-5 py-3 border-t">
              <p className="text-xs text-muted-foreground">
                Page {page + 1} sur {pageCount}
              </p>
              <div className="flex gap-1.5">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8"
                  disabled={page === 0}
                  onClick={() => setPage((value) => Math.max(0, value - 1))}
                >
                  <ChevronLeft className="size-3.5" />
                  Precedent
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8"
                  disabled={page + 1 >= pageCount}
                  onClick={() => setPage((value) => value + 1)}
                >
                  Suivant
                  <ChevronRight className="size-3.5" />
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Principales sources */}
        {summary && summary.top_sources.length > 0 && (
          <div className="rounded-xl border bg-card overflow-hidden">
            <div className="px-5 py-3 border-b">
              <h2 className="text-sm font-semibold">Principales sources d’attaque (24 h)</h2>
              <p className="text-xs text-muted-foreground">
                Adresses IP a l’origine du plus grand nombre d’alertes
              </p>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Adresse IP</TableHead>
                  <TableHead className="text-right">Alertes</TableHead>
                  <TableHead className="text-right">Flux cumules</TableHead>
                  {canWrite && <TableHead className="text-right">Action</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {summary.top_sources.map((row) => (
                  <TableRow key={row.source_ip} className="text-xs">
                    <TableCell className="font-mono">{row.source_ip}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">{row.alerts}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">{row.flows}</TableCell>
                    {canWrite && (
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-red-600 dark:text-red-400"
                          onClick={() =>
                            block.mutate({
                              address: row.source_ip,
                              reason: `Source recurrente — ${row.alerts} alertes sur 24 h`,
                            })
                          }
                        >
                          <Ban className="size-3.5" />
                          Bloquer
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}
