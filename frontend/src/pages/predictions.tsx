import { useQuery } from '@tanstack/react-query';
import { Brain, Download, Loader2, Percent } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { EmptyState, PageHeader } from '@/components/shared/app-layout';
import { ChartTooltip } from '@/components/shared/chart-tooltip';
import { ClassBadge } from '@/components/shared/severity-badge';
import { useTheme } from '@/components/shared/theme-provider';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';
import { formatCompact, formatNumber, formatTime, vizPalette } from '@/lib/viz';
import { errorMessage } from '@/service/api.service';
import {
  downloadCsv,
  fetchPredictionDistribution,
  fetchPredictions,
} from '@/service/monitoring.service';

const CONFIDENCE_STEPS = [
  { value: '0', label: 'Toutes' },
  { value: '70', label: '≥ 70 %' },
  { value: '90', label: '≥ 90 %' },
  { value: '99', label: '≥ 99 %' },
];

const PROTOCOL_LABELS: Record<number, string> = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };

/** Page Predictions : repartition des classes, niveaux de confiance et
 * detail des flux classes par le modele. */
export default function PredictionsPage() {
  const { theme } = useTheme();
  const palette = vizPalette(theme);
  const [onlyAttacks, setOnlyAttacks] = useState(false);
  const [attackType, setAttackType] = useState('all');
  const [minConfidence, setMinConfidence] = useState('0');

  const { data: distribution } = useQuery({
    queryKey: ['prediction-distribution'],
    queryFn: () => fetchPredictionDistribution(24),
    refetchInterval: 20000,
  });

  const filters = {
    limit: 100,
    only_attacks: onlyAttacks || undefined,
    attack_type: attackType === 'all' ? undefined : attackType,
    min_confidence: Number(minConfidence) || undefined,
  };

  const { data: predictions, isLoading } = useQuery({
    queryKey: ['predictions', filters],
    queryFn: () => fetchPredictions(filters),
    refetchInterval: 15000,
  });

  const chartData = (distribution ?? [])
    .filter((row) => row.count > 0)
    .sort((a, b) => b.count - a.count);

  const observedClasses = (distribution ?? []).filter((row) => row.count > 0).map((row) => row.name);

  return (
    <div className="min-w-0">
      <PageHeader
        title="Predictions"
        subtitle="Classification detaillee des flux par le modele Random Forest"
        icon={Brain}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              downloadCsv('/predictions/export', 'predictions.csv', {
                only_attacks: onlyAttacks || undefined,
              }).catch((error) => toast.error(errorMessage(error)))
            }
          >
            <Download className="size-3.5" />
            Exporter en CSV
          </Button>
        }
      />

      <div className="p-4 md:p-6 space-y-5 max-w-[1600px]">
        {/* Repartition des classes */}
        <div className="rounded-xl border bg-card p-5 space-y-3">
          <div>
            <h2 className="text-sm font-semibold">Repartition des classes predites (24 h)</h2>
            <p className="text-xs text-muted-foreground">
              Nombre de flux par classe — bleu pour le trafic legitime, rouge pour les attaques
            </p>
          </div>
          {chartData.length ? (
            <ResponsiveContainer width="100%" height={26 * chartData.length + 60}>
              <BarChart data={chartData} layout="vertical" barCategoryGap="22%">
                <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fill: palette.muted, fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(value) => formatCompact(value)}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fill: palette.muted, fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  width={72}
                  interval={0}
                />
                <Tooltip
                  content={<ChartTooltip valueFormatter={(v) => `${formatNumber(v)} flux`} />}
                  cursor={{ fill: palette.grid, opacity: 0.3 }}
                />
                <Bar isAnimationActive={false} dataKey="count" name="Flux" radius={[0, 4, 4, 0]} maxBarSize={22}>
                  {chartData.map((row) => (
                    <Cell key={row.name} fill={row.is_attack ? palette.attack : palette.benign} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState message="Aucune prediction sur les dernieres 24 heures" />
          )}
        </div>

        {/* Niveaux de confiance par classe */}
        {chartData.length > 0 && (
          <div className="rounded-xl border bg-card p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold">Niveaux de confiance</h2>
              <p className="text-xs text-muted-foreground">
                Confiance moyenne du modele pour chaque classe observee
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {chartData.map((row) => (
                <div key={row.name} className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <ClassBadge name={row.name} />
                    <span className="text-xs font-mono text-muted-foreground tabular-nums">
                      {row.avg_confidence.toFixed(1)} % · {formatNumber(row.count)} flux
                    </span>
                  </div>
                  <Progress value={row.avg_confidence} className="h-2" />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filtres + tableau des flux classes */}
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="flex flex-wrap items-end justify-between gap-3 px-5 py-3 border-b">
            <div>
              <h2 className="text-sm font-semibold">Flux classes</h2>
              <p className="text-xs text-muted-foreground">
                Les 100 predictions les plus recentes
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <Switch
                  id="only-attacks"
                  checked={onlyAttacks}
                  onCheckedChange={setOnlyAttacks}
                />
                <Label htmlFor="only-attacks" className="text-xs">
                  Attaques uniquement
                </Label>
              </div>
              <Select value={attackType} onValueChange={setAttackType}>
                <SelectTrigger className="h-8 w-[140px] text-xs">
                  <SelectValue placeholder="Classe" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Toutes les classes</SelectItem>
                  {observedClasses.map((name) => (
                    <SelectItem key={name} value={name}>
                      {name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={minConfidence} onValueChange={setMinConfidence}>
                <SelectTrigger className="h-8 w-[120px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONFIDENCE_STEPS.map((step) => (
                    <SelectItem key={step.value} value={step.value}>
                      {step.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {isLoading ? (
            <div className="flex justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin text-primary" />
            </div>
          ) : !predictions?.length ? (
            <EmptyState
              message="Aucune prediction pour ces criteres"
              hint="Desactivez les filtres ou attendez le prochain cycle d’analyse."
            />
          ) : (
            <div className="max-h-[600px] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 bg-card z-10">
                  <TableRow>
                    <TableHead>Heure</TableHead>
                    <TableHead>Classe predite</TableHead>
                    <TableHead>Confiance</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Cible</TableHead>
                    <TableHead>Proto</TableHead>
                    <TableHead className="text-right">Port dest.</TableHead>
                    <TableHead className="text-right">Paquets</TableHead>
                    <TableHead className="text-right">Debit (o/s)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {predictions.map((prediction) => (
                    <TableRow
                      key={prediction.id}
                      className={cn('text-xs', prediction.is_attack && 'bg-red-500/5')}
                    >
                      <TableCell className="text-muted-foreground whitespace-nowrap">
                        {formatTime(prediction.prediction_timestamp)}
                      </TableCell>
                      <TableCell>
                        <ClassBadge name={prediction.prediction} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2 min-w-[120px]">
                          <Progress value={prediction.confidence} className="h-1.5 flex-1" />
                          <span className="font-mono tabular-nums text-[11px] w-12 text-right">
                            {prediction.confidence.toFixed(1)}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono">{prediction.flow?.src_ip ?? '—'}</TableCell>
                      <TableCell className="font-mono">{prediction.flow?.dst_ip ?? '—'}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">
                        {prediction.flow ? PROTOCOL_LABELS[prediction.flow.protocol] ?? prediction.flow.protocol : '—'}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {prediction.flow?.dst_port ?? '—'}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {prediction.flow
                          ? formatNumber(prediction.flow.tot_fwd_pkts + prediction.flow.tot_bwd_pkts)
                          : '—'}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {prediction.flow ? formatCompact(prediction.flow.flow_byts_s) : '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>

        <p className="text-[11px] text-muted-foreground flex items-center gap-1.5">
          <Percent className="w-3 h-3" aria-hidden />
          La confiance correspond a la probabilite maximale renvoyee par la foret aleatoire pour la
          classe retenue.
        </p>
      </div>
    </div>
  );
}
