import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertCircle,
  Gauge,
  Loader2,
  Radar as RadarIcon,
  ShieldAlert,
  ShieldCheck,
  Target,
  TrendingUp,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { EmptyState, PageHeader } from '@/components/shared/app-layout';
import { ChartTooltip } from '@/components/shared/chart-tooltip';
import { KpiCard } from '@/components/shared/kpi-card';
import { SourceFilter, TOUTES_SOURCES } from '@/components/shared/source-filter';
import { SeverityBadge, StatusBadge } from '@/components/shared/severity-badge';
import { useTheme } from '@/components/shared/theme-provider';
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
import {
  formatBytes,
  formatCompact,
  formatHour,
  formatNumber,
  relativeTime,
  vizPalette,
} from '@/lib/viz';
import { fetchDashboard } from '@/service/monitoring.service';
import { useState } from 'react';

const RANGES = [
  { value: '1', label: 'Derniere heure' },
  { value: '6', label: '6 dernieres heures' },
  { value: '24', label: '24 dernieres heures' },
  { value: '168', label: '7 derniers jours' },
];

/** Encadre un graphique avec son titre et sa legende explicative. */
function ChartCard({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border bg-card p-5 space-y-3">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      {children}
    </div>
  );
}

/** Page Tableau de bord : indicateurs cles et les quatre visualisations de
 * synthese (distribution des classes, part du trafic malveillant,
 * evolution temporelle, confiance par classe). */
export default function DashboardPage() {
  const { theme } = useTheme();
  const palette = vizPalette(theme);
  const [hours, setHours] = useState('24');
  // Provenance des donnees : evite d'additionner trafic simule et trafic reel.
  const [source, setSource] = useState(TOUTES_SOURCES);

  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', hours, source],
    queryFn: () =>
      fetchDashboard(Number(hours), source === TOUTES_SOURCES ? undefined : source),
    refetchInterval: 20000,
  });

  if (isLoading) {
    return (
      <>
        <PageHeader title="Tableau de bord" subtitle="Indicateurs cles et graphiques de synthese" icon={Gauge} />
        <div className="flex flex-col items-center gap-3 py-24 text-muted-foreground">
          <Loader2 className="w-7 h-7 animate-spin text-primary" />
          <p className="text-sm">Chargement des indicateurs…</p>
        </div>
      </>
    );
  }

  if (error || !data) {
    return (
      <>
        <PageHeader title="Tableau de bord" subtitle="Indicateurs cles et graphiques de synthese" icon={Gauge} />
        <div className="p-6 max-w-md mx-auto">
          <div className="rounded-xl border bg-card p-6 text-center space-y-3">
            <AlertCircle className="w-8 h-8 text-amber-500 mx-auto" aria-hidden />
            <p className="font-semibold">Donnees indisponibles</p>
            <p className="text-sm text-muted-foreground">
              Impossible de joindre <code>/api/dashboard</code>. Verifiez que le backend FastAPI est
              demarre.
            </p>
          </div>
        </div>
      </>
    );
  }

  const { overview, class_distribution, attacks_over_time, confidence_by_class, recent_attacks } = data;
  const underAttack = overview.system_status === 'ATTACK';

  // ── Histogramme : distribution des classes (encodage benin / malveillant) ──
  const distribution = class_distribution
    .filter((row) => row.count > 0)
    .sort((a, b) => b.count - a.count);

  // ── Camembert : trafic normal contre trafic malveillant ───────────────────
  const trafficSplit = [
    { name: 'Trafic legitime', value: overview.benign_flows, color: palette.benign },
    { name: 'Trafic malveillant', value: overview.total_attacks, color: palette.attack },
  ].filter((slice) => slice.value > 0);

  // ── Courbe : evolution des attaques dans le temps ─────────────────────────
  const timeline = attacks_over_time.map((row) => ({
    heure: formatHour(row.bucket),
    Attaques: row.attacks,
    Legitimes: row.benign,
  }));

  // ── Graphique polaire : confiance moyenne du modele par classe ────────────
  const radar = confidence_by_class
    .filter((row) => row.count > 0)
    .map((row) => ({ classe: row.name, Confiance: Number(row.avg_confidence.toFixed(1)) }));

  return (
    <div className="min-w-0">
      <PageHeader
        title="Tableau de bord"
        subtitle="Indicateurs cles, graphiques de synthese et dernieres alertes"
        icon={Gauge}
        actions={
          <>
            <SourceFilter value={source} onChange={setSource} />
            <Select value={hours} onValueChange={setHours}>
              <SelectTrigger className="h-8 w-[170px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {RANGES.map((range) => (
                  <SelectItem key={range.value} value={range.value}>
                    {range.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </>
        }
      />

      <div className="p-4 md:p-6 space-y-6 max-w-[1600px]">
        {/* Indicateurs cles de performance */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <KpiCard
            label="Etat du systeme"
            value={underAttack ? 'Attaque' : 'Normal'}
            sub={
              overview.last_attack_at
                ? `Derniere alerte ${relativeTime(overview.last_attack_at)}`
                : 'Aucune alerte enregistree'
            }
            icon={underAttack ? ShieldAlert : ShieldCheck}
            tone={underAttack ? 'danger' : 'success'}
          />
          <KpiCard
            label="Flux analyses"
            value={formatCompact(overview.total_flows)}
            sub={`${formatNumber(overview.benign_flows)} legitimes · ${formatNumber(overview.total_attacks)} malveillants`}
            icon={Activity}
          />
          <KpiCard
            label="Taux d’attaque"
            value={`${overview.attack_ratio.toFixed(1)} %`}
            sub={`${overview.distinct_attack_types} type(s) d’attaque observe(s)`}
            icon={Target}
            tone={overview.attack_ratio > 20 ? 'danger' : 'default'}
          />
          <KpiCard
            label="Debit courant"
            value={`${formatNumber(overview.packets_per_second)} pkt/s`}
            sub={`${formatBytes(overview.bytes_per_second)}/s${overview.top_source_ip ? ` · top source ${overview.top_source_ip}` : ''}`}
            icon={Gauge}
          />
        </div>

        {/* Graphiques */}
        <div className="grid lg:grid-cols-2 gap-5">
          <ChartCard
            title="Distribution des classes detectees"
            description="Nombre de flux par classe — le libelle porte l’identite, la couleur le caractere du trafic"
          >
            {distribution.length ? (
              <>
                <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: palette.benign }}
                      aria-hidden
                    />
                    Trafic legitime
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: palette.attack }}
                      aria-hidden
                    />
                    Attaque DDoS
                  </span>
                </div>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={distribution} barCategoryGap="25%">
                    <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} vertical={false} />
                    <XAxis
                      dataKey="name"
                      tick={{ fill: palette.muted, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      angle={-35}
                      textAnchor="end"
                      height={55}
                      interval={0}
                    />
                    <YAxis
                      tick={{ fill: palette.muted, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      width={45}
                      tickFormatter={(value) => formatCompact(value)}
                    />
                    <Tooltip
                      content={<ChartTooltip valueFormatter={(v) => `${formatNumber(v)} flux`} />}
                      cursor={{ fill: palette.grid, opacity: 0.3 }}
                    />
                    <Bar isAnimationActive={false} dataKey="count" name="Flux" radius={[4, 4, 0, 0]} maxBarSize={44}>
                      {distribution.map((row) => (
                        <Cell
                          key={row.name}
                          fill={row.is_attack ? palette.attack : palette.benign}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </>
            ) : (
              <EmptyState message="Aucune prediction sur la periode" />
            )}
          </ChartCard>

          <ChartCard
            title="Trafic legitime contre trafic malveillant"
            description="Repartition des flux classes par le modele sur la periode selectionnee"
          >
            {trafficSplit.length ? (
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie
                    isAnimationActive={false}
                    data={trafficSplit}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={62}
                    outerRadius={95}
                    paddingAngle={2}
                    strokeWidth={2}
                    stroke={palette.surface}
                    label={({ name, percent }) =>
                      `${name} — ${((percent ?? 0) * 100).toFixed(1)} %`
                    }
                    labelLine={false}
                    fontSize={11}
                  >
                    {trafficSplit.map((slice) => (
                      <Cell key={slice.name} fill={slice.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={<ChartTooltip valueFormatter={(v) => `${formatNumber(v)} flux`} />}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState message="Aucun flux classe sur la periode" />
            )}
          </ChartCard>

          <ChartCard
            title="Evolution des attaques dans le temps"
            description="Flux classes par heure — malveillants contre legitimes"
          >
            {timeline.length > 1 ? (
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={timeline} margin={{ top: 5, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} vertical={false} />
                  <XAxis
                    dataKey="heure"
                    tick={{ fill: palette.muted, fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    minTickGap={24}
                  />
                  <YAxis
                    tick={{ fill: palette.muted, fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    width={45}
                  />
                  <Tooltip
                    content={<ChartTooltip valueFormatter={(v) => `${formatNumber(v)} flux`} />}
                    cursor={{ stroke: palette.axis, strokeWidth: 1 }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11, paddingTop: 8 }} />
                  <Line
                    isAnimationActive={false}
                    type="monotone"
                    dataKey="Attaques"
                    stroke={palette.attack}
                    strokeWidth={2}
                    dot={{ r: 3, strokeWidth: 2, stroke: palette.surface }}
                    activeDot={{ r: 5 }}
                  />
                  <Line
                    isAnimationActive={false}
                    type="monotone"
                    dataKey="Legitimes"
                    stroke={palette.benign}
                    strokeWidth={2}
                    dot={{ r: 3, strokeWidth: 2, stroke: palette.surface }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState
                message="Historique insuffisant"
                hint="La courbe apparait des que plusieurs cycles horaires sont enregistres."
              />
            )}
          </ChartCard>

          <ChartCard
            title="Confiance du modele par classe"
            description="Confiance moyenne des predictions, par classe observee (0 a 100 %)"
          >
            {radar.length >= 3 ? (
              <ResponsiveContainer width="100%" height={260}>
                <RadarChart data={radar} outerRadius="72%">
                  <PolarGrid stroke={palette.grid} />
                  <PolarAngleAxis dataKey="classe" tick={{ fill: palette.muted, fontSize: 10 }} />
                  {/* Les graduations radiales chevauchent les libelles de classe :
                      l'echelle 0-100 % est rappelee dans le sous-titre et l'infobulle. */}
                  <PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} />
                  <Radar
                    isAnimationActive={false}
                    name="Confiance moyenne"
                    dataKey="Confiance"
                    stroke={palette.benign}
                    strokeWidth={2}
                    fill={palette.benign}
                    fillOpacity={0.22}
                  />
                  <Tooltip content={<ChartTooltip valueFormatter={(v) => `${v.toFixed(1)} %`} />} />
                </RadarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState
                message="Trop peu de classes observees"
                hint="Le graphique polaire requiert au moins trois classes predites."
              />
            )}
          </ChartCard>
        </div>

        {/* Dernieres alertes */}
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="flex items-center justify-between gap-3 px-5 py-3 border-b">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-primary" aria-hidden />
              <div>
                <h2 className="text-sm font-semibold">Dernieres alertes</h2>
                <p className="text-xs text-muted-foreground">
                  Les 10 evenements les plus recents
                </p>
              </div>
            </div>
            <Link
              to="/history"
              className="text-xs text-muted-foreground hover:text-foreground border rounded-md px-3 py-1.5 transition-colors"
            >
              Voir l’historique
            </Link>
          </div>

          {recent_attacks.length === 0 ? (
            <EmptyState message="Aucune attaque enregistree" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Horodatage</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Cible</TableHead>
                  <TableHead className="text-right">Flux</TableHead>
                  <TableHead className="text-right">Confiance</TableHead>
                  <TableHead>Criticite</TableHead>
                  <TableHead>Etat</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent_attacks.map((attack) => (
                  <TableRow key={attack.id} className="text-xs">
                    <TableCell className="text-muted-foreground">
                      {relativeTime(attack.timestamp)}
                    </TableCell>
                    <TableCell className="font-mono font-medium">{attack.attack_type}</TableCell>
                    <TableCell className="font-mono">{attack.source_ip}</TableCell>
                    <TableCell className="font-mono">{attack.destination_ip}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {attack.flows_count}
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
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>

        <p className="text-[11px] text-muted-foreground flex items-center gap-1.5">
          <RadarIcon className="w-3 h-3" aria-hidden />
          Les 12 classes du modele sont identifiees par leur libelle ; la couleur ne code que la
          nature du trafic (legitime ou malveillant), de facon a rester lisible en vision des
          couleurs deficiente.
        </p>
      </div>
    </div>
  );
}
