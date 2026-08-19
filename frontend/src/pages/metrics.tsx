import { useQuery } from '@tanstack/react-query';
import { BarChart2, CheckCircle2, Info, Loader2, Target } from 'lucide-react';
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
import { KpiCard } from '@/components/shared/kpi-card';
import { useTheme } from '@/components/shared/theme-provider';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';
import { formatDateTime, formatNumber, vizPalette } from '@/lib/viz';
import { fetchModelMetrics } from '@/service/monitoring.service';

/** Formate un ratio 0-1 en pourcentage, ou un tiret si la valeur est absente. */
function pct(value: number | null | undefined): string {
  return value == null ? '—' : `${(value * 100).toFixed(2)} %`;
}

/** Sous-titre rappelant la moyenne ponderee quand le modele la fournit. */
function weightedSub(weighted: number | null | undefined): string {
  return weighted == null
    ? 'Moyenne non ponderee'
    : `Moyenne non ponderee · ponderee ${pct(weighted)}`;
}

/** Page Metriques : performances du modele a l'entrainement et comportement
 * observe en production. */
export default function MetricsPage() {
  const { theme } = useTheme();
  const palette = vizPalette(theme);

  const { data, isLoading } = useQuery({
    queryKey: ['model-metrics'],
    queryFn: () => fetchModelMetrics(24),
    refetchInterval: 60000,
  });

  if (isLoading || !data) {
    return (
      <>
        <PageHeader
          title="Metriques"
          subtitle="Performances du modele et statistiques par classe"
          icon={BarChart2}
        />
        <div className="flex justify-center py-24">
          <Loader2 className="w-7 h-7 animate-spin text-primary" />
        </div>
      </>
    );
  }

  const { model, training, feature_importances, production } = data;
  const labels = training.labels ?? [];
  const perClass = Object.entries(training.per_class ?? {});

  // Graphique : F1-score par classe (une seule mesure, une seule teinte)
  const f1Chart = perClass.map(([name, metrics]) => ({
    classe: name,
    'F1-score': Number((metrics.f1 * 100).toFixed(1)),
    is_attack: name !== 'BENIGN',
  }));

  const importanceChart = feature_importances.map((row) => ({
    caracteristique: row.feature,
    Importance: Number((row.importance * 100).toFixed(2)),
  }));

  return (
    <div className="min-w-0">
      <PageHeader
        title="Metriques"
        subtitle="Performances du modele, statistiques par classe et taux de detection"
        icon={BarChart2}
      />

      <div className="p-4 md:p-6 space-y-5 max-w-[1600px]">
        {/* Bandeau : provenance du modele */}
        <div
          className={cn(
            'rounded-xl border px-4 py-3 flex items-start gap-3',
            model.is_demo ? 'bg-amber-500/10 border-amber-500/30' : 'bg-primary/5'
          )}
        >
          <Info
            className={cn(
              'w-4 h-4 shrink-0 mt-0.5',
              model.is_demo ? 'text-amber-600 dark:text-amber-400' : 'text-primary'
            )}
            aria-hidden
          />
          <div className="text-xs space-y-1">
            <p className="font-semibold">
              {model.algorithm ?? 'Modele'} · {model.n_features} caracteristiques ·{' '}
              {model.n_classes} classes
            </p>
            <p className="text-muted-foreground">
              Jeu de donnees : {model.dataset ?? 'non renseigne'}
              {model.trained_at && ` · entraine le ${formatDateTime(model.trained_at)}`}
            </p>
            {model.is_demo && (
              <p className="text-amber-700 dark:text-amber-300">
                Modele de demonstration genere automatiquement. Deposez les artefacts du notebook
                CICDDoS2019 dans <code>backend/app/ml/artifacts/</code> (model.joblib, scaler.joblib,
                metadata.json) puis rechargez le modele depuis l’Administration.
              </p>
            )}
          </div>
        </div>

        {/* Les 4 metriques du memoire */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <KpiCard
            label="Accuracy"
            value={pct(training.accuracy)}
            sub={`${formatNumber(training.n_test ?? 0)} echantillons de test`}
            icon={Target}
          />
          {/* Macro = moyenne simple des 12 classes ; ponderee = par leur support.
              L'ecart entre les deux revele les classes minoritaires mal predites. */}
          <KpiCard
            label="Precision (macro)"
            value={pct(training.precision_macro)}
            sub={weightedSub(training.precision_weighted)}
            icon={Target}
          />
          <KpiCard
            label="Recall (macro)"
            value={pct(training.recall_macro)}
            sub={weightedSub(training.recall_weighted)}
            icon={Target}
          />
          <KpiCard
            label="F1-Score (macro)"
            value={pct(training.f1_macro)}
            sub={weightedSub(training.f1_weighted)}
            icon={CheckCircle2}
          />
        </div>

        <Tabs defaultValue="par-classe">
          <TabsList>
            <TabsTrigger value="par-classe">Par classe</TabsTrigger>
            <TabsTrigger value="caracteristiques">Caracteristiques</TabsTrigger>
            <TabsTrigger value="confusion">Matrice de confusion</TabsTrigger>
            <TabsTrigger value="production">En production</TabsTrigger>
          </TabsList>

          {/* ── Performances par classe ── */}
          <TabsContent value="par-classe" className="space-y-5">
            <div className="rounded-xl border bg-card p-5 space-y-3">
              <div>
                <h2 className="text-sm font-semibold">F1-score par classe d’attaque</h2>
                <p className="text-xs text-muted-foreground">
                  Sur le jeu de test — bleu pour le trafic legitime, rouge pour les attaques
                </p>
              </div>
              {f1Chart.length ? (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={f1Chart} barCategoryGap="25%">
                    <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} vertical={false} />
                    <XAxis
                      dataKey="classe"
                      tick={{ fill: palette.muted, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      angle={-35}
                      textAnchor="end"
                      height={55}
                      interval={0}
                    />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fill: palette.muted, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      width={42}
                      tickFormatter={(value) => `${value}%`}
                    />
                    <Tooltip
                      content={<ChartTooltip valueFormatter={(v) => `${v.toFixed(1)} %`} />}
                      cursor={{ fill: palette.grid, opacity: 0.3 }}
                    />
                    <Bar isAnimationActive={false} dataKey="F1-score" radius={[4, 4, 0, 0]} maxBarSize={44}>
                      {f1Chart.map((row) => (
                        <Cell
                          key={row.classe}
                          fill={row.is_attack ? palette.attack : palette.benign}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="Metriques d’entrainement indisponibles" />
              )}
            </div>

            <div className="rounded-xl border bg-card overflow-hidden">
              <div className="px-5 py-3 border-b">
                <h2 className="text-sm font-semibold">Rapport de classification</h2>
                <p className="text-xs text-muted-foreground">
                  Precision, rappel et F1 par classe, avec le support du jeu de test
                </p>
              </div>
              {perClass.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Classe</TableHead>
                      <TableHead className="text-right">Precision</TableHead>
                      <TableHead className="text-right">Rappel</TableHead>
                      <TableHead className="text-right">F1-score</TableHead>
                      <TableHead className="text-right">Support</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {perClass.map(([name, metrics]) => (
                      <TableRow key={name} className="text-xs">
                        <TableCell>
                          <ClassBadge name={name} />
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {pct(metrics.precision)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {pct(metrics.recall)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums font-semibold text-primary">
                          {pct(metrics.f1)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums text-muted-foreground">
                          {formatNumber(metrics.support)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState message="Rapport indisponible" />
              )}
            </div>
          </TabsContent>

          {/* ── Importance des caracteristiques ── */}
          <TabsContent value="caracteristiques">
            <div className="rounded-xl border bg-card p-5 space-y-3">
              <div>
                <h2 className="text-sm font-semibold">
                  Caracteristiques les plus discriminantes
                </h2>
                <p className="text-xs text-muted-foreground">
                  Importance relative attribuee par la foret aleatoire (15 premieres sur{' '}
                  {model.n_features})
                </p>
              </div>
              {importanceChart.length ? (
                <ResponsiveContainer width="100%" height={420}>
                  <BarChart data={importanceChart} layout="vertical" barCategoryGap="20%">
                    <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} horizontal={false} />
                    <XAxis
                      type="number"
                      tick={{ fill: palette.muted, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      tickFormatter={(value) => `${value}%`}
                    />
                    <YAxis
                      type="category"
                      dataKey="caracteristique"
                      tick={{ fill: palette.muted, fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      width={175}
                      interval={0}
                    />
                    <Tooltip
                      content={<ChartTooltip valueFormatter={(v) => `${v.toFixed(2)} %`} />}
                      cursor={{ fill: palette.grid, opacity: 0.3 }}
                    />
                    <Bar
                    isAnimationActive={false}
                      dataKey="Importance"
                      fill={palette.benign}
                      radius={[0, 4, 4, 0]}
                      maxBarSize={18}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="Importances indisponibles pour ce modele" />
              )}
            </div>
          </TabsContent>

          {/* ── Matrice de confusion ── */}
          <TabsContent value="confusion">
            <div className="rounded-xl border bg-card p-5 space-y-3">
              <div>
                <h2 className="text-sm font-semibold">Matrice de confusion</h2>
                <p className="text-xs text-muted-foreground">
                  Lignes : classe reelle · colonnes : classe predite · l’intensite code le nombre de
                  flux
                </p>
              </div>
              {training.confusion_matrix?.length ? (
                <ConfusionMatrix matrix={training.confusion_matrix} labels={labels} accent={palette.benign} />
              ) : (
                <div className="rounded-lg border border-dashed px-4 py-6 text-center space-y-2">
                  <p className="text-sm font-medium">Matrice non fournie par le notebook</p>
                  <p className="text-xs text-muted-foreground max-w-lg mx-auto">
                    Le certificat d’entraînement livre les scores par classe et les importances,
                    mais la matrice y a été exportée en image, pas en données — elle ne peut donc
                    pas être reconstruite ici.
                  </p>
                  <p className="text-xs text-muted-foreground max-w-lg mx-auto">
                    Pour la remplir : ajoutez <code>confusion_matrix</code> (liste de listes) dans
                    <code className="mx-1">metrics</code> de
                    <code className="mx-1">backend/app/ml/artifacts/metadata.json</code>, depuis le
                    notebook —
                    <code className="mx-1">
                      confusion_matrix(y_test, y_pred).tolist()
                    </code>
                    — puis rechargez le modèle.
                  </p>
                </div>
              )}
            </div>
          </TabsContent>

          {/* ── Comportement en production ── */}
          <TabsContent value="production" className="space-y-5">
            <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
              <KpiCard
                label="Predictions realisees"
                value={formatNumber(production.total_predictions)}
                sub={`Sur ${production.window_hours} h`}
                icon={BarChart2}
              />
              <KpiCard
                label="Attaques detectees"
                value={formatNumber(production.attacks_detected)}
                sub="Flux classes comme malveillants"
                icon={Target}
                tone={production.attacks_detected > 0 ? 'danger' : 'default'}
              />
              <KpiCard
                label="Taux de detection"
                value={`${production.detection_rate.toFixed(2)} %`}
                sub="Part des flux malveillants"
                icon={CheckCircle2}
              />
            </div>

            <div className="rounded-xl border bg-card overflow-hidden">
              <div className="px-5 py-3 border-b">
                <h2 className="text-sm font-semibold">Statistiques par classe en production</h2>
                <p className="text-xs text-muted-foreground">
                  Volumes et confiance observes sur les {production.window_hours} dernieres heures,
                  compares au F1 d’entrainement
                </p>
              </div>
              {production.per_class.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Classe</TableHead>
                      <TableHead className="text-right">Flux</TableHead>
                      <TableHead className="text-right">Part</TableHead>
                      <TableHead className="text-right">Confiance moy.</TableHead>
                      <TableHead className="text-right">Min</TableHead>
                      <TableHead className="text-right">Max</TableHead>
                      <TableHead className="text-right">F1 (test)</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {production.per_class.map((row) => (
                      <TableRow key={row.class_name} className="text-xs">
                        <TableCell>
                          <ClassBadge name={row.class_name} />
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {formatNumber(row.count)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {row.share.toFixed(1)} %
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums font-semibold">
                          {row.avg_confidence.toFixed(1)} %
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums text-muted-foreground">
                          {row.min_confidence.toFixed(1)} %
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums text-muted-foreground">
                          {row.max_confidence.toFixed(1)} %
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums text-primary">
                          {row.training ? pct(row.training.f1) : '—'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState message="Aucune prediction sur la periode" />
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

/** Matrice de confusion : rampe sequentielle a une seule teinte, valeurs toujours lisibles. */
function ConfusionMatrix({
  matrix,
  labels,
  accent,
}: {
  matrix: number[][];
  labels: string[];
  accent: string;
}) {
  const max = Math.max(...matrix.flat(), 1);

  return (
    <div className="overflow-x-auto">
      <table className="border-separate border-spacing-0.5 text-[10px]">
        <thead>
          <tr>
            <th className="p-1" />
            {labels.map((label) => (
              <th
                key={label}
                className="p-1 text-muted-foreground font-medium align-bottom whitespace-nowrap"
              >
                <span className="inline-block [writing-mode:vertical-rl] rotate-180">{label}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={labels[i] ?? i}>
              <th className="p-1 pr-2 text-right text-muted-foreground font-medium whitespace-nowrap">
                {labels[i] ?? i}
              </th>
              {row.map((value, j) => {
                const intensity = value / max;
                const diagonal = i === j;
                return (
                  <td
                    key={j}
                    title={`${labels[i]} classe ${labels[j]} : ${value}`}
                    className={cn(
                      'w-9 h-9 text-center font-mono tabular-nums rounded-sm',
                      intensity > 0.55 ? 'text-white' : 'text-foreground',
                      diagonal && 'ring-1 ring-inset ring-primary/40'
                    )}
                    style={{
                      backgroundColor: value
                        ? `color-mix(in oklab, ${accent} ${Math.max(8, intensity * 100)}%, transparent)`
                        : undefined,
                    }}
                  >
                    {value || ''}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
