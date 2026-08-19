import { useMutation } from '@tanstack/react-query';
import {
  CheckCircle2,
  FileSearch,
  FileUp,
  Info,
  Loader2,
  ShieldAlert,
  Target,
  X,
} from 'lucide-react';
import { useRef, useState } from 'react';
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
import { toast } from 'sonner';

import { EmptyState, PageHeader } from '@/components/shared/app-layout';
import { ChartTooltip } from '@/components/shared/chart-tooltip';
import { KpiCard } from '@/components/shared/kpi-card';
import { ClassBadge } from '@/components/shared/severity-badge';
import { useTheme } from '@/components/shared/theme-provider';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';
import { formatNumber, vizPalette } from '@/lib/viz';
import { errorMessage } from '@/service/api.service';
import { analyzeFile } from '@/service/monitoring.service';
import type { FileAnalysis } from '@/types';

const EXTENSIONS = '.pcap,.pcapng,.cap,.dmp,.csv,.txt';

/**
 * Page Analyse de fichier : rejoue une capture (PCAP) ou une extraction
 * CICFlowMeter (CSV) a travers le modele, sans dependre de la capture temps reel.
 */
/**
 * Ramene une etiquette a une forme comparable. Le dataset CICDDoS2019 nomme ses
 * classes « DrDoS_DNS » ou « UDP-lag » la ou le modele predit « DNS » et
 * « UDPLag » : sans cela, une prediction juste s'afficherait comme fausse.
 */
function cleClasse(etiquette: string): string {
  const cle = etiquette.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  return cle.startsWith('DRDOS') && cle !== 'DRDOS' ? cle.slice(5) : cle;
}

export default function AnalyzePage() {
  const { theme } = useTheme();
  const palette = vizPalette(theme);
  const [fichier, setFichier] = useState<File | null>(null);
  const [surviole, setSurviole] = useState(false);
  const champRef = useRef<HTMLInputElement>(null);

  const analyse = useMutation({
    mutationFn: analyzeFile,
    onSuccess: (r) =>
      toast.success(
        `${formatNumber(r.flows_analyzed)} flux analyses · ${r.attacks_detected} attaque(s)`
      ),
    onError: (error) => toast.error(errorMessage(error), { duration: 12000 }),
  });

  const resultat = analyse.data;

  /** Retient le fichier choisi, qu'il vienne du sélecteur ou d'un glisser-déposer. */
  const choisir = (nouveau: File | undefined) => {
    if (!nouveau) return;
    setFichier(nouveau);
    analyse.reset();
  };

  const distribution = (resultat?.distribution ?? []).filter((c) => c.count > 0);

  return (
    <div className="min-w-0">
      <PageHeader
        title="Analyse de fichier"
        subtitle="Rejouer une capture PCAP ou une extraction CICFlowMeter a travers le modele"
        icon={FileSearch}
      />

      <div className="p-4 md:p-6 space-y-5 max-w-[1400px]">
        {/* Zone de dépôt */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setSurviole(true);
          }}
          onDragLeave={() => setSurviole(false)}
          onDrop={(e) => {
            e.preventDefault();
            setSurviole(false);
            choisir(e.dataTransfer.files?.[0]);
          }}
          className={cn(
            'rounded-xl border-2 border-dashed p-8 text-center transition-colors',
            surviole ? 'border-primary bg-primary/5' : 'border-border bg-card'
          )}
        >
          <FileUp className="w-8 h-8 mx-auto text-muted-foreground mb-3" aria-hidden />
          <p className="text-sm font-medium">
            Glissez un fichier ici, ou{' '}
            <button
              type="button"
              className="text-primary underline underline-offset-2"
              onClick={() => champRef.current?.click()}
            >
              parcourez vos fichiers
            </button>
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Capture <code>.pcap</code>, <code>.pcapng</code> ou CSV CICFlowMeter · 200 Mo maximum
          </p>
          <input
            ref={champRef}
            type="file"
            accept={EXTENSIONS}
            className="hidden"
            onChange={(e) => choisir(e.target.files?.[0])}
          />

          {fichier && (
            <div className="mt-5 inline-flex items-center gap-3 rounded-lg border bg-background px-3 py-2">
              <span className="text-xs font-mono truncate max-w-[280px]">{fichier.name}</span>
              <span className="text-[11px] text-muted-foreground">
                {(fichier.size / 1024 / 1024).toFixed(1)} Mo
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={() => {
                  setFichier(null);
                  analyse.reset();
                }}
              >
                <X className="size-3.5" />
                <span className="sr-only">Retirer le fichier</span>
              </Button>
            </div>
          )}

          <div className="mt-5">
            <Button
              disabled={!fichier || analyse.isPending}
              onClick={() => fichier && analyse.mutate(fichier)}
            >
              {analyse.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              {analyse.isPending ? 'Analyse en cours…' : 'Analyser'}
            </Button>
          </div>
        </div>

        {/* Rappel méthodologique : les deux voies n'ont pas la même fidélité. */}
        <div className="rounded-xl border bg-primary/5 px-4 py-3 flex items-start gap-3">
          <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" aria-hidden />
          <p className="text-xs text-muted-foreground">
            Un <strong className="text-foreground">CSV CICFlowMeter</strong> donne les résultats les
            plus fidèles : les 31 caractéristiques sont alors calculées par l’outil de référence. Sur
            un <strong className="text-foreground">PCAP</strong>, elles sont reconstituées par
            l’agrégation simplifiée intégrée, dont les définitions diffèrent légèrement. Si le
            fichier contient une colonne <code>Label</code>, l’exactitude du modèle est mesurée
            automatiquement.
          </p>
        </div>

        {analyse.isPending && (
          <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
            <Loader2 className="w-7 h-7 animate-spin text-primary" />
            <p className="text-sm">Lecture du fichier et classification des flux…</p>
          </div>
        )}

        {resultat && <Resultats resultat={resultat} palette={palette} distribution={distribution} />}
      </div>
    </div>
  );
}

/** Affiche la synthèse retournée par le backend. */
function Resultats({
  resultat,
  palette,
  distribution,
}: {
  resultat: FileAnalysis;
  palette: ReturnType<typeof vizPalette>;
  distribution: FileAnalysis['distribution'];
}) {
  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiCard
          label="Flux analysés"
          value={formatNumber(resultat.flows_analyzed)}
          sub={
            resultat.format === 'pcap'
              ? `${formatNumber(resultat.packets_read)} paquets lus`
              : 'depuis le CSV CICFlowMeter'
          }
          icon={FileSearch}
        />
        <KpiCard
          label="Attaques détectées"
          value={formatNumber(resultat.attacks_detected)}
          sub={
            resultat.attacks_below_threshold > 0
              ? `${resultat.attack_ratio} % des flux · ${resultat.attacks_below_threshold} sous le seuil de ${resultat.confidence_threshold} %`
              : `${resultat.attack_ratio} % des flux · seuil ${resultat.confidence_threshold} %`
          }
          icon={ShieldAlert}
          tone={resultat.attacks_detected > 0 ? 'danger' : 'success'}
        />
        <KpiCard
          label="Classes observées"
          value={distribution.length}
          sub={distribution.map((c) => c.name).slice(0, 3).join(', ')}
          icon={Target}
        />
        <KpiCard
          label="Exactitude mesurée"
          value={resultat.ground_truth ? `${resultat.ground_truth.exactitude} %` : '—'}
          sub={
            resultat.ground_truth
              ? `${resultat.ground_truth.corrects}/${resultat.ground_truth.total} vs colonne Label`
              : 'aucune colonne Label dans le fichier'
          }
          icon={CheckCircle2}
        />
      </div>

      {resultat.missing_features.length > 0 && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3">
          <p className="text-xs text-amber-700 dark:text-amber-300">
            <strong>{resultat.missing_features.length} caractéristique(s) absente(s)</strong> du
            fichier, mises à zéro : {resultat.missing_features.join(', ')}. Les prédictions peuvent
            s’en trouver dégradées.
          </p>
        </div>
      )}

      {resultat.ground_truth && resultat.ground_truth.par_classe.length > 0 && (
        <div className="rounded-xl border bg-card p-5 space-y-3">
          <div>
            <h2 className="text-sm font-semibold">Exactitude par classe réelle</h2>
            <p className="text-xs text-muted-foreground">
              Le taux global seul est trompeur quand les classes sont déséquilibrées
            </p>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Classe du fichier</TableHead>
                <TableHead className="text-right">Flux</TableHead>
                <TableHead className="text-right">Corrects</TableHead>
                <TableHead className="text-right">Exactitude</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {resultat.ground_truth.par_classe.map((classe) => (
                <TableRow key={classe.label} className="text-xs">
                  <TableCell className="font-mono">{classe.label}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">
                    {formatNumber(classe.total)}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums">
                    {formatNumber(classe.corrects)}
                  </TableCell>
                  <TableCell
                    className={cn(
                      'text-right font-mono tabular-nums font-semibold',
                      classe.exactitude >= 70
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : classe.exactitude >= 40
                          ? 'text-amber-600 dark:text-amber-400'
                          : 'text-red-600 dark:text-red-400'
                    )}
                  >
                    {classe.exactitude.toFixed(1)} %
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="rounded-xl border bg-card p-5 space-y-3">
        <div>
          <h2 className="text-sm font-semibold">Répartition des classes</h2>
          <p className="text-xs text-muted-foreground">
            Bleu pour le trafic légitime, rouge pour les attaques
          </p>
        </div>
        {distribution.length ? (
          <ResponsiveContainer width="100%" height={26 * distribution.length + 60}>
            <BarChart data={distribution} layout="vertical" barCategoryGap="22%">
              <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} horizontal={false} />
              <XAxis
                type="number"
                tick={{ fill: palette.muted, fontSize: 10 }}
                axisLine={false}
                tickLine={false}
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
                {distribution.map((row) => (
                  <Cell key={row.name} fill={row.is_attack ? palette.attack : palette.benign} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState message="Aucune classe détectée" />
        )}
      </div>

      {resultat.top_sources.length > 0 && (
        <div className="grid md:grid-cols-2 gap-5">
          <TableauIp titre="Principales sources malveillantes" lignes={resultat.top_sources} />
          <TableauIp titre="Cibles les plus visées" lignes={resultat.top_targets} />
        </div>
      )}

      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="px-5 py-3 border-b">
          <h2 className="text-sm font-semibold">Échantillon des flux classés</h2>
          <p className="text-xs text-muted-foreground">
            Les {resultat.sample.length} premiers flux du fichier
          </p>
        </div>
        <div className="max-h-[500px] overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-card z-10">
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead className="text-right">Port</TableHead>
                <TableHead>Prédiction</TableHead>
                <TableHead className="text-right">Confiance</TableHead>
                {resultat.ground_truth && <TableHead>Vérité</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {resultat.sample.map((ligne, index) => {
                const correct =
                  ligne.label && cleClasse(ligne.label) === cleClasse(ligne.prediction);
                return (
                  <TableRow
                    key={index}
                    className={cn('text-xs', ligne.is_attack && 'bg-red-500/5')}
                  >
                    <TableCell className="font-mono">{ligne.src_ip || '—'}</TableCell>
                    <TableCell className="font-mono">{ligne.dst_ip || '—'}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {ligne.dst_port ?? '—'}
                    </TableCell>
                    <TableCell>
                      <ClassBadge name={ligne.prediction} />
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {ligne.confidence.toFixed(1)} %
                    </TableCell>
                    {resultat.ground_truth && (
                      <TableCell>
                        <span
                          className={cn(
                            'font-mono text-[11px]',
                            correct
                              ? 'text-emerald-600 dark:text-emerald-400'
                              : 'text-red-600 dark:text-red-400'
                          )}
                        >
                          {ligne.label ?? '—'} {correct ? '✓' : '✗'}
                        </span>
                      </TableCell>
                    )}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </div>
    </>
  );
}

/** Petit tableau d'adresses IP avec leur volume de flux. */
function TableauIp({ titre, lignes }: { titre: string; lignes: { ip: string; flows: number }[] }) {
  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="px-5 py-3 border-b">
        <h2 className="text-sm font-semibold">{titre}</h2>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Adresse IP</TableHead>
            <TableHead className="text-right">Flux malveillants</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {lignes.map((ligne) => (
            <TableRow key={ligne.ip} className="text-xs">
              <TableCell className="font-mono">{ligne.ip}</TableCell>
              <TableCell className="text-right font-mono tabular-nums">{ligne.flows}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
