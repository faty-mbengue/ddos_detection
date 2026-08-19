import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowDownUp, Gauge, Pause, Play, ShieldAlert, ShieldCheck, Wifi } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { EmptyState, PageHeader } from '@/components/shared/app-layout';
import { ChartTooltip } from '@/components/shared/chart-tooltip';
import { KpiCard } from '@/components/shared/kpi-card';
import { SourceFilter, TOUTES_SOURCES } from '@/components/shared/source-filter';
import { useTheme } from '@/components/shared/theme-provider';
import { Button } from '@/components/ui/button';
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
import { useWebSocket } from '@/hooks/use-websocket';
import { cn } from '@/lib/utils';
import { PROTOCOL_STYLES, formatBytes, formatNumber, formatTime, vizPalette } from '@/lib/viz';
import { fetchLiveStats, fetchPackets, fetchStatsHistory } from '@/service/monitoring.service';
import type { Packet } from '@/types';

const MAX_ROWS = 300;

interface PacketEvent {
  type: string;
  data: Packet[];
}

/** Un paquet est "a risque" si son protocole et son contenu evoquent une rafale d'attaque. */
function isRisky(packet: Packet): boolean {
  return /\[SYN\]|\[DNS\]|\[LDAP\]|\[MSSQL\]|\[NTP\]|\[NetBIOS\]|\[SNMP\]|\[SSDP\]|\[TFTP\]|\[UDPLag\]/.test(
    packet.info
  );
}

/** Page Flux Live : tableau des paquets en temps reel (WebSocket), debit
 * reseau et statistiques instantanees. */
export default function LivePage() {
  const { theme } = useTheme();
  const palette = vizPalette(theme);
  const [streamed, setStreamed] = useState<Packet[]>([]);
  const [paused, setPaused] = useState(false);
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [autoScroll, setAutoScroll] = useState(true);
  // Provenance des indicateurs : simule, reel, ou les deux.
  const [source, setSource] = useState(TOUTES_SOURCES);
  const bodyRef = useRef<HTMLDivElement>(null);

  // Amorce le tableau avec les derniers paquets deja captures
  const { data: initial } = useQuery({
    queryKey: ['packets-initial'],
    queryFn: () => fetchPackets(150),
    refetchOnMount: 'always',
  });

  // Le tableau combine le flux WebSocket (le plus recent) et l'amorce initiale
  const packets = useMemo(() => {
    const seen = new Set(streamed.map((packet) => packet.packet_no));
    const backlog = (initial ?? []).filter((packet) => !seen.has(packet.packet_no));
    return [...streamed, ...backlog].slice(0, MAX_ROWS);
  }, [streamed, initial]);

  const { data: stats } = useQuery({
    queryKey: ['live-stats', source],
    queryFn: () => fetchLiveStats(source === TOUTES_SOURCES ? undefined : source),
    refetchInterval: 5000,
  });

  const { data: history } = useQuery({
    queryKey: ['stats-history'],
    queryFn: () => fetchStatsHistory(60),
    refetchInterval: 15000,
  });

  const onMessage = useCallback(
    (message: PacketEvent) => {
      if (message.type !== 'packets' || paused) return;
      setStreamed((current) => [...message.data].reverse().concat(current).slice(0, MAX_ROWS));
    },
    [paused]
  );

  const wsState = useWebSocket<PacketEvent>({ channel: 'packets', onMessage });

  // Defilement automatique vers le haut a l'arrivee de nouveaux paquets
  useEffect(() => {
    if (autoScroll && !paused) bodyRef.current?.scrollTo({ top: 0 });
  }, [packets, autoScroll, paused]);

  const visible =
    protocolFilter === 'ALL' ? packets : packets.filter((p) => p.protocol === protocolFilter);

  const throughput = (history ?? []).map((row) => ({
    time: formatTime(row.timestamp),
    'Paquets/s': Math.round(row.packets_per_second),
    'Ko/s': Math.round(row.bytes_per_second / 1024),
  }));

  const underAttack = stats?.system_status === 'ATTACK';

  return (
    <div className="min-w-0">
      <PageHeader
        title="Flux Live"
        subtitle="Paquets circulant sur le reseau, captures en continu"
        icon={Activity}
        actions={
          <>
            <SourceFilter value={source} onChange={setSource} />
            <span
              className={cn(
                'hidden sm:inline-flex items-center gap-1.5 text-[11px] rounded-full border px-2 py-1',
                wsState === 'open'
                  ? 'text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                  : 'text-muted-foreground'
              )}
            >
              <Wifi className="w-3 h-3" aria-hidden />
              {wsState === 'open' ? 'Connecte' : wsState === 'connecting' ? 'Connexion…' : 'Hors ligne'}
            </span>
            <Button variant="outline" size="sm" onClick={() => setPaused((p) => !p)}>
              {paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
              {paused ? 'Reprendre' : 'Suspendre'}
            </Button>
          </>
        }
      />

      <div className="p-4 md:p-6 space-y-6 max-w-[1600px]">
        {/* Statistiques instantanees */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <KpiCard
            label="Etat du systeme"
            value={underAttack ? 'Attaque' : 'Normal'}
            sub={
              underAttack
                ? `${stats?.active_attacks ?? 0} alerte(s) active(s)`
                : 'Aucune attaque active'
            }
            icon={underAttack ? ShieldAlert : ShieldCheck}
            tone={underAttack ? 'danger' : 'success'}
          />
          <KpiCard
            label="Debit paquets"
            value={`${formatNumber(stats?.packets_per_second ?? 0)}/s`}
            sub={`${formatBytes(stats?.bytes_per_second ?? 0)}/s`}
            icon={Gauge}
          />
          <KpiCard
            label="Flux analyses"
            value={formatNumber(stats?.total_flows ?? 0)}
            sub={`${formatNumber(stats?.benign_flows ?? 0)} legitimes`}
            icon={ArrowDownUp}
          />
          <KpiCard
            label="Flux malveillants"
            value={formatNumber(stats?.total_attacks ?? 0)}
            sub={
              stats?.last_attack
                ? `Derniere : ${stats.last_attack.attack_type}`
                : 'Aucune detection'
            }
            icon={ShieldAlert}
            tone={(stats?.total_attacks ?? 0) > 0 ? 'danger' : 'default'}
          />
        </div>

        {/* Visualisation du debit reseau */}
        <div className="rounded-xl border bg-card p-5 space-y-3">
          <div>
            <h2 className="text-sm font-semibold">Debit reseau</h2>
            <p className="text-xs text-muted-foreground">
              Paquets par seconde et kilo-octets par seconde, releves a chaque cycle d’analyse
            </p>
          </div>
          {throughput.length > 1 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={throughput} margin={{ top: 5, right: 8, bottom: 0, left: 0 }}>
                <defs>
                  <linearGradient id="pps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={palette.benign} stopOpacity={0.28} />
                    <stop offset="100%" stopColor={palette.benign} stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="bps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={palette.secondary} stopOpacity={0.28} />
                    <stop offset="100%" stopColor={palette.secondary} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={{ fill: palette.muted, fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  minTickGap={30}
                />
                <YAxis
                  tick={{ fill: palette.muted, fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  width={45}
                />
                <Tooltip
                  content={<ChartTooltip valueFormatter={(v) => formatNumber(v)} />}
                  cursor={{ stroke: palette.axis, strokeWidth: 1 }}
                />
                <Legend wrapperStyle={{ fontSize: 11, paddingTop: 8 }} />
                <Area
                    isAnimationActive={false}
                  type="monotone"
                  dataKey="Paquets/s"
                  stroke={palette.benign}
                  strokeWidth={2}
                  fill="url(#pps)"
                />
                <Area
                    isAnimationActive={false}
                  type="monotone"
                  dataKey="Ko/s"
                  stroke={palette.secondary}
                  strokeWidth={2}
                  fill="url(#bps)"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState
              message="Pas encore assez de releves"
              hint="Le graphique se remplit a chaque cycle d’analyse."
            />
          )}
        </div>

        {/* Tableau des paquets */}
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b">
            <div>
              <h2 className="text-sm font-semibold">Paquets en temps reel</h2>
              <p className="text-xs text-muted-foreground">
                {visible.length} paquet(s) affiche(s){paused && ' · flux suspendu'}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Select value={protocolFilter} onValueChange={setProtocolFilter}>
                <SelectTrigger className="h-8 w-[130px] text-xs">
                  <SelectValue placeholder="Protocole" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Tous protocoles</SelectItem>
                  <SelectItem value="TCP">TCP</SelectItem>
                  <SelectItem value="UDP">UDP</SelectItem>
                  <SelectItem value="ICMP">ICMP</SelectItem>
                </SelectContent>
              </Select>
              <Button
                variant={autoScroll ? 'secondary' : 'outline'}
                size="sm"
                className="h-8 text-xs"
                onClick={() => setAutoScroll((value) => !value)}
              >
                Defilement auto
              </Button>
            </div>
          </div>

          <div ref={bodyRef} className="max-h-[520px] overflow-auto">
            {visible.length === 0 ? (
              <EmptyState
                message="Aucun paquet capture"
                hint="Verifiez que la boucle de capture est demarree (Administration)."
              />
            ) : (
              <Table>
                <TableHeader className="sticky top-0 bg-card z-10">
                  <TableRow>
                    <TableHead className="w-16">N°</TableHead>
                    <TableHead className="w-20">Temps</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead className="w-20">Protocole</TableHead>
                    <TableHead className="w-20 text-right">Longueur</TableHead>
                    <TableHead>Information</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((packet, index) => {
                    const risky = isRisky(packet);
                    return (
                      <TableRow
                        key={`${packet.packet_no}-${index}`}
                        className={cn('text-xs', risky && 'bg-red-500/5')}
                      >
                        <TableCell className="font-mono text-muted-foreground tabular-nums">
                          {packet.packet_no}
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground tabular-nums">
                          {packet.time.toFixed(2)}
                        </TableCell>
                        <TableCell className="font-mono">{packet.src_ip}</TableCell>
                        <TableCell className="font-mono">{packet.dst_ip}</TableCell>
                        <TableCell
                          className={cn(
                            'font-mono font-medium',
                            PROTOCOL_STYLES[packet.protocol] ?? 'text-muted-foreground'
                          )}
                        >
                          {packet.protocol}
                        </TableCell>
                        <TableCell className="font-mono text-right tabular-nums">
                          {packet.length}
                        </TableCell>
                        <TableCell
                          className={cn(
                            'font-mono max-w-[420px] truncate',
                            risky ? 'text-red-600 dark:text-red-400' : 'text-muted-foreground'
                          )}
                          title={packet.info}
                        >
                          {packet.info}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
