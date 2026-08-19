import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Ban,
  Cpu,
  Loader2,
  Mail,
  Play,
  Plus,
  RefreshCw,
  Settings,
  ShieldCheck,
  ShieldOff,
  Square,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';

import { EmptyState, PageHeader } from '@/components/shared/app-layout';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { KpiCard } from '@/components/shared/kpi-card';
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
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useAuth } from '@/hooks/use-auth';
import { cn } from '@/lib/utils';
import { formatDateTime, relativeTime } from '@/lib/viz';
import { errorMessage } from '@/service/api.service';
import {
  blockIp,
  controlPipeline,
  createUser,
  deleteUser,
  fetchBlockedIps,
  fetchEmailStatus,
  fetchFirewallStatus,
  fetchInterfaces,
  fetchSettings,
  fetchSystemStatus,
  fetchUsers,
  reloadModel,
  sendTestEmail,
  unblockIp,
  updateSettings,
  updateUser,
} from '@/service/monitoring.service';
import type { BlockedIP, SystemSettings, User, UserRole } from '@/types';

/** Les trois sources possibles pour les donnees analysees. */
const CAPTURE_MODES = [
  {
    value: 'simulator',
    label: 'Simulateur — trafic synthetique',
    hint: 'Trafic genere par le backend, reproduisant les signatures CICDDoS2019. Aucune donnee reelle.',
  },
  {
    value: 'external',
    label: 'Agent externe — trafic reel de la machine',
    hint: 'Aucune capture interne : lancez tools/capture_agent.py, qui capture et pousse sur /api/ingest.',
  },
  {
    value: 'tshark',
    label: 'tshark — capture dans le conteneur',
    hint: 'Capture directe par le backend. Linux uniquement, avec docker-compose.capture.yml.',
  },
] as const;

const ROLE_OPTIONS: { value: UserRole; label: string }[] = [
  { value: 'admin', label: 'Administrateur' },
  { value: 'analyst', label: 'Analyste' },
  { value: 'viewer', label: 'Lecture seule' },
];

/** Page Administration : etat du systeme, configuration, utilisateurs et
 * adresses IP bloquees. Reservee au role administrateur. */
export default function AdminPage() {
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ['system-status'],
    queryFn: fetchSystemStatus,
    refetchInterval: 10000,
  });

  return (
    <div className="min-w-0">
      <PageHeader
        title="Administration"
        subtitle="Utilisateurs, configuration du systeme et adresses IP bloquees"
        icon={Settings}
      />

      <div className="p-4 md:p-6 space-y-5 max-w-[1400px]">
        {/* Etat du systeme */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <KpiCard
            label="Boucle d’analyse"
            value={status?.pipeline_running ? 'Active' : 'Arretee'}
            sub={`${status?.cycles ?? 0} cycles · toutes les ${status?.interval_seconds ?? '—'} s`}
            icon={Cpu}
            tone={status?.pipeline_running ? 'success' : 'danger'}
          />
          <KpiCard
            label="Capture"
            value={status?.capture.backend ?? '—'}
            sub={`Interface ${status?.capture.interface ?? '—'} · ${status?.capture.packets_captured ?? 0} paquets`}
            icon={Cpu}
          />
          <KpiCard
            label="Modele"
            value={status?.model.ready ? 'Charge' : 'Absent'}
            sub={status?.model.model_type ?? 'Aucun artefact'}
            icon={Cpu}
            tone={status?.model.ready ? 'success' : 'danger'}
          />
          <KpiCard
            label="Clients temps reel"
            value={status?.ws_clients ?? 0}
            sub={
              status?.last_cycle_at
                ? `Dernier cycle ${relativeTime(status.last_cycle_at)}`
                : 'Aucun cycle execute'
            }
            icon={Users}
          />
        </div>

        {status?.last_error && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3">
            <p className="text-xs text-amber-700 dark:text-amber-300">
              <strong>Derniere erreur du pipeline :</strong> {status.last_error}
            </p>
          </div>
        )}

        <Tabs defaultValue="config">
          <TabsList>
            <TabsTrigger value="config">Configuration</TabsTrigger>
            <TabsTrigger value="users">Utilisateurs</TabsTrigger>
            <TabsTrigger value="ips">IP bloquees</TabsTrigger>
          </TabsList>

          <TabsContent value="config">
            <SettingsPanel running={status?.pipeline_running ?? false} onChanged={() => queryClient.invalidateQueries({ queryKey: ['system-status'] })} />
          </TabsContent>

          <TabsContent value="users">
            <UsersPanel currentUsername={currentUser?.username ?? ''} />
          </TabsContent>

          <TabsContent value="ips">
            <BlockedIpsPanel />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

// ── Configuration du systeme ─────────────────────────────────────────────────

/** Onglet Configuration : parametres de capture et de detection, modifiables
 * a chaud, plus le controle de la boucle d'analyse et du modele. */
function SettingsPanel({ running, onChanged }: { running: boolean; onChanged: () => void }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ['settings'], queryFn: fetchSettings });

  // Quelles interfaces le backend peut-il reellement ecouter ?
  const { data: interfaces } = useQuery({
    queryKey: ['interfaces'],
    queryFn: fetchInterfaces,
    refetchInterval: 60000,
  });
  const realInterfaces = interfaces?.real_interfaces ?? [];

  // Les alertes email peuvent-elles partir ?
  const { data: email } = useQuery({
    queryKey: ['email-status'],
    queryFn: fetchEmailStatus,
    refetchInterval: 60000,
  });

  // Les modifications locales se superposent aux valeurs du serveur : pas de
  // synchronisation par effet, donc pas de rendu en cascade.
  const [edits, setEdits] = useState<Partial<SystemSettings>>({});
  const form = data ? { ...data, ...edits } : null;

  const testEmail = useMutation({
    mutationFn: sendTestEmail,
    onSuccess: (result) => {
      if (result.sent) toast.success(result.detail);
      else toast.error(result.detail, { duration: 10000 });
      queryClient.invalidateQueries({ queryKey: ['email-status'] });
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const save = useMutation({
    mutationFn: (payload: Partial<SystemSettings>) => updateSettings(payload),
    onSuccess: () => {
      setEdits({});
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      onChanged();
      toast.success('Configuration enregistree');
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const pipeline = useMutation({
    mutationFn: controlPipeline,
    onSuccess: (result) => {
      onChanged();
      toast.success(result.pipeline_running ? 'Boucle d’analyse demarree' : 'Boucle d’analyse arretee');
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const reload = useMutation({
    mutationFn: reloadModel,
    onSuccess: () => {
      onChanged();
      queryClient.invalidateQueries({ queryKey: ['model-metrics'] });
      toast.success('Modele recharge depuis le disque');
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  if (!form) {
    return (
      <div className="flex justify-center py-16">
        <Loader2 className="w-6 h-6 animate-spin text-primary" />
      </div>
    );
  }

  const update = <K extends keyof SystemSettings>(key: K, value: SystemSettings[K]) =>
    setEdits((current) => ({ ...current, [key]: value }));

  return (
    <div className="space-y-5">
      <form
        className="rounded-xl border bg-card p-5 space-y-5"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate(form);
        }}
      >
        <div>
          <h2 className="text-sm font-semibold">Parametres de capture et de detection</h2>
          <p className="text-xs text-muted-foreground">
            Applique immediatement a la boucle d’analyse, sans redemarrage
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="capture-backend" className="text-xs">
              Mode de capture
            </Label>
            <Select
              value={form.capture_backend}
              onValueChange={(value) => update('capture_backend', value)}
            >
              <SelectTrigger id="capture-backend">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CAPTURE_MODES.map((mode) => (
                  <SelectItem key={mode.value} value={mode.value}>
                    {mode.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              {CAPTURE_MODES.find((m) => m.value === form.capture_backend)?.hint ??
                'Source des donnees analysees'}
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="interface" className="text-xs">
              Interface reseau a surveiller
            </Label>
            {/* Les interfaces reellement capturables sont proposees en liste ;
                la saisie libre reste possible pour preparer un autre serveur. */}
            {realInterfaces.length > 0 ? (
              <Select
                value={form.capture_interface}
                onValueChange={(value) => update('capture_interface', value)}
              >
                <SelectTrigger id="interface">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {realInterfaces.map((name) => (
                    <SelectItem key={name} value={name}>
                      {name}
                    </SelectItem>
                  ))}
                  {!realInterfaces.includes(form.capture_interface) && (
                    <SelectItem value={form.capture_interface}>
                      {form.capture_interface} (non detectee)
                    </SelectItem>
                  )}
                </SelectContent>
              </Select>
            ) : (
              <Input
                id="interface"
                value={form.capture_interface}
                onChange={(event) => update('capture_interface', event.target.value)}
                placeholder="eth0"
              />
            )}
            <p className="text-[11px] text-muted-foreground">
              {interfaces?.explanation ??
                'Utilisee uniquement par le backend de capture tshark'}
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="interval" className="text-xs">
              Duree du cycle d’analyse (secondes)
            </Label>
            <Input
              id="interval"
              type="number"
              min={5}
              max={300}
              value={form.analysis_interval}
              onChange={(event) => update('analysis_interval', Number(event.target.value))}
            />
            <p className="text-[11px] text-muted-foreground">
              15 s par defaut, conformement a la specification
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="confidence" className="text-xs">
              Seuil de confiance pour retenir une attaque
            </Label>
            <Input
              id="confidence"
              type="number"
              step="0.05"
              min={0}
              max={1}
              value={form.confidence_threshold}
              onChange={(event) => update('confidence_threshold', Number(event.target.value))}
            />
            <p className="text-[11px] text-muted-foreground">
              Entre 0 et 1 — soit {(form.confidence_threshold * 100).toFixed(0)} % de confiance
              minimale
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="flow-threshold" className="text-xs">
              Nombre de flux minimum pour lever une alerte
            </Label>
            <Input
              id="flow-threshold"
              type="number"
              min={1}
              max={1000}
              value={form.flow_threshold}
              onChange={(event) => update('flow_threshold', Number(event.target.value))}
            />
            <p className="text-[11px] text-muted-foreground">
              Evite les alertes sur un flux malveillant isole
            </p>
          </div>
        </div>

        <div className="space-y-3 pt-2 border-t">
          <div className="flex items-center justify-between gap-3 pt-3">
            <div>
              <Label htmlFor="auto-block" className="text-xs">
                Blocage automatique des IP
              </Label>
              <p className="text-[11px] text-muted-foreground">
                Bloque la source des attaques de criticite elevee ou critique
              </p>
            </div>
            <Switch
              id="auto-block"
              checked={form.auto_block}
              onCheckedChange={(checked) => update('auto_block', checked)}
            />
          </div>

          <div className="flex items-center justify-between gap-3">
            <div>
              <Label htmlFor="email-alerts" className="text-xs">
                Notifications par email
              </Label>
              <p className="text-[11px] text-muted-foreground">
                Necessite une configuration SMTP cote backend
              </p>
            </div>
            <Switch
              id="email-alerts"
              checked={form.email_alerts}
              onCheckedChange={(checked) => update('email_alerts', checked)}
            />
          </div>

          {/* Diagnostic SMTP : sans lui, on ne sait pas pourquoi rien ne part. */}
          {email && (
            <div
              className={cn(
                'rounded-lg border px-3 py-2.5 flex items-start gap-2.5',
                email.configured ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-amber-500/10 border-amber-500/30'
              )}
            >
              <Mail
                className={cn(
                  'w-4 h-4 shrink-0 mt-0.5',
                  email.configured
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-amber-600 dark:text-amber-400'
                )}
                aria-hidden
              />
              <div className="text-[11px] space-y-0.5 min-w-0 flex-1">
                <p className="font-semibold">{email.explanation}</p>
                {email.configured && (
                  <p className="text-muted-foreground">
                    {email.user} → {email.recipients.join(', ')} · expediteur{' '}
                    {email.effective_sender}
                  </p>
                )}
                {email.sender_warning && (
                  <p className="text-amber-700 dark:text-amber-300">{email.sender_warning}</p>
                )}
                {email.missing.includes('SMTP_PASSWORD') && (
                  <p className="text-muted-foreground">
                    Renseignez un mot de passe d’application Google dans <code>.env</code>,
                    puis redemarrez le backend.
                  </p>
                )}
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-7 text-xs shrink-0"
                disabled={testEmail.isPending}
                onClick={() => testEmail.mutate()}
              >
                {testEmail.isPending && <Loader2 className="w-3 h-3 animate-spin" />}
                Tester
              </Button>
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="recipients" className="text-xs">
              Destinataires des alertes
            </Label>
            <Input
              id="recipients"
              value={form.alert_recipients}
              onChange={(event) => update('alert_recipients', event.target.value)}
              placeholder="soc@exemple.com, admin@exemple.com"
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-2 pt-2 border-t">
          <Button type="submit" disabled={save.isPending} className="mt-3">
            {save.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Enregistrer
          </Button>
          <Button
            type="button"
            variant="outline"
            className="mt-3"
            disabled={pipeline.isPending}
            onClick={() => pipeline.mutate(running ? 'stop' : 'start')}
          >
            {running ? <Square className="size-3.5" /> : <Play className="size-3.5" />}
            {running ? 'Arreter la capture' : 'Demarrer la capture'}
          </Button>
          <Button
            type="button"
            variant="outline"
            className="mt-3"
            disabled={reload.isPending}
            onClick={() => reload.mutate()}
          >
            <RefreshCw className={reload.isPending ? 'size-3.5 animate-spin' : 'size-3.5'} />
            Recharger le modele
          </Button>
        </div>
      </form>
    </div>
  );
}

// ── Gestion des utilisateurs ─────────────────────────────────────────────────

/** Onglet Utilisateurs : creation, changement de role, activation et
 * suppression (avec confirmation) des comptes. */
function UsersPanel({ currentUsername }: { currentUsername: string }) {
  const queryClient = useQueryClient();
  const { data: users, isLoading } = useQuery({ queryKey: ['users'], queryFn: fetchUsers });
  const [showForm, setShowForm] = useState(false);
  const [draft, setDraft] = useState({
    username: '',
    email: '',
    password: '',
    role: 'viewer' as UserRole,
  });

  // Utilisateur en attente de confirmation de suppression (null = boite fermee)
  const [pendingDeletion, setPendingDeletion] = useState<User | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users'] });

  const create = useMutation({
    mutationFn: () => createUser(draft),
    onSuccess: (user) => {
      toast.success(`Utilisateur ${user.username} cree`);
      setDraft({ username: '', email: '', password: '', role: 'viewer' });
      setShowForm(false);
      invalidate();
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const patch = useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: Parameters<typeof updateUser>[1] }) =>
      updateUser(id, payload),
    onSuccess: () => {
      toast.success('Utilisateur mis a jour');
      invalidate();
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const remove = useMutation({
    mutationFn: deleteUser,
    onSuccess: (_, id) => {
      const supprime = users?.find((u) => u.id === id);
      toast.success(`Utilisateur ${supprime?.username ?? ''} supprime`);
      setPendingDeletion(null);
      invalidate();
    },
    onError: (error) => {
      // La boite reste ouverte : l'administrateur voit l'erreur et peut reessayer
      toast.error(errorMessage(error));
    },
  });

  return (
    <div className="space-y-4">
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="flex items-center justify-between gap-3 px-5 py-3 border-b">
          <div>
            <h2 className="text-sm font-semibold">Comptes utilisateurs</h2>
            <p className="text-xs text-muted-foreground">
              Trois niveaux d’acces : administrateur, analyste, lecture seule
            </p>
          </div>
          <Button size="sm" variant={showForm ? 'secondary' : 'default'} onClick={() => setShowForm((v) => !v)}>
            {showForm ? 'Annuler' : <><UserPlus className="size-3.5" />Nouvel utilisateur</>}
          </Button>
        </div>

        {showForm && (
          <form
            className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 p-5 border-b bg-muted/20"
            onSubmit={(event) => {
              event.preventDefault();
              create.mutate();
            }}
          >
            <div className="space-y-1.5">
              <Label className="text-xs">Nom d’utilisateur</Label>
              <Input
                required
                minLength={3}
                value={draft.username}
                onChange={(event) => setDraft({ ...draft, username: event.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Email</Label>
              <Input
                type="email"
                required
                value={draft.email}
                onChange={(event) => setDraft({ ...draft, email: event.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Mot de passe</Label>
              <Input
                type="password"
                required
                minLength={6}
                value={draft.password}
                onChange={(event) => setDraft({ ...draft, password: event.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Role</Label>
              <Select
                value={draft.role}
                onValueChange={(value) => setDraft({ ...draft, role: value as UserRole })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLE_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end">
              <Button type="submit" className="w-full" disabled={create.isPending}>
                {create.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="size-4" />}
                Creer
              </Button>
            </div>
          </form>
        )}

        {isLoading ? (
          <div className="flex justify-center py-16">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
          </div>
        ) : !users?.length ? (
          <EmptyState message="Aucun utilisateur" />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Utilisateur</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Cree le</TableHead>
                <TableHead>Derniere connexion</TableHead>
                <TableHead>Actif</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => {
                const self = user.username === currentUsername;
                return (
                  <TableRow key={user.id} className="text-xs">
                    <TableCell className="font-medium">
                      {user.username}
                      {self && <span className="text-muted-foreground"> (vous)</span>}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{user.email}</TableCell>
                    <TableCell>
                      <Select
                        value={user.role}
                        onValueChange={(value) =>
                          patch.mutate({ id: user.id, payload: { role: value as UserRole } })
                        }
                      >
                        <SelectTrigger className="h-7 w-[150px] text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {ROLE_OPTIONS.map((option) => (
                            <SelectItem key={option.value} value={option.value}>
                              {option.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDateTime(user.created_at)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {user.last_login ? relativeTime(user.last_login) : 'jamais'}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={user.is_active}
                        disabled={self}
                        onCheckedChange={(checked) =>
                          patch.mutate({ id: user.id, payload: { is_active: checked } })
                        }
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-red-600 dark:text-red-400"
                        disabled={self}
                        title={
                          self
                            ? 'Impossible de supprimer son propre compte'
                            : `Supprimer ${user.username}`
                        }
                        onClick={() => setPendingDeletion(user)}
                      >
                        <Trash2 className="size-3.5" />
                        <span className="sr-only">Supprimer {user.username}</span>
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </div>

      {/* Confirmation obligatoire avant toute suppression de compte */}
      <ConfirmDialog
        open={pendingDeletion !== null}
        onOpenChange={(open) => {
          if (!open && !remove.isPending) setPendingDeletion(null);
        }}
        title="Supprimer cet utilisateur ?"
        variant="destructive"
        confirmLabel="Supprimer definitivement"
        pending={remove.isPending}
        onConfirm={() => pendingDeletion && remove.mutate(pendingDeletion.id)}
        description={
          <>
            Le compte{' '}
            <span className="font-mono font-medium text-foreground">
              {pendingDeletion?.username}
            </span>{' '}
            ({pendingDeletion?.email}), de role{' '}
            <span className="font-medium text-foreground">
              {ROLE_OPTIONS.find((r) => r.value === pendingDeletion?.role)?.label ??
                pendingDeletion?.role}
            </span>
            , sera supprime. Cette action est irreversible : l’utilisateur perdra
            immediatement l’acces a la plateforme.
          </>
        }
      />
    </div>
  );
}

// ── IP bloquees ──────────────────────────────────────────────────────────────

/** Onglet IP bloquees : liste, ajout manuel et deblocage (avec confirmation).
 * Affiche si le pare-feu applique reellement les regles. */
function BlockedIpsPanel() {
  const queryClient = useQueryClient();
  const { data: entries, isLoading } = useQuery({
    queryKey: ['blocked-ips'],
    queryFn: fetchBlockedIps,
  });

  // Etat reel du pare-feu : sans lui, l'utilisateur ne peut pas savoir si le
  // blocage agit sur le reseau ou n'est qu'un inventaire.
  const { data: firewall } = useQuery({
    queryKey: ['firewall'],
    queryFn: fetchFirewallStatus,
    refetchInterval: 30000,
  });

  const [address, setAddress] = useState('');
  const [reason, setReason] = useState('');
  const [pendingUnblock, setPendingUnblock] = useState<BlockedIP | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['blocked-ips'] });

  const add = useMutation({
    mutationFn: () => blockIp(address.trim(), reason.trim() || 'Blocage manuel'),
    onSuccess: (entry) => {
      toast.success(`IP ${entry.ip_address} bloquee`);
      setAddress('');
      setReason('');
      invalidate();
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const remove = useMutation({
    mutationFn: unblockIp,
    onSuccess: (_, id) => {
      const debloquee = entries?.find((e) => e.id === id);
      toast.success(`IP ${debloquee?.ip_address ?? ''} debloquee`);
      setPendingUnblock(null);
      invalidate();
    },
    // La boite reste ouverte en cas d'echec, pour permettre un nouvel essai
    onError: (error) => toast.error(errorMessage(error)),
  });

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="px-5 py-3 border-b">
        <h2 className="text-sm font-semibold">Adresses IP bloquees</h2>
        <p className="text-xs text-muted-foreground">
          Ajout manuel ou blocage automatique apres detection d’une attaque
        </p>
      </div>

      {/* Le blocage a-t-il un effet reseau reel ? La reponse doit etre visible
          sans avoir a lire la documentation. */}
      {firewall && (
        <div
          className={cn(
            'flex items-start gap-3 px-5 py-3 border-b',
            firewall.active ? 'bg-emerald-500/10' : 'bg-amber-500/10'
          )}
        >
          {firewall.active ? (
            <ShieldCheck
              className="w-4 h-4 shrink-0 mt-0.5 text-emerald-600 dark:text-emerald-400"
              aria-hidden
            />
          ) : (
            <ShieldOff
              className="w-4 h-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400"
              aria-hidden
            />
          )}
          <div className="text-xs space-y-0.5">
            <p className="font-semibold">
              {firewall.active
                ? `Blocage applique — pare-feu ${firewall.backend}`
                : 'Blocage non applique au reseau'}
            </p>
            <p className="text-muted-foreground">{firewall.explanation}</p>
            {firewall.last_error && (
              <p className="font-mono text-[11px] text-amber-700 dark:text-amber-300">
                {firewall.last_error}
              </p>
            )}
          </div>
        </div>
      )}

      <form
        className="grid gap-3 sm:grid-cols-[220px_1fr_auto] p-5 border-b bg-muted/20"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate();
        }}
      >
        <div className="space-y-1.5">
          <Label className="text-xs" htmlFor="ip">
            Adresse IP
          </Label>
          <Input
            id="ip"
            required
            placeholder="203.0.113.42"
            value={address}
            onChange={(event) => setAddress(event.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs" htmlFor="reason">
            Motif
          </Label>
          <Input
            id="reason"
            placeholder="Blocage manuel"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </div>
        <div className="flex items-end">
          <Button type="submit" disabled={add.isPending}>
            {add.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Ban className="size-4" />}
            Bloquer
          </Button>
        </div>
      </form>

      {isLoading ? (
        <div className="flex justify-center py-16">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
        </div>
      ) : !entries?.length ? (
        <EmptyState message="Aucune IP bloquee" />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Adresse IP</TableHead>
              <TableHead>Motif</TableHead>
              <TableHead>Origine</TableHead>
              <TableHead>Bloquee le</TableHead>
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {entries.map((entry) => (
              <TableRow key={entry.id} className="text-xs">
                <TableCell className="font-mono font-medium">{entry.ip_address}</TableCell>
                <TableCell className="text-muted-foreground">{entry.reason}</TableCell>
                <TableCell>
                  <span
                    className={
                      entry.is_automatic
                        ? 'inline-flex rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-700 dark:text-amber-300'
                        : 'inline-flex rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground'
                    }
                  >
                    {entry.is_automatic ? 'Automatique' : entry.blocked_by}
                  </span>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {formatDateTime(entry.created_at)}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    title={`Debloquer ${entry.ip_address}`}
                    onClick={() => setPendingUnblock(entry)}
                  >
                    Debloquer <span className="sr-only">{entry.ip_address}</span>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* Debloquer laisse a nouveau passer le trafic : confirmation requise */}
      <ConfirmDialog
        open={pendingUnblock !== null}
        onOpenChange={(open) => {
          if (!open && !remove.isPending) setPendingUnblock(null);
        }}
        title="Debloquer cette adresse IP ?"
        variant="destructive"
        confirmLabel="Debloquer"
        pending={remove.isPending}
        onConfirm={() => pendingUnblock && remove.mutate(pendingUnblock.id)}
        description={
          <>
            L’adresse{' '}
            <span className="font-mono font-medium text-foreground">
              {pendingUnblock?.ip_address}
            </span>{' '}
            {pendingUnblock?.is_automatic
              ? 'a ete bloquee automatiquement apres detection d’une attaque'
              : `a ete bloquee manuellement par ${pendingUnblock?.blocked_by}`}
            {pendingUnblock?.reason ? ` (${pendingUnblock.reason})` : ''}. La debloquer
            autorisera de nouveau son trafic
            {firewall?.active ? ' et retirera la regle de pare-feu correspondante' : ''}.
          </>
        }
      />
    </div>
  );
}
