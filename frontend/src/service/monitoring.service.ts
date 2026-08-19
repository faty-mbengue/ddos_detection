import api from './api.service';
import type {
  Attack,
  BlockedIP,
  DashboardData,
  EmailStatus,
  FileAnalysis,
  FirewallStatus,
  InterfacesStatus,
  LiveStats,
  ModelMetrics,
  Packet,
  Paginated,
  Prediction,
  Statistic,
  SystemSettings,
  SystemStatus,
  User,
  UserRole,
} from '@/types';

// ── Trafic temps reel ────────────────────────────────────────────────────────

/** Derniers paquets captures, filtrables par protocole. */
export async function fetchPackets(limit = 100, protocol?: string): Promise<Packet[]> {
  const { data } = await api.get<Packet[]>('/packets', { params: { limit, protocol } });
  return data;
}

/** Statistiques instantanees de la page Flux Live, filtrables par provenance. */
export async function fetchLiveStats(source?: string): Promise<LiveStats> {
  const { data } = await api.get<LiveStats>('/stats/live', { params: { source } });
  return data;
}

/** Historique du debit reseau pour le graphique temporel. */
export async function fetchStatsHistory(limit = 120): Promise<Statistic[]> {
  const { data } = await api.get<Statistic[]>('/stats/history', { params: { limit } });
  return data;
}

// ── Tableau de bord ──────────────────────────────────────────────────────────

/** Toutes les donnees agregees du tableau de bord.
 *
 * `source` isole une provenance ("simulator", "external", "tshark") pour ne pas
 * additionner du trafic simule avec du trafic reel.
 */
export async function fetchDashboard(hours = 24, source?: string): Promise<DashboardData> {
  const { data } = await api.get<DashboardData>('/dashboard', { params: { hours, source } });
  return data;
}

/** Etat du pipeline, de la capture, du modele et du pare-feu. */
export async function fetchSystemStatus(): Promise<SystemStatus> {
  const { data } = await api.get<SystemStatus>('/system/status');
  return data;
}

// ── Predictions ──────────────────────────────────────────────────────────────

export interface PredictionFilters {
  limit?: number;
  offset?: number;
  only_attacks?: boolean;
  attack_type?: string;
  min_confidence?: number;
}

/** Classifications recentes, selon les filtres fournis. */
export async function fetchPredictions(filters: PredictionFilters = {}): Promise<Prediction[]> {
  const { data } = await api.get<Prediction[]>('/predictions', { params: filters });
  return data;
}

/** Nombre de flux et confiance moyenne par classe. */
export async function fetchPredictionDistribution(
  hours = 24
): Promise<{ name: string; count: number; avg_confidence: number; is_attack: boolean }[]> {
  const { data } = await api.get('/predictions/distribution', { params: { hours } });
  return data;
}

/** Classe un vecteur de caracteristiques a la demande. */
export async function predictOne(features: number[], persist = false) {
  const { data } = await api.post('/predict', { features, persist });
  return data as {
    prediction: string;
    class_index: number;
    confidence: number;
    is_attack: boolean;
    probabilities: Record<string, number>;
  };
}

// ── Historique des alertes ───────────────────────────────────────────────────

export interface AttackFilters {
  limit?: number;
  offset?: number;
  attack_type?: string;
  severity?: string;
  attack_status?: string;
  ip?: string;
  since?: string;
  until?: string;
  sort?: 'recent' | 'severity';
}

/** Journal des alertes, filtre et pagine. */
export async function fetchAttacks(filters: AttackFilters = {}): Promise<Paginated<Attack>> {
  const { data } = await api.get<Paginated<Attack>>('/attacks', { params: filters });
  return data;
}

/** Types d'attaques presents dans l'historique. */
export async function fetchAttackTypes(): Promise<{ attack_type: string; count: number }[]> {
  const { data } = await api.get('/attacks/types');
  return data;
}

/** Synthese des alertes : criticite, types, principales sources. */
export async function fetchAttackSummary(hours = 24) {
  const { data } = await api.get('/attacks/summary', { params: { hours } });
  return data as {
    window_hours: number;
    by_severity: { severity: string; count: number }[];
    by_type: { attack_type: string; count: number; avg_confidence: number }[];
    top_sources: { source_ip: string; alerts: number; flows: number }[];
  };
}

/** Marque une alerte comme traitee. */
export async function mitigateAttack(id: number): Promise<Attack> {
  const { data } = await api.patch<Attack>(`/attacks/${id}/mitigate`);
  return data;
}

/** Telecharge un export CSV en declenchant la sauvegarde navigateur. */
export async function downloadCsv(path: string, filename: string, params?: object): Promise<void> {
  const response = await api.get(path, { params, responseType: 'blob' });
  const url = URL.createObjectURL(response.data as Blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// ── Modele ───────────────────────────────────────────────────────────────────

/** Metriques du modele, a l'entrainement et en production. */
export async function fetchModelMetrics(hours = 24): Promise<ModelMetrics> {
  const { data } = await api.get<ModelMetrics>('/model/metrics', { params: { hours } });
  return data;
}

/** Liste ordonnee des caracteristiques attendues par le modele. */
export async function fetchModelFeatures(): Promise<{
  n_features: number;
  features: string[];
  classes: string[];
}> {
  const { data } = await api.get('/model/features');
  return data;
}

/** Recharge les artefacts du modele depuis le disque (admin). */
export async function reloadModel() {
  const { data } = await api.post('/model/reload');
  return data;
}

// ── Analyse de fichier ───────────────────────────────────────────────────────

/** Envoie un PCAP ou un CSV CICFlowMeter et retourne l'analyse complete.
 *
 * Rien n'est enregistre en base : le resultat est purement consultatif, ce qui
 * evite de melanger une capture rejouee au trafic reellement surveille.
 */
export async function analyzeFile(fichier: File): Promise<FileAnalysis> {
  const corps = new FormData();
  corps.append('file', fichier);
  const { data } = await api.post<FileAnalysis>('/analysis/upload', corps, {
    headers: { 'Content-Type': 'multipart/form-data' },
    // Un gros PCAP peut demander plusieurs minutes de lecture par tshark.
    timeout: 600000,
  });
  return data;
}

// ── Administration ───────────────────────────────────────────────────────────

/** Liste des comptes utilisateurs. */
export async function fetchUsers(): Promise<User[]> {
  const { data } = await api.get<User[]>('/admin/users');
  return data;
}

/** Cree un compte utilisateur. */
export async function createUser(payload: {
  username: string;
  email: string;
  password: string;
  role: UserRole;
}): Promise<User> {
  const { data } = await api.post<User>('/admin/users', payload);
  return data;
}

/** Met a jour un compte (email, role, activation, mot de passe). */
export async function updateUser(
  id: number,
  payload: Partial<{ email: string; password: string; role: UserRole; is_active: boolean }>
): Promise<User> {
  const { data } = await api.patch<User>(`/admin/users/${id}`, payload);
  return data;
}

/** Supprime definitivement un compte. */
export async function deleteUser(id: number): Promise<void> {
  await api.delete(`/admin/users/${id}`);
}

/** Configuration de detection actuellement appliquee. */
export async function fetchSettings(): Promise<SystemSettings> {
  const { data } = await api.get<SystemSettings>('/admin/settings');
  return data;
}

/** Applique une modification de configuration, a chaud. */
export async function updateSettings(payload: Partial<SystemSettings>): Promise<SystemSettings> {
  const { data } = await api.put<SystemSettings>('/admin/settings', payload);
  return data;
}

/** Demarre ou arrete la boucle de capture et d'analyse. */
export async function controlPipeline(action: 'start' | 'stop'): Promise<SystemStatus> {
  const { data } = await api.post<SystemStatus>(`/admin/pipeline/${action}`);
  return data;
}

/** Liste des adresses IP bloquees. */
export async function fetchBlockedIps(): Promise<BlockedIP[]> {
  const { data } = await api.get<BlockedIP[]>('/admin/blocked-ips');
  return data;
}

/** Indique si les blocages posent de vraies regles de pare-feu ou restent documentaires. */
export async function fetchFirewallStatus(): Promise<FirewallStatus> {
  const { data } = await api.get<FirewallStatus>('/admin/firewall');
  return data;
}

/** Interfaces reseau reellement capturables, avec le diagnostic associe. */
export async function fetchInterfaces(): Promise<InterfacesStatus> {
  const { data } = await api.get<InterfacesStatus>('/admin/interfaces');
  return data;
}

/** Etat de la configuration des alertes email. */
export async function fetchEmailStatus(): Promise<EmailStatus> {
  const { data } = await api.get<EmailStatus>('/admin/email');
  return data;
}

/** Envoie un email de test aux destinataires configures. */
export async function sendTestEmail(): Promise<{ sent: boolean; detail: string }> {
  const { data } = await api.post('/admin/email/test');
  return data;
}

/** Bloque une adresse IP et pose la regle de pare-feu si actif. */
export async function blockIp(ip_address: string, reason: string): Promise<BlockedIP> {
  const { data } = await api.post<BlockedIP>('/admin/blocked-ips', { ip_address, reason });
  return data;
}

/** Debloque une adresse IP et retire sa regle de pare-feu. */
export async function unblockIp(id: number): Promise<void> {
  await api.delete(`/admin/blocked-ips/${id}`);
}
