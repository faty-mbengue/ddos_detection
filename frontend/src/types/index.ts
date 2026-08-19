// Contrats partages avec l'API FastAPI (app/schemas)

export const CLASS_NAMES = [
  'BENIGN',
  'DNS',
  'LDAP',
  'MSSQL',
  'NTP',
  'NetBIOS',
  'SNMP',
  'SSDP',
  'Syn',
  'TFTP',
  'UDP',
  'UDPLag',
] as const;

export type ClassName = (typeof CLASS_NAMES)[number];
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AttackStatus = 'ACTIVE' | 'MITIGATED';
export type UserRole = 'admin' | 'analyst' | 'viewer';

// ── Authentification ─────────────────────────────────────────────────────────

export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

// ── Trafic ───────────────────────────────────────────────────────────────────

export interface Packet {
  id?: number;
  timestamp: string;
  packet_no: number;
  time: number;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  length: number;
  info: string;
}

export interface FlowSummary {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  flow_duration: number;
  flow_byts_s: number;
  flow_pkts_s: number;
  tot_fwd_pkts: number;
  tot_bwd_pkts: number;
  totlen_fwd_pkts: number;
  totlen_bwd_pkts: number;
}

export interface Prediction {
  id: number;
  flow_id: number | null;
  prediction: ClassName | string;
  confidence: number;
  is_attack: boolean;
  prediction_timestamp: string;
  flow?: FlowSummary | null;
}

export interface Attack {
  id: number;
  timestamp: string;
  attack_type: string;
  source_ip: string;
  destination_ip: string;
  flows_count: number;
  total_bytes: number;
  total_packets: number;
  duration: number;
  avg_confidence: number;
  severity: Severity;
  status: AttackStatus;
}

// ── Tableau de bord ──────────────────────────────────────────────────────────

export interface Statistic {
  id: number;
  timestamp: string;
  total_flows: number;
  total_attacks: number;
  benign_flows: number;
  packets_per_second: number;
  bytes_per_second: number;
  active_attacks: number;
}

export interface Overview {
  total_flows: number;
  total_attacks: number;
  benign_flows: number;
  active_attacks: number;
  attack_ratio: number;
  packets_per_second: number;
  bytes_per_second: number;
  distinct_attack_types: number;
  top_source_ip: string | null;
  last_attack_at: string | null;
  system_status: 'NORMAL' | 'ATTACK';
  updated_at: string;
}

export interface DashboardData {
  overview: Overview;
  class_distribution: { name: string; count: number; is_attack: boolean }[];
  attacks_over_time: { bucket: string; attacks: number; benign: number }[];
  confidence_by_class: { name: string; avg_confidence: number; count: number }[];
  recent_attacks: Attack[];
  throughput_history: Statistic[];
}

export interface LiveStats {
  total_flows: number;
  total_attacks: number;
  benign_flows: number;
  packets_per_second: number;
  bytes_per_second: number;
  active_attacks: number;
  system_status: 'NORMAL' | 'ATTACK';
  last_attack: Attack | null;
  timestamp: string;
}

// ── Modele ───────────────────────────────────────────────────────────────────

export interface ClassMetrics {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface ModelMetrics {
  model: {
    algorithm: string | null;
    dataset: string | null;
    trained_at: string | null;
    is_demo: boolean;
    n_features: number;
    n_classes: number;
  };
  training: {
    accuracy: number | null;
    /** Moyennes non ponderees, calculees sur les 12 classes. */
    precision_macro: number | null;
    recall_macro: number | null;
    f1_macro: number | null;
    /** Moyennes ponderees par le support de chaque classe. */
    precision_weighted?: number | null;
    recall_weighted?: number | null;
    f1_weighted?: number | null;
    per_class: Record<string, ClassMetrics>;
    confusion_matrix: number[][] | null;
    labels: string[];
    n_train: number | null;
    n_test: number | null;
  };
  feature_importances: { feature: string; importance: number }[];
  production: {
    window_hours: number;
    total_predictions: number;
    attacks_detected: number;
    detection_rate: number;
    per_class: {
      class_name: string;
      count: number;
      share: number;
      avg_confidence: number;
      min_confidence: number;
      max_confidence: number;
      is_attack: boolean;
      training: ClassMetrics | null;
    }[];
  };
}

export interface SystemStatus {
  pipeline_running: boolean;
  cycles: number;
  last_cycle_at: string | null;
  interval_seconds: number;
  last_error: string | null;
  capture: {
    backend: string;
    running: boolean;
    interface: string;
    packets_captured: number;
    uptime_seconds: number;
  };
  model: { ready: boolean; model_type: string | null; is_demo: boolean };
  ws_clients: number;
}

// ── Administration ───────────────────────────────────────────────────────────

/** Etat du service de pare-feu : le blocage agit-il reellement sur le reseau ? */
export interface FirewallStatus {
  enabled: boolean;
  backend: string;
  active: boolean;
  available: boolean;
  last_error: string | null;
  explanation: string;
}

/** Une interface reseau vue par le backend. */
export interface NetworkInterface {
  name: string;
  description: string;
  /** Pseudo-interface Wireshark (sshdump, randpkt…) : ne capture aucun trafic local. */
  pseudo: boolean;
  /** Interface speciale de libpcap (`any`, `lo`). */
  special: boolean;
}

/** Ce que le backend peut reellement capturer, et pourquoi. */
export interface InterfacesStatus {
  available: boolean;
  interfaces: NetworkInterface[];
  real_interfaces?: string[];
  capture_possible: boolean;
  current: string;
  backend: string;
  in_container?: boolean;
  host_network?: boolean | null;
  explanation: string;
}

/** Etat de la configuration des alertes email. */
export interface EmailStatus {
  enabled: boolean;
  configured: boolean;
  host: string | null;
  port: number;
  starttls: boolean;
  user: string | null;
  /** Adresse declaree dans SMTP_FROM. */
  sender: string;
  /** Adresse qui arrivera reellement chez le destinataire. */
  effective_sender: string;
  /** true si le fournisseur remplacera l'expediteur declare. */
  sender_rewritten: boolean;
  sender_warning: string | null;
  recipients: string[];
  missing: string[];
  explanation: string;
}

export interface BlockedIP {
  id: number;
  ip_address: string;
  reason: string;
  blocked_by: string;
  is_automatic: boolean;
  created_at: string;
}

export interface SystemSettings {
  /** Moteur de capture : simulator | external | tshark */
  capture_backend: string;
  capture_interface: string;
  analysis_interval: number;
  confidence_threshold: number;
  flow_threshold: number;
  auto_block: boolean;
  email_alerts: boolean;
  alert_recipients: string;
}

/** Resultat de l'analyse d'un fichier depose (PCAP ou CSV CICFlowMeter). */
export interface FileAnalysis {
  filename: string;
  format: 'pcap' | 'csv';
  packets_read: number;
  flows_analyzed: number;
  attacks_detected: number;
  attack_ratio: number;
  confidence_threshold: number;
  attacks_below_threshold: number;
  /** Caracteristiques absentes du CSV, mises a zero. */
  missing_features: string[];
  distribution: {
    name: string;
    count: number;
    share: number;
    avg_confidence: number;
    is_attack: boolean;
  }[];
  top_sources: { ip: string; flows: number }[];
  top_targets: { ip: string; flows: number }[];
  /** Present si le fichier porte une colonne Label : compare la prediction a la verite. */
  ground_truth: {
    disponible: boolean;
    exactitude: number;
    corrects: number;
    total: number;
    par_classe: {
      label: string;
      total: number;
      corrects: number;
      exactitude: number;
    }[];
  } | null;
  sample: {
    src_ip: string;
    dst_ip: string;
    dst_port: number | null;
    prediction: string;
    confidence: number;
    is_attack: boolean;
    label: string | null;
  }[];
}

export interface Paginated<T> {
  total: number;
  limit: number;
  offset: number;
  items: T[];
}
