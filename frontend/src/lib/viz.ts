/**
 * Palette de visualisation.
 *
 * Les 12 classes du modele ne sont PAS encodees par 12 couleurs : au-dela de
 * huit teintes, aucune palette ne reste distinguable (y compris en vision des
 * couleurs deficiente). L'encodage suit le sens des donnees — trafic legitime
 * contre trafic malveillant — soit deux teintes seulement, l'identite de la
 * classe etant portee par l'axe et les etiquettes.
 *
 * Chaque paire ci-dessous a ete validee dans les deux modes (bande de clarte,
 * plancher de chroma, separation CVD, plancher vision normale, contraste >= 3:1
 * sur la surface des cartes) :
 *   clair  #ffffff : benign/attack ΔE CVD 21.6 · debit ΔE CVD 24.7
 *   sombre #171717 : benign/attack ΔE CVD 19.2 · debit ΔE CVD 26.8
 */

export type VizMode = 'light' | 'dark';

interface VizPalette {
  benign: string;
  attack: string;
  /** Deuxieme mesure des graphiques de debit (paquets/s vs octets/s). */
  secondary: string;
  grid: string;
  axis: string;
  muted: string;
  text: string;
  surface: string;
}

const PALETTES: Record<VizMode, VizPalette> = {
  light: {
    benign: '#2a78d6',
    attack: '#e34948',
    secondary: '#eb6834',
    grid: '#e1e0d9',
    axis: '#c3c2b7',
    muted: '#898781',
    text: '#0b0b0b',
    surface: '#ffffff',
  },
  dark: {
    benign: '#3987e5',
    attack: '#e66767',
    secondary: '#d95926',
    grid: '#2c2c2a',
    axis: '#383835',
    muted: '#898781',
    text: '#ffffff',
    surface: '#171717',
  },
};

export function vizPalette(mode: VizMode): VizPalette {
  return PALETTES[mode];
}

/** Palette de statut, reservee a la criticite des alertes (jamais aux series). */
export const SEVERITY_COLORS: Record<string, string> = {
  LOW: '#0ca30c', // good
  MEDIUM: '#fab219', // warning
  HIGH: '#ec835a', // serious
  CRITICAL: '#d03b3b', // critical
};

/** Classes utilitaires Tailwind associees a la criticite (badge + icone). */
export const SEVERITY_STYLES: Record<string, string> = {
  LOW: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
  MEDIUM: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
  HIGH: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30',
  CRITICAL: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30',
};

/** Mise en couleur du tableau de paquets, par protocole. */
export const PROTOCOL_STYLES: Record<string, string> = {
  TCP: 'text-blue-600 dark:text-blue-400',
  UDP: 'text-violet-600 dark:text-violet-400',
  ICMP: 'text-amber-600 dark:text-amber-400',
};

// ── Formatage ────────────────────────────────────────────────────────────────

const BYTE_UNITS = ['o', 'Ko', 'Mo', 'Go', 'To'];

export function formatBytes(value: number, digits = 1): string {
  if (!value || value < 0) return '0 o';
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), BYTE_UNITS.length - 1);
  return `${(value / 1024 ** exponent).toFixed(exponent === 0 ? 0 : digits)} ${BYTE_UNITS[exponent]}`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat('fr-FR').format(Math.round(value));
}

export function formatCompact(value: number): string {
  return new Intl.NumberFormat('fr-FR', { notation: 'compact', maximumFractionDigits: 1 }).format(
    value
  );
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('fr-FR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    year: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatHour(iso: string): string {
  return new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}

export function relativeTime(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `il y a ${seconds} s`;
  if (seconds < 3600) return `il y a ${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `il y a ${Math.floor(seconds / 3600)} h`;
  return `il y a ${Math.floor(seconds / 86400)} j`;
}
