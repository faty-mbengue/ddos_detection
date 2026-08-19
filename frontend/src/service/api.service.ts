import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
export const WS_BASE_URL = (() => {
  const configured = import.meta.env.VITE_WS_URL;
  if (configured?.startsWith('ws')) return configured;

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}${configured || '/ws'}`;
})();

export const TOKEN_KEY = 'ddos-monitor-token';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { Accept: 'application/json' },
  timeout: 30000,
});

// Injecte le jeton JWT sur chaque requete
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Un 401 signifie session expiree : on purge et on renvoie vers la connexion
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config?.url?.includes('/auth/login')) {
      localStorage.removeItem(TOKEN_KEY);
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

/** Extrait un message d'erreur lisible d'une reponse FastAPI. */
export function errorMessage(error: unknown, fallback = 'Une erreur est survenue'): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
    if (error.code === 'ERR_NETWORK') return 'Backend injoignable — verifiez que l’API est demarree';
    // nginx repond en HTML sur un depassement de taille : aucun `detail` a lire.
    if (error.response?.status === 413) {
      return 'Fichier trop volumineux pour le serveur web (limite 200 Mo). Deposez un extrait.';
    }
    return error.message || fallback;
  }
  return error instanceof Error ? error.message : fallback;
}

export default api;
