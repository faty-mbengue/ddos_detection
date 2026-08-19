import api, { TOKEN_KEY } from './api.service';
import type { TokenResponse, User } from '@/types';

const USER_KEY = 'ddos-monitor-user';

/** Authentifie l'utilisateur et memorise son jeton et son profil. */
export async function login(username: string, password: string): Promise<TokenResponse> {
  // L'endpoint OAuth2 de FastAPI attend un formulaire, pas du JSON
  const body = new URLSearchParams({ username, password });
  const { data } = await api.post<TokenResponse>('/auth/login', body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  localStorage.setItem(TOKEN_KEY, data.access_token);
  localStorage.setItem(USER_KEY, JSON.stringify(data.user));
  return data;
}

/** Efface le jeton et le profil stockes localement. */
export function logout(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

/** Retourne le jeton JWT stocke, ou null. */
export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

/** Retourne le profil memorise, ou null s'il est absent ou illisible. */
export function getStoredUser(): User | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

/** Revalide la session aupres de l'API et rafraichit le profil. */
export async function fetchMe(): Promise<User> {
  const { data } = await api.get<User>('/auth/me');
  localStorage.setItem(USER_KEY, JSON.stringify(data));
  return data;
}

/** Change le mot de passe de l'utilisateur connecte. */
export async function changePassword(current: string, next: string): Promise<void> {
  await api.post('/auth/change-password', null, { params: { current, new: next } });
}
