import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import * as authService from '@/service/auth.service';
import type { User } from '@/types';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  canWrite: boolean;
  login: (username: string, password: string) => Promise<User>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Fournit la session courante a toute l'application. */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(() => authService.getStoredUser());
  const [loading, setLoading] = useState(Boolean(authService.getToken()));

  // Revalide le jeton stocke au chargement de l'application.
  // Sans jeton, `loading` vaut deja false : rien a faire.
  useEffect(() => {
    if (!authService.getToken()) return;

    let alive = true;
    authService
      .fetchMe()
      .then((me) => alive && setUser(me))
      .catch(() => {
        if (!alive) return;
        authService.logout();
        setUser(null);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const { user: authenticated } = await authService.login(username, password);
    setUser(authenticated);
    return authenticated;
  }, []);

  const logout = useCallback(() => {
    authService.logout();
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      isAuthenticated: Boolean(user),
      isAdmin: user?.role === 'admin',
      canWrite: user?.role === 'admin' || user?.role === 'analyst',
      login,
      logout,
    }),
    [user, loading, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Accede a la session ; echoue hors d'un AuthProvider. */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth doit etre utilise dans un AuthProvider');
  return context;
}
