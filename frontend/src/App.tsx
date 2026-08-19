import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from '@/components/shared/app-layout';
import { ThemeProvider } from '@/components/shared/theme-provider';
import { Toaster } from '@/components/ui/sonner';
import { useAuth, AuthProvider } from '@/hooks/use-auth';
import AdminPage from '@/pages/admin';
import AnalyzePage from '@/pages/analyze';
import DashboardPage from '@/pages/dashboard';
import HistoryPage from '@/pages/history';
import LivePage from '@/pages/live';
import LoginPage from '@/pages/login';
import MetricsPage from '@/pages/metrics';
import PredictionsPage from '@/pages/predictions';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1, staleTime: 5000 },
  },
});

/** Barriere d'authentification : redirige vers /login si la session est absente. */
function RequireAuth({ children, adminOnly = false }: { children: React.ReactNode; adminOnly?: boolean }) {
  const { isAuthenticated, isAdmin, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 text-muted-foreground">
        <Loader2 className="w-7 h-7 animate-spin text-primary" />
        <p className="text-sm">Verification de la session…</p>
      </div>
    );
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (adminOnly && !isAdmin) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

/** Reprend la derniere page visitee, comme demande dans la specification. */
function LastVisitedRedirect() {
  const last = localStorage.getItem('ddos-monitor-last-page');
  return <Navigate to={last && last !== '/' ? last : '/live'} replace />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="light" storageKey="ddos-monitor-theme">
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<LoginPage />} />

              <Route
                element={
                  <RequireAuth>
                    <AppLayout />
                  </RequireAuth>
                }
              >
                <Route path="/live" element={<LivePage />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/predictions" element={<PredictionsPage />} />
                <Route path="/metrics" element={<MetricsPage />} />
                <Route path="/analyze" element={<AnalyzePage />} />
                <Route
                  path="/admin"
                  element={
                    <RequireAuth adminOnly>
                      <AdminPage />
                    </RequireAuth>
                  }
                />
              </Route>

              <Route path="/" element={<LastVisitedRedirect />} />
              <Route path="*" element={<Navigate to="/live" replace />} />
            </Routes>
          </BrowserRouter>

          <Toaster position="top-right" richColors closeButton />
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
