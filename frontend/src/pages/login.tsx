import { Loader2, Lock, ShieldCheck, User } from 'lucide-react';
import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { toast } from 'sonner';

import { ModeToggle } from '@/components/shared/theme-toogle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/hooks/use-auth';
import { errorMessage } from '@/service/api.service';

/** Page de connexion : authentification JWT contre /api/auth/login. */
export default function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (isAuthenticated) return <Navigate to="/live" replace />;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const user = await login(username.trim(), password);
      toast.success(`Bienvenue ${user.username}`);
      navigate('/live', { replace: true });
    } catch (err) {
      setError(errorMessage(err, 'Connexion impossible'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <div className="flex justify-end p-4">
        <ModeToggle />
      </div>

      <div className="flex-1 flex items-center justify-center px-4 pb-16">
        <div className="w-full max-w-sm space-y-6">
          <div className="text-center space-y-3">
            <div className="inline-flex p-3 rounded-2xl bg-primary/10">
              <ShieldCheck className="w-7 h-7 text-primary" aria-hidden />
            </div>
            <div>
              <h1 className="text-2xl font-bold">DDoS Monitor</h1>
              <p className="text-sm text-muted-foreground">
                Surveillance et detection des attaques DDoS en temps reel
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 p-6 rounded-xl border bg-card">
            <div className="space-y-2">
              <Label htmlFor="username">Nom d’utilisateur</Label>
              <div className="relative">
                <User
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  id="username"
                  className="pl-9"
                  autoComplete="username"
                  required
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="admin"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Mot de passe</Label>
              <div className="relative">
                <Lock
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  id="password"
                  type="password"
                  className="pl-9"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="••••••••"
                />
              </div>
            </div>

            {error && (
              <p className="text-xs text-red-600 dark:text-red-400 bg-red-500/10 border border-red-500/30 rounded-md px-3 py-2">
                {error}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
              Se connecter
            </Button>

            <p className="text-[11px] text-muted-foreground text-center pt-1">
              Authentification JWT · roles administrateur, analyste et lecture seule
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
