import { AlertTriangle, Loader2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** "destructive" pour une action irreversible (suppression). */
  variant?: 'default' | 'destructive';
  pending?: boolean;
  onConfirm: () => void;
}

/**
 * Confirmation d'une action sensible. Le bouton de confirmation recoit le focus
 * initial pour rester accessible au clavier, et Echap ou le bouton Annuler
 * ferment la boite sans rien declencher.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirmer',
  cancelLabel = 'Annuler',
  variant = 'default',
  pending = false,
  onConfirm,
}: ConfirmDialogProps) {
  const destructive = variant === 'destructive';

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-start gap-3">
            {destructive && (
              <div className="p-2 rounded-lg bg-red-500/10 shrink-0">
                <AlertTriangle
                  className="w-5 h-5 text-red-600 dark:text-red-400"
                  aria-hidden
                />
              </div>
            )}
            <div className="space-y-2 min-w-0 text-left">
              <DialogTitle>{title}</DialogTitle>
              <DialogDescription asChild>
                <div>{description}</div>
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={pending}
            onClick={() => onOpenChange(false)}
          >
            {cancelLabel}
          </Button>
          <Button
            type="button"
            variant={destructive ? 'destructive' : 'default'}
            disabled={pending}
            onClick={onConfirm}
          >
            {pending && <Loader2 className="w-4 h-4 animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
