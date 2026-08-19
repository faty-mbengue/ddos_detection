import { Database } from 'lucide-react';

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

/** Valeur speciale : ne filtre rien. */
export const TOUTES_SOURCES = 'all';

const SOURCES = [
  { value: TOUTES_SOURCES, label: 'Toutes les sources' },
  { value: 'external', label: 'Trafic reel (agent)' },
  { value: 'tshark', label: 'Trafic reel (conteneur)' },
  { value: 'simulator', label: 'Trafic simule' },
];

/**
 * Selecteur de provenance des donnees.
 *
 * La base peut contenir a la fois du trafic simule et du trafic reel : sans ce
 * filtre, les indicateurs additionneraient les deux, ce qui fausserait toute
 * lecture des resultats.
 */
export function SourceFilter({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <Database className="w-3.5 h-3.5 text-muted-foreground shrink-0" aria-hidden />
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="h-8 w-[185px] text-xs" aria-label="Provenance des donnees">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {SOURCES.map((source) => (
            <SelectItem key={source.value} value={source.value}>
              {source.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
