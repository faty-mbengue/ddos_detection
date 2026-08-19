/** Infobulle commune a tous les graphiques Recharts (survol par defaut). */
export function ChartTooltip({
  active,
  payload,
  label,
  valueFormatter,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number | string; color?: string }>;
  label?: string | number;
  valueFormatter?: (value: number) => string;
}) {
  if (!active || !payload?.length) return null;

  return (
    <div className="bg-popover border rounded-lg shadow-lg px-3 py-2 text-xs space-y-1">
      {label !== undefined && <p className="font-semibold text-foreground">{label}</p>}
      {payload.map((item, index) => (
        <div key={`${item.name}-${index}`} className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ backgroundColor: item.color }}
            aria-hidden
          />
          <span className="text-muted-foreground">{item.name} :</span>
          <span className="font-mono font-semibold text-foreground tabular-nums">
            {typeof item.value === 'number' && valueFormatter
              ? valueFormatter(item.value)
              : item.value}
          </span>
        </div>
      ))}
    </div>
  );
}
