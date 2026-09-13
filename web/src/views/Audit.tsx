import { RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api, type AuditRow } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const TONE = { allowed: "good", refused: "bad", error: "warn" } as const;

export function Audit() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const load = useCallback(() => {
    api.audit().then(setRows).catch(() => setRows([]));
  }, []);
  useEffect(load, [load]);

  return (
    <div className="space-y-4 py-5">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1.5">
          <h2 className="text-xl font-semibold text-teal-deep">Audit trail</h2>
          <p className="max-w-3xl text-sm leading-relaxed text-ink/60">
            Every security decision is written down. This view is itself tenant-scoped: you are
            looking at your own tenant's activity only.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load}>
          <RefreshCw className="size-3.5" />
          Refresh
        </Button>
      </div>

      {rows.length === 0 ? (
        <p className="text-sm text-ink/50">Nothing recorded yet. Ask a question first.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-line">
          <table className="w-full text-left text-[0.82rem]">
            <thead className="bg-surface text-ink/55">
              <tr>
                {["time", "event", "verdict", "layer", "rows", "detail"].map((column) => (
                  <th key={column} className="px-3 py-2 font-medium">
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index} className="border-t border-line/70">
                  <td className="px-3 py-1.5 tabular-nums text-ink/50">{row.time}</td>
                  <td className="px-3 py-1.5">{row.event}</td>
                  <td className="px-3 py-1.5">
                    <Badge tone={TONE[row.verdict as keyof typeof TONE] ?? "neutral"}>
                      {row.verdict}
                    </Badge>
                  </td>
                  <td className="px-3 py-1.5 text-teal">{row.layer ?? ""}</td>
                  <td className="px-3 py-1.5 tabular-nums">{row.rows ?? ""}</td>
                  <td className="max-w-[32rem] truncate px-3 py-1.5 text-ink/60">{row.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
