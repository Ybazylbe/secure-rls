import { AlertTriangle, Ban, Check, Database, ShieldAlert, SkipForward } from "lucide-react";

import type { Step } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Disclosure } from "@/components/ui/disclosure";
import { cn } from "@/lib/utils";

const STATE = {
  ok: { icon: Check, tone: "good", label: "ran" },
  rejected: { icon: Ban, tone: "bad", label: "refused" },
  skipped: { icon: SkipForward, tone: "neutral", label: "not dispatched" },
  unverifiable: { icon: AlertTriangle, tone: "warn", label: "unverified" },
} as const;

function Table({ rows }: { rows: Record<string, unknown>[] }) {
  const columns = Object.keys(rows[0] ?? {});
  return (
    <div className="overflow-x-auto rounded-lg border border-line">
      <table className="w-full text-left text-[0.8rem]">
        <thead className="bg-surface text-ink/60">
          <tr>
            {columns.map((c) => (
              <th key={c} className="px-3 py-1.5 font-medium">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 12).map((row, i) => (
            <tr key={i} className="border-t border-line/70">
              {columns.map((c) => (
                <td key={c} className="max-w-[22rem] truncate px-3 py-1.5">
                  {formatCell(row[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 12 && (
        <p className="px-3 py-1.5 text-[0.75rem] text-ink/50">
          {rows.length - 12} further rows not shown
        </p>
      )}
    </div>
  );
}

function formatCell(value: unknown) {
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return value.toLocaleString("en-US", { maximumFractionDigits: 2 });
  return String(value);
}

export function Trace({ steps }: { steps: Step[] }) {
  if (steps.length === 0) {
    return <p className="text-[0.8rem] text-ink/50">Answered without calling a tool.</p>;
  }
  return (
    <div className="space-y-2">
      {steps.map((step, index) => {
        const meta = STATE[step.state];
        const Icon = step.refused ? Ban : meta.icon;
        const tone = step.refused ? "bad" : meta.tone;
        return (
          <Disclosure
            key={index}
            defaultOpen={step.state !== "ok" || step.refused}
            summary={
              <span className="flex flex-1 items-center gap-2">
                <Icon
                  className={cn(
                    "size-3.5",
                    tone === "good" && "text-[#57661a]",
                    tone === "bad" && "text-red-600",
                    tone === "warn" && "text-amber-600",
                  )}
                />
                <span className="font-medium text-teal-deep">step {index + 1}</span>
                <code className="rounded bg-white px-1.5 py-0.5 text-[0.72rem] text-teal">
                  {step.tool}
                </code>
                {step.flags.length > 0 && (
                  <Badge tone="warn" className="ml-auto">
                    <ShieldAlert className="size-3" />
                    untrusted content
                  </Badge>
                )}
              </span>
            }
          >
            <pre className="overflow-x-auto rounded-lg bg-white p-2.5 text-[0.72rem] text-ink/70">
              {JSON.stringify(step.arguments, null, 2)}
            </pre>

            {step.state === "rejected" && (
              <p className="rounded-lg bg-red-50 px-3 py-2 text-[0.8rem] text-red-800">
                Refused before it ran: the arguments are not ones this tool declares. Nothing
                executed.
              </p>
            )}
            {step.state === "skipped" && (
              <p className="rounded-lg bg-surface px-3 py-2 text-[0.8rem] text-ink/65">
                The step limit was reached before this call was dispatched, so it never ran.
              </p>
            )}
            {step.state === "unverifiable" && (
              <p className="rounded-lg bg-amber-50 px-3 py-2 text-[0.8rem] text-amber-800">
                The tool ran but its output was not recorded, so nothing here can be verified.
              </p>
            )}
            {step.refused && step.reason && (
              <p className="rounded-lg bg-red-50 px-3 py-2 text-[0.8rem] text-red-800">
                {step.reason}
              </p>
            )}

            {step.sql && (
              <div className="space-y-1">
                {/* A refused statement is shown so the reader can see what was
                    attempted, but it must not be labelled as executed: that
                    reads as "the base table was queried" on the attack screen. */}
                <p
                  className={cn(
                    "flex items-center gap-1.5 text-[0.75rem] font-medium",
                    step.refused ? "text-red-700" : "text-ink/60",
                  )}
                >
                  {step.refused ? <Ban className="size-3.5" /> : <Database className="size-3.5" />}
                  {step.refused
                    ? "SQL that was refused — no rows were returned"
                    : "SQL actually executed, after the guard rewrote it"}
                </p>
                <pre
                  className={cn(
                    "overflow-x-auto rounded-lg p-2.5 text-[0.72rem]",
                    step.refused
                      ? "bg-red-50/60 text-red-900/70"
                      : "bg-white text-teal-deep",
                  )}
                >
                  {step.sql}
                </pre>
              </div>
            )}
            {step.rewrites.map((note) => (
              <p key={note} className="text-[0.75rem] text-ink/50">
                guard: {note}
              </p>
            ))}
            {step.rows.length > 0 && <Table rows={step.rows} />}
          </Disclosure>
        );
      })}
    </div>
  );
}
