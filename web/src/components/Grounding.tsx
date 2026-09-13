import { Database, TriangleAlert } from "lucide-react";

import type { Answer } from "@/api";

/**
 * Figures in the answer that no tool result contains.
 *
 * The containment verdict says nothing about invented content: an answer can
 * keep every foreign row out and still print a fabricated table for a tenant
 * that does not exist. The grounding check already computes which numbers were
 * never returned by a tool; this makes that visible next to the answer instead
 * of leaving it in the payload.
 */
export function Grounding({ answer }: { answer: Answer }) {
  const claimed = answer.claimed_tenants ?? [];
  const scope = answer.scope;
  const shown = answer.ungrounded.slice(0, 8);
  const more = answer.ungrounded.length - shown.length;
  if (!scope?.calls && shown.length === 0 && claimed.length === 0) return null;

  return (
    <div className="space-y-1.5">
      {scope?.calls > 0 && (
        // Written by the server, not the model, so it holds even when the
        // answer text above attributes the data to someone else.
        <p className="flex items-center gap-1.5 text-[0.75rem] text-ink/50">
          <Database className="size-3" />
          Source: {scope.tenant}'s data only · {scope.rows} row{scope.rows === 1 ? "" : "s"} from{" "}
          {scope.calls} tool call{scope.calls === 1 ? "" : "s"}
        </p>
      )}
      {claimed.length > 0 && (
        // A table labelled with another tenant reads as a leak even when it is
        // invented. Say plainly which it is, because the verdict alone does not
        // appear next to the text a viewer is reading.
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[0.8rem] text-amber-900">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
          <p>
            <span className="font-medium">
              The answer presents rows for {claimed.map((t) => `"${t}"`).join(", ")}.
            </span>{" "}
            No tool result contains rows for that tenant, so the model wrote them itself — treat
            that part of the answer as false.
          </p>
        </div>
      )}
      {shown.length > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[0.8rem] text-amber-900">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
          <p>
            <span className="font-medium">Not from any tool result:</span>{" "}
            {shown.map((n) => n.toLocaleString("en-US", { maximumFractionDigits: 2 })).join(", ")}
            {more > 0 && ` and ${more} more`}. The model wrote these figures itself; treat them as
            unverified.
          </p>
        </div>
      )}
    </div>
  );
}
