import { TriangleAlert } from "lucide-react";

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
  if (answer.ungrounded.length === 0) return null;

  const shown = answer.ungrounded.slice(0, 8);
  const more = answer.ungrounded.length - shown.length;
  return (
    <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[0.8rem] text-amber-900">
      <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
      <p>
        <span className="font-medium">Not from any tool result:</span>{" "}
        {shown.map((n) => n.toLocaleString("en-US", { maximumFractionDigits: 2 })).join(", ")}
        {more > 0 && ` and ${more} more`}. The model wrote these figures itself; treat them as
        unverified.
      </p>
    </div>
  );
}
