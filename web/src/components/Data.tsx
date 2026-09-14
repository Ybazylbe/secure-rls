import { ListChecks, Table2 } from "lucide-react";
import { useState } from "react";

import type { Answer } from "@/api";
import { Table } from "@/components/Trace";
import { cn } from "@/lib/utils";

/**
 * The rows behind an answer, never typed by the model.
 *
 * When the model picked the rows its answer is about, those are shown: it
 * named them by label and the server looked the values up in the tool
 * results, so they cannot be invented, mislabelled or attributed to another
 * tenant. Otherwise each tool result can be viewed, the last one first -- with
 * a single "last result" view, an answer built from salaries and then a count
 * showed only the count.
 */
export function Data({ answer }: { answer: Answer }) {
  // Chart results are drawn by Charts, with their own table view.
  const results = answer.steps.filter(
    (step) => step.state === "ok" && !step.refused && step.rows.length > 0 && !step.chart,
  );
  const [chosen, setChosen] = useState(results.length - 1);
  const selected = answer.selected_rows ?? [];
  const ignored = answer.ignored_refs ?? [];

  if (selected.length > 0) {
    return (
      <div className="space-y-1.5">
        <p className="flex items-center gap-1.5 text-[0.75rem] font-medium text-ink/60">
          <ListChecks className="size-3.5" />
          Rows in this answer · {answer.scope.tenant} · {selected.length}
          {ignored.length > 0 &&
            ` · ${ignored.length} label${ignored.length === 1 ? "" : "s"} matched no row and were ignored`}
        </p>
        <Table rows={selected} total={selected.length} />
      </div>
    );
  }

  const shown = results[Math.min(Math.max(chosen, 0), results.length - 1)];
  if (!shown) return null;
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-1.5 text-[0.75rem] font-medium text-ink/60">
        <Table2 className="size-3.5" />
        Data · {answer.scope.tenant}
        {results.map((step, index) => (
          <button
            key={index}
            type="button"
            onClick={() => setChosen(index)}
            className={cn(
              "rounded-full border px-2 py-0.5 font-mono text-[0.7rem] transition-colors",
              step === shown
                ? "border-teal-deep bg-teal-deep text-white"
                : "border-line bg-white text-teal hover:bg-surface",
            )}
          >
            {step.tool} · {step.row_count}
          </button>
        ))}
      </div>
      <Table rows={shown.rows} total={shown.row_count} />
    </div>
  );
}
