import { Table2 } from "lucide-react";

import type { Answer } from "@/api";
import { Table } from "@/components/Trace";

/**
 * The rows behind an answer, taken straight from the tool results.
 *
 * The model is told not to copy tables into its answer, and the server removes
 * any it writes anyway, because a copy can be wrong: it has mislabelled whose
 * rows they were and invented rows outright. This panel is the one place the
 * user sees data, and nothing in it was written by the model.
 */
export function Data({ answer }: { answer: Answer }) {
  const withRows = answer.steps.filter(
    (step) => step.state === "ok" && !step.refused && step.rows.length > 0,
  );
  const last = withRows.at(-1);
  if (!last) return null;
  return (
    <div className="space-y-1.5">
      <p className="flex items-center gap-1.5 text-[0.75rem] font-medium text-ink/60">
        <Table2 className="size-3.5" />
        Data from <code className="text-teal">{last.tool}</code> · {answer.scope.tenant} ·{" "}
        {last.row_count} row{last.row_count === 1 ? "" : "s"}
        {withRows.length > 1 && ` (the last of ${withRows.length} results; all are in the trace)`}
      </p>
      <Table rows={last.rows} total={last.row_count} />
    </div>
  );
}
