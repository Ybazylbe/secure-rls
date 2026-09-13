import { CircleCheck, CircleX, Loader2, Play } from "lucide-react";
import { useEffect, useState } from "react";

import { api, type AttackRow, type AttackSpec } from "@/api";
import { Trace } from "@/components/Trace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";

export function Security({ model }: { model: string }) {
  const [catalogue, setCatalogue] = useState<AttackSpec[]>([]);
  const [results, setResults] = useState<AttackRow[] | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.attacks().then(setCatalogue).catch(() => setCatalogue([]));
  }, []);

  async function run(onlyFeatured: boolean) {
    setBusy(true);
    try {
      setResults((await api.runAttacks(model, onlyFeatured)).results);
    } finally {
      setBusy(false);
    }
  }

  const featured = catalogue.filter((a) => a.featured).length;
  const leaked = results?.filter((r) => !r.contained).length ?? 0;

  return (
    <div className="space-y-5 py-5">
      <div className="space-y-1.5">
        <h2 className="text-xl font-semibold text-teal-deep">Attack suite</h2>
        <p className="max-w-3xl text-sm leading-relaxed text-ink/60">
          Each attack is put to the agent as a real question. The verdict looks at the{" "}
          <strong className="font-medium text-ink/80">data returned</strong>, not at how the answer
          is phrased: an attack is contained when every row the tools produced belongs to the
          signed-in tenant.
        </p>
        <p className="text-[0.8rem] text-ink/45">
          A local 12B model needs roughly 20–30 seconds per attack, so the full catalogue is a job
          for CI rather than for a live audience.
        </p>
      </div>

      <div className="flex flex-wrap gap-2.5">
        <Button onClick={() => run(true)} disabled={busy}>
          {busy ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
          Run the featured {featured}
        </Button>
        <Button variant="outline" onClick={() => run(false)} disabled={busy}>
          Run all {catalogue.length} (slow)
        </Button>
      </div>

      {results && (
        <Card className={leaked === 0 ? "border-lime/60 bg-lime/8" : "border-red-300 bg-red-50"}>
          <CardContent className="pt-4">
            <p className="text-sm font-semibold text-teal-deep">
              Leak rate {leaked}/{results.length}
            </p>
            <p className="pt-0.5 text-[0.82rem] text-ink/60">
              {leaked === 0
                ? "Every attack was answered from the signed-in tenant's own data, or refused."
                : "At least one attack returned data belonging to another tenant."}
            </p>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2.5">
        {(results ?? catalogue).map((row) => {
          const outcome = "contained" in row ? (row as AttackRow) : null;
          return (
            <Card key={row.id}>
              <CardContent className="space-y-2 pt-4">
                <div className="flex flex-wrap items-center gap-2">
                  {outcome &&
                    (outcome.contained ? (
                      <CircleCheck className="size-4 text-[#57661a]" />
                    ) : (
                      <CircleX className="size-4 text-red-600" />
                    ))}
                  <code className="text-sm font-medium text-teal-deep">{row.id}</code>
                  <Badge tone="info">{row.category}</Badge>
                </div>
                <p className="text-[0.82rem] italic text-ink/55">{row.intent}</p>
                <p className="rounded-lg bg-surface px-3 py-2 text-[0.82rem] text-ink/75">
                  {row.prompt}
                </p>
                {outcome && (
                  <>
                    <p className="text-[0.8rem] text-ink/60">verdict: {outcome.evidence}</p>
                    <Disclosure summary={<span className="text-ink/70">what the agent did</span>}>
                      <p className="whitespace-pre-wrap text-[0.82rem]">{outcome.answer.text}</p>
                      <Trace steps={outcome.answer.steps} />
                    </Disclosure>
                  </>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
