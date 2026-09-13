import { Loader2, Users } from "lucide-react";
import { useState } from "react";

import { api, type Answer } from "@/api";
import { Trace } from "@/components/Trace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

const TENANTS = ["acme", "beta", "gamma"];

export function Compare({ tenant, model }: { tenant: string; model: string }) {
  const others = TENANTS.filter((t) => t !== tenant);
  const [question, setQuestion] = useState("What is the average salary by department?");
  const [other, setOther] = useState(others[0]);
  const [pair, setPair] = useState<{ mine: Answer & { tenant: string }; theirs: Answer & { tenant: string } } | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      setPair(await api.compare(question, model, other));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5 py-5">
      <div className="space-y-1.5">
        <h2 className="text-xl font-semibold text-teal-deep">Same question, two tenants</h2>
        <p className="max-w-3xl text-sm leading-relaxed text-ink/60">
          Nothing about the question changes — only who is asking. The second identity is built on
          the server from the closed tenant list; this view demonstrates isolation, it does not
          offer a way around it.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <Input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          className="max-w-xl flex-1"
        />
        <div className="flex gap-1.5">
          {others.map((name) => (
            <Button
              key={name}
              variant={other === name ? "primary" : "outline"}
              size="sm"
              onClick={() => setOther(name)}
            >
              {name}
            </Button>
          ))}
        </div>
        <Button onClick={run} disabled={busy}>
          {busy ? <Loader2 className="size-4 animate-spin" /> : <Users className="size-4" />}
          Ask both
        </Button>
      </div>

      {pair && (
        <div className="grid gap-4 lg:grid-cols-2">
          {[pair.mine, pair.theirs].map((side) => (
            <Card key={side.tenant}>
              <CardContent className="space-y-3 pt-4">
                <Badge tone="info">{side.tenant}</Badge>
                <p className="whitespace-pre-wrap text-sm leading-relaxed">{side.text}</p>
                <Trace steps={side.steps} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
