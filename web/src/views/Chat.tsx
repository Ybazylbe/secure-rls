import { ArrowUp, Bot, Loader2, User } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api, type Answer, type HistoryTurn } from "@/api";
import { Charts } from "@/components/Chart";
import { Data } from "@/components/Data";
import { Grounding } from "@/components/Grounding";
import { Trace } from "@/components/Trace";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** One question and the agent's answer to it. */
export type Turn = { question: string; answer: Answer };

/** How many prior turns are sent as context. Mirrors agent.MAX_HISTORY_TURNS
 * on the backend, which ignores anything past its own window anyway; kept in
 * step here only so the request does not carry turns nobody will read. */
const HISTORY_WINDOW = 4;

/** Example questions shown as buttons above the input box: [button label, question]. */
const SUGGESTIONS: [string, string][] = [
  ["Avg salary", "What is the average salary in Engineering?"],
  ["By department", "Which departments have the highest average salary?"],
  ["Outliers", "Which employees have an unusual salary for their department?"],
  ["Top earners", "List the five highest paid employees with their departments."],
  ["Notes", "Who is flagged as a retention risk in the review notes?"],
];

/** The Chat view: the conversation so far, suggested questions, and the input box. */
export function Chat({
  tenant,
  model,
  turns,
  onTurn,
}: {
  tenant: string;
  model: string;
  turns: Turn[];
  onTurn: (turn: Turn) => void;
}) {
  const [draft, setDraft] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const foot = useRef<HTMLDivElement>(null);

  useEffect(() => {
    foot.current?.scrollIntoView({ behavior: "smooth" });
  }, [turns.length, pending]);

  /** Send a question to the agent and add the answer to the conversation. */
  async function send(question: string) {
    if (!question.trim() || pending) return;
    setDraft("");
    setPending(question);
    setError(null);
    try {
      const history: HistoryTurn[] = turns
        .slice(-HISTORY_WINDOW)
        .map((turn) => ({ question: turn.question, answer: turn.answer.text }));
      onTurn({ question, answer: await api.ask(question, model, history) });
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed");
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 space-y-6 overflow-y-auto px-1 pt-6 pb-6">
        {turns.length === 0 && !pending && (
          <div className="pt-1">
            <h2 className="text-xl font-semibold text-teal-deep">Ask about {tenant}'s employees</h2>
            <p className="pt-1 text-sm text-ink/55">
              Every answer is computed from the rows you are allowed to see. Open a step to check
              the SQL that ran.
            </p>
          </div>
        )}

        {turns.map((turn, index) => (
          <div key={index} className="space-y-4">
            <Bubble side="user">{turn.question}</Bubble>
            <Bubble side="assistant">
              <p className="whitespace-pre-wrap">{turn.answer.text}</p>
              <div className="space-y-3 pt-3">
                <Grounding answer={turn.answer} />
                <Charts answer={turn.answer} />
                <Data answer={turn.answer} />
                <Trace steps={turn.answer.steps} />
              </div>
            </Bubble>
          </div>
        ))}

        {pending && (
          <div className="space-y-4">
            <Bubble side="user">{pending}</Bubble>
            <Bubble side="assistant">
              <span className="flex items-center gap-2 text-sm text-ink/50">
                <Loader2 className="size-4 animate-spin" />
                Thinking…
              </span>
            </Bubble>
          </div>
        )}

        {error && <p className="text-sm text-red-600">{error}</p>}
        <div ref={foot} />
      </div>

      <div className="space-y-2.5 border-t border-line pt-3 pb-6">
        <div className="flex flex-wrap gap-2">
          {SUGGESTIONS.map(([label, question]) => (
            <Button
              key={label}
              variant="outline"
              size="chip"
              title={question}
              onClick={() => send(question)}
            >
              {label}
            </Button>
          ))}
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            send(draft);
          }}
          className="flex items-center gap-2 rounded-full border border-line bg-white px-4 py-1.5
                     shadow-sm shadow-teal-deep/5 focus-within:border-cyan"
        >
          <input
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder={`Ask about ${tenant}'s employees`}
            className="h-9 flex-1 bg-transparent text-sm outline-none placeholder:text-ink/40"
          />
          <Button type="submit" variant="accent" size="icon" disabled={!draft.trim() || !!pending}>
            <ArrowUp className="size-4" />
          </Button>
        </form>
      </div>
    </div>
  );
}

/** One chat bubble, on the right for the user and on the left for the assistant. */
function Bubble({ side, children }: { side: "user" | "assistant"; children: React.ReactNode }) {
  const mine = side === "user";
  return (
    <div className={cn("flex items-start gap-2.5", mine && "flex-row-reverse")}>
      <span
        className={cn(
          "mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg",
          mine ? "bg-teal-deep text-white" : "bg-cyan/15 text-teal-deep",
        )}
      >
        {mine ? <User className="size-3.5" /> : <Bot className="size-3.5" />}
      </span>
      <div
        className={cn(
          "rounded-2xl px-4 py-2.5 text-sm leading-relaxed",
          mine
            ? "max-w-[72%] bg-teal-deep text-white"
            : "flex-1 border border-line bg-white text-ink",
        )}
      >
        {children}
      </div>
    </div>
  );
}
