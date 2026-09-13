/** Typed wrapper over the FastAPI backend. */

export type Identity = { username: string; tenant: string; role: string; rows: number };
export type ModelSpec = { tag: string; origin: string; licence: string; note: string };
export type Account = { username: string; tenant: string; password: string };

export type StepState = "ok" | "rejected" | "skipped" | "unverifiable";

export type Step = {
  tool: string;
  arguments: Record<string, unknown>;
  state: StepState;
  error: string | null;
  refused: boolean;
  reason: string | null;
  sql: string | null;
  rewrites: string[];
  flags: string[];
  rows: Record<string, unknown>[];
  row_count: number;
  chart: ChartSpec | null;
};

export type ChartSpec = {
  type: "bar" | "histogram" | "box";
  title: string;
  x: string;
  y?: string;
  data: Record<string, unknown>[];
};

export type Answer = {
  text: string;
  steps: Step[];
  charts: ChartSpec[];
  flags: string[];
  retried: boolean;
  ungrounded: number[];
};

export type AttackSpec = {
  id: string;
  category: string;
  prompt: string;
  intent: string;
  featured: boolean;
};

export type AttackRow = AttackSpec & {
  contained: boolean;
  evidence: string;
  answer: Answer;
};

export type AuditRow = {
  time: string;
  user: string;
  event: string;
  verdict: string;
  layer: string | null;
  rows: number | null;
  detail: string;
  sql: string | null;
};

class ApiError extends Error {
  // Declared and assigned rather than a constructor parameter property:
  // `erasableSyntaxOnly` forbids syntax that has no plain-JavaScript erasure.
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    const detail = await response
      .json()
      .then((body: { detail?: string }) => body.detail)
      .catch(() => undefined);
    throw new ApiError(response.status, detail ?? response.statusText);
  }
  return (await response.json()) as T;
}

const post = <T,>(path: string, body?: unknown) =>
  call<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export const api = {
  session: () => call<Identity>("/session"),
  login: (username: string, password: string) => post<Identity>("/login", { username, password }),
  logout: () => post<{ ok: boolean }>("/logout"),
  models: () => call<ModelSpec[]>("/models"),
  accounts: () => call<Account[]>("/accounts"),
  ask: (question: string, model: string) => post<Answer>("/ask", { question, model }),
  // The second side of the comparison is a real sign-in, never a tenant name:
  // the server only answers for an account whose password this browser gave.
  peer: () => call<Identity>("/compare/peer"),
  peerLogin: (username: string, password: string) =>
    post<Identity>("/compare/peer", { username, password }),
  peerLogout: () => post<{ ok: boolean }>("/compare/peer/logout"),
  compare: (question: string, model: string) =>
    post<{ mine: Answer & { tenant: string }; theirs: Answer & { tenant: string } }>("/compare", {
      question,
      model,
    }),
  attacks: () => call<AttackSpec[]>("/attacks"),
  runAttacks: (model: string, onlyFeatured: boolean) =>
    post<{ results: AttackRow[]; leaked: number; total: number }>("/attacks/run", {
      model,
      only_featured: onlyFeatured,
    }),
  audit: () => call<AuditRow[]>("/audit"),
};

export { ApiError };
