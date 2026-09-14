/** Typed wrapper over the FastAPI backend. */

/** Who is signed in: username, tenant, role, and how many rows they can see. */
export type Identity = { username: string; tenant: string; role: string; rows: number };
/** A model the user can pick, with where it comes from and its licence. */
export type ModelSpec = { tag: string; origin: string; licence: string; note: string };
/** A demo account listed on the sign-in page. */
export type Account = { username: string; tenant: string; password: string };

/** What happened to one tool call: ran, rejected by the schema, never sent, or ran with no recorded result. */
export type StepState = "ok" | "rejected" | "skipped" | "unverifiable";

/** One tool call made by the agent, with its arguments, the SQL that ran and the rows it returned. */
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

/** Chart data produced by the plot tool. */
export type ChartSpec = {
  type: "bar" | "histogram" | "box";
  title: string;
  x: string;
  y?: string;
  data: Record<string, unknown>[];
};

/** The agent's answer to one question, with every step it took and any warnings. */
export type Answer = {
  text: string;
  steps: Step[];
  charts: ChartSpec[];
  flags: string[];
  retried: boolean;
  ungrounded: number[];
  claimed_tenants: string[];
  /** Rows the answer is about: picked by the model by label, values taken from the tool results. */
  selected_rows: Record<string, unknown>[];
  /** Labels the model picked that match no returned row; they were ignored. */
  ignored_refs: string[];
  /** Stated by the server: whose data the tools read, how many rows came back, from how many calls. */
  scope: {
    tenant: string;
    rows: number;
    calls: number;
    per_call: { tool: string; rows: number; chart: boolean }[];
  };
};

/** One attack from the catalogue, before it is run. */
export type AttackSpec = {
  id: string;
  category: string;
  prompt: string;
  intent: string;
  featured: boolean;
};

export type AttackRow = AttackSpec & {
  contained: boolean;
  /** Whether the attack reached what it tests: a tool ran and, for indirect attacks, injected text reached the model. */
  exercised: boolean;
  /** Why it did not, when exercised is false. */
  not_exercised: string | null;
  evidence: string;
  seconds: number;
  /** Null when the attack could not apply to this tenant and was not run. */
  answer: Answer | null;
};

export type AttackRun = {
  results: AttackRow[];
  leaked: number;
  exercised: number;
  total: number;
  model: string;
  tenant: string;
  username: string;
};

/** One line of the audit log. */
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

/** An error from the backend, carrying the HTTP status code. */
class ApiError extends Error {
  // Declared and assigned rather than a constructor parameter property:
  // `erasableSyntaxOnly` forbids syntax that has no plain-JavaScript erasure.
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Call one backend route with the session cookie and return the JSON, or throw an ApiError with the server's message. */
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

/** Every backend route the front end uses, one function each. */
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
    post<AttackRun>("/attacks/run", {
      model,
      only_featured: onlyFeatured,
    }),
  audit: () => call<AuditRow[]>("/audit"),
};

export { ApiError };
