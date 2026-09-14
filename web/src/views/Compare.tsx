import { Loader2, LogIn, LogOut, Users } from "lucide-react";
import { useEffect, useState } from "react";

import { api, type Account, type Answer, type Identity } from "@/api";
import { Charts } from "@/components/Chart";
import { Data } from "@/components/Data";
import { Grounding } from "@/components/Grounding";
import { Trace } from "@/components/Trace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

/** One side of the comparison: an answer and the tenant it was answered for. */
type Side = Answer & { tenant: string };

/**
 * The Side by side view. First asks for a second account from another tenant, then
 * puts the same question to both accounts and shows the answers next to each other.
 */
export function Compare({ tenant, model }: { tenant: string; model: string }) {
  const [peer, setPeer] = useState<Identity | null>(null);
  const [question, setQuestion] = useState("What is the average salary by department?");
  const [pair, setPair] = useState<{ mine: Side; theirs: Side } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.peer().then(setPeer).catch(() => setPeer(null));
  }, [tenant]);

  /** Ask the question for both signed-in accounts. */
  async function run() {
    setBusy(true);
    setError(null);
    try {
      setPair(await api.compare(question, model));
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed");
    } finally {
      setBusy(false);
    }
  }

  /** Sign out the second account and clear the comparison. */
  async function signOutPeer() {
    await api.peerLogout().catch(() => undefined);
    setPeer(null);
    setPair(null);
  }

  return (
    <div className="space-y-5 py-5">
      <div className="space-y-1.5">
        <h2 className="text-xl font-semibold text-teal-deep">Same question, two tenants</h2>
        <p className="max-w-3xl text-sm leading-relaxed text-ink/60">
          Nothing about the question changes — only who is asking. Both sides are real sign-ins:
          the second account's answer is shown only because you signed in as that account, with its
          own password. There is no way to ask on another tenant's behalf by naming it.
        </p>
      </div>

      {peer === null ? (
        <PeerSignIn tenant={tenant} onSignedIn={setPeer} />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 text-sm text-ink/60">
            Comparing <Badge tone="info">{tenant}</Badge> with
            <Badge tone="info">
              {peer.tenant} · {peer.username}
            </Badge>
            <Button variant="outline" size="sm" onClick={signOutPeer}>
              <LogOut className="size-3.5" />
              Sign out {peer.username}
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <Input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              className="max-w-xl flex-1"
            />
            <Button onClick={run} disabled={busy || !question.trim()}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Users className="size-4" />}
              Ask both
            </Button>
          </div>
        </>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}

      {pair && peer && (
        <div className="grid gap-4 lg:grid-cols-2">
          {[pair.mine, pair.theirs].map((side) => (
            <Card key={side.tenant}>
              <CardContent className="space-y-3 pt-4">
                <Badge tone="info">{side.tenant}</Badge>
                <p className="whitespace-pre-wrap text-sm leading-relaxed">{side.text}</p>
                <Grounding answer={side} />
                <Charts answer={side} />
                <Data answer={side} />
                <Trace steps={side.steps} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * The form for signing in the second account. It lists demo accounts from other
 * tenants but fills in only the username: the password must be typed.
 */
function PeerSignIn({
  tenant,
  onSignedIn,
}: {
  tenant: string;
  onSignedIn: (identity: Identity) => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.accounts().then(setAccounts).catch(() => setAccounts([]));
  }, []);

  /** Sign in the second account on the server. */
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await api.peerLogin(username, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed");
    } finally {
      setBusy(false);
    }
  }

  const others = accounts.filter((account) => account.tenant !== tenant);

  return (
    <Card className="max-w-xl">
      <CardContent className="space-y-3 pt-4">
        <p className="text-sm font-medium text-teal-deep">
          Sign in a second account from another tenant
        </p>
        <form onSubmit={submit} className="space-y-2.5">
          <div className="flex gap-2">
            <Input
              placeholder="Username"
              autoComplete="off"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <Input
              type="password"
              placeholder="Password"
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <Button type="submit" disabled={busy || !username || !password}>
            <LogIn className="size-4" />
            {busy ? "Signing in…" : "Sign in second account"}
          </Button>
        </form>
        {others.length > 0 && (
          <p className="text-[0.78rem] leading-relaxed text-ink/50">
            Demo accounts outside {tenant}:{" "}
            {others.map((account, index) => (
              <span key={account.username}>
                {index > 0 && ", "}
                <button
                  type="button"
                  className="text-teal underline-offset-2 hover:underline"
                  onClick={() => setUsername(account.username)}
                >
                  {account.username}
                </button>{" "}
                ({account.tenant})
              </span>
            ))}
            . Clicking fills the username only — the password still has to be typed.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
