import { Lock, LogIn } from "lucide-react";
import { useEffect, useState } from "react";

import { api, type Account, type Identity } from "@/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export function Login({ onSignedIn }: { onSignedIn: (identity: Identity) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [accounts, setAccounts] = useState<Account[]>([]);

  useEffect(() => {
    api.accounts().then(setAccounts).catch(() => setAccounts([]));
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await api.login(username, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-surface/50 px-6 py-16">
      <div className="grid w-full max-w-4xl gap-10 md:grid-cols-[1fr_1.1fr]">
        <div className="space-y-5">
          <div className="flex items-center gap-2.5">
            <span className="flex size-9 items-center justify-center rounded-xl bg-teal-deep text-white">
              <Lock className="size-4.5" />
            </span>
            <h1 className="text-xl font-semibold text-teal-deep">Secure RLS Analyst</h1>
          </div>
          <p className="text-sm leading-relaxed text-ink/60">
            A conversational analyst over multi-tenant HR data. The tenant is fixed at sign-in and
            cannot be changed by anything you or the model say.
          </p>

          <form onSubmit={submit} className="space-y-3 pt-1">
            <Input
              placeholder="Username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <Input
              type="password"
              placeholder="Password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            {error && <p className="text-sm text-red-600">{error}</p>}
            <Button type="submit" disabled={busy} className="w-full">
              <LogIn className="size-4" />
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </div>

        <Card className="h-fit">
          <CardContent className="pt-4">
            <p className="pb-3 text-sm font-medium text-teal-deep">Demo accounts</p>
            <table className="w-full text-left text-sm">
              <thead className="text-ink/50">
                <tr>
                  <th className="pb-2 font-medium">user</th>
                  <th className="pb-2 font-medium">tenant</th>
                  <th className="pb-2 font-medium">password</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((account) => (
                  <tr
                    key={account.username}
                    className="cursor-pointer border-t border-line/70 hover:bg-surface"
                    onClick={() => {
                      setUsername(account.username);
                      setPassword(account.password);
                    }}
                  >
                    <td className="py-1.5">{account.username}</td>
                    <td className="py-1.5 text-teal">{account.tenant}</td>
                    <td className="py-1.5 text-ink/50">{account.password}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="pt-3 text-[0.78rem] leading-relaxed text-ink/50">
              alice and arthur share a tenant on purpose: the boundary is the tenant, not the
              individual. Click a row to fill the form.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
