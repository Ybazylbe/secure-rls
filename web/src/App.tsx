import {
  ClipboardList,
  LogOut,
  MessageSquare,
  Plus,
  Shield,
  Users,
} from "lucide-react";
import { useEffect, useState } from "react";

import { api, type Identity, type ModelSpec } from "@/api";
import { Chat, type Turn } from "@/views/Chat";
import { Audit } from "@/views/Audit";
import { Compare } from "@/views/Compare";
import { Login } from "@/views/Login";
import { Security } from "@/views/Security";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

/** The four views in the top navigation bar. */
const VIEWS = [
  { id: "chat", label: "Chat", icon: MessageSquare },
  { id: "security", label: "Security", icon: Shield },
  { id: "compare", label: "Side by side", icon: Users },
  { id: "audit", label: "Audit", icon: ClipboardList },
] as const;

type ViewId = (typeof VIEWS)[number]["id"];
/** One chat conversation kept in the browser: a title and its questions and answers. */
type Conversation = { id: string; title: string; turns: Turn[] };

/**
 * The whole app. Shows the sign-in page until a session exists, then the sidebar
 * (tenant, model, conversations) and whichever of the four views is selected.
 */
export default function App() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [checked, setChecked] = useState(false);
  const [models, setModels] = useState<ModelSpec[]>([]);
  const [model, setModel] = useState("");
  const [view, setView] = useState<ViewId>("chat");
  const [chats, setChats] = useState<Conversation[]>([blank()]);
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    api
      .session()
      .then(setIdentity)
      .catch(() => setIdentity(null))
      .finally(() => setChecked(true));
    api
      .models()
      .then((list) => {
        setModels(list);
        setModel((previous) => previous || list[0]?.tag || "");
      })
      .catch(() => setModels([]));
  }, []);

  if (!checked) return null;
  if (!identity) return <Login onSignedIn={setIdentity} />;

  const spec = models.find((m) => m.tag === model);
  const chat = chats[current] ?? chats[0];

  /** Add a question and its answer to the open conversation; the first question becomes its title. */
  function addTurn(turn: Turn) {
    setChats((previous) =>
      previous.map((conversation, index) =>
        index === current
          ? {
              ...conversation,
              turns: [...conversation.turns, turn],
              title:
                conversation.turns.length === 0
                  ? turn.question.slice(0, 42) + (turn.question.length > 42 ? "…" : "")
                  : conversation.title,
            }
          : conversation,
      ),
    );
  }

  /** Sign out on the server, then forget the user and their conversations in the browser. */
  async function signOut() {
    await api.logout().catch(() => undefined);
    setIdentity(null);
    setChats([blank()]);
    setCurrent(0);
  }

  return (
    <div className="flex h-full">
      <aside className="flex w-72 shrink-0 flex-col gap-4 border-r border-line bg-surface/70 px-4 py-4">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-teal-deep">
            Tenant
            <code className="rounded-md bg-white px-1.5 py-0.5 text-[0.72rem] text-teal">
              {identity.tenant}
            </code>
          </p>
          <p className="pt-0.5 text-[0.78rem] text-ink/55">
            {identity.username} · {identity.role} ·{" "}
            <strong className="font-semibold text-ink/75">{identity.rows}</strong> employees visible
          </p>
        </div>

        <div className="space-y-1.5">
          <p className="text-[0.72rem] font-medium uppercase tracking-wide text-ink/40">Model</p>
          <Select value={model} onValueChange={setModel}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {models.map((option) => (
                <SelectItem key={option.tag} value={option.tag}>
                  {option.tag}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {spec && (
            <p className="text-[0.74rem] leading-snug text-ink/45">
              {spec.origin} · {spec.licence}
            </p>
          )}
        </div>

        <div className="flex min-h-0 flex-1 flex-col gap-1.5">
          <Button
            variant="outline"
            size="sm"
            className="w-full"
            onClick={() => {
              setChats((previous) => [...previous, blank()]);
              setCurrent(chats.length);
              setView("chat");
            }}
          >
            <Plus className="size-3.5" />
            New conversation
          </Button>
          <p className="pt-1 text-[0.72rem] font-medium uppercase tracking-wide text-ink/40">
            Conversations
          </p>
          <div className="min-h-0 flex-1 space-y-0.5 overflow-y-auto">
            {chats.map((conversation, index) => (
              <button
                key={conversation.id}
                onClick={() => {
                  setCurrent(index);
                  setView("chat");
                }}
                className={cn(
                  "w-full truncate rounded-lg px-2.5 py-1.5 text-left text-[0.82rem] transition-colors",
                  index === current
                    ? "bg-cyan/18 font-medium text-teal-deep"
                    : "text-ink/65 hover:bg-cyan/10",
                )}
              >
                {conversation.title}
              </button>
            ))}
          </div>
        </div>

        <Button variant="ghost" size="sm" className="w-full" onClick={signOut}>
          <LogOut className="size-3.5" />
          Sign out
        </Button>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col px-8">
        <nav className="flex shrink-0 items-center gap-1 border-b border-line py-2.5">
          {VIEWS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setView(id)}
              className={cn(
                "inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-sm font-medium transition-colors",
                view === id
                  ? "bg-teal-deep text-white"
                  : "text-teal-deep hover:bg-surface",
              )}
            >
              <Icon className="size-4" />
              {label}
            </button>
          ))}
        </nav>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {view === "chat" && (
            <Chat
              tenant={identity.tenant}
              model={model}
              turns={chat.turns}
              onTurn={addTurn}
            />
          )}
          {view === "security" && <Security model={model} />}
          {view === "compare" && <Compare tenant={identity.tenant} model={model} />}
          {view === "audit" && <Audit />}
        </div>
      </main>
    </div>
  );
}

/** A new, empty conversation. */
function blank(): Conversation {
  return { id: crypto.randomUUID(), title: "New conversation", turns: [] };
}
