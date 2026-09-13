import { ChevronRight } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * A plain <details> dressed up. The reasoning trace is the one thing on screen
 * that must survive being printed, screenshotted and read by someone who does
 * not have the app open, so it stays semantic HTML rather than a JS widget.
 */
export function Disclosure({
  summary,
  defaultOpen = false,
  className,
  children,
}: {
  summary: React.ReactNode;
  defaultOpen?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <details
      open={defaultOpen}
      className={cn("group rounded-xl border border-line bg-surface/60", className)}
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-sm">
        <ChevronRight className="size-3.5 text-ink/40 transition-transform group-open:rotate-90" />
        {summary}
      </summary>
      <div className="space-y-3 px-3 pb-3">{children}</div>
    </details>
  );
}
