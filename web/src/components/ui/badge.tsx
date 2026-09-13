import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";

import { cn } from "@/lib/utils";

/** Colour variants for badges. */
const badge = cva(
  "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.72rem] font-medium",
  {
    variants: {
      tone: {
        neutral: "bg-surface text-teal",
        good: "bg-lime/20 text-[#57661a]",
        bad: "bg-red-50 text-red-700",
        warn: "bg-amber-50 text-amber-700",
        info: "bg-cyan/12 text-teal-deep",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

/** A small rounded label, coloured by tone (good, bad, warn, info, neutral). */
export function Badge({
  className,
  tone,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) {
  return <span className={cn(badge({ tone, className }))} {...props} />;
}
