import * as React from "react";

import { cn } from "@/lib/utils";

/** A text input in the app's style. */
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-10 w-full rounded-xl border border-line bg-white px-3.5 text-sm text-ink",
        "placeholder:text-ink/40 focus-visible:border-cyan focus-visible:outline-none",
        "focus-visible:ring-2 focus-visible:ring-cyan/25",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";
