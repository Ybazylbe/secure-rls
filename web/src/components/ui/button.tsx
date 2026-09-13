import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const button = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-medium " +
    "transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan/50 " +
    "disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "bg-teal-deep text-white hover:bg-teal",
        accent: "bg-cyan text-white hover:bg-teal",
        outline: "border border-line bg-white text-teal hover:border-cyan hover:bg-cyan/5",
        ghost: "text-ink/70 hover:bg-surface hover:text-teal-deep",
        quiet: "text-teal-deep hover:bg-cyan/10",
      },
      size: {
        sm: "h-8 px-3",
        md: "h-10 px-5",
        chip: "h-7 px-3 text-[0.8rem] font-normal",
        icon: "size-9",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {
  asChild?: boolean;
}

/** A button in one of the app's styles (primary, outline, ghost, accent) and sizes. */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(button({ variant, size, className }))} {...props} />;
  },
);
Button.displayName = "Button";
