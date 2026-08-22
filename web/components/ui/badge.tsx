import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "./button";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-blue-600 text-white shadow hover:bg-blue-700",
        secondary: "border-transparent bg-gray-800 text-gray-200 hover:bg-gray-700",
        destructive: "border-transparent bg-red-600/20 text-red-400 border-red-800/50",
        outline: "text-gray-200 border-gray-700",
        met: "border-emerald-800/50 bg-emerald-950/40 text-emerald-400 font-mono",
        gap: "border-red-800/50 bg-red-950/40 text-red-400 font-mono",
        manual: "border-amber-800/50 bg-amber-950/40 text-amber-400 font-mono",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
