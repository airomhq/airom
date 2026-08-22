import * as React from "react";
import { cn } from "./button";

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number; // 0 to 100
  color?: string;
}

const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  ({ className, value = 0, color = "bg-blue-600", ...props }, ref) => (
    <div
      ref={ref}
      className={cn("relative h-2 w-full overflow-hidden rounded-full bg-gray-800", className)}
      {...props}
    >
      <div
        className={cn("h-full transition-all duration-300", color)}
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  )
);
Progress.displayName = "Progress";

const Alert = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement> & { variant?: "default" | "destructive" | "warning" | "success" }>(
  ({ className, variant = "default", ...props }, ref) => {
    const variantStyles = {
      default: "bg-gray-800 text-gray-200 border-gray-700",
      destructive: "bg-red-950/40 text-red-300 border-red-800/50",
      warning: "bg-amber-950/40 text-amber-300 border-amber-800/50",
      success: "bg-emerald-950/40 text-emerald-300 border-emerald-800/50",
    };
    return (
      <div
        ref={ref}
        role="alert"
        className={cn("relative w-full rounded-lg border p-4 [&>svg~*]:pl-7 [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground", variantStyles[variant], className)}
        {...props}
      />
    );
  }
);
Alert.displayName = "Alert";

const AlertTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h5 ref={ref} className={cn("mb-1 font-medium leading-none tracking-tight", className)} {...props} />
  )
);
AlertTitle.displayName = "AlertTitle";

const AlertDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("text-sm [&_p]:leading-relaxed text-gray-300", className)} {...props} />
  )
);
AlertDescription.displayName = "AlertDescription";

export { Progress, Alert, AlertTitle, AlertDescription };
