import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: "up" | "down" | "neutral";
  trendValue?: string;
  variant?: "default" | "warning" | "danger" | "success";
}

export const StatCard = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  trendValue,
  variant = "default",
}: StatCardProps) => {
  const variantStyles = {
    default: "border-border/50 hover:border-primary/50",
    warning: "border-warning/30 hover:border-warning/60",
    danger: "border-destructive/30 hover:border-destructive/60",
    success: "border-success/30 hover:border-success/60",
  };

  const iconVariantStyles = {
    default: "text-primary bg-primary/10",
    warning: "text-warning bg-warning/10",
    danger: "text-destructive bg-destructive/10",
    success: "text-success bg-success/10",
  };

  return (
    <div
      className={cn(
        "glass-panel p-5 transition-all duration-300 group h-full flex flex-col justify-between",
        variantStyles[variant]
      )}
    >
      <div className="flex items-start justify-between mb-2">
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-wider text-muted-foreground">
            {title}
          </p>
          <p className="text-3xl font-display font-bold text-foreground">
            {value}
          </p>
        </div>
        <div
          className={cn(
            "p-3 rounded-lg transition-all duration-300 group-hover:scale-110",
            iconVariantStyles[variant]
          )}
        >
          <Icon className="w-6 h-6" />
        </div>
      </div>

      <div>
        {subtitle && (
          <p className="text-sm text-muted-foreground mb-1">{subtitle}</p>
        )}
        {trend && trendValue && (
          <div className="flex items-center gap-1 text-xs">
            <span
              className={cn(
                trend === "up" && "text-success",
                trend === "down" && "text-destructive",
                trend === "neutral" && "text-muted-foreground"
              )}
            >
              {trend === "up" && "↑"}
              {trend === "down" && "↓"}
              {trend === "neutral" && "→"}
              {trendValue}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
