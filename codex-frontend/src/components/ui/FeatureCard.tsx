import { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";

interface FeatureCardProps {
  title: string;
  description: string;
  icon: LucideIcon;
  href: string;
  variant?: "primary" | "secondary" | "accent" | "danger";
  badge?: string;
}

export const FeatureCard = ({
  title,
  description,
  icon: Icon,
  href,
  variant = "primary",
  badge,
}: FeatureCardProps) => {
  const variantStyles = {
    primary: {
      border: "border-primary/20 hover:border-primary/60",
      icon: "text-primary bg-primary/10 group-hover:bg-primary/20",
      glow: "group-hover:shadow-[0_0_30px_hsl(160_100%_50%/0.2)]",
    },
    secondary: {
      border: "border-secondary/20 hover:border-secondary/60",
      icon: "text-secondary bg-secondary/10 group-hover:bg-secondary/20",
      glow: "group-hover:shadow-[0_0_30px_hsl(185_100%_50%/0.2)]",
    },
    accent: {
      border: "border-accent/20 hover:border-accent/60",
      icon: "text-accent bg-accent/10 group-hover:bg-accent/20",
      glow: "group-hover:shadow-[0_0_30px_hsl(280_100%_60%/0.2)]",
    },
    danger: {
      border: "border-destructive/20 hover:border-destructive/60",
      icon: "text-destructive bg-destructive/10 group-hover:bg-destructive/20",
      glow: "group-hover:shadow-[0_0_30px_hsl(0_85%_60%/0.2)]",
    },
  };

  const styles = variantStyles[variant];

  return (
    <Link
      to={href}
      className={cn(
        "glass-panel p-6 group transition-all duration-500 block relative overflow-hidden",
        styles.border,
        styles.glow
      )}
    >
      {/* Scan line effect */}
      <div className="scan-line opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      {/* Badge */}
      {badge && (
        <span className="absolute top-3 right-3 px-2 py-0.5 text-[10px] uppercase tracking-wider bg-primary/20 text-primary rounded-full border border-primary/30">
          {badge}
        </span>
      )}

      <div
        className={cn(
          "w-14 h-14 rounded-lg flex items-center justify-center transition-all duration-300 mb-4",
          styles.icon
        )}
      >
        <Icon className="w-7 h-7" />
      </div>

      <h3 className="text-lg font-display font-semibold text-foreground mb-2 group-hover:neon-text transition-all duration-300">
        {title}
      </h3>

      <p className="text-sm text-muted-foreground leading-relaxed">
        {description}
      </p>

      <div className="mt-4 flex items-center text-xs text-primary opacity-0 group-hover:opacity-100 transition-all duration-300 transform translate-y-2 group-hover:translate-y-0">
        <span className="uppercase tracking-wider">Access Module</span>
        <span className="ml-2">→</span>
      </div>
    </Link>
  );
};
