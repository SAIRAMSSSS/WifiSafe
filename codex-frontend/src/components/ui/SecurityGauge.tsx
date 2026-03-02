import { useEffect, useState } from "react";

interface SecurityGaugeProps {
  score: number;
  size?: number;
  label?: string;
}

export const SecurityGauge = ({ score, size = 200, label = "Security Score" }: SecurityGaugeProps) => {
  // Ensure score is a valid number between 0 and 100
  const validScore = Math.max(0, Math.min(100, Number(score) || 0));
  const [animatedScore, setAnimatedScore] = useState(0);
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(validScore);
    }, 300);
    return () => clearTimeout(timer);
  }, [validScore]);

  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (animatedScore / 100) * circumference;

  const getScoreColor = () => {
    if (animatedScore >= 80) return "hsl(0, 100%, 50%)";
    if (animatedScore >= 60) return "hsl(0, 100%, 45%)";
    return "hsl(0, 85%, 60%)";
  };

  const getGlowColor = () => {
    if (animatedScore >= 80) return "hsl(0 100% 50% / 0.5)";
    if (animatedScore >= 60) return "hsl(0 100% 45% / 0.5)";
    return "hsl(0 85% 60% / 0.5)";
  };

  return (
    <div className="relative flex flex-col items-center">
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={strokeWidth}
          fill="none"
          className="stroke-muted"
        />
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={strokeWidth}
          fill="none"
          stroke={getScoreColor()}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{
            transition: "stroke-dashoffset 1.5s ease-out, stroke 0.5s ease",
            filter: `drop-shadow(0 0 10px ${getGlowColor()})`,
          }}
        />
        {/* Glow effect */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={strokeWidth + 4}
          fill="none"
          stroke={getScoreColor()}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          opacity={0.2}
          style={{
            transition: "stroke-dashoffset 1.5s ease-out",
          }}
        />
      </svg>
      
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span 
          className="text-5xl font-display font-bold neon-text"
          style={{ color: getScoreColor() }}
        >
          {isNaN(animatedScore) ? 0 : Math.round(animatedScore)}
        </span>
        <span className="text-sm text-muted-foreground uppercase tracking-widest mt-1">
          {label}
        </span>
      </div>
    </div>
  );
};
