import { cn } from "@/lib/utils";
import { Cpu, Monitor, HelpCircle } from "lucide-react";

interface DeviceCategoryBadgeProps {
    category?: 'IoT' | 'Normal' | 'Unknown' | null;
    className?: string;
}

export function DeviceCategoryBadge({ category, className }: DeviceCategoryBadgeProps) {
    // Default to Unknown if category not provided
    const deviceCategory = category || 'Unknown';

    const config = {
        IoT: {
            bg: 'bg-purple-500/10 border-purple-500/30',
            text: 'text-purple-400',
            icon: Cpu,
            label: 'IoT'
        },
        Normal: {
            bg: 'bg-blue-500/10 border-blue-500/30',
            text: 'text-blue-400',
            icon: Monitor,
            label: 'Normal'
        },
        Unknown: {
            bg: 'bg-gray-500/10 border-gray-500/30',
            text: 'text-gray-400',
            icon: HelpCircle,
            label: 'Unknown'
        }
    };

    const { bg, text, icon: Icon, label } = config[deviceCategory];

    return (
        <span className={cn(
            "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border",
            bg,
            text,
            className
        )}>
            <Icon className="w-3 h-3" />
            {label}
        </span>
    );
}
