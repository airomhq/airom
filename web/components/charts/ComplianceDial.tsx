import React from "react";

interface ComplianceDialProps {
  met: number;
  gap: number;
  manual: number;
  size?: number;
  strokeWidth?: number;
}

export const ComplianceDial: React.FC<ComplianceDialProps> = ({
  met,
  gap,
  manual,
  size = 160,
  strokeWidth = 14,
}) => {
  const total = met + gap + manual;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  const metRate = total > 0 ? met / total : 0;
  const gapRate = total > 0 ? gap / total : 0;
  const manualRate = total > 0 ? manual / total : 0;

  const metDash = metRate * circumference;
  const gapDash = gapRate * circumference;
  const manualDash = manualRate * circumference;

  const compliancePercent = total > 0 ? Math.round((met / (met + gap || 1)) * 100) : 0;

  return (
    <div className="relative flex flex-col items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="rotate-[-90deg]">
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="#1f2937"
          strokeWidth={strokeWidth}
        />
        {/* Met arc (Emerald) */}
        {met > 0 && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke="#10b981"
            strokeWidth={strokeWidth}
            strokeDasharray={`${metDash} ${circumference}`}
            strokeDashoffset={0}
            strokeLinecap="round"
          />
        )}
        {/* Gap arc (Red) */}
        {gap > 0 && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke="#ef4444"
            strokeWidth={strokeWidth}
            strokeDasharray={`${gapDash} ${circumference}`}
            strokeDashoffset={-metDash}
            strokeLinecap="round"
          />
        )}
        {/* Manual arc (Amber) */}
        {manual > 0 && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke="#f59e0b"
            strokeWidth={strokeWidth}
            strokeDasharray={`${manualDash} ${circumference}`}
            strokeDashoffset={-(metDash + gapDash)}
            strokeLinecap="round"
          />
        )}
      </svg>
      {/* Center Label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="text-3xl font-bold tracking-tight text-white">{compliancePercent}%</span>
        <span className="text-xs uppercase tracking-wider text-gray-400">Compliance</span>
      </div>
    </div>
  );
};
