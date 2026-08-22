import React from "react";
import { FrameworkCompliance } from "../../types";

interface RadarChartProps {
  frameworks: FrameworkCompliance[];
  size?: number;
}

export const RadarChart: React.FC<RadarChartProps> = ({ frameworks, size = 320 }) => {
  if (!frameworks || frameworks.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-gray-500 text-sm">
        No framework data available
      </div>
    );
  }

  const center = size / 2;
  const radius = size * 0.38;
  const count = frameworks.length;
  const angleStep = (Math.PI * 2) / count;

  // Compute polygon points for compliance rates
  const points = frameworks.map((f, i) => {
    const angle = i * angleStep - Math.PI / 2;
    const rate = Math.max(0.1, Math.min(1.0, f.complianceRate || (f.metCount / ((f.metCount + f.gapCount) || 1))));
    const r = radius * rate;
    const x = center + r * Math.cos(angle);
    const y = center + r * Math.sin(angle);
    return `${x},${y}`;
  });

  const polygonPath = points.join(" ");

  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg width={size} height={size} className="overflow-visible">
        {/* Background concentric reference webs */}
        {[0.25, 0.5, 0.75, 1.0].map((level, idx) => (
          <circle
            key={idx}
            cx={center}
            cy={center}
            r={radius * level}
            fill="transparent"
            stroke="#374151"
            strokeWidth="1"
            strokeDasharray={level < 1.0 ? "3 3" : "none"}
          />
        ))}

        {/* Radial axes */}
        {frameworks.map((f, i) => {
          const angle = i * angleStep - Math.PI / 2;
          const x = center + radius * Math.cos(angle);
          const y = center + radius * Math.sin(angle);
          return (
            <line
              key={i}
              x1={center}
              y1={center}
              x2={x}
              y2={y}
              stroke="#4b5563"
              strokeWidth="1"
            />
          );
        })}

        {/* Data Polygon */}
        <polygon
          points={polygonPath}
          fill="rgba(59, 130, 246, 0.25)"
          stroke="#3b82f6"
          strokeWidth="2"
        />

        {/* Data Vertices */}
        {frameworks.map((f, i) => {
          const angle = i * angleStep - Math.PI / 2;
          const rate = Math.max(0.1, Math.min(1.0, f.complianceRate || (f.metCount / ((f.metCount + f.gapCount) || 1))));
          const r = radius * rate;
          const x = center + r * Math.cos(angle);
          const y = center + r * Math.sin(angle);
          return (
            <circle
              key={i}
              cx={x}
              cy={y}
              r="4"
              fill="#60a5fa"
              stroke="#1e3a8a"
              strokeWidth="1.5"
            />
          );
        })}

        {/* Framework Labels */}
        {frameworks.map((f, i) => {
          const angle = i * angleStep - Math.PI / 2;
          const labelRadius = radius + 24;
          const x = center + labelRadius * Math.cos(angle);
          const y = center + labelRadius * Math.sin(angle);
          const anchor = Math.abs(x - center) < 10 ? "middle" : x > center ? "start" : "end";
          const percent = Math.round((f.complianceRate || (f.metCount / ((f.metCount + f.gapCount) || 1))) * 100);

          return (
            <g key={i}>
              <text
                x={x}
                y={y}
                textAnchor={anchor}
                className="fill-gray-300 text-[11px] font-medium"
              >
                {f.name.split(" ")[0]}
              </text>
              <text
                x={x}
                y={y + 12}
                textAnchor={anchor}
                className="fill-emerald-400 text-[10px] font-mono"
              >
                {percent}%
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
