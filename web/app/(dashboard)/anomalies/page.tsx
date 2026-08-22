"use client";

import React, { useState } from "react";
import { Flame, AlertTriangle, ShieldAlert, Filter, Search, Check, ExternalLink } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../components/ui/card";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { AnomalyLiveFeed } from "../../../components/anomaly/AnomalyLiveFeed";
import { AnomalyEvent } from "../../../types";

const mockHistoricalAnomalies: AnomalyEvent[] = [
  {
    id: "anom_101",
    repoId: "acme/loan-decisioning",
    repoName: "acme/loan-decisioning",
    type: "shadow-ai",
    severity: "HIGH",
    componentName: "pkg:pypi/anthropic@0.34.0",
    location: "src/underwriting/scorer.py:14",
    details: "Unapproved Claude 3.5 Sonnet import discovered in high-risk credit decisioning path.",
    timestamp: "2026-08-22 10:15 UTC",
  },
  {
    id: "anom_102",
    repoId: "acme/candidate-ranker",
    repoName: "acme/candidate-ranker",
    type: "config-drift",
    severity: "MEDIUM",
    componentName: "openai-gpt-4o",
    location: "src/hiring/agent.py:42",
    details: "Temperature parameter set to 0.85; exceeds permitted max 0.30 defined in .airomapproved manifest.",
    timestamp: "2026-08-22 09:42 UTC",
  },
  {
    id: "anom_103",
    repoId: "acme/patient-intake",
    repoName: "acme/patient-intake",
    type: "proximity-healthcare",
    severity: "HIGH",
    componentName: "pkg:pypi/langchain@0.3.0",
    location: "src/clinical/ehr_parser.py:8",
    details: "AI component detected in HIPAA/California Confidentiality of Medical Information Act protected path.",
    timestamp: "2026-08-22 08:20 UTC",
  },
  {
    id: "anom_104",
    repoId: "acme/credit-risk",
    repoName: "acme/credit-risk",
    type: "model-swap",
    severity: "HIGH",
    componentName: "meta-llama/Llama-3-70b",
    location: "src/models/loader.py:22",
    details: "Model swapped from approved GPT-4o to unapproved open-weights Llama 3 70B.",
    timestamp: "2026-08-22 07:15 UTC",
  },
];

export default function AnomaliesPage() {
  const [filterType, setFilterType] = useState<string>("all");
  const [search, setSearch] = useState("");

  const filtered = mockHistoricalAnomalies.filter((a) => {
    const matchesType = filterType === "all" || a.type === filterType;
    const matchesSearch =
      a.componentName.toLowerCase().includes(search.toLowerCase()) ||
      a.repoName.toLowerCase().includes(search.toLowerCase()) ||
      a.details.toLowerCase().includes(search.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Shadow AI & Regulatory Anomalies</h1>
        <p className="text-sm text-gray-400">
          Continuous anomaly detection for unauthorized model swaps, parameter drift, and statutory proximity tripwires.
        </p>
      </div>

      {/* Real-time SSE Stream Component */}
      <AnomalyLiveFeed />

      {/* Historical Audit & Filter Section */}
      <div className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-lg font-bold text-white">Historical Anomaly Audit</h2>
          <div className="flex items-center gap-3">
            <div className="relative w-64">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search anomaly..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full rounded-lg border border-gray-700 bg-gray-900 py-1.5 pl-9 pr-4 text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Anomaly Types</option>
              <option value="shadow-ai">Shadow AI</option>
              <option value="model-swap">Model Swap</option>
              <option value="config-drift">Config Drift</option>
              <option value="proximity-healthcare">Proximity: Healthcare</option>
              <option value="proximity-hiring">Proximity: Hiring</option>
              <option value="proximity-credit">Proximity: Credit</option>
            </select>
          </div>
        </div>

        <Card className="border-gray-800 bg-gray-900/60">
          <CardContent className="divide-y divide-gray-800/80 p-0">
            {filtered.map((a) => (
              <div key={a.id} className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge variant={a.severity === "HIGH" ? "gap" : "manual"}>{a.type.toUpperCase()}</Badge>
                    <span className="font-mono font-bold text-white">{a.componentName}</span>
                    <span className="text-gray-500">in {a.repoName}</span>
                  </div>
                  <p className="text-gray-300">{a.details}</p>
                  <div className="font-mono text-[11px] text-gray-500">{a.location}</div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-mono text-[11px] text-gray-400">{a.timestamp}</span>
                  <Button size="sm" variant="outline" className="text-xs gap-1 text-blue-400">
                    Remediate
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
