"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Cpu,
  AlertOctagon,
  CheckCircle2,
  FileCheck2,
  Flame,
  ArrowUpRight,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/card";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { ComplianceDial } from "../../components/charts/ComplianceDial";
import { RadarChart } from "../../components/charts/RadarChart";
import { OrgComplianceOverview, FrameworkCompliance, AnomalyEvent } from "../../types";

const mockOverview: OrgComplianceOverview = {
  orgId: "org_acme_enterprise",
  monitoredRepos: 24,
  totalAIComponents: 148,
  globalComplianceRate: 0.88,
  frameworks: [
    {
      frameworkId: "colorado-ai-act",
      name: "Colorado AI Act (SB 24-205)",
      version: "2024",
      authority: "Colorado Attorney General",
      metCount: 2,
      gapCount: 0,
      manualCount: 2,
      complianceRate: 1.0,
      controls: [],
    },
    {
      frameworkId: "nyc-ll144",
      name: "NYC Local Law 144 (AEDT)",
      version: "2021/144",
      authority: "NYC DCWP",
      metCount: 2,
      gapCount: 1,
      manualCount: 2,
      complianceRate: 0.67,
      controls: [],
    },
    {
      frameworkId: "ca-ab2013",
      name: "California AB 2013 (Training Data)",
      version: "2024",
      authority: "California Privacy Protection Agency",
      metCount: 2,
      gapCount: 0,
      manualCount: 0,
      complianceRate: 1.0,
      controls: [],
    },
    {
      frameworkId: "illinois-bipa",
      name: "Illinois BIPA (740 ILCS 14)",
      version: "740 ILCS 14",
      authority: "Illinois Circuit Court / Private Action",
      metCount: 3,
      gapCount: 0,
      manualCount: 2,
      complianceRate: 1.0,
      controls: [],
    },
    {
      frameworkId: "texas-traiga",
      name: "Texas TRAIGA (Gov Code § 2054)",
      version: "2024",
      authority: "Texas DIR & State AI Center",
      metCount: 2,
      gapCount: 0,
      manualCount: 2,
      complianceRate: 1.0,
      controls: [],
    },
    {
      frameworkId: "virginia-vcdpa",
      name: "Virginia VCDPA (§ 59.1-575)",
      version: "2023",
      authority: "Virginia Attorney General",
      metCount: 2,
      gapCount: 0,
      manualCount: 2,
      complianceRate: 1.0,
      controls: [],
    },
    {
      frameworkId: "nist-ai-rmf",
      name: "NIST AI RMF 1.0",
      version: "1.0",
      authority: "NIST & Federal Agencies",
      metCount: 6,
      gapCount: 1,
      manualCount: 4,
      complianceRate: 0.86,
      controls: [],
    },
    {
      frameworkId: "owasp-agentic",
      name: "OWASP Top 10 Agentic AI",
      version: "2026",
      authority: "OWASP Foundation",
      metCount: 4,
      gapCount: 0,
      manualCount: 6,
      complianceRate: 1.0,
      controls: [],
    },
  ],
  recentAnomalies: [
    {
      id: "anom_01",
      repoId: "acme/loan-decisioning",
      repoName: "acme/loan-decisioning",
      type: "shadow-ai",
      severity: "HIGH",
      componentName: "pkg:pypi/anthropic@0.34.0",
      location: "src/underwriting/scorer.py:14",
      details: "Discovered unauthorized Claude 3.5 Sonnet binding not listed in .airomapproved manifest.",
      timestamp: "12 mins ago",
    },
    {
      id: "anom_02",
      repoId: "acme/candidate-ranker",
      repoName: "acme/candidate-ranker",
      type: "config-drift",
      severity: "MEDIUM",
      componentName: "openai-gpt-4o",
      location: "src/hiring/agent.py:42",
      details: "Temperature parameter drifted to 0.85 (permitted maximum is 0.30 under NYC LL144 policy).",
      timestamp: "1 hour ago",
    },
  ],
};

export default function CockpitPage() {
  const [data, setData] = useState<OrgComplianceOverview>(mockOverview);
  const [refreshing, setRefreshing] = useState(false);

  const totalMet = data.frameworks.reduce((acc, f) => acc + f.metCount, 0);
  const totalGap = data.frameworks.reduce((acc, f) => acc + f.gapCount, 0);
  const totalManual = data.frameworks.reduce((acc, f) => acc + f.manualCount, 0);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => {
      setRefreshing(false);
    }, 600);
  };

  return (
    <div className="space-y-8">
      {/* Page Title & Refresh */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Executive Compliance Cockpit</h1>
          <p className="text-sm text-gray-400">
            Real-time multi-jurisdiction AI governance posture, shadow AI detection, and tamper-evident state ledger.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing} className="gap-2">
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin text-blue-400" : ""}`} />
            Refresh Telemetry
          </Button>
          <Link href="/reports">
            <Button size="sm" className="gap-2 bg-blue-600 hover:bg-blue-700">
              <FileCheck2 className="h-4 w-4" />
              Statutory Reports
            </Button>
          </Link>
        </div>
      </div>

      {/* Top 4 KPI Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Monitored AI Assets */}
        <Card className="border-gray-800 bg-gray-900/60">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-400">Monitored AI Assets</CardTitle>
            <Cpu className="h-4 w-4 text-blue-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{data.totalAIComponents}</div>
            <p className="text-xs text-gray-400 mt-1">Across {data.monitoredRepos} active repositories</p>
          </CardContent>
        </Card>

        {/* Global Compliance Rate */}
        <Card className="border-gray-800 bg-gray-900/60">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-400">Global Compliance Rate</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-emerald-400">{Math.round(data.globalComplianceRate * 100)}%</div>
            <p className="text-xs text-gray-400 mt-1">{totalMet} controls automatically satisfied</p>
          </CardContent>
        </Card>

        {/* Active Statutory Gaps */}
        <Card className="border-gray-800 bg-gray-900/60">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-400">Active Regulatory Gaps</CardTitle>
            <AlertOctagon className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400">{totalGap}</div>
            <p className="text-xs text-red-300/80 mt-1">Immediate remediation required</p>
          </CardContent>
        </Card>

        {/* Pending Human Attestations */}
        <Card className="border-gray-800 bg-gray-900/60">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-400">Pending Attestations</CardTitle>
            <FileCheck2 className="h-4 w-4 text-amber-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-400">{totalManual}</div>
            <p className="text-xs text-gray-400 mt-1">Manual controls awaiting legal sign-off</p>
          </CardContent>
        </Card>
      </div>

      {/* Visual Analytics Grid: Dials & Radar */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Circular Breakdown Dial */}
        <Card className="lg:col-span-5 border-gray-800 bg-gray-900/60 flex flex-col justify-between">
          <CardHeader>
            <CardTitle className="text-base text-white">Aggregated Control Distribution</CardTitle>
            <CardDescription className="text-gray-400 text-xs">
              Automated verdict distribution across all active statutory frameworks.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center py-4">
            <ComplianceDial met={totalMet} gap={totalGap} manual={totalManual} size={180} />
            <div className="mt-6 flex items-center justify-center gap-6 text-xs">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-emerald-500" />
                <span className="text-gray-300">Met: <strong>{totalMet}</strong></span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-red-500" />
                <span className="text-gray-300">Gap: <strong>{totalGap}</strong></span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-amber-500" />
                <span className="text-gray-300">Manual: <strong>{totalManual}</strong></span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Multi-Jurisdiction Radar */}
        <Card className="lg:col-span-7 border-gray-800 bg-gray-900/60">
          <CardHeader>
            <CardTitle className="text-base text-white">Multi-Jurisdiction Regulatory Radar</CardTitle>
            <CardDescription className="text-gray-400 text-xs">
              Continuous compliance posture across state and federal AI regulations.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-center py-2">
            <RadarChart frameworks={data.frameworks} size={280} />
          </CardContent>
        </Card>
      </div>

      {/* Statutory Framework Breakdown Table */}
      <Card className="border-gray-800 bg-gray-900/60">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base text-white">Statutory Frameworks Status</CardTitle>
            <CardDescription className="text-gray-400 text-xs">
              Status and control counts for all 8 active state and federal compliance packs.
            </CardDescription>
          </div>
          <Link href="/frameworks">
            <Button variant="ghost" size="sm" className="gap-1 text-xs text-blue-400">
              View All Frameworks
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          <div className="divide-y divide-gray-800/80">
            {data.frameworks.map((f) => {
              const rate = Math.round((f.complianceRate || (f.metCount / ((f.metCount + f.gapCount) || 1))) * 100);
              return (
                <div key={f.frameworkId} className="flex flex-col gap-2 py-3.5 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex flex-col">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-white">{f.name}</span>
                      <Badge variant={f.gapCount > 0 ? "gap" : "met"}>
                        {f.gapCount > 0 ? `${f.gapCount} GAP` : "COMPLIANT"}
                      </Badge>
                    </div>
                    <span className="text-xs text-gray-500">{f.authority}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className="text-emerald-400">{f.metCount} met</span>
                      <span className="text-gray-600">/</span>
                      <span className="text-red-400">{f.gapCount} gap</span>
                      <span className="text-gray-600">/</span>
                      <span className="text-amber-400">{f.manualCount} manual</span>
                    </div>
                    <div className="w-20 text-right font-bold text-sm text-white">
                      {rate}%
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Real-time Shadow AI & Anomaly Feed */}
      <Card className="border-gray-800 bg-gray-900/60">
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-red-400 animate-pulse" />
            <div>
              <CardTitle className="text-base text-white">Shadow AI & Regulatory Anomalies</CardTitle>
              <CardDescription className="text-gray-400 text-xs">
                Real-time security tripwires and unapproved asset discoveries.
              </CardDescription>
            </div>
          </div>
          <Badge variant="destructive" className="font-mono text-xs">
            {data.recentAnomalies.length} ALERTS ACTIVE
          </Badge>
        </CardHeader>
        <CardContent className="space-y-3">
          {data.recentAnomalies.map((anom) => (
            <div
              key={anom.id}
              className="flex flex-col gap-2 rounded-lg border border-red-900/40 bg-red-950/20 p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="gap">{anom.type.toUpperCase()}</Badge>
                  <span className="font-mono text-xs font-bold text-red-200">{anom.componentName}</span>
                  <span className="text-xs text-gray-500">in {anom.repoName}</span>
                </div>
                <p className="text-xs text-gray-300">{anom.details}</p>
                <div className="text-[11px] font-mono text-gray-500">{anom.location}</div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[11px] text-gray-400">{anom.timestamp}</span>
                <Link href={`/repos/${encodeURIComponent(anom.repoId)}/anomalies`}>
                  <Button size="sm" variant="outline" className="text-xs gap-1">
                    Investigate
                    <ExternalLink className="h-3 w-3" />
                  </Button>
                </Link>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
