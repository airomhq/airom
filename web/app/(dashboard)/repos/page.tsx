"use client";

import React, { useState } from "react";
import Link from "next/link";
import { GitBranch, Search, Lock, ShieldCheck, AlertTriangle, ArrowRight, ExternalLink } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../components/ui/card";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../../../components/ui/table";
import { RepositorySummary } from "../../../types";

const mockRepos: RepositorySummary[] = [
  {
    id: "acme-loan-decisioning",
    name: "acme/loan-decisioning",
    orgId: "org_acme_enterprise",
    defaultBranch: "main",
    lastScanAt: "2026-08-22T10:15:30Z",
    lastSnapshotHash: "4f9a2c89b71e4d3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183",
    totalComponents: 14,
    complianceRate: 0.86,
    activeGaps: 1,
    status: "warning",
  },
  {
    id: "acme-candidate-ranker",
    name: "acme/candidate-ranker",
    orgId: "org_acme_enterprise",
    defaultBranch: "main",
    lastScanAt: "2026-08-22T09:42:00Z",
    lastSnapshotHash: "8c71b29a01f9e83746a5b82c91e0294857162534a8e9102c9183746a5b82c91e",
    totalComponents: 8,
    complianceRate: 0.75,
    activeGaps: 1,
    status: "warning",
  },
  {
    id: "acme-customer-support-agent",
    name: "acme/customer-support-agent",
    orgId: "org_acme_enterprise",
    defaultBranch: "main",
    lastScanAt: "2026-08-22T08:30:15Z",
    lastSnapshotHash: "1e0294857162534a8e9102c9183746a5b82c91e0294857162534a8e9102c9183",
    totalComponents: 22,
    complianceRate: 1.0,
    activeGaps: 0,
    status: "compliant",
  },
  {
    id: "acme-biometric-auth-service",
    name: "acme/biometric-auth-service",
    orgId: "org_acme_enterprise",
    defaultBranch: "main",
    lastScanAt: "2026-08-22T07:12:00Z",
    lastSnapshotHash: "3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183746a5b82c91e02",
    totalComponents: 6,
    complianceRate: 1.0,
    activeGaps: 0,
    status: "compliant",
  },
];

export default function RepositoriesPage() {
  const [search, setSearch] = useState("");
  const [repos] = useState<RepositorySummary[]>(mockRepos);

  const filtered = repos.filter((r) => r.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Monitored Repositories</h1>
          <p className="text-sm text-gray-400">
            Tracked codebases with continuous AIBOM generation, tamper-evident hash-chain ledgers, and governance manifests.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative w-64">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search repository..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-900 py-1.5 pl-9 pr-4 text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
          </div>
        </div>
      </div>

      <Card className="border-gray-800 bg-gray-900/60">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Repository</TableHead>
                <TableHead>State Ledger</TableHead>
                <TableHead>AI Assets</TableHead>
                <TableHead>Compliance Rate</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((repo) => (
                <TableRow key={repo.id}>
                  <TableCell className="font-medium text-white">
                    <div className="flex items-center gap-2">
                      <GitBranch className="h-4 w-4 text-blue-400" />
                      <span>{repo.name}</span>
                    </div>
                    <span className="text-[11px] text-gray-500 font-mono">Branch: {repo.defaultBranch}</span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5 font-mono text-xs text-gray-400">
                      <Lock className="h-3 w-3 text-emerald-400" />
                      <span>{repo.lastSnapshotHash.slice(0, 12)}...</span>
                    </div>
                    <span className="text-[10px] text-gray-500">{new Date(repo.lastScanAt).toLocaleTimeString()}</span>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-gray-300">
                    {repo.totalComponents} components
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 rounded-full bg-gray-800 overflow-hidden">
                        <div
                          className={`h-full ${repo.complianceRate === 1.0 ? "bg-emerald-500" : "bg-amber-500"}`}
                          style={{ width: `${repo.complianceRate * 100}%` }}
                        />
                      </div>
                      <span className="font-mono text-xs font-semibold text-white">
                        {Math.round(repo.complianceRate * 100)}%
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {repo.status === "compliant" ? (
                      <Badge variant="met" className="gap-1">
                        <ShieldCheck className="h-3 w-3" />
                        COMPLIANT
                      </Badge>
                    ) : (
                      <Badge variant="gap" className="gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        {repo.activeGaps} GAP
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <Link href={`/repos/${repo.id}`}>
                      <Button size="sm" variant="ghost" className="gap-1 text-xs text-blue-400 hover:text-blue-300">
                        View Ledger & AIBOM
                        <ArrowRight className="h-3.5 w-3.5" />
                      </Button>
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
