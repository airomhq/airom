"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  GitBranch,
  Lock,
  ShieldCheck,
  CheckCircle2,
  AlertOctagon,
  FileCheck2,
  Check,
  X,
  History,
  Code2,
  FileText,
  Terminal,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../../components/ui/card";
import { Badge } from "../../../../components/ui/badge";
import { Button } from "../../../../components/ui/button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../../../../components/ui/table";
import { ScanSnapshot, ControlEvaluation } from "../../../../types";
import { verifyLedgerIntegrity, LedgerVerificationResult } from "../../../../lib/crypto";

const mockSnapshots: ScanSnapshot[] = [
  {
    scanId: "scan_01_98a72b",
    repoId: "acme/loan-decisioning",
    timestamp: "2026-08-22T08:00:00Z",
    aibomHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    controlsHash: "c1c2c3c4c5c6c1c2c3c4c5c6c1c2c3c4c5c6c1c2c3c4c5c6c1c2c3c4c5c6c1c2",
    prevHash: "",
    selfHash: "4f9a2c89b71e4d3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183",
    componentsCount: 12,
    metCount: 4,
    gapCount: 0,
    manualCount: 4,
  },
  {
    scanId: "scan_02_14f089",
    repoId: "acme/loan-decisioning",
    timestamp: "2026-08-22T09:00:00Z",
    aibomHash: "b1b2b3b4b5b6b1b2b3b4b5b6b1b2b3b4b5b6b1b2b3b4b5b6b1b2b3b4b5b6b1b2",
    controlsHash: "d1d2d3d4d5d6d1d2d3d4d5d6d1d2d3d4d5d6d1d2d3d4d5d6d1d2d3d4d5d6d1d2",
    prevHash: "4f9a2c89b71e4d3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183",
    selfHash: "8c71b29a01f9e83746a5b82c91e0294857162534a8e9102c9183746a5b82c91e",
    componentsCount: 14,
    metCount: 5,
    gapCount: 1,
    manualCount: 4,
  },
];

const mockControls: ControlEvaluation[] = [
  {
    id: "co.ai-act.risk-mgmt",
    frameworkId: "colorado-ai-act",
    title: "Risk Management Program (§ 6-1-1702)",
    category: "Governance & Policies",
    state: "manual",
    score: 0,
    rationale: "Confirm risk management program aligned with NIST AI RMF is documented and maintained.",
    evidence: [],
  },
  {
    id: "co.ai-act.impact-assessment",
    frameworkId: "colorado-ai-act",
    title: "Algorithmic Impact Assessment (§ 6-1-1703)",
    category: "Assessments",
    state: "met",
    score: 1.0,
    rationale: "Annual algorithmic impact assessment complete; model purpose and bias mitigation verified.",
    evidence: [
      {
        componentId: "airom:989de824357981e6",
        name: "openai-gpt-4o",
        purl: "pkg:pypi/openai@1.51.0",
        location: "src/underwriting/scorer.py:14",
        confidence: 0.95,
      },
    ],
  },
  {
    id: "co.ai-act.consumer-notice",
    frameworkId: "colorado-ai-act",
    title: "Consumer Disclosure (§ 6-1-1704)",
    category: "Transparency",
    state: "manual",
    score: 0,
    rationale: "Confirm consumer notice mechanism is visible in deployment UI before consequential decision.",
    evidence: [],
  },
  {
    id: "co.ai-act.incident-reporting",
    frameworkId: "colorado-ai-act",
    title: "Algorithmic Discrimination Notification (§ 6-1-1705)",
    category: "Incident Response",
    state: "met",
    score: 1.0,
    rationale: "Automated 90-day notification incident trigger active in ComplianceDB.",
    evidence: [],
  },
];

export default function RepoDetailPage() {
  const params = useParams();
  const repoId = params?.id as string;
  const [snapshots] = useState<ScanSnapshot[]>(mockSnapshots);
  const [controls] = useState<ControlEvaluation[]>(mockControls);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<LedgerVerificationResult | null>(null);

  const handleVerifyLedger = async () => {
    setVerifying(true);
    try {
      const result = await verifyLedgerIntegrity(snapshots);
      setVerificationResult(result);
    } catch (err: any) {
      setVerificationResult({
        isValid: false,
        totalSnapshots: snapshots.length,
        errorMessage: err.message,
      });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header Breadcrumb */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-gray-800 pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <Link href="/repos" className="hover:text-blue-400">Repositories</Link>
            <span>/</span>
            <span className="text-gray-200 font-mono">{repoId}</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white mt-1 flex items-center gap-2">
            <GitBranch className="h-6 w-6 text-blue-400" />
            {repoId}
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/reports">
            <Button size="sm" variant="outline" className="gap-2">
              <FileText className="h-4 w-4" />
              Generate Statutory Report
            </Button>
          </Link>
        </div>
      </div>

      {/* State Ledger Hash-Chain Verification Section */}
      <Card className="border-gray-800 bg-gray-900/60">
        <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-emerald-400" />
              <CardTitle className="text-base text-white">ComplianceDB Hash-Chain State Ledger</CardTitle>
            </div>
            <CardDescription className="text-gray-400 text-xs mt-1">
              Tamper-evident sequential ledger blocks sealed with SHA-256 cryptographic signatures.
            </CardDescription>
          </div>
          <Button
            size="sm"
            onClick={handleVerifyLedger}
            disabled={verifying}
            className="gap-2 bg-emerald-600 hover:bg-emerald-700 text-xs"
          >
            <ShieldCheck className="h-4 w-4" />
            {verifying ? "Verifying SHA-256..." : "Verify Ledger Integrity"}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {verificationResult && (
            <div
              className={`rounded-lg border p-4 text-xs font-mono ${
                verificationResult.isValid
                  ? "border-emerald-800/50 bg-emerald-950/30 text-emerald-300"
                  : "border-red-800/50 bg-red-950/30 text-red-300"
              }`}
            >
              <div className="flex items-center gap-2 font-bold text-sm">
                {verificationResult.isValid ? (
                  <>
                    <Check className="h-4 w-4 text-emerald-400" />
                    <span>LEDGER INTEGRITY VERIFIED (100% UNBROKEN)</span>
                  </>
                ) : (
                  <>
                    <X className="h-4 w-4 text-red-400" />
                    <span>LEDGER TAMPERING DETECTED</span>
                  </>
                )}
              </div>
              <p className="mt-1 text-[11px] opacity-90">
                {verificationResult.isValid
                  ? `Cryptographically verified ${verificationResult.totalSnapshots} sequential blocks with 0 bit-drift.`
                  : verificationResult.errorMessage}
              </p>
            </div>
          )}

          {/* Block Visualizer */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {snapshots.map((snap, idx) => (
              <div
                key={snap.scanId}
                className="rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs font-mono space-y-2 relative"
              >
                <div className="flex items-center justify-between text-gray-400">
                  <span className="font-bold text-white">Block #{idx + 1} ({snap.scanId})</span>
                  <span className="text-[10px] text-gray-500">{new Date(snap.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="text-gray-400">
                  <span className="text-gray-500">self_hash: </span>
                  <span className="text-emerald-400">{snap.selfHash.slice(0, 20)}...</span>
                </div>
                <div className="text-gray-400">
                  <span className="text-gray-500">prev_hash: </span>
                  <span className="text-blue-400">{snap.prevHash ? `${snap.prevHash.slice(0, 20)}...` : "(Genesis Block)"}</span>
                </div>
                <div className="flex items-center gap-3 pt-2 border-t border-gray-800/80 text-[11px]">
                  <span className="text-gray-300">{snap.componentsCount} components</span>
                  <span className="text-emerald-400">{snap.metCount} met</span>
                  <span className="text-red-400">{snap.gapCount} gap</span>
                  <span className="text-amber-400">{snap.manualCount} manual</span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Colorado AI Act Statutory Controls Breakdown */}
      <Card className="border-gray-800 bg-gray-900/60">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base text-white">Colorado AI Act (SB 24-205) Controls</CardTitle>
              <CardDescription className="text-gray-400 text-xs">
                Statutory requirement evaluations and code evidence mappings.
              </CardDescription>
            </div>
            <Badge variant="met">100% COMPLIANT</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="divide-y divide-gray-800/80">
            {controls.map((c) => (
              <div key={c.id} className="py-4 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-white">{c.id}</span>
                    <span className="text-sm text-gray-200">{c.title}</span>
                  </div>
                  <Badge variant={c.state === "met" ? "met" : c.state === "gap" ? "gap" : "manual"}>
                    {c.state.toUpperCase()}
                  </Badge>
                </div>
                <p className="text-xs text-gray-400">{c.rationale}</p>
                {c.evidence.length > 0 && (
                  <div className="mt-2 rounded bg-gray-950 p-2.5 text-xs font-mono text-gray-300 border border-gray-800">
                    <div className="text-[11px] text-gray-500 flex items-center gap-1 mb-1">
                      <Code2 className="h-3.5 w-3.5 text-blue-400" />
                      <span>Supporting Code Evidence:</span>
                    </div>
                    {c.evidence.map((ev, i) => (
                      <div key={i} className="flex items-center justify-between text-[11px]">
                        <span className="text-blue-300 font-bold">{ev.name} ({ev.purl})</span>
                        <span className="text-gray-500">{ev.location}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
