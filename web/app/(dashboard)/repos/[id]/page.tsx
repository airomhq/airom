"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  GitBranch,
  Lock,
  ShieldCheck,
  Check,
  X,
  FileText,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../../components/ui/card";
import { Button } from "../../../../components/ui/button";
import { ScanSnapshot, ControlEvaluation } from "../../../../types";
import { verifyLedgerIntegrity, LedgerVerificationResult } from "../../../../lib/crypto";
import { HashChainGraph } from "../../../../components/ledger/HashChainGraph";
import { GreenYellowRedReview } from "../../../../components/review/GreenYellowRedReview";

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
    id: "co.ai-act.incident-reporting",
    frameworkId: "colorado-ai-act",
    title: "Algorithmic Discrimination Notification (§ 6-1-1705)",
    category: "Incident Response",
    state: "met",
    score: 1.0,
    rationale: "Automated 90-day notification incident trigger active in ComplianceDB.",
    evidence: [],
  },
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
    id: "co.ai-act.consumer-notice",
    frameworkId: "colorado-ai-act",
    title: "Consumer Disclosure (§ 6-1-1704)",
    category: "Transparency",
    state: "manual",
    score: 0,
    rationale: "Confirm consumer notice mechanism is visible in deployment UI before consequential decision.",
    evidence: [],
  },
];

export default function RepoDetailPage() {
  const params = useParams();
  const repoId = params?.id as string;
  const [snapshots] = useState<ScanSnapshot[]>(mockSnapshots);
  const [controls] = useState<ControlEvaluation[]>(mockControls);
  const [attestations, setAttestations] = useState<Record<string, string>>({});
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<LedgerVerificationResult | null>(null);

  const handleAttestationChange = (controlId: string, value: string) => {
    setAttestations((prev) => ({ ...prev, [controlId]: value }));
  };

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
              Tamper-evident sequential ledger blocks sealed with SHA-256 cryptographic signatures. Click any block to inspect payload.
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

          {/* Interactive Hash-Chain Visualizer */}
          <HashChainGraph snapshots={snapshots} />
        </CardContent>
      </Card>

      {/* Colorado AI Act Statutory Controls Breakdown with Green/Yellow/Red Review */}
      <GreenYellowRedReview
        frameworkName="Colorado AI Act (SB 24-205)"
        controls={controls}
        attestations={attestations}
        onAttestationChange={handleAttestationChange}
      />
    </div>
  );
}
