"use client";

import React, { useState } from "react";
import {
  FileText,
  ShieldCheck,
  Download,
  CheckCircle2,
  Lock,
  Code2,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../components/ui/card";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { ControlEvaluation } from "../../../types";
import { GreenYellowRedReview } from "../../../components/review/GreenYellowRedReview";
import { AttestationSignModal } from "../../../components/review/AttestationSignModal";

const frameworkControlsMap: Record<string, { name: string; controls: ControlEvaluation[] }> = {
  "colorado-ai-act": {
    name: "Colorado AI Act (SB 24-205)",
    controls: [
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
    ],
  },
  "nyc-ll144": {
    name: "NYC Local Law 144 (AEDT)",
    controls: [
      {
        id: "nyc.ll144.bias-audit",
        frameworkId: "nyc-ll144",
        title: "Independent Annual Bias Audit (§ 20-871)",
        category: "Bias Audit",
        state: "manual",
        score: 0,
        rationale: "Upload or cite independent third-party bias audit published within the past 12 months.",
        evidence: [],
      },
      {
        id: "nyc.ll144.candidate-notice",
        frameworkId: "nyc-ll144",
        title: "10-Day Candidate Advance Notice (§ 20-872)",
        category: "Notice & Opt-Out",
        state: "met",
        score: 1.0,
        rationale: "Automated notice dispatch system detected in applicant tracking pipeline.",
        evidence: [
          {
            componentId: "airom:778ae912",
            name: "candidate-notification-agent",
            location: "src/hiring/notice.ts:32",
            confidence: 0.9,
          },
        ],
      },
    ],
  },
};

export default function ReportsPage() {
  const [selectedFramework, setSelectedFramework] = useState("colorado-ai-act");
  const [attestations, setAttestations] = useState<Record<string, string>>({
    "co.ai-act.risk-mgmt": "Risk management program verified under Enterprise NIST AI RMF governance policy v2.4.",
    "co.ai-act.consumer-notice": "Consumer notice modal active on production checkout UI (/src/ui/NoticeBanner.tsx).",
  });
  const [showSignModal, setShowSignModal] = useState(false);
  const [signedToken, setSignedToken] = useState<string | null>(null);

  const activeData = frameworkControlsMap[selectedFramework] || frameworkControlsMap["colorado-ai-act"];

  const handleAttestationChange = (controlId: string, value: string) => {
    setAttestations((prev) => ({ ...prev, [controlId]: value }));
  };

  const manualControls = activeData.controls.filter((c) => c.state === "manual");
  const unfilledManualCount = manualControls.filter((c) => !attestations[c.id]?.trim()).length;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-gray-800 pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Statutory Report Generator</h1>
          <p className="text-sm text-gray-400">
            Regulator-ready documentation packages grounded in AST code citations with human attestation sign-offs.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={selectedFramework}
            onChange={(e) => setSelectedFramework(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-white focus:border-blue-500 focus:outline-none"
          >
            <option value="colorado-ai-act">Colorado AI Act (SB 24-205)</option>
            <option value="nyc-ll144">NYC Local Law 144 (AEDT)</option>
          </select>
        </div>
      </div>

      {/* Green / Yellow / Red Review Gateway */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Interactive Review */}
        <div className="lg:col-span-2 space-y-6">
          <GreenYellowRedReview
            frameworkName={activeData.name}
            controls={activeData.controls}
            attestations={attestations}
            onAttestationChange={handleAttestationChange}
          />
        </div>

        {/* Right Col: Sign & Export Panel */}
        <div className="space-y-6">
          <Card className="border-gray-800 bg-gray-900/60 sticky top-24">
            <CardHeader>
              <CardTitle className="text-base text-white">Legal Sign-Off & Token</CardTitle>
              <CardDescription className="text-gray-400 text-xs">
                Mints a cryptographically signed HMAC attestation token sealing the report.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">
              <div className="rounded border border-gray-800 bg-gray-950 p-3 space-y-1.5 font-mono">
                <div className="flex justify-between text-gray-400">
                  <span>Signer:</span>
                  <span className="text-white">Sarah Chen</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Role:</span>
                  <span className="text-blue-400">Compliance Officer</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Statutory Standard:</span>
                  <span className="text-emerald-400">{activeData.name}</span>
                </div>
              </div>

              {signedToken ? (
                <div className="rounded border border-emerald-800/50 bg-emerald-950/30 p-3 space-y-2 text-emerald-300 font-mono">
                  <div className="flex items-center gap-1.5 font-bold">
                    <CheckCircle2 className="h-4 w-4" />
                    <span>REPORT SEALED & ATTESTED</span>
                  </div>
                  <div className="text-[10px] break-all text-gray-400">{signedToken}</div>
                </div>
              ) : (
                <Button
                  onClick={() => setShowSignModal(true)}
                  disabled={unfilledManualCount > 0}
                  className="w-full gap-2 bg-blue-600 hover:bg-blue-700"
                >
                  <Lock className="h-4 w-4" />
                  {unfilledManualCount > 0
                    ? `${unfilledManualCount} Attestations Missing`
                    : "Sign & Seal Report"}
                </Button>
              )}

              {signedToken && (
                <div className="space-y-2 pt-2">
                  <Button variant="outline" className="w-full gap-2 text-xs">
                    <Download className="h-4 w-4 text-blue-400" />
                    Download Statutory PDF (Annex IV)
                  </Button>
                  <Button variant="outline" className="w-full gap-2 text-xs">
                    <Code2 className="h-4 w-4 text-emerald-400" />
                    Export WCAG 2.1 AA HTML
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Attestation Sign Modal */}
      {showSignModal && (
        <AttestationSignModal
          frameworkId={selectedFramework}
          frameworkName={activeData.name}
          repoId="acme/loan-decisioning"
          unfilledManualCount={unfilledManualCount}
          onClose={() => setShowSignModal(false)}
          onSignSuccess={(token) => {
            setSignedToken(token);
            setShowSignModal(false);
          }}
        />
      )}
    </div>
  );
}
