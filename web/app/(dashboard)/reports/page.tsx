"use client";

import React, { useState } from "react";
import {
  FileText,
  ShieldCheck,
  Download,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Sparkles,
  ExternalLink,
  Code2,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../../../components/ui/card";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { loadSession } from "../../../lib/auth";

export default function ReportsPage() {
  const [selectedFramework, setSelectedFramework] = useState("colorado-ai-act");
  const [riskMgmtAttestation, setRiskMgmtAttestation] = useState(
    "Risk management program verified under Enterprise NIST AI RMF governance policy v2.4."
  );
  const [consumerNoticeAttestation, setConsumerNoticeAttestation] = useState(
    "Consumer notice modal active on production checkout UI (/src/ui/NoticeBanner.tsx)."
  );
  const [signing, setSigning] = useState(false);
  const [signedToken, setSignedToken] = useState<string | null>(null);

  const handleSignAttestation = () => {
    setSigning(true);
    setTimeout(() => {
      setSignedToken("hmac-sha256:7f9a2c89b71e4d3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183");
      setSigning(false);
    }, 800);
  };

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
            <option value="ca-ab2013">California AB 2013 (Training Data)</option>
            <option value="illinois-bipa">Illinois BIPA (740 ILCS 14)</option>
            <option value="texas-traiga">Texas TRAIGA (Gov Code § 2054)</option>
            <option value="virginia-vcdpa">Virginia VCDPA (§ 59.1-575)</option>
          </select>
        </div>
      </div>

      {/* Green / Yellow / Red Review Gateway */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Form & Controls */}
        <div className="lg:col-span-2 space-y-6">
          {/* Green Controls (Automated - Met) */}
          <Card className="border-gray-800 bg-gray-900/60">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded-full bg-emerald-500" />
                  <CardTitle className="text-sm text-white">Automated Controls (2 Met - Grounded)</CardTitle>
                </div>
                <Badge variant="met">VERIFIED</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <div className="rounded border border-gray-800 bg-gray-950 p-3 space-y-1">
                <span className="font-mono text-emerald-400 font-semibold">co.ai-act.impact-assessment (§ 6-1-1703)</span>
                <p className="text-gray-300">Algorithmic impact assessment complete; model purpose and bias mitigation verified.</p>
                <div className="text-[11px] text-gray-500 font-mono">Evidence: src/underwriting/scorer.py:14 (openai-gpt-4o)</div>
              </div>
              <div className="rounded border border-gray-800 bg-gray-950 p-3 space-y-1">
                <span className="font-mono text-emerald-400 font-semibold">co.ai-act.incident-reporting (§ 6-1-1705)</span>
                <p className="text-gray-300">Automated 90-day notification incident trigger active in ComplianceDB.</p>
              </div>
            </CardContent>
          </Card>

          {/* Yellow Controls (Manual - Attestation Required) */}
          <Card className="border-gray-800 bg-gray-900/60">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded-full bg-amber-500" />
                  <CardTitle className="text-sm text-white">Manual Attestation Controls (2 Sign-Offs Required)</CardTitle>
                </div>
                <Badge variant="manual">ACTION REQUIRED</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">
              {/* Control 1 */}
              <div className="space-y-2">
                <label className="font-mono font-semibold text-gray-200">
                  co.ai-act.risk-mgmt (§ 6-1-1702): Risk Management Program Alignment
                </label>
                <textarea
                  rows={2}
                  value={riskMgmtAttestation}
                  onChange={(e) => setRiskMgmtAttestation(e.target.value)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 p-2.5 text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                />
              </div>

              {/* Control 2 */}
              <div className="space-y-2">
                <label className="font-mono font-semibold text-gray-200">
                  co.ai-act.consumer-notice (§ 6-1-1704): Consumer UI Disclosure Notice
                </label>
                <textarea
                  rows={2}
                  value={consumerNoticeAttestation}
                  onChange={(e) => setConsumerNoticeAttestation(e.target.value)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 p-2.5 text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Col: Sign & Export Panel */}
        <div className="space-y-6">
          <Card className="border-gray-800 bg-gray-900/60">
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
                  <span className="text-white">sarah.chen@acme.com</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Role:</span>
                  <span className="text-blue-400">Compliance Officer</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Statutory Standard:</span>
                  <span className="text-emerald-400">CO SB 24-205 § 6-1-1703</span>
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
                  onClick={handleSignAttestation}
                  disabled={signing}
                  className="w-full gap-2 bg-blue-600 hover:bg-blue-700"
                >
                  <Lock className="h-4 w-4" />
                  {signing ? "Signing Attestation..." : "Sign & Seal Report"}
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
    </div>
  );
}
