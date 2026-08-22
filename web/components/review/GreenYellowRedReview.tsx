"use client";

import React, { useState } from "react";
import { CheckCircle2, AlertTriangle, ShieldAlert, FileText, Code2, ExternalLink, Lock } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { ControlEvaluation } from "../../types";
import { EvidenceViewer } from "./EvidenceViewer";

interface GreenYellowRedReviewProps {
  frameworkName: string;
  controls: ControlEvaluation[];
  attestations: Record<string, string>;
  onAttestationChange: (controlId: string, value: string) => void;
}

export const GreenYellowRedReview: React.FC<GreenYellowRedReviewProps> = ({
  frameworkName,
  controls,
  attestations,
  onAttestationChange,
}) => {
  const [selectedEvidenceControl, setSelectedEvidenceControl] = useState<ControlEvaluation | null>(null);

  const greenControls = controls.filter((c) => c.state === "met");
  const yellowControls = controls.filter((c) => c.state === "manual");
  const redControls = controls.filter((c) => c.state === "gap");

  return (
    <div className="space-y-6">
      {/* Green Section: Automated & Met Controls */}
      <Card className="border-gray-800 bg-gray-900/60">
        <CardHeader className="pb-3 border-b border-gray-800/80">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-emerald-500 animate-pulse" />
              <CardTitle className="text-sm font-bold text-white">
                Tier 1: Automated & Grounded Controls ({greenControls.length} Met)
              </CardTitle>
            </div>
            <Badge variant="met">100% EVIDENCE-GROUNDED</Badge>
          </div>
          <CardDescription className="text-xs text-gray-400">
            Satisfied automatically through AST source code analysis, model header parsing, and dataset inventory.
          </CardDescription>
        </CardHeader>
        <CardContent className="divide-y divide-gray-800/60 p-0">
          {greenControls.map((c) => (
            <div key={c.id} className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="font-bold text-emerald-400">{c.id}</span>
                  <span className="text-white font-sans">{c.title}</span>
                </div>
                <p className="text-xs text-gray-400">{c.rationale}</p>
              </div>
              {c.evidence && c.evidence.length > 0 && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setSelectedEvidenceControl(c)}
                  className="gap-1.5 text-xs text-blue-400 shrink-0"
                >
                  <Code2 className="h-3.5 w-3.5" />
                  View AST Evidence ({c.evidence.length})
                </Button>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Yellow Section: Manual Human Attestations Required */}
      <Card className="border-gray-800 bg-gray-900/60">
        <CardHeader className="pb-3 border-b border-gray-800/80">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-amber-500" />
              <CardTitle className="text-sm font-bold text-white">
                Tier 2: Manual Human Attestations ({yellowControls.length} Required)
              </CardTitle>
            </div>
            <Badge variant="manual">LEGAL SIGN-OFF REQUIRED</Badge>
          </div>
          <CardDescription className="text-xs text-gray-400">
            Statutory requirements governing organizational policy, bias audits, or consumer disclosures.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 p-4">
          {yellowControls.map((c) => (
            <div key={c.id} className="rounded-lg border border-gray-800 bg-gray-950 p-4 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-amber-400">{c.id}</span>
                <span className="text-gray-400 font-sans">{c.title}</span>
              </div>
              <p className="text-gray-300">{c.rationale}</p>
              <div className="pt-2">
                <label className="text-[11px] uppercase tracking-wider text-gray-400 font-semibold block mb-1">
                  Legal Justification & Policy Reference:
                </label>
                <textarea
                  rows={2}
                  value={attestations[c.id] || ""}
                  onChange={(e) => onAttestationChange(c.id, e.target.value)}
                  placeholder="Enter attestation statement, internal policy doc ID, or compliance justification..."
                  className="w-full rounded-lg border border-gray-700 bg-gray-900 p-2.5 text-xs text-white placeholder-gray-600 focus:border-amber-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Red Section: Non-Compliant Gaps (if any) */}
      {redControls.length > 0 && (
        <Card className="border-red-900/50 bg-red-950/20">
          <CardHeader className="pb-3 border-b border-red-900/40">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-red-500 animate-ping" />
                <CardTitle className="text-sm font-bold text-red-300">
                  Tier 3: Statutory Gaps ({redControls.length} Non-Compliant)
                </CardTitle>
              </div>
              <Badge variant="gap">IMMEDIATE ACTION</Badge>
            </div>
            <CardDescription className="text-xs text-red-400/80">
              Missing mandatory statutory elements or identified high-risk CVEs/shadow AI.
            </CardDescription>
          </CardHeader>
          <CardContent className="divide-y divide-red-900/40 p-0">
            {redControls.map((c) => (
              <div key={c.id} className="p-4 space-y-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-red-400">{c.id}</span>
                  <span className="text-white">{c.title}</span>
                </div>
                <p className="text-red-300/90">{c.rationale}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Evidence Viewer Modal */}
      {selectedEvidenceControl && (
        <EvidenceViewer
          controlTitle={selectedEvidenceControl.title}
          controlId={selectedEvidenceControl.id}
          evidence={selectedEvidenceControl.evidence}
          onClose={() => setSelectedEvidenceControl(null)}
        />
      )}
    </div>
  );
};
