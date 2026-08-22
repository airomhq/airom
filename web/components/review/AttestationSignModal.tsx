"use client";

import React, { useState } from "react";
import { Lock, ShieldCheck, CheckCircle2, X, Download, Code2, AlertTriangle } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";

interface AttestationSignModalProps {
  frameworkId: string;
  frameworkName: string;
  repoId: string;
  unfilledManualCount: number;
  onClose: () => void;
  onSignSuccess: (token: string) => void;
}

export const AttestationSignModal: React.FC<AttestationSignModalProps> = ({
  frameworkId,
  frameworkName,
  repoId,
  unfilledManualCount,
  onClose,
  onSignSuccess,
}) => {
  const [signerName, setSignerName] = useState("Sarah Chen");
  const [signerEmail, setSignerEmail] = useState("sarah.chen@acme-corp.com");
  const [signerTitle, setSignerTitle] = useState("Chief Compliance Officer");
  const [agree, setAgree] = useState(false);
  const [signing, setSigning] = useState(false);
  const [signedToken, setSignedToken] = useState<string | null>(null);

  const handleSign = () => {
    if (!agree) return;
    setSigning(true);

    setTimeout(() => {
      const token = `hmac-sha256:airo_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`;
      setSignedToken(token);
      setSigning(false);
      onSignSuccess(token);
    }, 900);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <Card className="w-full max-w-xl border-gray-800 bg-gray-900 shadow-2xl overflow-hidden">
        <CardHeader className="flex flex-row items-center justify-between border-b border-gray-800 pb-4">
          <div className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-blue-400" />
            <CardTitle className="text-base font-bold text-white">Execute Statutory Attestation</CardTitle>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-4 w-4" />
          </Button>
        </CardHeader>

        <CardContent className="space-y-4 p-6 text-xs">
          {unfilledManualCount > 0 && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-800/50 bg-amber-950/30 p-3 text-amber-300">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>
                <strong>{unfilledManualCount} manual controls</strong> still require justification before signing.
              </span>
            </div>
          )}

          <div className="rounded-lg border border-gray-800 bg-gray-950 p-4 space-y-2 font-mono">
            <div className="flex justify-between text-gray-400">
              <span>Framework:</span>
              <span className="text-white font-bold">{frameworkName}</span>
            </div>
            <div className="flex justify-between text-gray-400">
              <span>Repository Target:</span>
              <span className="text-blue-400">{repoId}</span>
            </div>
            <div className="flex justify-between text-gray-400">
              <span>Cryptographic Scheme:</span>
              <span className="text-emerald-400 font-bold">HMAC-SHA256 Detached Attestation</span>
            </div>
          </div>

          {!signedToken ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[11px] text-gray-400 font-semibold uppercase">Signer Legal Name</label>
                  <input
                    type="text"
                    value={signerName}
                    onChange={(e) => setSignerName(e.target.value)}
                    className="w-full rounded border border-gray-700 bg-gray-950 p-2 text-xs text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] text-gray-400 font-semibold uppercase">Signer Corporate Title</label>
                  <input
                    type="text"
                    value={signerTitle}
                    onChange={(e) => setSignerTitle(e.target.value)}
                    className="w-full rounded border border-gray-700 bg-gray-950 p-2 text-xs text-white"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-gray-400 font-semibold uppercase">Corporate Email</label>
                <input
                  type="email"
                  value={signerEmail}
                  onChange={(e) => setSignerEmail(e.target.value)}
                  className="w-full rounded border border-gray-700 bg-gray-950 p-2 text-xs text-white"
                />
              </div>

              <div className="flex items-start gap-2 pt-2">
                <input
                  type="checkbox"
                  id="legalConsent"
                  checked={agree}
                  onChange={(e) => setAgree(e.target.checked)}
                  className="mt-0.5 rounded border-gray-700 bg-gray-950 text-blue-600 focus:ring-blue-500"
                />
                <label htmlFor="legalConsent" className="text-[11px] text-gray-400 leading-relaxed">
                  I certify under penalty of applicable state and federal statutory laws that the evidence,
                  justifications, and manual attestations provided in this document are true, accurate, and complete.
                </label>
              </div>

              <Button
                onClick={handleSign}
                disabled={!agree || signing || unfilledManualCount > 0}
                className="w-full gap-2 bg-blue-600 hover:bg-blue-700 mt-2"
              >
                <Lock className="h-4 w-4" />
                {signing ? "Minting HMAC Signature..." : "Sign and Seal Regulatory Report"}
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="rounded-lg border border-emerald-800/50 bg-emerald-950/40 p-4 space-y-2 text-emerald-300 font-mono text-center">
                <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
                <h4 className="font-bold text-sm">STATUTORY REPORT SEALED SUCCESSFULLY</h4>
                <div className="text-[10px] break-all text-gray-300 bg-gray-900 p-2 rounded">
                  {signedToken}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <Button variant="outline" className="gap-2 text-xs">
                  <Download className="h-4 w-4 text-blue-400" />
                  Download PDF
                </Button>
                <Button variant="outline" className="gap-2 text-xs">
                  <Code2 className="h-4 w-4 text-emerald-400" />
                  Export HTML
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
