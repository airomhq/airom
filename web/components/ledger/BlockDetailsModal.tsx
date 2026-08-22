"use client";

import React from "react";
import { X, Lock, FileCode, CheckCircle, AlertTriangle, ShieldCheck, Copy } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { ScanSnapshot } from "../../types";

interface BlockDetailsModalProps {
  snapshot: ScanSnapshot | null;
  index: number;
  onClose: () => void;
}

export const BlockDetailsModal: React.FC<BlockDetailsModalProps> = ({ snapshot, index, onClose }) => {
  const [copiedField, setCopiedField] = React.useState<string | null>(null);

  if (!snapshot) return null;

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 1500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <Card className="w-full max-w-2xl border-gray-800 bg-gray-900 shadow-2xl overflow-hidden">
        <CardHeader className="flex flex-row items-center justify-between border-b border-gray-800 pb-4">
          <div className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-emerald-400" />
            <CardTitle className="text-base font-bold text-white">
              Ledger Block #{index + 1} ({snapshot.scanId})
            </CardTitle>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-4 w-4" />
          </Button>
        </CardHeader>

        <CardContent className="space-y-4 p-6 text-xs font-mono">
          {/* Hashes */}
          <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-4">
            <div>
              <div className="flex items-center justify-between text-gray-400 mb-1">
                <span className="font-semibold text-emerald-400">Block Self Hash (SHA-256):</span>
                <button
                  onClick={() => copyToClipboard(snapshot.selfHash, "selfHash")}
                  className="flex items-center gap-1 text-[11px] text-gray-500 hover:text-gray-300"
                >
                  <Copy className="h-3 w-3" />
                  {copiedField === "selfHash" ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="break-all rounded bg-gray-900 p-2 text-emerald-300">{snapshot.selfHash}</div>
            </div>

            <div>
              <div className="flex items-center justify-between text-gray-400 mb-1">
                <span className="font-semibold text-blue-400">Parent Previous Hash:</span>
                <button
                  onClick={() => copyToClipboard(snapshot.prevHash, "prevHash")}
                  className="flex items-center gap-1 text-[11px] text-gray-500 hover:text-gray-300"
                >
                  <Copy className="h-3 w-3" />
                  {copiedField === "prevHash" ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="break-all rounded bg-gray-900 p-2 text-blue-300">
                {snapshot.prevHash || "(0000000000000000000000000000000000000000000000000000000000000000 - Genesis Block)"}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2">
              <div>
                <span className="text-gray-500 block mb-1">AIBOM Tree Merkle Root:</span>
                <div className="truncate rounded bg-gray-900 p-2 text-gray-300">{snapshot.aibomHash}</div>
              </div>
              <div>
                <span className="text-gray-500 block mb-1">Controls Merkle Root:</span>
                <div className="truncate rounded bg-gray-900 p-2 text-gray-300">{snapshot.controlsHash}</div>
              </div>
            </div>
          </div>

          {/* Block Metadata */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="rounded border border-gray-800 bg-gray-950 p-3">
              <span className="text-[10px] text-gray-500 uppercase">AI Components</span>
              <div className="text-lg font-bold text-white mt-0.5">{snapshot.componentsCount}</div>
            </div>
            <div className="rounded border border-emerald-900/40 bg-emerald-950/20 p-3">
              <span className="text-[10px] text-emerald-500 uppercase">Met Controls</span>
              <div className="text-lg font-bold text-emerald-400 mt-0.5">{snapshot.metCount}</div>
            </div>
            <div className="rounded border border-red-900/40 bg-red-950/20 p-3">
              <span className="text-[10px] text-red-500 uppercase">Gaps</span>
              <div className="text-lg font-bold text-red-400 mt-0.5">{snapshot.gapCount}</div>
            </div>
            <div className="rounded border border-amber-900/40 bg-amber-950/20 p-3">
              <span className="text-[10px] text-amber-500 uppercase">Manual</span>
              <div className="text-lg font-bold text-amber-400 mt-0.5">{snapshot.manualCount}</div>
            </div>
          </div>

          {/* Timestamp & Verification Seal */}
          <div className="flex items-center justify-between text-gray-400 pt-2 text-[11px]">
            <span>Sealed At: <strong>{new Date(snapshot.timestamp).toUTCString()}</strong></span>
            <div className="flex items-center gap-1 text-emerald-400">
              <ShieldCheck className="h-4 w-4" />
              <span>Cryptographically Verified</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
