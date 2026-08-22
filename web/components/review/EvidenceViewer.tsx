"use client";

import React from "react";
import { X, Code2, ShieldCheck, FileText, CheckCircle2 } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";

interface EvidenceOccurrence {
  componentId: string;
  name: string;
  purl?: string;
  location: string;
  confidence: number;
}

interface EvidenceViewerProps {
  controlTitle: string;
  controlId: string;
  evidence: EvidenceOccurrence[];
  onClose: () => void;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({
  controlTitle,
  controlId,
  evidence,
  onClose,
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <Card className="w-full max-w-2xl border-gray-800 bg-gray-900 shadow-2xl overflow-hidden">
        <CardHeader className="flex flex-row items-center justify-between border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Code2 className="h-5 w-5 text-blue-400" />
              <CardTitle className="text-base font-bold text-white">AST Evidence Inspector</CardTitle>
            </div>
            <p className="text-xs text-gray-400 font-mono">Control: {controlId}</p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-4 w-4" />
          </Button>
        </CardHeader>

        <CardContent className="space-y-4 p-6 text-xs">
          <div className="rounded-lg border border-gray-800 bg-gray-950 p-4">
            <h4 className="font-semibold text-white mb-1">{controlTitle}</h4>
            <p className="text-gray-400 text-xs">
              The scanner discovered the following concrete code occurrences satisfying this statutory control.
            </p>
          </div>

          <div className="space-y-3">
            {evidence.map((ev, idx) => (
              <div
                key={idx}
                className="rounded-lg border border-gray-800 bg-gray-950 p-4 font-mono space-y-2"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-blue-300">{ev.name}</span>
                  <Badge variant="met">{(ev.confidence * 100).toFixed(0)}% CONFIDENCE</Badge>
                </div>
                {ev.purl && (
                  <div className="text-gray-400 text-[11px]">
                    <span className="text-gray-500">PURL: </span>
                    <span className="text-gray-200">{ev.purl}</span>
                  </div>
                )}
                <div className="text-gray-400 text-[11px]">
                  <span className="text-gray-500">Location: </span>
                  <span className="text-emerald-400 font-semibold">{ev.location}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-end pt-2">
            <Button size="sm" onClick={onClose} className="bg-blue-600 hover:bg-blue-700">
              Done Reviewing
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
