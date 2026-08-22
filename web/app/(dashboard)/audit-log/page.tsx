"use client";

import React, { useState } from "react";
import { History, ShieldCheck, Lock, Search, Download, CheckCircle2 } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../components/ui/card";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../../../components/ui/table";

const mockAuditEvents = [
  {
    id: "evt_soc2_99812a",
    timestamp: "2026-08-22T10:15:30Z",
    actor: "sarah.chen@acme.com",
    role: "COMPLIANCE_OFFICER",
    action: "ATTESTATION_SIGNED",
    target: "acme/loan-decisioning (co.ai-act.risk-mgmt)",
    signature: "hmac-sha256:7f9a2c89b71e4d3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183",
    status: "SEALED",
  },
  {
    id: "evt_soc2_99812b",
    timestamp: "2026-08-22T09:42:00Z",
    actor: "alex.dev@acme.com",
    role: "DEVELOPER",
    action: "SCAN_SNAPSHOT_COMMITTED",
    target: "acme/candidate-ranker (scan_02_14f089)",
    signature: "hmac-sha256:8c71b29a01f9e83746a5b82c91e0294857162534a8e9102c9183746a5b82c91e",
    status: "SEALED",
  },
  {
    id: "evt_soc2_99812c",
    timestamp: "2026-08-22T08:30:15Z",
    actor: "admin@acme.com",
    role: "ADMIN",
    action: "API_KEY_GENERATED",
    target: "CI_RUNNER_PROD_KEY (scope: repo:read, scan:write)",
    signature: "hmac-sha256:1e0294857162534a8e9102c9183746a5b82c91e0294857162534a8e9102c9183",
    status: "SEALED",
  },
  {
    id: "evt_soc2_99812d",
    timestamp: "2026-08-22T07:12:00Z",
    actor: "system_gateway",
    role: "SYSTEM",
    action: "SIEM_STREAM_DELIVERED",
    target: "Splunk HEC Endpoint (10,000 events flushed)",
    signature: "hmac-sha256:3a8e9102c9183746a5b82c91e0294857162534a8e9102c9183746a5b82c91e02",
    status: "SEALED",
  },
];

export default function AuditLogPage() {
  const [events] = useState(mockAuditEvents);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">SOC 2 Immutable Audit Trail</h1>
          <p className="text-sm text-gray-400">
            Append-only cryptographic event ledger for compliance attestations, API key actions, and scan commits.
          </p>
        </div>
        <Button variant="outline" size="sm" className="gap-2 text-xs">
          <Download className="h-4 w-4" />
          Export Signed Audit Bundle (.jsonl)
        </Button>
      </div>

      <Card className="border-gray-800 bg-gray-900/60">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Event ID & Timestamp</TableHead>
                <TableHead>Actor & Role</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Target Entity</TableHead>
                <TableHead>HMAC Signature</TableHead>
                <TableHead className="text-right">Integrity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((evt) => (
                <TableRow key={evt.id}>
                  <TableCell className="font-mono text-xs">
                    <div className="font-bold text-white">{evt.id}</div>
                    <span className="text-[10px] text-gray-500">{new Date(evt.timestamp).toUTCString()}</span>
                  </TableCell>
                  <TableCell className="text-xs">
                    <div className="font-medium text-gray-200">{evt.actor}</div>
                    <Badge variant="secondary" className="text-[10px] font-mono mt-0.5">
                      {evt.role}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs font-semibold text-blue-400">
                    {evt.action}
                  </TableCell>
                  <TableCell className="text-xs text-gray-300 font-mono">
                    {evt.target}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-emerald-400">
                    {evt.signature.slice(0, 16)}...
                  </TableCell>
                  <TableCell className="text-right">
                    <Badge variant="met" className="gap-1">
                      <ShieldCheck className="h-3 w-3" />
                      {evt.status}
                    </Badge>
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
