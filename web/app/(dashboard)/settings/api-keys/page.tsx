"use client";

import React, { useState } from "react";
import { KeyRound, Plus, Copy, Trash2, ShieldCheck, Lock, Check } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../../components/ui/card";
import { Badge } from "../../../../components/ui/badge";
import { Button } from "../../../../components/ui/button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../../../../components/ui/table";

const mockApiKeys = [
  {
    id: "key_01_ci_runner",
    name: "GitHub Actions CI Runner",
    prefix: "airo_live_8f9a2c",
    scopes: ["repo:read", "scan:write", "ledger:append"],
    createdAt: "2026-08-01",
    lastUsed: "5 mins ago",
  },
  {
    id: "key_02_prod_gateway",
    name: "Production Gateway Ingestion",
    prefix: "airo_live_3e102d",
    scopes: ["scan:write", "anomaly:publish"],
    createdAt: "2026-07-15",
    lastUsed: "Just now",
  },
  {
    id: "key_03_auditor_token",
    name: "Deloitte Read-Only Auditor Key",
    prefix: "airo_live_1c44bb",
    scopes: ["repo:read", "audit:read", "report:export"],
    createdAt: "2026-08-10",
    lastUsed: "2 days ago",
  },
];

export default function ApiKeysPage() {
  const [keys] = useState(mockApiKeys);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (prefix: string, id: string) => {
    navigator.clipboard.writeText(`${prefix}************************`);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Enterprise API Keys</h1>
          <p className="text-sm text-gray-400">
            Generate and manage scoped bearer tokens for CI/CD pipelines, runtime gateways, and compliance reporting.
          </p>
        </div>
        <Button size="sm" className="gap-2 bg-blue-600 hover:bg-blue-700 text-xs">
          <Plus className="h-4 w-4" />
          Create New API Key
        </Button>
      </div>

      <Card className="border-gray-800 bg-gray-900/60">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Key Name</TableHead>
                <TableHead>Token Prefix</TableHead>
                <TableHead>Assigned Scopes</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id}>
                  <TableCell>
                    <div className="font-semibold text-white text-xs">{k.name}</div>
                    <div className="text-[10px] text-gray-500 font-mono">Created on {k.createdAt}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 font-mono text-xs text-blue-300">
                      <span>{k.prefix}...</span>
                      <button
                        onClick={() => handleCopy(k.prefix, k.id)}
                        className="text-gray-500 hover:text-gray-300"
                      >
                        {copiedId === k.id ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {k.scopes.map((s) => (
                        <Badge key={s} variant="secondary" className="font-mono text-[10px]">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-gray-400">{k.lastUsed}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" className="text-gray-400 hover:text-red-400">
                      <Trash2 className="h-4 w-4" />
                    </Button>
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
