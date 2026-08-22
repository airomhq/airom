"use client";

import React, { useState } from "react";
import { Users, UserPlus, Shield, KeyRound, Check, Trash2 } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../../components/ui/card";
import { Badge } from "../../../../components/ui/badge";
import { Button } from "../../../../components/ui/button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../../../../components/ui/table";
import { UserRole } from "../../../../types";

const mockMembers = [
  {
    id: "usr_01",
    name: "Sarah Chen",
    email: "sarah.chen@acme-corp.com",
    role: "compliance_officer" as UserRole,
    status: "active",
    lastLogin: "10 mins ago",
  },
  {
    id: "usr_02",
    name: "David Kim",
    email: "david.kim@acme-corp.com",
    role: "admin" as UserRole,
    status: "active",
    lastLogin: "1 hour ago",
  },
  {
    id: "usr_03",
    name: "Alex Johnson",
    email: "alex.dev@acme-corp.com",
    role: "developer" as UserRole,
    status: "active",
    lastLogin: "2 hours ago",
  },
  {
    id: "usr_04",
    name: "Elena Rostova",
    email: "elena.audit@deloitte-external.com",
    role: "auditor" as UserRole,
    status: "active",
    lastLogin: "1 day ago",
  },
];

export default function TeamSettingsPage() {
  const [members] = useState(mockMembers);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Team & RBAC Permissions</h1>
          <p className="text-sm text-gray-400">
            Manage organization members, role-based access control tiers, and attestation signing permissions.
          </p>
        </div>
        <Button size="sm" className="gap-2 bg-blue-600 hover:bg-blue-700 text-xs">
          <UserPlus className="h-4 w-4" />
          Invite Team Member
        </Button>
      </div>

      <Card className="border-gray-800 bg-gray-900/60">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Member</TableHead>
                <TableHead>Role Tier</TableHead>
                <TableHead>Attestation Authority</TableHead>
                <TableHead>Last Active</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.map((m) => (
                <TableRow key={m.id}>
                  <TableCell>
                    <div className="font-semibold text-white text-xs">{m.name}</div>
                    <div className="text-[11px] text-gray-400 font-mono">{m.email}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="font-mono text-[10px] uppercase">
                      {m.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {m.role === "compliance_officer" || m.role === "admin" ? (
                      <Badge variant="met" className="gap-1 text-[10px]">
                        <Check className="h-3 w-3" />
                        CAN SIGN ATTESTATIONS
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-[10px] text-gray-500">
                        READ-ONLY ACCESS
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-gray-400">{m.lastLogin}</TableCell>
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
