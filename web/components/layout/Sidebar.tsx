"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  GitBranch,
  FileText,
  AlertTriangle,
  Settings,
  Users,
  KeyRound,
  History,
  Lock,
} from "lucide-react";
import { cn } from "../ui/button";

const navItems = [
  { name: "Executive Cockpit", href: "/", icon: LayoutDashboard },
  { name: "Repositories", href: "/repos", icon: GitBranch },
  { name: "Frameworks & Laws", href: "/frameworks", icon: ShieldAlert },
  { name: "Statutory Reports", href: "/reports", icon: FileText },
  { name: "Shadow AI & Anomalies", href: "/anomalies", icon: AlertTriangle },
  { name: "SOC 2 Audit Trail", href: "/audit-log", icon: History },
  { name: "Team & RBAC", href: "/settings/team", icon: Users },
  { name: "API Keys", href: "/settings/api-keys", icon: KeyRound },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-gray-800 bg-gray-950 text-gray-200">
      {/* Brand Header */}
      <div className="flex h-16 items-center gap-3 border-b border-gray-800 px-6">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 shadow-md shadow-blue-500/20">
          <ShieldAlert className="h-5 w-5 text-white" />
        </div>
        <div className="flex flex-col">
          <span className="text-base font-bold tracking-tight text-white">AIROM</span>
          <span className="text-[10px] font-mono uppercase tracking-widest text-blue-400">Enterprise AI Gov</span>
        </div>
      </div>

      {/* Nav Links */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                  : "text-gray-400 hover:bg-gray-900 hover:text-gray-200"
              )}
            >
              <Icon className={cn("h-4 w-4", isActive ? "text-blue-400" : "text-gray-500")} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* ComplianceDB Status Card */}
      <div className="p-4">
        <div className="rounded-lg border border-gray-800/80 bg-gray-900/60 p-3 text-xs">
          <div className="flex items-center justify-between text-gray-300">
            <span className="flex items-center gap-1.5 font-medium">
              <Lock className="h-3.5 w-3.5 text-emerald-400" />
              State Ledger
            </span>
            <span className="rounded-full bg-emerald-950 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-400 border border-emerald-800/40">
              UNBROKEN
            </span>
          </div>
          <p className="mt-1.5 text-[11px] text-gray-500">
            SHA-256 tamper-evident chain validated across all snapshots.
          </p>
        </div>
      </div>
    </aside>
  );
};
