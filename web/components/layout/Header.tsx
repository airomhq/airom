"use client";

import React from "react";
import { Bell, ShieldCheck, ChevronDown, LogOut, UserCheck } from "lucide-react";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { loadSession, clearSession } from "../../lib/auth";

export const Header: React.FC = () => {
  const [session, setSession] = React.useState<any>(null);

  React.useEffect(() => {
    setSession(loadSession());
  }, []);

  const handleLogout = () => {
    clearSession();
    window.location.href = "/login";
  };

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-gray-800 bg-gray-950/80 px-6 backdrop-blur">
      {/* Active Org Selector */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-xs text-gray-200">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-semibold">{session?.orgId || "Acme Enterprise Corp"}</span>
          <Badge variant="outline" className="text-[10px] text-blue-400 border-blue-800/40">
            ENTERPRISE TIER
          </Badge>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* System Health */}
        <div className="hidden md:flex items-center gap-2 text-xs text-gray-400">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <span>Gateway: <strong>Healthy (v0.5.0)</strong></span>
        </div>

        {/* User Role Badge */}
        {session && (
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="gap-1 font-mono text-[11px]">
              <UserCheck className="h-3 w-3 text-blue-400" />
              {session.role?.toUpperCase() || "COMPLIANCE_OFFICER"}
            </Badge>
            <span className="text-xs text-gray-400 hidden lg:inline">{session.email}</span>
          </div>
        )}

        {/* Logout Button */}
        <Button variant="ghost" size="sm" onClick={handleLogout} className="text-gray-400 hover:text-red-400">
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </header>
  );
};
