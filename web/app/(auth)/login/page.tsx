"use client";

import React, { useState } from "react";
import { ShieldAlert, KeyRound, ArrowRight, Lock, Sparkles } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../../../components/ui/card";
import { Button } from "../../../components/ui/button";
import { saveSession } from "../../../lib/auth";

export default function LoginPage() {
  const [apiKey, setApiKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      setError("Please provide an AIROM Enterprise API Key or SSO Token.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Simulate API key verification / token exchange
      const mockSession = {
        userId: "usr_99812a",
        email: "sarah.chen@acme-corp.com",
        role: "compliance_officer" as const,
        orgId: "org_acme_enterprise",
        token: apiKey.startsWith("airo_") ? apiKey : `airo_live_${apiKey}`,
      };

      saveSession(mockSession);
      window.location.href = "/";
    } catch (err: any) {
      setError(err.message || "Failed to authenticate. Please check your API key.");
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = (role: "admin" | "compliance_officer" | "auditor") => {
    saveSession({
      userId: `usr_demo_${role}`,
      email: `${role}@acme-corp.com`,
      role: role,
      orgId: "org_acme_enterprise",
      token: `airo_demo_key_${role}_2026`,
    });
    window.location.href = "/";
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-4 relative overflow-hidden">
      {/* Background glow accents */}
      <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-blue-600/10 blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 h-96 w-96 rounded-full bg-emerald-600/10 blur-3xl pointer-events-none" />

      <Card className="w-full max-w-md border-gray-800 bg-gray-900/90 shadow-2xl relative z-10">
        <CardHeader className="space-y-3 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-blue-600 shadow-lg shadow-blue-500/25">
            <ShieldAlert className="h-6 w-6 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold text-white">AIROM Enterprise</CardTitle>
          <CardDescription className="text-gray-400">
            Sign in to access your organization's statutory AI compliance ledger and governance cockpit.
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleLogin}>
          <CardContent className="space-y-4">
            {error && (
              <div className="rounded-lg border border-red-800/50 bg-red-950/40 p-3 text-xs text-red-300">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-gray-300">
                API Key or SSO Bearer Token
              </label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
                <input
                  type="password"
                  placeholder="airo_live_..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 py-2 pl-9 pr-4 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>

            <Button type="submit" disabled={loading} className="w-full gap-2">
              {loading ? "Authenticating..." : "Sign In to Gateway"}
              <ArrowRight className="h-4 w-4" />
            </Button>
          </CardContent>
        </form>

        <CardFooter className="flex flex-col space-y-3 border-t border-gray-800/80 pt-4 text-center">
          <div className="flex items-center justify-center gap-1.5 text-xs text-gray-400">
            <Sparkles className="h-3.5 w-3.5 text-blue-400" />
            <span>Quick Demo Role Sign-in:</span>
          </div>
          <div className="grid grid-cols-3 gap-2 w-full">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleDemoLogin("compliance_officer")}
              className="text-xs"
            >
              Legal/Officer
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleDemoLogin("admin")}
              className="text-xs"
            >
              Admin
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleDemoLogin("auditor")}
              className="text-xs"
            >
              Auditor
            </Button>
          </div>
        </CardFooter>
      </Card>
    </div>
  );
}
