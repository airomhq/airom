"use client";

import React, { useEffect, useState } from "react";
import { Flame, ShieldAlert, AlertTriangle, Radio, BellRing, ExternalLink } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { AnomalyEvent } from "../../types";

export const AnomalyLiveFeed: React.FC = () => {
  const [events, setEvents] = useState<AnomalyEvent[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    // Connect to backend SSE endpoint
    const eventSource = new EventSource("/api/v1/events/stream");

    eventSource.onopen = () => {
      setConnected(true);
    };

    eventSource.addEventListener("anomaly_detected", (e: MessageEvent) => {
      try {
        const rawData = JSON.parse(e.data);
        const newEvent: AnomalyEvent = {
          id: `ev_${Date.now()}`,
          repoId: rawData.repo || "acme/repo",
          repoName: rawData.repo || "acme/repo",
          type: rawData.type || "shadow-ai",
          severity: rawData.severity || "HIGH",
          componentName: rawData.component || "unapproved-ai-asset",
          location: rawData.file || "src/app.py:1",
          details: rawData.details || "Discovered new AI asset violating active .airomapproved policy.",
          timestamp: new Date().toLocaleTimeString(),
        };

        setEvents((prev) => [newEvent, ...prev.slice(0, 19)]);
      } catch (err) {
        console.error("Failed to parse SSE event payload:", err);
      }
    });

    eventSource.onerror = () => {
      setConnected(false);
    };

    return () => {
      eventSource.close();
    };
  }, []);

  return (
    <Card className="border-gray-800 bg-gray-900/60">
      <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-gray-800/80">
        <div className="flex items-center gap-2">
          <Flame className="h-5 w-5 text-red-400 animate-pulse" />
          <CardTitle className="text-sm font-bold text-white">Live Anomaly & Shadow AI Stream</CardTitle>
        </div>
        <div className="flex items-center gap-2">
          <Badge
            variant={connected ? "met" : "gap"}
            className="gap-1.5 font-mono text-[10px]"
          >
            <Radio className={`h-3 w-3 ${connected ? "animate-pulse text-emerald-400" : "text-red-400"}`} />
            {connected ? "LIVE SSE CONNECTED" : "RECONNECTING"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 p-4">
        {events.length === 0 ? (
          <div className="flex h-32 flex-col items-center justify-center text-center text-gray-500 text-xs">
            <BellRing className="h-6 w-6 text-gray-600 mb-2" />
            <p>Listening for real-time anomalies across all active repository scans...</p>
          </div>
        ) : (
          events.map((anom) => (
            <div
              key={anom.id}
              className="flex flex-col gap-2 rounded-lg border border-red-900/40 bg-red-950/20 p-3.5 sm:flex-row sm:items-center sm:justify-between text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="gap">{anom.type.toUpperCase()}</Badge>
                  <span className="font-mono font-bold text-red-300">{anom.componentName}</span>
                  <span className="text-gray-500">in {anom.repoName}</span>
                </div>
                <p className="text-gray-300">{anom.details}</p>
                <div className="text-[11px] font-mono text-gray-500">{anom.location}</div>
              </div>
              <span className="text-[11px] font-mono text-gray-400 shrink-0">{anom.timestamp}</span>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
};
