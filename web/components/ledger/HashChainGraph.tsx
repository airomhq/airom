"use client";

import React, { useState } from "react";
import { Lock, ArrowRight, ShieldCheck, AlertOctagon, Info } from "lucide-react";
import { ScanSnapshot } from "../../types";
import { BlockDetailsModal } from "./BlockDetailsModal";

interface HashChainGraphProps {
  snapshots: ScanSnapshot[];
}

export const HashChainGraph: React.FC<HashChainGraphProps> = ({ snapshots }) => {
  const [selectedSnapshot, setSelectedSnapshot] = useState<ScanSnapshot | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);

  if (!snapshots || snapshots.length === 0) {
    return (
      <div className="flex h-40 items-center justify-center text-gray-500 text-xs">
        No state ledger snapshots found for this repository.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Visual Chain Nodes */}
      <div className="flex items-center gap-4 overflow-x-auto pb-4 pt-2">
        {snapshots.map((snap, index) => {
          const isGenesis = index === 0;
          const isTip = index === snapshots.length - 1;

          return (
            <React.Fragment key={snap.scanId}>
              {/* Block Node Card */}
              <button
                type="button"
                onClick={() => {
                  setSelectedSnapshot(snap);
                  setSelectedIndex(index);
                }}
                className="group relative flex min-w-[220px] flex-col rounded-xl border border-gray-800 bg-gray-950 p-4 text-left font-mono transition-all hover:border-emerald-500/50 hover:shadow-lg hover:shadow-emerald-500/10 focus:outline-none"
              >
                <div className="flex items-center justify-between pb-2 border-b border-gray-800/80">
                  <span className="text-xs font-bold text-white group-hover:text-emerald-400">
                    Block #{index + 1}
                  </span>
                  <span className="text-[10px] text-gray-500">
                    {isGenesis ? "GENESIS" : isTip ? "HEAD TIP" : "BLOCK"}
                  </span>
                </div>

                <div className="mt-2.5 space-y-1.5 text-[11px]">
                  <div>
                    <span className="text-gray-500 text-[10px] block">Self Hash:</span>
                    <span className="text-emerald-400 font-bold">{snap.selfHash.slice(0, 14)}...</span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Prev Link:</span>
                    <span className="text-blue-400">{snap.prevHash ? `${snap.prevHash.slice(0, 14)}...` : "(Genesis)"}</span>
                  </div>
                </div>

                <div className="mt-3 flex items-center justify-between border-t border-gray-800/80 pt-2 text-[10px]">
                  <span className="text-gray-300">{snap.componentsCount} components</span>
                  <span className="text-emerald-400 font-semibold">{snap.metCount} met</span>
                  {snap.gapCount > 0 && <span className="text-red-400 font-semibold">{snap.gapCount} gap</span>}
                </div>
              </button>

              {/* Arrow Connector */}
              {!isTip && (
                <div className="flex items-center text-gray-600">
                  <ArrowRight className="h-5 w-5 shrink-0" />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Modal Inspector */}
      {selectedSnapshot && (
        <BlockDetailsModal
          snapshot={selectedSnapshot}
          index={selectedIndex}
          onClose={() => setSelectedSnapshot(null)}
        />
      )}
    </div>
  );
};
