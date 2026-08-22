import { ScanSnapshot } from "../types";

/**
 * Computes the SHA-256 hash string for a given text payload using WebCrypto (browser) or Node crypto.
 */
export async function sha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Fallback for Node.js test environment
  const { createHash } = await import("crypto");
  return createHash("sha256").update(text).digest("hex");
}

/**
 * Computes snapshot hash following ComplianceDB invariant:
 * self_hash = SHA256(scan_id | timestamp | aibom_hash | controls_hash | prev_hash)
 */
export async function computeSnapshotHash(
  scanId: string,
  timestamp: string,
  aibomHash: string,
  controlsHash: string,
  prevHash: string
): Promise<string> {
  const payload = `${scanId}|${timestamp}|${aibomHash}|${controlsHash}|${prevHash}`;
  return sha256(payload);
}

export interface LedgerVerificationResult {
  isValid: boolean;
  totalSnapshots: number;
  brokenAtIndex?: number;
  expectedHash?: string;
  actualHash?: string;
  errorMessage?: string;
}

/**
 * Iterates through a sequential chain of snapshots and validates unbroken cryptographic link.
 */
export async function verifyLedgerIntegrity(
  snapshots: ScanSnapshot[]
): Promise<LedgerVerificationResult> {
  if (!snapshots || snapshots.length === 0) {
    return { isValid: true, totalSnapshots: 0 };
  }

  let expectedPrevHash = "";

  for (let i = 0; i < snapshots.length; i++) {
    const s = snapshots[i];

    // Verify parent link
    if (i > 0 && s.prevHash !== expectedPrevHash) {
      return {
        isValid: false,
        totalSnapshots: snapshots.length,
        brokenAtIndex: i,
        expectedHash: expectedPrevHash,
        actualHash: s.prevHash,
        errorMessage: `Parent hash mismatch at block #${i}: Expected previous hash "${expectedPrevHash}", but found "${s.prevHash}".`,
      };
    }

    // Verify self-hash
    const computedSelfHash = await computeSnapshotHash(
      s.scanId,
      s.timestamp,
      s.aibomHash,
      s.controlsHash,
      s.prevHash
    );

    if (computedSelfHash !== s.selfHash) {
      return {
        isValid: false,
        totalSnapshots: snapshots.length,
        brokenAtIndex: i,
        expectedHash: computedSelfHash,
        actualHash: s.selfHash,
        errorMessage: `Tampered payload at block #${i}: Computed SHA-256 hash "${computedSelfHash}" does not match recorded block hash "${s.selfHash}".`,
      };
    }

    expectedPrevHash = s.selfHash;
  }

  return {
    isValid: true,
    totalSnapshots: snapshots.length,
  };
}
