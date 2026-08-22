import { createHash } from "crypto";

export async function sha256(text) {
  return createHash("sha256").update(text).digest("hex");
}

export async function computeSnapshotHash(scanId, timestamp, aibomHash, controlsHash, prevHash) {
  const payload = `${scanId}|${timestamp}|${aibomHash}|${controlsHash}|${prevHash}`;
  return sha256(payload);
}

export async function verifyLedgerIntegrity(snapshots) {
  if (!snapshots || snapshots.length === 0) {
    return { isValid: true, totalSnapshots: 0 };
  }

  let expectedPrevHash = "";

  for (let i = 0; i < snapshots.length; i++) {
    const s = snapshots[i];

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
