import test from "node:test";
import assert from "node:assert";
import { computeSnapshotHash, verifyLedgerIntegrity } from "../crypto.js";

test("computeSnapshotHash generates deterministic SHA-256", async () => {
  const hash1 = await computeSnapshotHash("scan-01", "2026-08-22T10:00:00Z", "aibom_123", "controls_456", "");
  const hash2 = await computeSnapshotHash("scan-01", "2026-08-22T10:00:00Z", "aibom_123", "controls_456", "");
  assert.strictEqual(hash1, hash2);
  assert.strictEqual(hash1.length, 64);
});

test("verifyLedgerIntegrity validates unbroken 3-block chain", async () => {
  const snap1 = {
    scanId: "s1",
    repoId: "acme/test",
    timestamp: "2026-08-22T10:00:00Z",
    aibomHash: "a1",
    controlsHash: "c1",
    prevHash: "",
    selfHash: "",
    componentsCount: 5,
    metCount: 2,
    gapCount: 0,
    manualCount: 1,
  };
  snap1.selfHash = await computeSnapshotHash(snap1.scanId, snap1.timestamp, snap1.aibomHash, snap1.controlsHash, snap1.prevHash);

  const snap2 = {
    scanId: "s2",
    repoId: "acme/test",
    timestamp: "2026-08-22T11:00:00Z",
    aibomHash: "a2",
    controlsHash: "c2",
    prevHash: snap1.selfHash,
    selfHash: "",
    componentsCount: 6,
    metCount: 3,
    gapCount: 0,
    manualCount: 1,
  };
  snap2.selfHash = await computeSnapshotHash(snap2.scanId, snap2.timestamp, snap2.aibomHash, snap2.controlsHash, snap2.prevHash);

  const result = await verifyLedgerIntegrity([snap1, snap2]);
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.totalSnapshots, 2);
});

test("verifyLedgerIntegrity detects tampered block", async () => {
  const snap1 = {
    scanId: "s1",
    repoId: "acme/test",
    timestamp: "2026-08-22T10:00:00Z",
    aibomHash: "a1",
    controlsHash: "c1",
    prevHash: "",
    selfHash: "forged_invalid_hash_12345678901234567890123456789012345678901234567890",
    componentsCount: 5,
    metCount: 2,
    gapCount: 0,
    manualCount: 1,
  };

  const result = await verifyLedgerIntegrity([snap1]);
  assert.strictEqual(result.isValid, false);
  assert.strictEqual(result.brokenAtIndex, 0);
});
