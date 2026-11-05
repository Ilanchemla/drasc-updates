import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  approvalPlatforms,
  validateApproval,
  validateCurrentChannel,
} from "./validate-bundle.mjs";

const runtime = "a".repeat(64);
const approval = {
  version: "0.1.70",
  commit: "b".repeat(40),
  sourceSha256: "c".repeat(64),
  platforms: ["android"],
  android: {
    sha256: "d".repeat(64),
    runtime,
    previousChecksum: "0".repeat(64),
  },
};
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" });
const envelope = () => {
  const payload = JSON.stringify({
    platform: "android",
    runtime,
    checksum: "e".repeat(64),
    version: "0.1.69",
  });
  return {
    payload,
    signature: sign("sha256", Buffer.from(payload), keys.privateKey).toString(
      "base64",
    ),
  };
};

test("Android-only approval needs no iPhone payload and cannot approve iPhone", () => {
  assert.equal(validateApproval(approval), approval);
  assert.deepEqual(approvalPlatforms(approval), ["android"]);
  assert.throws(
    () =>
      validateCurrentChannel(null, "ios", approval, publicKey, {
        allowBootstrap: true,
      }),
    /not approved/,
  );
  for (const platforms of [
    [],
    ["other"],
    ["android", "android"],
    "android",
    ["android", "ios", "other"],
  ])
    assert.throws(
      () => validateApproval({ ...approval, platforms }),
      /platforms/,
    );
});

test("a missing channel is created only by explicit native-profile approval and the zero previous checksum", () => {
  assert.equal(
    validateCurrentChannel(null, "android", approval, publicKey, {
      allowBootstrap: true,
    }),
    "bootstrap",
  );
  assert.throws(() =>
    validateCurrentChannel(null, "android", approval, publicKey),
  );
  assert.throws(() =>
    validateCurrentChannel(
      null,
      "android",
      {
        ...approval,
        android: { ...approval.android, previousChecksum: "f".repeat(64) },
      },
      publicKey,
      { allowBootstrap: true },
    ),
  );
});

test("bootstrap never replaces an existing signed channel or bypasses its signature", () => {
  assert.throws(
    () =>
      validateCurrentChannel(envelope(), "android", approval, publicKey, {
        allowBootstrap: true,
      }),
    /changed since approval/,
  );
  const signed = envelope();
  signed.signature = "invalid";
  assert.throws(
    () =>
      validateCurrentChannel(signed, "android", approval, publicKey, {
        allowBootstrap: true,
      }),
    /signature invalid/,
  );
  const next = {
    ...approval,
    android: { ...approval.android, previousChecksum: "e".repeat(64) },
  };
  assert.equal(
    validateCurrentChannel(envelope(), "android", next, publicKey, {
      allowBootstrap: true,
    }),
    "publish",
  );
});
