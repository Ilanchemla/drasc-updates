import test from "node:test";
import assert from "node:assert/strict";
import {
  runtimeIsApproved,
  validateCurrentChannel,
} from "./validate-bundle.mjs";

const android = "a".repeat(64),
  ios = "b".repeat(64),
  testIphone = "c".repeat(64);
const original = { runtimes: { android, ios } };
test("existing native channels retain their exact runtime selection", () => {
  assert(runtimeIsApproved(original, "android", android));
  assert(runtimeIsApproved(original, "ios", ios));
  assert.equal(runtimeIsApproved(original, "ios", testIphone), false);
  assert.equal(runtimeIsApproved(original, "android", ios), false);
});
test("an explicitly validated test iPhone can coexist with the original iPhone", () => {
  const config = { ...original, additionalRuntimes: { ios: [testIphone] } };
  assert(runtimeIsApproved(config, "ios", testIphone));
  assert(runtimeIsApproved(config, "ios", ios));
  assert(runtimeIsApproved(config, "android", android));
  assert.equal(runtimeIsApproved(config, "android", testIphone), false);
  assert.equal(runtimeIsApproved(config, "ios", "d".repeat(64)), false);
});
test("wildcards, malformed additional profiles and unknown platforms never authorize a runtime", () => {
  for (const extra of ["*", ["*"], ["c"], [testIphone, "*"]])
    assert.equal(
      runtimeIsApproved(
        { ...original, additionalRuntimes: { ios: extra } },
        "ios",
        testIphone,
      ),
      false,
    );
  assert.equal(runtimeIsApproved(original, "web", ios), false);
  assert.equal(runtimeIsApproved(original, "ios", ""), false);
});

test("a first test iPhone channel still needs an explicitly approved absent-channel bootstrap", () => {
  const approval = {
    version: "0.1.75",
    commit: "d".repeat(40),
    sourceSha256: "e".repeat(64),
    platforms: ["ios"],
    ios: {
      runtime: testIphone,
      sha256: "f".repeat(64),
      previousChecksum: "0".repeat(64),
    },
  };
  assert.equal(
    validateCurrentChannel(null, "ios", approval, "unused", {
      allowBootstrap: true,
    }),
    "bootstrap",
  );
  assert.throws(() => validateCurrentChannel(null, "ios", approval, "unused"));
  assert.throws(() =>
    validateCurrentChannel(
      null,
      "ios",
      {
        ...approval,
        ios: { ...approval.ios, previousChecksum: "1".repeat(64) },
      },
      "unused",
      { allowBootstrap: true },
    ),
  );
});
