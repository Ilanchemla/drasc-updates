import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify, sign } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import {
  validateApproval,
  inspectZip,
  validateBundle,
  validateCurrentChannel,
  signBundle,
  digest,
} from "./validate-bundle.mjs";
function zipSync(files) {
  const local = [],
    central = [];
  let offset = 0;
  for (const [name, data] of Object.entries(files)) {
    const filename = Buffer.from(name),
      compressed = deflateRawSync(data);
    let crc = 0xffffffff;
    for (const byte of data) {
      crc ^= byte;
      for (let i = 0; i < 8; i++)
        crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(8, 8);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(compressed.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(filename.length, 26);
    local.push(header, filename, compressed);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(8, 10);
    record.writeUInt32LE(crc, 16);
    record.writeUInt32LE(compressed.length, 20);
    record.writeUInt32LE(data.length, 24);
    record.writeUInt16LE(filename.length, 28);
    record.writeUInt32LE(offset, 42);
    central.push(record, filename);
    offset += header.length + filename.length + compressed.length;
  }
  const directory = Buffer.concat(central),
    end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}
const build = {
  version: "0.1.39",
  gitCommit: "a".repeat(40),
  sourceSha256: "b".repeat(64),
  mode: "android",
  nativeRuntime: "c".repeat(64),
};
const pack = (files) =>
  Buffer.from(
    zipSync(
      Object.fromEntries(
        Object.entries(files).map(([key, value]) => [key, Buffer.from(value)]),
      ),
    ),
  );
const bytes = pack({
  "index.html": "<html>fixture</html>",
  "drasc-build.json": JSON.stringify(build),
  "assets/app.js": "throw Error('never execute')",
});
const approval = {
  version: build.version,
  commit: build.gitCommit,
  sourceSha256: build.sourceSha256,
  android: {
    sha256: digest(bytes),
    runtime: build.nativeRuntime,
    previousChecksum: "f".repeat(64),
  },
  ios: {
    sha256: "d".repeat(64),
    runtime: "e".repeat(64),
    previousChecksum: "f".repeat(64),
  },
};
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" });
test("accepted bundle is inspected as data, never executed", () => {
  assert.deepEqual(inspectZip(bytes).build, build);
  assert.equal(validateBundle(bytes, "android", approval).fileCount, 3);
});
test("an altered byte is rejected before signing", () => {
  const altered = Buffer.from(bytes);
  altered[45] ^= 1;
  assert.throws(
    () => signBundle(altered, "android", approval, keys.privateKey, publicKey),
    /approved hash/,
  );
});
test("version, source, commit and native runtime must all match approval", () => {
  for (const key of [
    "version",
    "gitCommit",
    "sourceSha256",
    "nativeRuntime",
    "mode",
  ]) {
    const altered = pack({
      "index.html": "fixture",
      "drasc-build.json": JSON.stringify({ ...build, [key]: "unexpected" }),
    });
    const withDigest = {
      ...approval,
      android: { ...approval.android, sha256: digest(altered) },
    };
    assert.throws(
      () => validateBundle(altered, "android", withDigest),
      /identity/,
    );
  }
});
test("traversal, absolute, ambiguous and executable symlink paths are rejected", () => {
  for (const name of [
    "../escape",
    "/absolute",
    "dir/../escape",
    "C:/drive",
    "dir\\escape",
    "bad\u0000name",
  ]) {
    assert.throws(
      () =>
        inspectZip(
          pack({
            "index.html": "x",
            "drasc-build.json": JSON.stringify(build),
            [name]: "data",
          }),
        ),
      /ZIP path/,
    );
  }
  const altered = Buffer.from(bytes);
  const central = altered.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  altered.writeUInt32LE((0xa000 << 16) >>> 0, central + 38);
  assert.throws(() => inspectZip(altered), /Unsafe ZIP record/);
});
test("truncated archives and oversized descriptors are rejected", () => {
  assert.throws(
    () => inspectZip(bytes.subarray(0, bytes.length - 1)),
    /ZIP directory/,
  );
  const large = pack({
    "index.html": "x",
    "drasc-build.json": JSON.stringify({
      ...build,
      padding: "x".repeat(20000),
    }),
  });
  assert.throws(() => inspectZip(large), /descriptor too large/);
});
test("incorrect installed signing key is rejected", () => {
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.throws(
    () => signBundle(bytes, "android", approval, other.privateKey, publicKey),
    /Signing key differs/,
  );
});
test("signed payload and ZIP independently verify against the installed key", () => {
  const envelope = signBundle(
    bytes,
    "android",
    approval,
    keys.privateKey,
    publicKey,
  );
  const manifest = JSON.parse(envelope.payload);
  assert.equal(
    verify(
      "sha256",
      Buffer.from(envelope.payload),
      keys.publicKey,
      Buffer.from(envelope.signature, "base64"),
    ),
    true,
  );
  assert.equal(
    verify(
      "sha256",
      bytes,
      keys.publicKey,
      Buffer.from(manifest.signature, "base64"),
    ),
    true,
  );
  assert.equal(manifest.checksum, digest(bytes));
  assert.equal(
    manifest.url,
    `https://github.com/Ilanchemla/drasc-updates/releases/download/ota-${digest(bytes)}/drasc-android.zip`,
  );
});
test("partial or shell-shaped approvals cannot enter the publisher", () => {
  for (const value of [
    null,
    {},
    { ...approval, commit: "a; command" },
    { ...approval, version: "0.1.39\nx" },
    { ...approval, version: "0.1.39\n" },
    { ...approval, ios: null },
  ]) {
    assert.throws(() => validateApproval(value));
  }
});
test("current channel must be signed, unchanged, and older than the approved release", () => {
  const current = {
    platform: "android",
    runtime: build.nativeRuntime,
    version: "0.1.38",
    checksum: approval.android.previousChecksum,
  };
  const envelope = (value) => {
    const payload = JSON.stringify(value);
    return {
      payload,
      signature: sign("sha256", Buffer.from(payload), keys.privateKey).toString(
        "base64",
      ),
    };
  };
  assert.equal(
    validateCurrentChannel(envelope(current), "android", approval, publicKey),
    "publish",
  );
  assert.throws(
    () =>
      validateCurrentChannel(
        { ...envelope(current), payload: "{}" },
        "android",
        approval,
        publicKey,
      ),
    /signature/,
  );
  assert.throws(
    () =>
      validateCurrentChannel(
        envelope({ ...current, checksum: "0".repeat(64) }),
        "android",
        approval,
        publicKey,
      ),
    /changed/,
  );
  for (const version of ["0.1.39", "0.1.40", "1.0.0"])
    assert.throws(
      () =>
        validateCurrentChannel(
          envelope({ ...current, version }),
          "android",
          approval,
          publicKey,
        ),
      /rollback/,
    );
  const published = {
    ...current,
    version: approval.version,
    checksum: approval.android.sha256,
    commit: approval.commit,
    sourceSha256: approval.sourceSha256,
  };
  assert.equal(
    validateCurrentChannel(envelope(published), "android", approval, publicKey),
    "already-published",
  );
});
