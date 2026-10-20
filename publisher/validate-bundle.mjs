import { createHash, createPublicKey, sign, verify } from "node:crypto";
import { inflateRawSync } from "node:zlib";
const maxZip = 100 * 1024 * 1024,
  maxExpanded = 180 * 1024 * 1024;
export const digest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export function validateApproval(value) {
  if (
    !value ||
    !/^0\.\d+\.\d+$/.test(value.version) ||
    !/^[0-9a-f]{40}$/.test(value.commit) ||
    !/^[0-9a-f]{64}$/.test(value.sourceSha256)
  )
    throw Error("Invalid approval identity");
  for (const mode of ["android", "ios"])
    if (
      !/^[0-9a-f]{64}$/.test(value[mode]?.sha256) ||
      !/^[0-9a-f]{64}$/.test(value[mode]?.runtime) ||
      !/^[0-9a-f]{64}$/.test(value[mode]?.previousChecksum)
    )
      throw Error(
        "Exact bundle hashes, runtimes and previous channels are required",
      );
  const fields = [
    value.version,
    value.commit,
    value.sourceSha256,
    ...["android", "ios"].flatMap((mode) => [
      value[mode].sha256,
      value[mode].runtime,
      value[mode].previousChecksum,
    ]),
  ];
  if (fields.some((field) => field.trim() !== field))
    throw Error("Whitespace in approval identity");
  return value;
}
export function validateCurrentChannel(envelope, mode, approval, publicKey) {
  validateApproval(approval);
  if (
    typeof envelope?.payload !== "string" ||
    typeof envelope.signature !== "string" ||
    !verify(
      "sha256",
      Buffer.from(envelope.payload),
      publicKey,
      Buffer.from(envelope.signature, "base64"),
    )
  )
    throw Error("Current channel signature invalid");
  const current = JSON.parse(envelope.payload);
  if (current.platform !== mode || current.runtime !== approval[mode].runtime)
    throw Error("Current channel platform mismatch");
  if (
    current.checksum === approval[mode].sha256 &&
    current.version === approval.version &&
    current.commit === approval.commit &&
    current.sourceSha256 === approval.sourceSha256
  )
    return "already-published";
  if (current.checksum !== approval[mode].previousChecksum)
    throw Error("Current channel changed since approval");
  const before = current.version?.split(".").map(Number),
    after = approval.version.split(".").map(Number);
  if (
    !before ||
    before.length !== 3 ||
    before.some((n) => !Number.isSafeInteger(n) || n < 0)
  )
    throw Error("Invalid current version");
  const first = after.findIndex((n, i) => n !== before[i]);
  if (first < 0 || after[first] < before[first])
    throw Error("Refusing a rollback or replacement of the same version");
  return "publish";
}
// Parse bounded ZIP metadata and the build descriptor, without extracting files
// or importing/running any code from the application bundle.
export function inspectZip(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 22 || bytes.length > maxZip)
    throw Error("Invalid ZIP size");
  let eocd = -1;
  for (let p = bytes.length - 22; p >= Math.max(0, bytes.length - 65557); p--)
    if (
      bytes.readUInt32LE(p) === 0x06054b50 &&
      p + 22 + bytes.readUInt16LE(p + 20) === bytes.length
    ) {
      eocd = p;
      break;
    }
  if (eocd < 0 || bytes.readUInt16LE(eocd + 4) || bytes.readUInt16LE(eocd + 6))
    throw Error("Split or missing ZIP directory");
  const count = bytes.readUInt16LE(eocd + 10),
    size = bytes.readUInt32LE(eocd + 12),
    start = bytes.readUInt32LE(eocd + 16);
  if (
    count < 2 ||
    count > 10000 ||
    count !== bytes.readUInt16LE(eocd + 8) ||
    start + size !== eocd
  )
    throw Error("Invalid ZIP directory");
  let p = start,
    total = 0,
    build;
  const names = new Set(),
    ranges = [];
  for (let i = 0; i < count; i++) {
    if (p + 46 > eocd || bytes.readUInt32LE(p) !== 0x02014b50)
      throw Error("Invalid ZIP record");
    const flags = bytes.readUInt16LE(p + 8),
      method = bytes.readUInt16LE(p + 10);
    const compressed = bytes.readUInt32LE(p + 20),
      expanded = bytes.readUInt32LE(p + 24);
    const nameLength = bytes.readUInt16LE(p + 28),
      extra = bytes.readUInt16LE(p + 30),
      comment = bytes.readUInt16LE(p + 32);
    const external = bytes.readUInt32LE(p + 38),
      local = bytes.readUInt32LE(p + 42);
    if (
      p + 46 + nameLength + extra + comment > eocd ||
      flags & 1 ||
      ![0, 8].includes(method) ||
      ((external >>> 16) & 0xf000) === 0xa000
    )
      throw Error("Unsafe ZIP record");
    const name = bytes.subarray(p + 46, p + 46 + nameLength).toString("utf8");
    if (
      !name ||
      name.startsWith("/") ||
      /[\x00-\x1f\\:]/.test(name) ||
      name.split("/").some((x) => x === ".." || x === ".") ||
      names.has(name)
    )
      throw Error("Unsafe or duplicate ZIP path");
    names.add(name);
    total += expanded;
    if (total > maxExpanded || expanded > 70 * 1024 * 1024)
      throw Error("ZIP expansion limit exceeded");
    if (local + 30 > start || bytes.readUInt32LE(local) !== 0x04034b50)
      throw Error("Invalid local ZIP header");
    const localNameLength = bytes.readUInt16LE(local + 26),
      localExtra = bytes.readUInt16LE(local + 28);
    const begin = local + 30 + localNameLength + localExtra,
      end = begin + compressed;
    if (
      end > start ||
      bytes.readUInt16LE(local + 6) !== flags ||
      bytes.readUInt16LE(local + 8) !== method ||
      bytes
        .subarray(local + 30, local + 30 + localNameLength)
        .toString("utf8") !== name
    )
      throw Error("ZIP header mismatch");
    if (ranges.some(([a, b]) => local < b && end > a))
      throw Error("Overlapping ZIP entries");
    ranges.push([local, end]);
    if (name === "drasc-build.json") {
      if (expanded > 16384) throw Error("Build descriptor too large");
      const data =
        method === 0
          ? bytes.subarray(begin, end)
          : inflateRawSync(bytes.subarray(begin, end), {
              maxOutputLength: 16384,
            });
      if (data.length !== expanded) throw Error("Invalid descriptor length");
      build = JSON.parse(data.toString("utf8"));
    }
    p += 46 + nameLength + extra + comment;
  }
  if (p !== eocd || !names.has("index.html") || !build)
    throw Error("Incomplete application ZIP");
  return { build, fileCount: names.size };
}
export function validateBundle(bytes, mode, approval) {
  validateApproval(approval);
  if (!["android", "ios"].includes(mode)) throw Error("Unknown platform");
  if (digest(bytes) !== approval[mode].sha256)
    throw Error("Bundle differs from approved hash");
  const { build, fileCount } = inspectZip(bytes);
  if (
    build.version !== approval.version ||
    build.gitCommit !== approval.commit ||
    build.sourceSha256 !== approval.sourceSha256 ||
    build.mode !== mode ||
    build.nativeRuntime !== approval[mode].runtime
  )
    throw Error("Build identity differs from approval");
  return { build, fileCount };
}
export function signBundle(bytes, mode, approval, privateKey, publicKey) {
  const validated = validateBundle(bytes, mode, approval);
  if (
    createPublicKey(privateKey).export({ type: "spki", format: "pem" }) !==
    publicKey
  )
    throw Error("Signing key differs from installed application");
  const checksum = digest(bytes),
    bundleId = `ota-${checksum}`;
  const signature = sign("sha256", bytes, privateKey).toString("base64");
  if (!verify("sha256", bytes, publicKey, Buffer.from(signature, "base64")))
    throw Error("Bundle signature verification failed");
  const payload = JSON.stringify({
    schema: 1,
    platform: mode,
    runtime: validated.build.nativeRuntime,
    version: approval.version,
    commit: approval.commit,
    sourceSha256: approval.sourceSha256,
    bundleId,
    checksum,
    signature,
    url: `https://github.com/Ilanchemla/drasc-updates/releases/download/${bundleId}/drasc-${mode}.zip`,
  });
  return {
    payload,
    signature: sign("sha256", Buffer.from(payload), privateKey).toString(
      "base64",
    ),
  };
}
