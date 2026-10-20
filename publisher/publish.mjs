import fs from "node:fs";
import {
  validateApproval,
  validateBundle,
  validateCurrentChannel,
  signBundle,
  digest,
} from "./validate-bundle.mjs";
const repository = "Ilanchemla/drasc-updates";
const config = JSON.parse(
  fs.readFileSync(new URL("./installed-app.json", import.meta.url), "utf8"),
);
const approval = validateApproval(
  JSON.parse(process.env.APPROVAL_JSON || "null"),
);
const staging = process.env.STAGING_TAG;
if (
  !/^candidate-0\.\d+\.\d+-[a-f0-9]{12}$/.test(staging || "") ||
  staging !== `candidate-${approval.version}-${approval.commit.slice(0, 12)}`
)
  throw Error("Wrong staging release");
if (
  process.env.GITHUB_REPOSITORY !== repository ||
  process.env.GITHUB_REF !== "refs/heads/release-control"
)
  throw Error("Protected release-control branch required");
if (process.env.GITHUB_EVENT_NAME !== "workflow_dispatch")
  throw Error("Manual approval required");
for (const mode of ["android", "ios"])
  if (approval[mode].runtime !== config.runtimes[mode])
    throw Error("Native runtime change requires separate native validation");
const token = process.env.GITHUB_TOKEN;
if (!token) throw Error("Scoped publication token missing");
async function request(
  route,
  {
    method = "GET",
    body,
    binary = false,
    allowMissing = false,
    octets = false,
  } = {},
) {
  const origin = binary
    ? "https://uploads.github.com"
    : "https://api.github.com";
  const response = await fetch(`${origin}/repos/${repository}/${route}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: octets
        ? "application/octet-stream"
        : "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": binary ? "application/zip" : "application/json",
    },
    body: body === undefined ? undefined : binary ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(120000),
  });
  if (response.status === 404 && allowMissing) return null;
  if (!response.ok) throw Error(`GitHub publication HTTP ${response.status}`);
  if (octets) return Buffer.from(await response.arrayBuffer());
  return response.status === 204 ? null : response.json();
}
const release = await request(`releases/tags/${staging}`);
if (!release.draft) throw Error("Staging release must remain draft");
const bundles = {};
const channels = {};
for (const mode of ["android", "ios"]) {
  const matching = release.assets.filter((x) => x.name === `drasc-${mode}.zip`);
  if (matching.length !== 1 || matching[0].size > 100 * 1024 * 1024)
    throw Error("Staged bundle missing or too large");
  const bytes = await request(`releases/assets/${matching[0].id}`, {
    octets: true,
  });
  validateBundle(bytes, mode, approval);
  bundles[mode] = bytes;
  const channel = `${mode}/${approval[mode].runtime}/latest.json`;
  const current = await request(`contents/${channel}?ref=main`);
  const envelope = JSON.parse(
    Buffer.from(current.content, "base64").toString("utf8"),
  );
  const action = validateCurrentChannel(
    envelope,
    mode,
    approval,
    config.publicKey,
  );
  channels[mode] = { path: channel, sha: current.sha, action };
}
if (process.env.PUBLICATION_MODE === "verify") {
  const preflight = {
    approval,
    controlCommit: process.env.GITHUB_SHA,
    stagingTag: staging,
    channels,
    verified: true,
  };
  fs.writeFileSync(
    "preflight-proof.json",
    JSON.stringify(preflight, null, 2) + "\n",
  );
  if (process.env.GITHUB_STEP_SUMMARY)
    fs.appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `## Paquets vérifiés avant accès à la clé\n\nVersion : ${approval.version}\n\nCommit applicatif : \`${approval.commit}\`\n\nSources : \`${approval.sourceSha256}\`\n\nAndroid SHA-256 : \`${approval.android.sha256}\`\n\niPhone SHA-256 : \`${approval.ios.sha256}\`\n\nContrôle de signature : \`${process.env.GITHUB_SHA}\`\n`,
    );
  console.log(JSON.stringify(preflight));
  process.exit(0);
}
if (process.env.PUBLICATION_MODE !== "publish")
  throw Error("Explicit publication mode required");
// All artifacts are checked before signing. No npm, checkout of application
// sources, child process, or application module runs in this program.
const privateKey = process.env.DRASC_OTA_PRIVATE_KEY;
if (!privateKey) throw Error("Protected signing secret missing");
const envelopes = {};
for (const mode of ["android", "ios"])
  envelopes[mode] = signBundle(
    bundles[mode],
    mode,
    approval,
    privateKey,
    config.publicKey,
  );
const proof = {
  version: approval.version,
  commit: approval.commit,
  sourceSha256: approval.sourceSha256,
  controlCommit: process.env.GITHUB_SHA,
  platforms: [],
};
for (const mode of ["android", "ios"]) {
  const manifest = JSON.parse(envelopes[mode].payload),
    bytes = bundles[mode];
  let target = await request(`releases/tags/${manifest.bundleId}`, {
    allowMissing: true,
  });
  if (!target)
    target = await request("releases", {
      method: "POST",
      body: {
        tag_name: manifest.bundleId,
        target_commitish: "release-control",
        name: `Drasc ${mode} ${approval.version} — ${approval.commit.slice(0, 7)}`,
        body: `Paquet signé depuis la branche de publication protégée. Sources : ${approval.commit}. SHA-256 : ${digest(bytes)}.`,
        make_latest: "false",
      },
    });
  const existing = target.assets.find((x) => x.name === `drasc-${mode}.zip`);
  if (existing && existing.digest !== `sha256:${manifest.checksum}`)
    throw Error("Existing immutable bundle differs");
  if (!existing)
    await request(`releases/${target.id}/assets?name=drasc-${mode}.zip`, {
      method: "POST",
      body: bytes,
      binary: true,
    });
  const channel = channels[mode];
  if (channel.action !== "already-published")
    await request(`contents/${channel.path}`, {
      method: "PUT",
      body: {
        message: `Publish verified ${mode} OTA ${approval.version}`,
        content: Buffer.from(
          JSON.stringify(envelopes[mode], null, 2) + "\n",
        ).toString("base64"),
        branch: "main",
        sha: channel.sha,
      },
    });
  proof.platforms.push({
    mode,
    runtime: manifest.runtime,
    checksum: manifest.checksum,
    bundleId: manifest.bundleId,
    channel: channel.path,
  });
}
fs.writeFileSync(
  "publication-proof.json",
  JSON.stringify(proof, null, 2) + "\n",
);
console.log(JSON.stringify(proof));
