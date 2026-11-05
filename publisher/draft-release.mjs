export async function getDraftRelease(request, releaseId, expectedTag) {
  if (releaseId === "auto") {
    if (!/^candidate-0\.\d+\.\d+-[a-f0-9]{12}$/.test(expectedTag || ""))
      throw Error("Exact candidate tag required");
    // Authenticated push access is required for draft listings. Never use the
    // published-only tag endpoint or inspect application/session credentials.
    const recent = await request("releases?per_page=100");
    const matches = Array.isArray(recent)
      ? recent.filter((r) => r.tag_name === expectedTag && r.draft === true)
      : [];
    if (matches.length !== 1)
      throw Error("A unique recent draft matching approval is required");
    releaseId = String(matches[0].id);
  }
  if (!/^[1-9][0-9]{0,14}$/.test(String(releaseId || "")))
    throw Error("A numeric staging release ID is required");
  const release = await request(`releases/${releaseId}`);
  if (
    !release ||
    String(release.id) !== String(releaseId) ||
    release.tag_name !== expectedTag ||
    release.draft !== true ||
    !Array.isArray(release.assets)
  )
    throw Error("Staging release identity differs from approval");
  return release;
}
