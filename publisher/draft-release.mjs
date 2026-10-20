export async function getDraftRelease(request, releaseId, expectedTag) {
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
