import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import {getDraftRelease} from "./draft-release.mjs";
import {validateBundle} from "./validate-bundle.mjs";
const repository="Ilanchemla/drasc-updates";
assert.equal(process.env.GITHUB_REPOSITORY,repository);
const approval=JSON.parse(fs.readFileSync(new URL("./candidate-039.json",import.meta.url)));
async function request(route,binary=false){
  const response=await fetch(`https://api.github.com/repos/${repository}/${route}`,{
    headers:{Authorization:`Bearer ${process.env.GITHUB_TOKEN}`,Accept:binary?"application/octet-stream":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"},
    signal:AbortSignal.timeout(60000)
  });
  if(!response.ok)throw Error(`Read-only draft check ${route.split("/")[0]} HTTP ${response.status}`);
  return binary?Buffer.from(await response.arrayBuffer()):response.json();
}
const release=await getDraftRelease(request,418575808,"candidate-0.1.39-1aede12f3b9b");
const checked=[];
for(const mode of ["android","ios"]){
  const assets=release.assets.filter(x=>x.name===`drasc-${mode}.zip`);
  assert.equal(assets.length,1);
  const bytes=await request(`releases/assets/${assets[0].id}`,true);
  validateBundle(bytes,mode,approval);
  checked.push({platform:mode,sha256:crypto.createHash("sha256").update(bytes).digest("hex")});
}
console.log(JSON.stringify({draftReadWithReadOnlyToken:true,releaseId:release.id,checked,signingKeyUsed:false,published:false}));
