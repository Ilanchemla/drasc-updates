import test from "node:test";
import assert from "node:assert/strict";
import {getDraftRelease} from "./draft-release.mjs";
const tag="candidate-0.1.39-1aede12f3b9b";
const draft={id:418575808,tag_name:tag,draft:true,assets:[]};
test("a draft is retrieved by numeric release ID without the published-tag endpoint",async()=>{
  const routes=[];
  assert.deepEqual(await getDraftRelease(async route=>{routes.push(route);return draft;},418575808,tag),draft);
  assert.deepEqual(routes,["releases/418575808"]);
});
test("invalid release identifiers cannot select another endpoint",async()=>{
  for(const id of [null,"",0,-1,"12/../../secrets","1?query=1",1.5,"0".repeat(30)]){
    let called=false;
    await assert.rejects(getDraftRelease(async()=>{called=true;},id,tag),/numeric/);
    assert.equal(called,false);
  }
});
test("a different draft, tag, or published release is rejected",async()=>{
  for(const changed of [{id:1},{tag_name:"other"},{draft:false},{assets:null}]){
    await assert.rejects(getDraftRelease(async()=>({...draft,...changed}),draft.id,tag),/identity/);
  }
});
