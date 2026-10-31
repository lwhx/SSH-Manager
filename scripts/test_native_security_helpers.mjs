import test from "node:test";
import assert from "node:assert/strict";
import {SIGNER_RECOVERY_FLAG,EMPTY_STAGING_SQL,validateEmptyStagingQuery,verifyWorkerTargets} from "./native_security_helpers.mjs";
const columns=["nodes","operations","paired_agents","pairing_tokens","device_nonces","node_keys","verifications","snapshots"];
const empty=()=>[{success:true,results:[Object.fromEntries(columns.map(k=>[k,0]))]}];
test("empty D1 identity tables permit one-time signer recovery only with complete verification",()=>{
 assert.equal(SIGNER_RECOVERY_FLAG,"CONFIRM_EMPTY_STAGING_SIGNER_REPAIR");
 assert.equal(validateEmptyStagingQuery(empty()),true);
 assert.match(EMPTY_STAGING_SQL,/FROM agent_credentials/);
 for(const col of columns){
  const result=empty();result[0].results[0][col]=1;
  assert.throws(()=>validateEmptyStagingQuery(result),new RegExp(col));
 }
 assert.throws(()=>validateEmptyStagingQuery([{success:false,results:[]}]));
 assert.throws(()=>validateEmptyStagingQuery([{success:true,results:[{nodes:0}]}]));
});
test("actual target Worker must match D1, public key and SSH safety lock before signer upload",()=>{
 const cfg={bindings:[
  {name:"DB",type:"d1",database_id:"00000000-0000-4000-8000-000000000001"},
  {name:"COMMAND_PUBLIC_KEY",type:"plain_text",text:"a".repeat(43)},
  {name:"MANUAL_SSH_ACTIONS_ENABLED",type:"plain_text",text:"false"},
  {name:"NODE_SESSIONS",type:"durable_object_namespace",class_name:"NodeSession"},
  {name:"COMMAND_PRIVATE_KEY",type:"secret_text"}
 ]};
 const requirements={publicKey:"a".repeat(43),databaseId:"00000000-0000-4000-8000-000000000001",requireSigner:true};
 assert.equal(verifyWorkerTargets(cfg,requirements),true);
 for(const fn of [
  x=>x.bindings[0].database_id="11111111-0000-4000-8000-000000000001",
  x=>x.bindings[1].text="b".repeat(43),
  x=>x.bindings[2].text="true",
  x=>x.bindings[3].script_name="old-gateway",
  x=>x.bindings.pop()
 ]){
  const bad=structuredClone(cfg);fn(bad);
  assert.throws(()=>verifyWorkerTargets(bad,requirements));
 }
});
