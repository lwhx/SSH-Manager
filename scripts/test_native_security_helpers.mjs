import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {SIGNER_RECOVERY_FLAG,EMPTY_STAGING_SQL,validateEmptyStagingQuery,verifyWorkerTargets,
 DELETED_WORKER_RECOVERY_FLAG,DELETED_WORKER_RECOVERY_SQL,validateDeletedWorkerStagingQuery,
 UNRESOLVED_OPERATION_PREFLIGHT_SQL,validateUnresolvedOperationPreflight,
 buildUnresolvedOperationPreflightArgs} from "./native_security_helpers.mjs";
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

test("deleted Worker recovery retains unpaired nodes but blocks all active or historical identities",()=>{
 assert.equal(DELETED_WORKER_RECOVERY_FLAG,"CONFIRM_UNPAIRED_STAGING_WORKER_RECREATE");
 assert.match(DELETED_WORKER_RECOVERY_SQL,/status!='unpaired'/);
 assert.match(DELETED_WORKER_RECOVERY_SQL,/FROM node_ssh_proof_keys/);
 assert.match(DELETED_WORKER_RECOVERY_SQL,/active_pair_tokens/);
 assert.doesNotMatch(DELETED_WORKER_RECOVERY_SQL,/\bDELETE\b|\bUPDATE\b|\bDROP\b/i);
 const columns=["total_nodes","non_unpaired_nodes","paired_agents","used_pair_tokens",
  "active_pair_tokens","device_nonces","operations","node_keys","verifications","snapshots","proof_keys"];
 const good=()=>[{success:true,results:[Object.fromEntries(columns.map(key=>[key,0]))]}];
 const unpaired=good();unpaired[0].results[0].total_nodes=3;
 assert.deepEqual(validateDeletedWorkerStagingQuery(unpaired),{totalNodes:3});
 for(const key of columns.slice(1)){
  const bad=good();bad[0].results[0][key]=1;
  assert.throws(()=>validateDeletedWorkerStagingQuery(bad),new RegExp(key));
 }
 for(const key of columns){
  const missing=good();delete missing[0].results[0][key];
  assert.throws(()=>validateDeletedWorkerStagingQuery(missing));
 }
 assert.throws(()=>validateDeletedWorkerStagingQuery([{success:false,results:[]}]));
 const negative=good();negative[0].results[0].total_nodes=-1;
 assert.throws(()=>validateDeletedWorkerStagingQuery(negative));
});


test("existing Staging D1 requires a read-only single-flight check before migration",()=>{
 assert.match(UNRESOLVED_OPERATION_PREFLIGHT_SQL,/FROM operations/);
 assert.match(UNRESOLVED_OPERATION_PREFLIGHT_SQL,/HAVING COUNT\(\*\)\s*>\s*1/);
 assert.match(UNRESOLVED_OPERATION_PREFLIGHT_SQL,/status IN \('CREATED','DISPATCHED','RUNNING'\)/);
 assert.doesNotMatch(UNRESOLVED_OPERATION_PREFLIGHT_SQL,/\b(?:DELETE|UPDATE|INSERT|ALTER|DROP|REPLACE|PRAGMA)\b/i);
 assert.equal(validateUnresolvedOperationPreflight([{success:true,results:[]}]),true);
 for(const bad of [
  [{success:false,results:[]}],
  [{success:true,results:[{node_id:"test",unresolved_count:2}]}],
  [{success:true,results:[{node_id:"test",unresolved_count:1}]}],
  [{success:true,results:null}],
  [{success:true}],
  [],
  [{success:true,results:[]},{success:true,results:[]}]
 ]){
  assert.throws(()=>validateUnresolvedOperationPreflight(bad),/Staging D1/i);
 }
 const script=readFileSync(new URL("./cloudflare_native_deploy.mjs",import.meta.url),"utf8");
 const begin=script.indexOf("async function update("),end=script.indexOf("async function main(",begin);
 assert(begin>=0&&end>begin,"Could not locate existing Worker update");
 const updateRoutine=script.slice(begin,end);
 const check=updateRoutine.indexOf("assertNoDuplicateUnresolvedOperations();");
 const migrate=updateRoutine.indexOf("migrate();");
 assert(check>=0&&migrate>check,"Staging migration must be preceded by read-only D1 operation preflight");
});

test("all read-only recovery gates target the actual Staging D1 database",()=>{
 const config="/repo/wrangler.single.staging.native.jsonc";
 const queries=[EMPTY_STAGING_SQL,DELETED_WORKER_RECOVERY_SQL,UNRESOLVED_OPERATION_PREFLIGHT_SQL];
 for(const sql of queries){
  assert.deepEqual(buildUnresolvedOperationPreflightArgs("ssh-manager-staging",config,sql),[
   "d1","execute","ssh-manager-staging","--remote","--json",
   "--config",config,"--command",sql
  ]);
 }
});

test("Staging D1 preflight executes against the configured database name, not the binding label",()=>{
 const config="/repo/wrangler.single.staging.native.jsonc";
 assert.deepEqual(buildUnresolvedOperationPreflightArgs("ssh-manager-staging",config),[
  "d1","execute","ssh-manager-staging","--remote","--json",
  "--config",config,"--command",UNRESOLVED_OPERATION_PREFLIGHT_SQL
 ]);
});
