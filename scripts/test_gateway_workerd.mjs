// Staging contract: execute the real Agent Gateway Worker with local workerd
// and local-only D1. Never contacts remote Cloudflare or an actual VPS.
import {createHash, randomBytes, webcrypto} from "node:crypto";
import {spawn, execFileSync} from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import {fileURLToPath} from "node:url";

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const wrangler=path.join(root,"node_modules",".bin","wrangler");
const repoConfig=path.join(root,"wrangler.single.staging.example.jsonc");
const state=fs.mkdtempSync(path.join(os.tmpdir(),"ssh-manager-d1-ci-"));
const configFile=path.join(root,".staging-local-"+process.pid+".jsonc");
const seedFile=path.join(state,"seed.sql");
const host="http://127.0.0.1:8799";
const id={
 node:"10000000-0000-4000-8000-000000000001",
 actor:"20000000-0000-4000-8000-000000000001",
 key:"30000000-0000-4000-8000-000000000001",
 op:"40000000-0000-4000-8000-000000000001",
 verify:"50000000-0000-4000-8000-000000000001",
 op2:"60000000-0000-4000-8000-000000000001",
 verify2:"70000000-0000-4000-8000-000000000001",
 proof:"80000000-0000-4000-8000-000000000001",
 keyRow:"90000000-0000-4000-8000-000000000001",
 pairNode:"a0000000-0000-4000-8000-000000000001",
 pairToken:"b0000000-0000-4000-8000-000000000001",
};
const rev="a".repeat(64),nonceHash="b".repeat(64);
const fingerprint="SHA256:"+"A".repeat(43);
const t=Math.floor(Date.now()/1000);
const pairingToken="local-only-pairing-token-"+"x".repeat(24);
const pairingTokenHash=createHash("sha256").update(pairingToken).digest("hex");
const toURL=b=>Buffer.from(b).toString("base64url");
const q=s=>"'"+String(s).replaceAll("'","''")+"'";
let worker;
let workerLog="";
function cli(args){
 return execFileSync(wrangler,args,{cwd:root,encoding:"utf8",timeout:60000,
  maxBuffer:3*1024*1024,env:{...process.env,WRANGLER_SEND_METRICS:"false",CI:"true"}});
}
function d1(args=[]){
 return cli(["d1","execute","ssh-manager","--config",configFile,
   "--local","--persist-to",state,...args]);
}
function insert(table,columns,values){
 assert.equal(columns.length,values.length);
 return "INSERT INTO "+table+"("+columns.join(",")+") VALUES ("+
   values.map(v=>v===null?"NULL":typeof v==="number"?String(v):q(v)).join(",")+");";
}
function verificationPrepareOp(operation,verification){
 const command=JSON.stringify({
  v:1,id:operation,node_id:id.node,action:"ssh.verification.prepare",
  actor:id.actor,expected_revision:rev,
  payload:{verification_id:verification,nonce_hash:nonceHash,login_user:"root",
   fingerprint,key_id:id.key,config_revision:rev}
 });
 return insert("operations",[
  "id","node_id","action","operator_id","idempotency_key","expected_revision",
  "command_json","signature","status","created_at","expires_at"
 ],[operation,id.node,"ssh.verification.prepare",id.actor,"prepare-"+verification,
  rev,command,"fixture-signer","DISPATCHED",t-5,t+300]);
}
function seedSql(devicePublic,rootPublic){
 const challenge=(verification)=>insert("ssh_verifications",[
  "id","node_id","key_fingerprint","login_user","config_revision",
  "nonce_hash","status","created_at","expires_at","public_key_id","issued_by"
 ],[verification,id.node,fingerprint,"root",rev,nonceHash,"PENDING",t-5,t+300,id.key,id.actor]);
 return [
  "PRAGMA foreign_keys=ON;",
  insert("users",["id","email","role","status","created_at"],
   [id.actor,"owner@ci.invalid","owner","active",t-100]),
  insert("nodes",["id","name","ssh_host","login_user","status","init_stage","config_revision","created_at"],
   [id.node,"local-worker-ci","192.0.2.10","root","online","WAITING_VERIFICATION",rev,t-100]),
  insert("nodes",["id","name","ssh_host","login_user","status","init_stage","config_revision","created_at"],
   [id.pairNode,"pairing-fixture","192.0.2.11","root","unpaired","WAITING_PAIR","unverified",t-100]),
  insert("pairing_tokens",["id","node_id","token_hash","expires_at","created_by"],
   [id.pairToken,id.pairNode,pairingTokenHash,t+600,id.actor]),
  insert("agent_credentials",["node_id","public_key","paired_at"],
   [id.node,devicePublic,t-50]),
  insert("public_keys",["id","purpose","name","algorithm","public_key","fingerprint","version","created_by","created_at"],
   [id.key,"daily","fixture","ssh-ed25519","fixture-public",fingerprint,1,id.actor,t-100]),
  insert("node_keys",["id","node_id","public_key_id","login_user","purpose","state"],
   [id.keyRow,id.node,id.key,"root","daily","installed"]),
  insert("node_ssh_proof_keys",["node_id","public_key","fingerprint","approved_by","created_at"],
   [id.node,rootPublic,"SHA256:local-fixture",id.actor,t-60]),
  // The second operation is inserted only after the first terminal result.
  verificationPrepareOp(id.op,id.verify),
  challenge(id.verify)
 ].join("\n");
}
async function signedRequest(url,payload,deviceKey){
 const body=JSON.stringify(payload);
 const timestamp=Math.floor(Date.now()/1000);
 const nonce=toURL(randomBytes(24));
 const digest=createHash("sha256").update(body).digest("hex");
 const toSign=["POST",url,timestamp,nonce,digest].join("\n");
 const signature=toURL(await webcrypto.subtle.sign("Ed25519",deviceKey.privateKey,
  new TextEncoder().encode(toSign)));
 return {body,headers:{
  "Content-Type":"application/json","X-Node-Id":id.node,
  "X-Device-Timestamp":String(timestamp),"X-Device-Nonce":nonce,
  "X-Device-Signature":signature
 }};
}
async function send(endpoint,payload,deviceKey){
 const signed=await signedRequest(endpoint,payload,deviceKey);
 const res=await fetch(host+endpoint,{method:"POST",...signed});
 const json=await res.json();
 return {status:res.status,json,signed};
}
function expectCode(res,status,code){
 assert.equal(res.status,status,"HTTP="+res.status+" "+JSON.stringify(res.json));
 assert.equal(res.json.error,code);
}
function query(sql){
 const out=cli(["d1","execute","ssh-manager","--config",configFile,"--local",
  "--persist-to",state,"--command",sql,"--json"]);
 const decoded=JSON.parse(out);
 assert(Array.isArray(decoded)&&decoded.length>0,"Unexpected wrangler D1 --json payload");
 assert.equal(decoded[0].success,true,"Local D1 query failed: "+sql);
 return decoded[0].results;
}
async function ready(){
 for(let i=0;i<90;i++){
  if(worker.exitCode!==null)throw Error("Worker exited early: "+workerLog.slice(-3000));
  try{
   const res=await fetch(host+"/anything",{signal:AbortSignal.timeout(600)});
   if(res)return;
  }catch{}
  await new Promise(resolve=>setTimeout(resolve,250));
 }
 throw Error("Local workerd startup failed: "+workerLog.slice(-4000));
}
async function main(){
 if(process.argv.slice(2).join("")!=="--local-only"){
  throw Error("Explicit --local-only is required. No remote resources are allowed.");
 }
 const device=await webcrypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const rootKey=await webcrypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const devicePublic=toURL(await webcrypto.subtle.exportKey("raw",device.publicKey));
 const rootPublic=toURL(await webcrypto.subtle.exportKey("raw",rootKey.publicKey));
 const cfg=JSON.parse(fs.readFileSync(repoConfig,"utf8"));
 cfg.name="ssh-manager-single-local-contract";
 // Test with Agent host = loopback; remove Custom Domain routes only. The
 // same Worker still serves real built assets on Control host after JWT gate.
 delete cfg.routes;
 cfg.workers_dev=true;
 cfg.vars.CONTROL_HOSTNAME="console.local.invalid";
 cfg.vars.AGENT_HOSTNAME="127.0.0.1";
 cfg.d1_databases[0].database_name="ssh-manager";
 cfg.d1_databases[0].database_id="00000000-0000-4000-8000-000000000001";
 cfg.d1_databases[0].remote=false;
 cfg.vars.COMMAND_PUBLIC_KEY=devicePublic;
 fs.writeFileSync(configFile,JSON.stringify(cfg,null,2),{mode:0o600});
 cli(["d1","migrations","apply","ssh-manager","--config",configFile,
   "--local","--persist-to",state]);
 fs.writeFileSync(seedFile,seedSql(devicePublic,rootPublic),{mode:0o600});
 d1(["--file",seedFile]);
 worker=spawn(wrangler,["dev","--config",configFile,"--local","--port","8799",
  "--ip","127.0.0.1","--persist-to",state],{
  cwd:root,env:{...process.env,WRANGLER_SEND_METRICS:"false",CI:"true"},
  stdio:["ignore","pipe","pipe"]
 });
 for(const stream of [worker.stdout,worker.stderr]){
  stream.on("data",b=>{workerLog=(workerLog+b.toString()).slice(-12000)});
 }
 await ready();
 // Same Worker must reject admin API and assets through unprotected Agent hostname.
 let boundary=await fetch(host+"/api/v1/health");
 assert.equal(boundary.status,404,"Management API leaked through Agent host");
 boundary=await fetch(host+"/");
 assert.equal(boundary.status,404,"SPA leaked through Agent host");
 boundary=await fetch(host+"/index.html");
 assert.equal(boundary.status,404,"Static asset leaked through Agent host");
 boundary=await fetch(host+"/agent/v1/health");
 assert.equal(boundary.status,200,"Agent hostname failed to route");
 assert.equal((await boundary.json()).agent_auth,"device-ed25519");
 // Agent pairing must be audited in the same D1 transaction as credential
 // creation and one-time token consumption. An audit failure must roll back all.
 const pairingDevice=await webcrypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const pairingPublic=toURL(await webcrypto.subtle.exportKey("raw",pairingDevice.publicKey));
 d1(["--command","CREATE TRIGGER ci_fail_agent_pair_audit BEFORE INSERT ON audit_logs "+
  "WHEN NEW.action='agent.pair' BEGIN SELECT RAISE(ABORT, 'CI_ABORT_PAIR_AUDIT'); END"]);
 let pairResponse=await fetch(host+"/agent/v1/pair",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({node_id:id.pairNode,token:pairingToken,public_key:pairingPublic})});
 assert.equal(pairResponse.status,500,"Audit failure must abort the pairing transaction");
 let pairState=query("SELECT (SELECT COUNT(*) FROM agent_credentials WHERE node_id="+q(id.pairNode)+
  ") AS credentials,(SELECT used_at FROM pairing_tokens WHERE id="+q(id.pairToken)+
  ") AS used_at,(SELECT status FROM nodes WHERE id="+q(id.pairNode)+
  ") AS node_status,(SELECT COUNT(*) FROM audit_logs WHERE node_id="+q(id.pairNode)+
  " AND action='agent.pair') AS audit_count");
 assert.equal(pairState[0].credentials,0,"credential insert must roll back with audit failure");
 assert.equal(pairState[0].used_at,null,"pairing token must remain unused after rollback");
 assert.equal(pairState[0].node_status,"unpaired");
 assert.equal(pairState[0].audit_count,0);
 d1(["--command","DROP TRIGGER ci_fail_agent_pair_audit"]);
 pairResponse=await fetch(host+"/agent/v1/pair",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({node_id:id.pairNode,token:pairingToken,public_key:pairingPublic})});
 assert.equal(pairResponse.status,201,JSON.stringify(await pairResponse.clone().json()));
 pairState=query("SELECT (SELECT COUNT(*) FROM agent_credentials WHERE node_id="+q(id.pairNode)+
  ") AS credentials,(SELECT used_at FROM pairing_tokens WHERE id="+q(id.pairToken)+
  ") AS used_at,(SELECT status FROM nodes WHERE id="+q(id.pairNode)+
  ") AS node_status,(SELECT COUNT(*) FROM audit_logs WHERE node_id="+q(id.pairNode)+
  " AND action='agent.pair') AS audit_count");
 assert.equal(pairState[0].credentials,1);
 assert(pairState[0].used_at>0);
 assert.equal(pairState[0].node_status,"online");
 assert.equal(pairState[0].audit_count,1,"successful pairing must create exactly one audit event");
 const pairReplay=await fetch(host+"/agent/v1/pair",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({node_id:id.pairNode,token:pairingToken,public_key:pairingPublic})});
 expectCode({status:pairReplay.status,json:await pairReplay.json()},409,"NODE_ALREADY_PAIRED");
 assert.equal(query("SELECT COUNT(*) AS count FROM audit_logs WHERE node_id="+q(id.pairNode)+
  " AND action='agent.pair'")[0].count,1,"replayed pairing must not duplicate audit");

 // Raw unsigned HTTP, even with a valid device ID, can never mutate D1.
 let res=await fetch(host+"/agent/v1/report",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({operation_id:id.op,status:"SUCCEEDED"})});
 assert.equal(res.status,401,"Unsigned Agent report unexpectedly accepted");

 const att={
  v:1,proof_id:id.proof,node_id:id.node,verification_id:id.verify,key_id:id.key,
  login_user:"root",fingerprint,config_revision:rev,nonce_hash:nonceHash,
  authenticated_at:t-3,observed_at:t-2,
  client_ip:"203.0.113.5",client_port:50001,sshd_pid:1555
 };
 const payload=JSON.stringify(att);
 const proofSig=toURL(await webcrypto.subtle.sign("Ed25519",rootKey.privateKey,
  new TextEncoder().encode(payload)));
 const proof={payload,signature:proofSig};
 // Root evidence must NOT be discarded if Helper's preparation report has
 // not yet reached D1. A delayed result remains retryable until expiry.
 expectCode(await send("/agent/v1/ssh-proof",proof,device),409,
  "CHALLENGE_PREPARATION_UNCONFIRMED");

 const prepared={operation_id:id.op,status:"SUCCEEDED",
  result_code:"VERIFICATION_PREPARED",
  detail:{verification_id:id.verify,verified_login:false}};
 const first=await send("/agent/v1/report",prepared,device);
 assert.equal(first.status,200,JSON.stringify(first.json));
 assert.equal(first.json.accepted,true);
 // Device nonce replay is separate from idempotent *business* acknowledgement.
 const replay=await fetch(host+"/agent/v1/report",{method:"POST",...first.signed});
 expectCode({status:replay.status,json:await replay.json()},409,"REPLAY");
 const retry=await send("/agent/v1/report",prepared,device);
 assert.equal(retry.status,200);
 assert.equal(retry.json.idempotent,true);
 expectCode(await send("/agent/v1/report",{
  ...prepared,detail:{verification_id:id.verify,verified_login:true}
 },device),409,"CONFLICTING_OPERATION_REPORT");

 expectCode(await send("/agent/v1/ssh-proof",{
  payload:payload+" ",signature:proofSig
 },device),403,"ROOT_SSH_PROOF_SIGNATURE_OR_CONTEXT_INVALID");
 const verified=await send("/agent/v1/ssh-proof",proof,device);
 assert.equal(verified.status,200,JSON.stringify(verified.json));
 assert.equal(verified.json.status,"VERIFIED");
 const rootRetry=await send("/agent/v1/ssh-proof",proof,device);
 assert.equal(rootRetry.status,200);
 assert.equal(rootRetry.json.idempotent,true);
 let rows=query("SELECT (SELECT status FROM ssh_verifications WHERE id="+q(id.verify)+
  ") AS challenge_status,(SELECT init_stage FROM nodes WHERE id="+q(id.node)+
  ") AS node_stage,(SELECT verified_at FROM node_keys WHERE id="+q(id.keyRow)+
  ") AS verified_at,(SELECT COUNT(*) FROM audit_logs WHERE node_id="+q(id.node)+
  ") AS audit_count");
 assert.equal(rows[0].challenge_status,"VERIFIED");
 assert.equal(rows[0].node_stage,"KEY_VERIFIED");
 assert(rows[0].verified_at>0);
 assert.equal(rows[0].audit_count,2,"One prepare + one root proof, no duplicate audit");

 // The schema correctly allows only ONE PENDING SSH challenge per VPS.
 // Create the second challenge only after the first is VERIFIED; this also
 // tests that a successful proof permits the next manual verification.
 d1(["--command",insert("ssh_verifications",[
  "id","node_id","key_fingerprint","login_user","config_revision",
  "nonce_hash","status","created_at","expires_at","public_key_id","issued_by"
 ],[id.verify2,id.node,fingerprint,"root",rev,nonceHash,
   "PENDING",t-5,t+300,id.key,id.actor])]);
 // The previous operation has a terminal result, so the next can be
 // dispatched without violating per-node single-flight.
 d1(["--command",verificationPrepareOp(id.op2,id.verify2)]);
 // Simulate D1 audit insertion failure while a second helper prepare report
 // arrives. The Worker must not leave operations SUCCEEDED without
 // ssh_verifications.prepared_at.
 d1(["--command","CREATE TRIGGER ci_fail_report_audit BEFORE INSERT ON audit_logs "+
  "WHEN NEW.operation_id="+q(id.op2)+" BEGIN SELECT RAISE(ABORT, 'CI_ABORT_AUDIT'); END"]);
 const second={operation_id:id.op2,status:"SUCCEEDED",
  result_code:"VERIFICATION_PREPARED",
  detail:{verification_id:id.verify2,verified_login:false}};
 const failed=await send("/agent/v1/report",second,device);
 assert.equal(failed.status,500,"Synthetic D1 failure must abort report");
 rows=query("SELECT (SELECT status FROM operations WHERE id="+q(id.op2)+
  ") AS operation_status,(SELECT prepared_at FROM ssh_verifications WHERE id="+q(id.verify2)+
  ") AS prepared_at");
 assert.equal(rows[0].operation_status,"DISPATCHED");
 assert.equal(rows[0].prepared_at,null);
 d1(["--command","DROP TRIGGER ci_fail_report_audit"]);
 const recovered=await send("/agent/v1/report",second,device);
 assert.equal(recovered.status,200,JSON.stringify(recovered.json));
 rows=query("SELECT (SELECT status FROM operations WHERE id="+q(id.op2)+
  ") AS operation_status,(SELECT prepared_at FROM ssh_verifications WHERE id="+q(id.verify2)+
  ") AS prepared_at");
 assert.equal(rows[0].operation_status,"SUCCEEDED");
 assert(rows[0].prepared_at>0);
 
 // P4/P5: exercise the ACTUAL local Gateway and D1 with a per-node Root
 // operation receipt (the Agent only transports it, never signs it).
 const special={
  disable:"a0000000-0000-4000-8000-000000000001",
  restore:"a0000000-0000-4000-8000-000000000002",
  rescue:"a0000000-0000-4000-8000-000000000003",
  revoke:"a0000000-0000-4000-8000-000000000004",
  badRestore:"a0000000-0000-4000-8000-000000000005",
  rescueKey:"b0000000-0000-4000-8000-000000000001"
 };
 const changedRev="c".repeat(64),restoredRev="d".repeat(64);
 const snapshot="e".repeat(32),rescueFP="SHA256:"+"B".repeat(43);
 function addManual(op,action,revision,extra){
  const tick=Math.floor(Date.now()/1000);
  const command={v:1,id:op,node_id:id.node,actor:id.actor,action,
   issued_at:tick-5,expires_at:tick+45,expected_revision:revision,
   payload:{login_user:"root",confirm_node_id:id.node,
    reason:"Administrator explicitly approved isolated staging operation",...extra}};
  d1(["--command",insert("operations",[
   "id","node_id","action","operator_id","idempotency_key","expected_revision",
   "command_json","signature","status","created_at","expires_at"
  ],[op,id.node,action,id.actor,"staging-"+op,revision,JSON.stringify(command),
    "signed-command-fixture","DISPATCHED",tick-5,tick+45])]);
  return command;
 }
 async function rootTerminal(command,resultCode,result,{failed=false,noWrite=false}={}){
  const receipt={v:1,node_id:id.node,operation_id:command.id,
   action:command.action,result_code:resultCode,
   expected_revision:command.expected_revision,
   detail_sha256:createHash("sha256").update(JSON.stringify(result)).digest("hex"),
   executed_at:command.issued_at+5};
  if(noWrite)receipt.no_ssh_write=true;
  const payload=JSON.stringify(receipt);
  return {operation_id:command.id,status:failed?"FAILED":"SUCCEEDED",result_code:resultCode,
   detail:{result,root_receipt:{payload,
    signature:toURL(await webcrypto.subtle.sign("Ed25519",rootKey.privateKey,
      new TextEncoder().encode(payload)))}}};
 }
 const disable=addManual(special.disable,"ssh.password.disable",rev,
  {verification_id:id.verify,proof_id:id.proof});
 const disabledData={snapshot_ref:snapshot,before_revision:rev,after_revision:changedRev,
  config_hash:"f".repeat(64),passwordauthentication:false,kbdinteractiveauthentication:false};
 const disableReport=await rootTerminal(disable,"PASSWORD_DISABLED",disabledData);
 expectCode(await send("/agent/v1/report",{
  ...disableReport,detail:{result:disabledData}
 },device),403,"ROOT_MANUAL_RECEIPT_INVALID");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(special.disable))[0].status,
  "DISPATCHED","untrusted Agent success mutated D1");
 assert.equal((await send("/agent/v1/report",disableReport,device)).status,200);
 let manualRows=query("SELECT init_stage,config_revision FROM nodes WHERE id="+q(id.node));
 assert.equal(manualRows[0].init_stage,"PASSWORD_DISABLED");
 assert.equal(manualRows[0].config_revision,changedRev);
 assert.equal(query("SELECT count(*) AS n FROM ssh_config_snapshots WHERE node_id="+q(id.node))[0].n,1);
 const invalid=addManual(special.badRestore,"ssh.config.rollback",changedRev,
  {snapshot_ref:"1".repeat(32)});
 const invalidReport=await rootTerminal(invalid,"SSH_CONFIG_ROLLED_BACK",{
  snapshot_ref:"1".repeat(32),before_revision:changedRev,after_revision:restoredRev,
  config_hash:rev,passwordauthentication:true,kbdinteractiveauthentication:true});
 assert.equal((await send("/agent/v1/report",invalidReport,device)).status,500,
  "invalid snapshot must abort the full D1 transaction");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(special.badRestore))[0].status,
  "DISPATCHED","D1 committed failed snapshot transition");
 // Agent-authenticated FAILED MUST NOT release this VPS without an
 // independently signed Root receipt attesting that no SSH write occurred.
 const failedUnsigned={operation_id:special.badRestore,status:"FAILED",
  result_code:"MANUAL_NODE_CONFIRMATION_REQUIRED",
  detail:{result:{code:"MANUAL_NODE_CONFIRMATION_REQUIRED"}}};
 expectCode(await send("/agent/v1/report",failedUnsigned,device),403,"ROOT_MANUAL_RECEIPT_INVALID");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(special.badRestore))[0].status,
  "DISPATCHED","unsigned FAILED released a VPS operation lock");
 // A forged valid signature for a potentially partial write must also fail
 // the Gateway's strict no-write result-code allowlist.
 const signedAmbiguous=await rootTerminal(invalid,"PASSWORD_DISABLE_MANUAL_REVIEW",
  {code:"PASSWORD_DISABLE_MANUAL_REVIEW"},{failed:true,noWrite:true});
 expectCode(await send("/agent/v1/report",signedAmbiguous,device),403,"ROOT_MANUAL_RECEIPT_INVALID");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(special.badRestore))[0].status,
  "DISPATCHED","signed ambiguous result released a VPS lock");
 // The local-only fixture never touched SSH. A signed prewrite failure can
 // safely close the synthetic operation, with the same Root proof key.
 const trustedNoWrite=await rootTerminal(invalid,"MANUAL_NODE_CONFIRMATION_REQUIRED",
  {code:"MANUAL_NODE_CONFIRMATION_REQUIRED"},{failed:true,noWrite:true});
 const terminated=await send("/agent/v1/report",trustedNoWrite,device);
 assert.equal(terminated.status,200,JSON.stringify(terminated.json));
 assert.equal(query("SELECT status FROM operations WHERE id="+q(special.badRestore))[0].status,
  "FAILED","trusted Root prewrite failure should release the fixture");
 const duplicate=await send("/agent/v1/report",trustedNoWrite,device);
 assert.equal(duplicate.status,200,JSON.stringify(duplicate.json));
 assert.equal(duplicate.json.idempotent,true);
 const restore=addManual(special.restore,"ssh.password.restore",changedRev,
  {snapshot_ref:snapshot});
 const restoreReport=await rootTerminal(restore,"PASSWORD_POLICY_RESTORED",{
  snapshot_ref:snapshot,before_revision:changedRev,after_revision:restoredRev,
  config_hash:rev,passwordauthentication:true,kbdinteractiveauthentication:true});
 assert.equal((await send("/agent/v1/report",restoreReport,device)).status,200);
 manualRows=query("SELECT init_stage,config_revision FROM nodes WHERE id="+q(id.node));
 assert.equal(manualRows[0].init_stage,"POLICY_INSPECTED");
 assert.equal(manualRows[0].config_revision,restoredRev);
 const restored=query("SELECT restored_at FROM ssh_config_snapshots WHERE node_id="+q(id.node));
 assert(restored[0].restored_at>0);
 d1(["--command",insert("public_keys",[
  "id","purpose","name","algorithm","public_key","fingerprint",
  "version","created_by","created_at"
 ],[special.rescueKey,"rescue","test","ssh-ed25519",
  "ssh-ed25519 fixture",rescueFP,1,id.actor,Math.floor(Date.now()/1000)])]);
 const rescue=addManual(special.rescue,"ssh.rescue.enable",restoredRev,
  {key_id:special.rescueKey,fingerprint:rescueFP,public_key:"ssh-ed25519 fixture"});
 const enableResult={key_fingerprint:rescueFP,file_checked:true,
  before_sha256:"2".repeat(64),after_sha256:"3".repeat(64),
  snapshot_ref:"4".repeat(32),already_present:false};
 const enabled=await send("/agent/v1/report",
  await rootTerminal(rescue,"RESCUE_KEY_INSTALLED",enableResult),device);
 assert.equal(enabled.status,200,JSON.stringify(enabled.json));
 assert.equal(query("SELECT state FROM node_keys WHERE public_key_id="+q(special.rescueKey))[0].state,"installed");
 const revoke=addManual(special.revoke,"ssh.rescue.revoke",restoredRev,
  {key_id:special.rescueKey,fingerprint:rescueFP,public_key:"ssh-ed25519 fixture"});
 const revokeResult={key_fingerprint:rescueFP,file_checked:true,
  before_sha256:"3".repeat(64),after_sha256:"2".repeat(64),snapshot_ref:"5".repeat(32)};
 const revoked=await send("/agent/v1/report",
  await rootTerminal(revoke,"RESCUE_KEY_REVOKED",revokeResult),device);
 assert.equal(revoked.status,200,JSON.stringify(revoked.json));
 assert.equal(query("SELECT state FROM node_keys WHERE public_key_id="+q(special.rescueKey))[0].state,"revoked");
 // The daily public-key install cannot rely on Agent-supplied file_checked.
 // A compromised Agent must not turn a forged success or false FAILED into
 // a terminal result and unlock subsequent privileged node operations.
 const dailyFailure=addManual("c0000000-0000-4000-8000-000000000001",
  "ssh.daily.install",restoredRev,{key_id:id.key,fingerprint});
 expectCode(await send("/agent/v1/report",{
  operation_id:dailyFailure.id,status:"FAILED",result_code:"DAILY_INSTALL_DISABLED",
  detail:{result:{code:"DAILY_INSTALL_DISABLED"}}
 },device),403,"ROOT_DAILY_RECEIPT_INVALID");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(dailyFailure.id))[0].status,
  "DISPATCHED","unsigned daily install failure released node operation lock");
 const dailyAmbiguous=await rootTerminal(dailyFailure,
  "KEY_INSTALL_FAILED_MANUAL_REVIEW",{code:"KEY_INSTALL_FAILED_MANUAL_REVIEW"},
  {failed:true,noWrite:true});
 expectCode(await send("/agent/v1/report",dailyAmbiguous,device),403,"ROOT_DAILY_RECEIPT_INVALID");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(dailyFailure.id))[0].status,
  "DISPATCHED","ambiguous public key write released node operation lock");
 const dailySafeFailure=await rootTerminal(dailyFailure,"DAILY_INSTALL_DISABLED",
  {code:"DAILY_INSTALL_DISABLED"},{failed:true,noWrite:true});
 assert.equal((await send("/agent/v1/report",dailySafeFailure,device)).status,200);
 assert.equal(query("SELECT status FROM operations WHERE id="+q(dailyFailure.id))[0].status,
  "FAILED","trusted prewrite daily failure not finalized");
 const dailySuccess=addManual("c0000000-0000-4000-8000-000000000002",
  "ssh.daily.install",restoredRev,{key_id:id.key,fingerprint});
 const dailyData={key_fingerprint:fingerprint,file_checked:true,already_present:false};
 expectCode(await send("/agent/v1/report",{
  operation_id:dailySuccess.id,status:"SUCCEEDED",
  result_code:"DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF",detail:dailyData
 },device),403,"ROOT_DAILY_RECEIPT_INVALID");
 assert.equal(query("SELECT status FROM operations WHERE id="+q(dailySuccess.id))[0].status,
  "DISPATCHED","untrusted Agent daily success changed node state");
 const signedDaily=await rootTerminal(dailySuccess,
  "DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF",dailyData);
 assert.equal((await send("/agent/v1/report",signedDaily,device)).status,200);
 assert.equal(query("SELECT status FROM operations WHERE id="+q(dailySuccess.id))[0].status,
  "SUCCEEDED","verified daily install receipt not committed");
 const dailyRetry=await send("/agent/v1/report",signedDaily,device);
 assert.equal(dailyRetry.status,200);
 assert.equal(dailyRetry.json.idempotent,true);
 console.log("PASS local workerd+D1 P4/P5: signed manual receipt required, "+
  "atomic password restore, snapshot guard, single-node rescue enable/revoke");
 console.log("PASS local workerd+D1: device signature, nonce replay, Root Ed25519 "+
  "proof, idempotence and audit-failure rollback (NO remote VPS/Cloudflare)");
}
try{
 await main();
}catch(e){
 console.error("Gateway local contract FAILED:",e instanceof Error?e.message:String(e));
 if(workerLog)console.error("workerd log:",workerLog.slice(-2500));
 process.exitCode=1;
}finally{
 if(worker){worker.kill("SIGTERM");await new Promise(resolve=>{
  if(worker.exitCode!==null){resolve();return}
  worker.once("exit",resolve);
  setTimeout(resolve,2500).unref();
 });}
 fs.rmSync(configFile,{force:true});
 fs.rmSync(state,{recursive:true,force:true});
}
