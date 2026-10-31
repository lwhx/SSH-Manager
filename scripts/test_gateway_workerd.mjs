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
const repoConfig=path.join(root,"wrangler.gateway.jsonc");
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
};
const rev="a".repeat(64),nonceHash="b".repeat(64);
const fingerprint="SHA256:"+"A".repeat(43);
const t=Math.floor(Date.now()/1000);
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
function seedSql(devicePublic,rootPublic){
 const cmd=(operation,verification)=>JSON.stringify({
  v:1,id:operation,node_id:id.node,action:"ssh.verification.prepare",
  actor:id.actor,expected_revision:rev,
  payload:{verification_id:verification,nonce_hash:nonceHash,login_user:"root",
   fingerprint,key_id:id.key,config_revision:rev}
 });
 const op=(operation,verification)=>insert("operations",[
  "id","node_id","action","operator_id","idempotency_key","expected_revision",
  "command_json","signature","status","created_at","expires_at"
 ],[operation,id.node,"ssh.verification.prepare",id.actor,"prepare-"+verification,
  rev,cmd(operation,verification),"fixture-signer","DISPATCHED",t-5,t+300]);
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
  insert("agent_credentials",["node_id","public_key","paired_at"],
   [id.node,devicePublic,t-50]),
  insert("public_keys",["id","purpose","name","algorithm","public_key","fingerprint","version","created_by","created_at"],
   [id.key,"daily","fixture","ssh-ed25519","fixture-public",fingerprint,1,id.actor,t-100]),
  insert("node_keys",["id","node_id","public_key_id","login_user","purpose","state"],
   [id.keyRow,id.node,id.key,"root","daily","installed"]),
  insert("node_ssh_proof_keys",["node_id","public_key","fingerprint","approved_by","created_at"],
   [id.node,rootPublic,"SHA256:local-fixture",id.actor,t-60]),
  op(id.op,id.verify),op(id.op2,id.verify2),
  challenge(id.verify),challenge(id.verify2)
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
 cfg.name="ssh-manager-gateway-local-contract";
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
