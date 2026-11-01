#!/usr/bin/env node
// Cloudflare-native GitHub Builds: ONE Worker, TWO domains, ZERO manual Wrangler config.
//
// First run in a NEW Staging account/environment: create exactly one D1,
// generate an ephemeral Ed25519 signer, deploy one Worker, and write the private
// signer directly to Cloudflare Secret. Subsequent runs read the DEPLOYED
// Worker's public bindings and NEVER rotate the signer or recreate D1.
//
// This script never updates production VPS, never enables manual SSH writes,
// and will not silently recover a partially deployed cryptographic identity.
import {existsSync,readFileSync,writeFileSync,rmSync} from "node:fs";
import {dirname,resolve,join} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";
import {buildSingleConfig,findStagingDatabase,generateCommandSigner} from "./cloudflare_quick_lib.mjs";
import {
 extractExistingStagingWorker,extractWhoamiAccount,requireCloudflareSettingsResponse,
 newCloudflareBootstrap,classifyWorkerForBootstrap,parseWranglerAuthToken
} from "./cloudflare_native_lib.mjs";
import {SIGNER_RECOVERY_FLAG,EMPTY_STAGING_SQL,validateEmptyStagingQuery,verifyWorkerTargets,
 DELETED_WORKER_RECOVERY_FLAG,DELETED_WORKER_RECOVERY_SQL,validateDeletedWorkerStagingQuery,
 UNRESOLVED_OPERATION_PREFLIGHT_SQL,validateUnresolvedOperationPreflight} from "./native_security_helpers.mjs";

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const WRANGLER=join(ROOT,"node_modules","wrangler","bin","wrangler.js");
const TEMPLATE=join(ROOT,"wrangler.single.staging.example.jsonc");
// Wrangler resolves entrypoint/assets relative to config directory -> repo ROOT.
const CONFIG=join(ROOT,"wrangler.single.staging.native.jsonc");
const NAME=process.env.WRANGLER_CI_OVERRIDE_NAME||"ssh-manager-staging";
const DB="ssh-manager-staging";

function run(entry,args,options={}){
 const input=typeof options.input==="string";
 const child=spawnSync(process.execPath,[entry,...args],{
  cwd:ROOT,env:process.env,encoding:"utf8",
  stdio:options.capture?["ignore","pipe","pipe"]:
   input?["pipe","inherit","inherit"]:"inherit",
  ...(input?{input:options.input}:{}),maxBuffer:4*1024*1024
 });
 if(child.error)throw Error("Cannot execute "+args[0]+": "+child.error.message);
 if(child.status!==0){
  // Never print private-key stdin or environment values in an error.
  throw Error("Command failed: "+args[0]+
   (options.capture?" (check Cloudflare API token/account permissions)":""));
 }
 return options.capture?String(child.stdout||""):"";
}
function wrangler(args,options={}){
 if(!existsSync(WRANGLER))throw Error("Wrangler not installed; run npm install.");
 return run(WRANGLER,args,options);
}
function accountId(){
 const envId=String(process.env.CLOUDFLARE_ACCOUNT_ID||"").trim();
 if(envId){
  if(!/^[a-f0-9]{32}$/i.test(envId))throw Error("Invalid CLOUDFLARE_ACCOUNT_ID");
  return envId;
 }
 let json;
 try{json=JSON.parse(wrangler(["whoami","--json"],{capture:true}));}
 catch{throw Error("Cannot discover Cloudflare account. Set CLOUDFLARE_ACCOUNT_ID as a build variable.");}
 return extractWhoamiAccount(json);
}
function authToken(){
 if(process.env.CLOUDFLARE_API_TOKEN)return process.env.CLOUDFLARE_API_TOKEN;
 // Reuse Wrangler's existing Cloudflare Builds credentials. The output is
 // captured in process memory only and NEVER printed or written to disk.
 let data;
 try{data=JSON.parse(wrangler(["auth","token","--json"],{capture:true}));}
 catch{throw Error(
  "Cannot access Cloudflare Builds credentials. Select a scoped Build API token "+
  "with Workers Scripts Read/Edit, Workers Routes Edit and D1 Read/Edit permissions.");
 }
 return parseWranglerAuthToken(data);
}
async function settings(id){
 const token=authToken();
 const response=await fetch(
  "https://api.cloudflare.com/client/v4/accounts/"+id+"/workers/scripts/"+NAME+"/settings",
  {headers:{Authorization:"Bearer "+token,Accept:"application/json"},
   signal:AbortSignal.timeout(12000)}
 );
 if(response.status===404)return null;
 if(response.status===401||response.status===403)throw Error(
  "Build API token cannot read the Worker; set Workers Scripts Read permission.");
 if(!response.ok)throw Error("Cloudflare Worker settings unavailable (HTTP "+response.status+").");
 let json;
 try{json=await response.json();}catch{throw Error("Invalid Cloudflare Worker settings response");}
 return requireCloudflareSettingsResponse(json);
}
function databaseList(){
 let value;
 try{value=JSON.parse(wrangler(["d1","list","--json"],{capture:true}));}
 catch{throw Error("D1 list unavailable. Build API token requires D1 Read/Edit permission.");}
 return value;
}
function writeConfig(config){
 if(existsSync(CONFIG))throw Error("Staging temporary Wrangler config exists; refusing overwrite");
 writeFileSync(CONFIG,JSON.stringify(config,null,2)+"\n",{flag:"wx",mode:0o600});
}
function originalSecretExists(){
 let items;
 try{items=JSON.parse(wrangler(["secret","list","--config",CONFIG,"--name",NAME],{capture:true}));}
 catch{throw Error("Unable to verify the existing Worker private signing secret");}
 if(!Array.isArray(items)||!items.some(x=>x?.name==="COMMAND_PRIVATE_KEY"))
  throw Error("Original COMMAND_PRIVATE_KEY missing; manual recovery required, no key rotation");
}
function buildAssets(){
 const npm=process.platform==="win32"?"npm.cmd":"npm";
 const head=spawnSync("git",["rev-parse","HEAD"],{
  cwd:ROOT,encoding:"utf8",stdio:["ignore","pipe","ignore"]
 });
 const gitSha=head.status===0?String(head.stdout||"").trim().toLowerCase():"";
 const pinned=/^[a-f0-9]{40}$/.test(gitSha)?gitSha:"";
 if(!pinned)console.warn("Cannot determine source Git SHA; the VPS installer wizard will remain disabled.");
 const res=spawnSync(npm,["run","build:web"],{
  cwd:ROOT,env:{...process.env,VITE_SSH_MANAGER_COMMIT:pinned},stdio:"inherit"
 });
 if(res.error||res.status!==0)throw Error("Control panel build failed");
 if(!existsSync(join(ROOT,"apps","console","dist","index.html")))
  throw Error("Built React assets are missing");
}
function assertNoDuplicateUnresolvedOperations(){
 const raw=wrangler(["d1","execute","DB","--remote","--json",
  "--config",CONFIG,"--command",UNRESOLVED_OPERATION_PREFLIGHT_SQL],{capture:true});
 let parsed;
 try{parsed=JSON.parse(raw);}catch{
  throw Error("Staging D1 operation preflight failed: invalid Wrangler JSON response");
 }
 validateUnresolvedOperationPreflight(parsed);
 console.log("[Staging] Read-only single-flight D1 operation preflight passed.");
}
function migrate(){
 wrangler(["d1","migrations","apply",DB,"--remote","--config",CONFIG]);
}
function deploy(){
 wrangler(["deploy","--config",CONFIG,"--name",NAME]);
}
async function initialize(template,id){
 const params=newCloudflareBootstrap(process.env);
 console.log("Control hostname: "+params.controlHost);
 console.log("Agent hostname:   "+params.agentHost);
 console.log("Access remains hostname-based: CONTROL ONLY. Never use Worker-level Access.");
 // The classification has already checked that NO staging D1 exists.
 // This is the only command that ever creates a D1 database.
 wrangler(["d1","create",DB,"--no-update-config"]);
 const created=findStagingDatabase(databaseList(),DB);
 if(!created)throw Error("New D1 is not visible. Stop; DO NOT rerun to rotate the signer.");
 const signer=generateCommandSigner();
 const cfg=buildSingleConfig(template,{...params,dbId:created.id,publicKey:signer.publicKey});
 cfg.name=NAME;
 writeConfig(cfg);
 console.log("[Staging] Created one D1 and prepared one Worker with SSH writes locked.");
 try{
  migrate();
  deploy();
  const deployed=await settings(id);
  verifyWorkerTargets(deployed,{publicKey:signer.publicKey,databaseId:created.id});
  // Private signer exists ONLY in Node process memory and Cloudflare Secret.
  wrangler(["secret","put","COMMAND_PRIVATE_KEY","--config",CONFIG,"--name",NAME],{
   input:signer.privateKeyPkcs8Base64+"\n"
  });
  originalSecretExists();
 }catch(err){
  console.error("First deployment did not finish. The Staging D1/Worker may exist.");
  console.error("DO NOT delete D1 or retry by rotating keys. See recovery section of deployment docs.");
  throw err;
 }
 console.log("INITIAL DEPLOY OK. Original private signer stored in Cloudflare only.");
}
// Read-only gate used before/after any deleted-Worker signer replacement.
// A previous unpaired node may be retained; an activated Agent/SSH history
// may never be silently rekeyed.
function assertUnpairedStagingD1(){
 const output=wrangler(["d1","execute","DB","--remote","--json",
  "--config",CONFIG,"--command",DELETED_WORKER_RECOVERY_SQL],{capture:true});
 let payload;
 try{payload=JSON.parse(output);}catch{
  throw Error("Deleted-Worker recovery cannot parse D1 safety check");
 }
 return validateDeletedWorkerStagingQuery(payload);
}
async function recreateDeletedWorker(template,dbs,id){
 if(process.env.SSH_MANAGER_RECOVER_DELETED_WORKER!==DELETED_WORKER_RECOVERY_FLAG)
  throw Error("Deleted-Worker recovery requires the exact one-time opt-in");
 const params=newCloudflareBootstrap(process.env);
 const original=findStagingDatabase(dbs,DB);
 if(!original)throw Error("Original Staging D1 was not found; no resource created");
 const signer=generateCommandSigner();
 const cfg=buildSingleConfig(template,{...params,dbId:original.id,publicKey:signer.publicKey});
 cfg.name=NAME;
 writeConfig(cfg);
 // Do NOT create/delete D1 or clean up old data. Only a provably inactive
 // Staging identity permits rotating the lost Worker signing key.
 const before=assertUnpairedStagingD1();
 console.log("[Staging] Recreating deleted Worker; reusing existing D1 with "+before.totalNodes+" unpaired nodes.");
 migrate();
 deploy();
 const deployed=await settings(id);
 verifyWorkerTargets(deployed,{publicKey:signer.publicKey,databaseId:original.id});
 // Recheck after publishing the public key to exclude a race where a device
 // paired between the first check and the matching secret upload.
 assertUnpairedStagingD1();
 wrangler(["secret","put","COMMAND_PRIVATE_KEY","--config",CONFIG,"--name",NAME],{
  input:signer.privateKeyPkcs8Base64+"\n"
 });
 originalSecretExists();
 console.log("DELETED WORKER RECOVERY OK. Existing Staging D1 retained.");
 console.log("Remove SSH_MANAGER_RECOVER_DELETED_WORKER from Cloudflare Build variables NOW.");
}

async function repairOrphanedSigner(template,remote,dbs,id){
 const emptyRecovery=process.env.SSH_MANAGER_RECOVER_EMPTY_STAGING===SIGNER_RECOVERY_FLAG;
 const deletedRecovery=process.env.SSH_MANAGER_RECOVER_DELETED_WORKER===DELETED_WORKER_RECOVERY_FLAG;
 if(!emptyRecovery&&!deletedRecovery)
  throw Error("Connected Worker has no signing secret. Recovery requires explicit one-time authorization.");
 if(emptyRecovery&&deletedRecovery)
  throw Error("Select exactly one recovery mode, not both.");
 const cfg=extractExistingStagingWorker(template,remote,dbs,{allowMissingSigner:true});
 cfg.name=NAME;
 writeConfig(cfg);
 verifyWorkerTargets(remote,{
  publicKey:cfg.vars.COMMAND_PUBLIC_KEY,databaseId:cfg.d1_databases[0].database_id
 });
 if(deletedRecovery){
  assertUnpairedStagingD1();
 }else{
  const query=wrangler(["d1","execute","DB","--remote","--json",
   "--config",CONFIG,"--command",EMPTY_STAGING_SQL],{capture:true});
  let data;
  try{data=JSON.parse(query);}catch{
   throw Error("Remote D1 recovery check returned invalid JSON; refusing signer reset");
  }
  validateEmptyStagingQuery(data);
 }
 const signer=generateCommandSigner();
 cfg.vars.COMMAND_PUBLIC_KEY=signer.publicKey;
 writeFileSync(CONFIG,JSON.stringify(cfg,null,2)+"\n",{mode:0o600});
 migrate();
 deploy();
 const deployed=await settings(id);
 verifyWorkerTargets(deployed,{publicKey:signer.publicKey,databaseId:cfg.d1_databases[0].database_id});
 if(deletedRecovery)assertUnpairedStagingD1();
 wrangler(["secret","put","COMMAND_PRIVATE_KEY","--config",CONFIG,"--name",NAME],{
  input:signer.privateKeyPkcs8Base64+"\n"
 });
 originalSecretExists();
 console.log(deletedRecovery?"DELETED WORKER RECOVERY OK. Remove SSH_MANAGER_RECOVER_DELETED_WORKER now.":"RECOVERY OK on the actual connected Worker. Remove SSH_MANAGER_RECOVER_EMPTY_STAGING now.");
}
async function update(template,remote,dbs,id){
 const missingSecret=!remote?.bindings?.some(x=>x?.name==="COMMAND_PRIVATE_KEY");
 if(missingSecret){
  await repairOrphanedSigner(template,remote,dbs,id);
  return;
 }
 const cfg=extractExistingStagingWorker(template,remote,dbs);
 cfg.name=NAME;
 writeConfig(cfg);
 console.log("[Staging] Reusing existing Worker, domains, Access, D1, DO and public signer.");
 originalSecretExists();
 assertNoDuplicateUnresolvedOperations();
 migrate();
 deploy();
 console.log("UPDATE OK. No new D1 and no signing key rotation.");
}
async function main(){
 if(process.argv.length!==2)throw Error("Use npm run cf:deploy without arguments");
 const branch=process.env.WORKERS_CI_BRANCH||process.env.GITHUB_REF_NAME;
 if(!/^(ssh-manager|ssh-manager-staging)$/.test(NAME))throw Error("Unexpected connected Cloudflare Worker name");
 if(process.env.WORKERS_CI&&!process.env.WRANGLER_CI_OVERRIDE_NAME)throw Error("Missing Cloudflare Builds Worker target: WRANGLER_CI_OVERRIDE_NAME");
 if(branch&&branch!=="main")throw Error("Only main may deploy Staging; previews are disabled");
 if(existsSync(CONFIG))throw Error("An existing temporary Staging config was found; refusing overwrite");
 if(Number(process.versions.node.split(".")[0])<22)throw Error("Node.js 22+ required");
 // Fail fast before creating any Cloudflare resource if React build fails.
 buildAssets();
 const id=accountId();
 const remote=await settings(id);
 const dbs=databaseList();
 const deletedValue=process.env.SSH_MANAGER_RECOVER_DELETED_WORKER;
 if(deletedValue&&deletedValue!==DELETED_WORKER_RECOVERY_FLAG)
  throw Error("Invalid deleted-Worker recovery flag; refusing deployment");
 const allowDeleted=deletedValue===DELETED_WORKER_RECOVERY_FLAG;
 const mode=classifyWorkerForBootstrap(remote,dbs,{allowDeletedWorkerRecovery:allowDeleted});
 if(allowDeleted&&mode!=="deleted-worker-recovery"&&
  remote?.bindings?.some(x=>x?.name==="COMMAND_PRIVATE_KEY"))
  throw Error("Recovered Worker already has a signer. Remove SSH_MANAGER_RECOVER_DELETED_WORKER.");
 const template=JSON.parse(readFileSync(TEMPLATE,"utf8"));
 console.log("Cloudflare single-Worker deployment mode: "+mode);
 try{
  if(mode==="new")await initialize(template,id);
  else if(mode==="deleted-worker-recovery")await recreateDeletedWorker(template,dbs,id);
  else await update(template,remote,dbs,id);
 }finally{
  rmSync(CONFIG,{force:true}); // Non-secret temporary configuration.
 }
 console.log("All SSH high-risk switches remain false; no VPS command was sent.");
 console.log("Next: verify Control Access on the management hostname and Agent device health.");
}
main().catch(err=>{
 console.error("Cloudflare Staging deploy safely stopped:",err instanceof Error?err.message:String(err));
 console.error("No production VPS operation or automatic SSH rollback was performed.");
 process.exitCode=1;
});
