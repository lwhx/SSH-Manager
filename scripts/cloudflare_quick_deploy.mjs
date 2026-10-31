#!/usr/bin/env node
// One Cloudflare Worker, two exact Custom Domains, one D1, one local Durable Object.
// Staging-only: never touches production SSH/VPS or silently rotates keys.
import {spawnSync} from "node:child_process";
import {existsSync,mkdirSync,readFileSync,renameSync,writeFileSync} from "node:fs";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {createInterface} from "node:readline/promises";
import {
 accessSettings,customDomain,buildSingleConfig,findStagingDatabase,
 generateCommandSigner,validateStoredConfig
} from "./cloudflare_quick_lib.mjs";

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const WRANGLER=join(ROOT,"node_modules","wrangler","bin","wrangler.js");
const TSC=join(ROOT,"node_modules","typescript","bin","tsc");
const VITE=join(ROOT,"node_modules","vite","bin","vite.js");
const CONFIG=join(ROOT,"wrangler.single.staging.local.jsonc");
const TEMPLATE=join(ROOT,"wrangler.single.staging.example.jsonc");
const STATE=join(ROOT,".ssh-manager-deploy","single-staging.json");
const OLD_STATE=join(ROOT,".ssh-manager-deploy","staging.json");
const OLD_CONTROL=join(ROOT,"wrangler.control.staging.local.jsonc");
const OLD_GATEWAY=join(ROOT,"wrangler.gateway.staging.local.jsonc");
const DB_NAME="ssh-manager-staging";

function readJSON(path){return JSON.parse(readFileSync(path,"utf8"));}
function writeJSON(path,obj){
 mkdirSync(dirname(path),{recursive:true,mode:0o700});
 const temp=path+".tmp-"+process.pid;
 writeFileSync(temp,JSON.stringify(obj,null,2)+"\n",{flag:"wx",mode:0o600});
 renameSync(temp,path);
}
function run(entry,args=[],opts={}){
 const capture=opts.capture===true;
 const input=typeof opts.input==="string";
 const result=spawnSync(process.execPath,[entry,...args],{
  cwd:ROOT,encoding:"utf8",env:process.env,
  stdio:capture?["ignore","pipe","pipe"]:input?["pipe","inherit","inherit"]:"inherit",
  ...(input?{input:opts.input}:{}),maxBuffer:4*1024*1024
 });
 if(result.error)throw Error("Failed to launch command: "+result.error.message);
 if(result.status!==0){
  throw Error("Command failed: "+args[0]+
   (capture?"; "+String(result.stderr||"").slice(0,240):""));
 }
 return capture?String(result.stdout||""):"";
}
function wrangler(args,opts={}){
 if(!existsSync(WRANGLER))throw Error("Wrangler missing. Run npm install first.");
 return run(WRANGLER,args,opts);
}
function getDatabase(){
 let value;
 try{value=JSON.parse(wrangler(["d1","list","--json"],{capture:true}));}
 catch{throw Error("Cannot read the Cloudflare D1 list safely. Check Wrangler login/account.");}
 return findStagingDatabase(value,DB_NAME);
}
function ensureDatabase(id){
 const db=getDatabase();
 if(!db||db.id!==id)throw Error("Cloudflare D1 UUID does not match saved staging DB. Stop.");
}
function ensureSecret(){
 let list;
 try{list=JSON.parse(wrangler(["secret","list","--config",CONFIG],{capture:true}));}
 catch{throw Error("Could not verify existing COMMAND_PRIVATE_KEY secret. Refusing redeploy.");}
 if(!Array.isArray(list)||!list.some(x=>x?.name==="COMMAND_PRIVATE_KEY")){
  throw Error("COMMAND_PRIVATE_KEY missing; signer cannot be recreated automatically. Manual recovery needed.");
 }
}
function rejectDualState(){
 if(existsSync(OLD_STATE)||existsSync(OLD_CONTROL)||existsSync(OLD_GATEWAY)){
  throw Error("Existing dual-Worker bootstrap state detected. Migration is NOT automatic. "+
   "Follow docs/MIGRATE_DUAL_TO_SINGLE.md and preserve current D1/signing keys.");
 }
}
function localState(){
 const count=Number(existsSync(CONFIG))+Number(existsSync(STATE));
 if(count!==0&&count!==2)throw Error("Partial staging config/state. Refusing to regenerate signer.");
 if(count===0)return null;
 const cfg=readJSON(CONFIG),state=readJSON(STATE);
 validateStoredConfig(cfg,state);
 return {cfg,state};
}
function build(){
 if(!existsSync(TSC)||!existsSync(VITE))throw Error("Run npm install first.");
 console.log("[Build] TypeScript check and Chinese web UI...");
 run(TSC,["--noEmit"]);
 run(VITE,["build","--config","apps/console/vite.config.ts"]);
}
function migrate(){
 console.log("[D1] Apply only ssh-manager-staging migrations...");
 wrangler(["d1","migrations","apply",DB_NAME,"--remote","--config",CONFIG]);
}
function deploy(){
 console.log("[Workers] Deploy exactly one Worker: ssh-manager-staging...");
 wrangler(["deploy","--config",CONFIG]);
}
async function prompts(){
 if(!process.stdin.isTTY)throw Error("First deployment needs an interactive terminal.");
 const io=createInterface({input:process.stdin,output:process.stdout});
 try{
  console.log("\nBefore proceeding, create a Cloudflare Access Self-hosted Application "+
   "for the CONTROL CUSTOM DOMAIN only, with a strict GitHub/Cloudflare Allow policy and MFA.");
  const input={
   controlHost:process.env.SSH_MANAGER_CONTROL_HOSTNAME||
    await io.question("Control hostname in your Cloudflare zone (e.g. console-staging.example.com): "),
   agentHost:process.env.SSH_MANAGER_AGENT_HOSTNAME||
    await io.question("Agent hostname in your Cloudflare zone (e.g. agent-staging.example.com): "),
   team:process.env.SSH_MANAGER_ACCESS_TEAM_DOMAIN||
    await io.question("Access team (myteam.cloudflareaccess.com): "),
   aud:process.env.SSH_MANAGER_ACCESS_AUD||
    await io.question("Control Access Application AUD: "),
   owner:process.env.SSH_MANAGER_OWNER_EMAIL||
    await io.question("Initial Owner email: ")
  };
  const controlHost=customDomain(input.controlHost);
  const agentHost=customDomain(input.agentHost);
  if(controlHost===agentHost)throw Error("Control and Agent domains must differ");
  const access=accessSettings(input);
  console.log("\nWorker custom domains: "+controlHost+" (Access), "+agentHost+" (signed devices).");
  console.log("This will never deploy old two-Worker names or modify VPS SSH.");
  const answer=await io.question("Type SINGLE-STAGING to provision a NEW single Worker: ");
  if(answer.trim()!=="SINGLE-STAGING")throw Error("Confirmation missing; no resources created");
  return {controlHost,agentHost,...access};
 }finally{io.close();}
}
function printNext(state){
 console.log("\nSINGLE WORKER STAGING DEPLOYED (NOT YET SECURITY-VERIFIED).");
 console.log("Control: https://"+state.control_hostname+" (Access must protect ALL paths)");
 console.log("Agent:   https://"+state.agent_hostname+" (device Ed25519 only)");
 console.log("Worker:  "+state.worker_name+"; D1: "+state.database_id);
 console.log("Do NOT enable worker-level Access: it would block Agent WebSocket upgrades.");
 console.log("Use a hostname-based Access Application covering ONLY the Control hostname.");
 console.log("Confirm workers.dev and preview URLs are disabled.");
 console.log("Run: python scripts/staging_remote_probe.py --staging-only "+
  "--control-url https://"+state.control_hostname+
  " --gateway-url https://"+state.agent_hostname);
 console.log("Validate that the Gateway hostname never serves /api/*, SPA or assets.");
 console.log("High-risk SSH actions remain OFF. No production VPS deployment was performed.");
 console.log("To update from this computer: git pull --ff-only && npm install && npm run cf:quick\n");
}
async function bootstrap(){
 const input=await prompts();
 let db=getDatabase();
 if(db){
  const io=createInterface({input:process.stdin,output:process.stdout});
  try{
   console.log("An existing D1 called "+DB_NAME+" was detected.");
   console.log("WARNING: an existing dual-Worker D1 may be paired to a different "+
    "Durable Object namespace. Do not migrate a live system with this wizard.");
   const confirm=await io.question('Type REUSE-SINGLE-D1 to explicitly reuse this data: ');
   if(confirm.trim()!=="REUSE-SINGLE-D1")throw Error("Existing D1 reuse not approved");
  }finally{io.close();}
 }else{
  console.log("[D1] Creating isolated "+DB_NAME+"...");
  wrangler(["d1","create",DB_NAME]);
  db=getDatabase();
  if(!db)throw Error("New staging D1 not visible. Investigate before retrying.");
 }
 const signer=generateCommandSigner();
 const cfg=buildSingleConfig(readJSON(TEMPLATE),{
  ...input,dbId:db.id,publicKey:signer.publicKey
 });
 const state={
  schema:"ssh-manager-single-worker-v1",environment:"staging",
  status:"bootstrapping",
  worker_name:cfg.name,database_id:db.id,
  command_public_key:signer.publicKey,
  control_hostname:input.controlHost,
  agent_hostname:input.agentHost,
  access_team_domain:input.team,
  access_aud:input.aud,
  owner_email:input.owner,
  created_at:new Date().toISOString()
 };
 writeJSON(CONFIG,cfg);
 writeJSON(STATE,state);
 console.log("[Local] Immutable public staging config saved; private key is NOT stored.");
 migrate();
 deploy();
 console.log("[Secret] Uploading Ed25519 PKCS#8 via stdin to SAME Worker...");
 wrangler(["secret","put","COMMAND_PRIVATE_KEY","--config",CONFIG],{
  input:signer.privateKeyPkcs8Base64+"\n"
 });
 state.status="ready";
 writeJSON(STATE,state);
 printNext(state);
}
function updateExisting(existing){
 console.log("[Staging] Reusing existing Worker, D1 and signer. No key rotation.");
 ensureDatabase(existing.state.database_id);
 ensureSecret();
 migrate();
 deploy();
 if(existing.state.status==="bootstrapping"){
  existing.state.status="ready";
  writeJSON(STATE,existing.state);
  console.log("Recovered interrupted bootstrap only because its original Control signer Secret exists.");
 }
 printNext(existing.state);
}
function offlineDryRun(){
 const signer=generateCommandSigner();
 const cfg=buildSingleConfig(readJSON(TEMPLATE),{
  dbId:"00000000-0000-4000-8000-000000000001",
  publicKey:signer.publicKey,
  controlHost:"console.staging.example.net",
  agentHost:"agent.staging.example.net",
  team:"staging.cloudflareaccess.com",
  aud:"offline-staging-aud-123456789",
  owner:"test@example.net"
 });
 if(cfg.routes.length!==2||cfg.name!=="ssh-manager-staging")throw Error("Dry-run routing invalid");
 console.log("DRY RUN PASS: ONE Worker, TWO custom domains, one D1/DO, Access gate, signer and SSH write locks.");
 console.log("No network call, no secrets uploaded, no local configuration modified.");
}
async function main(){
 const args=process.argv.slice(2);
 if(args.some(x=>!["--help","--dry-run"].includes(x)))throw Error("Supported: --help, --dry-run");
 if(args.includes("--help")){
  console.log("npm install && npx wrangler login && npm run cf:quick");
  console.log("Requires two Custom Domains within your Cloudflare zone and a Control-only Access app.");
  console.log("Repeat for updates without rotating signer. --dry-run is offline.");
  return;
 }
 if(Number(process.versions.node.split(".")[0])<22)throw Error("Node.js 22+ required");
 if(args.includes("--dry-run"))return offlineDryRun();
 rejectDualState();
 const existing=localState();
 build();
 if(existing)return updateExisting(existing);
 return bootstrap();
}
main().catch(err=>{
 console.error("\nSingle Worker deployment STOPPED:",err instanceof Error?err.message:String(err));
 if(existsSync(STATE)){
  console.error("Existing staged state preserved. DO NOT delete it or auto-rotate keys.");
  console.error("If the original Cloudflare COMMAND_PRIVATE_KEY is missing, "+
   "follow manual recovery in docs/MIGRATE_DUAL_TO_SINGLE.md.");
 }
 process.exitCode=1;
});
