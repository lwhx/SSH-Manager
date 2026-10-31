#!/usr/bin/env node
// Cloudflare STAGING quick deploy: one-time interactive bootstrap, then repeatable updates.
// Never deploys production Worker names, rotates existing signers or touches any VPS.
import {spawnSync} from "node:child_process";
import {existsSync,mkdirSync,readFileSync,renameSync,writeFileSync} from "node:fs";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {createInterface} from "node:readline/promises";
import {
 accessSettings,buildConfigs,findStagingDatabase,generateCommandSigner,validateStoredConfigs
} from "./cloudflare_quick_lib.mjs";

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const WRANGLER=join(ROOT,"node_modules","wrangler","bin","wrangler.js");
const TSC=join(ROOT,"node_modules","typescript","bin","tsc");
const VITE=join(ROOT,"node_modules","vite","bin","vite.js");
const CONTROL=join(ROOT,"wrangler.control.staging.local.jsonc");
const GATEWAY=join(ROOT,"wrangler.gateway.staging.local.jsonc");
const STATE=join(ROOT,".ssh-manager-deploy","staging.json");
const DB_NAME="ssh-manager-staging";

function readJSON(p){return JSON.parse(readFileSync(p,"utf8"));}
function writeJSON(p,data){
 mkdirSync(dirname(p),{recursive:true,mode:0o700});
 const tmp=p+".tmp-"+process.pid;
 writeFileSync(tmp,JSON.stringify(data,null,2)+"\n",{mode:0o600,flag:"wx"});
 renameSync(tmp,p);
}
function runNode(entry,args=[],options={}){
 const capture=options.capture===true;
 const withInput=typeof options.input==="string";
 const result=spawnSync(process.execPath,[entry,...args],{
  cwd:ROOT,encoding:"utf8",env:process.env,
  stdio:capture?["ignore","pipe","pipe"]:withInput?["pipe","inherit","inherit"]:"inherit",
  ...(withInput?{input:options.input}:{}),
  maxBuffer:4*1024*1024
 });
 if(result.error)throw Error("Command could not start: "+result.error.message);
 if(result.status!==0){
  // Never include command stdin (potentially the signer private key) in errors.
  throw Error("Command failed ("+result.status+"): "+(args[0]||"command")+
   (capture?"; "+String(result.stderr||"").slice(0,300):""));
 }
 return capture?String(result.stdout||""):"";
}
function wrangler(args,options={}){
 if(!existsSync(WRANGLER))throw Error("Missing Wrangler. Run npm ci before npm run cf:quick.");
 return runNode(WRANGLER,args,options);
}
function databaseList(){
 const output=wrangler(["d1","list","--json"],{capture:true});
 let parsed;
 try{parsed=JSON.parse(output);}catch{throw Error("Wrangler d1 list did not return JSON; refused to select a database");}
 return findStagingDatabase(parsed,DB_NAME);
}
function verifyDatabase(id){
 const remote=databaseList();
 if(!remote||remote.id!==id){
  throw Error("Current Cloudflare account does not contain the expected STAGING D1 UUID; refusing deploy");
 }
}
function verifyControlSecret(){
 let existing;
 try{existing=JSON.parse(wrangler(["secret","list","--config",CONTROL],{capture:true}));}
 catch{throw Error("Cannot verify Control Worker secret; refusing keyless redeploy");}
 if(!Array.isArray(existing)||!existing.some(item=>item?.name==="COMMAND_PRIVATE_KEY")){
  throw Error("COMMAND_PRIVATE_KEY is missing on Control Worker; refusing silent signer rotation");
 }
}
function validateLocal(){
 const count=Number(existsSync(CONTROL))+Number(existsSync(GATEWAY))+Number(existsSync(STATE));
 if(count!==0&&count!==3)throw Error("Partial local staging state: do not regenerate a signer; inspect local files");
 if(count===0)return null;
 const control=readJSON(CONTROL),gateway=readJSON(GATEWAY),state=readJSON(STATE);
 validateStoredConfigs(control,gateway,state);
 return {control,gateway,state};
}
function build(){
 if(!existsSync(TSC)||!existsSync(VITE))throw Error("Dependencies are missing. Run npm ci first.");
 console.log("\n[1/4] Checking code and building the Chinese web panel...");
 runNode(TSC,["--noEmit"]);
 runNode(VITE,["build","--config","apps/console/vite.config.ts"]);
}
function migrate(){
 console.log("\nApplying remote D1 migrations (Staging database only)...");
 // Wrangler asks for confirmation when running interactively.
 wrangler(["d1","migrations","apply","DB","--remote","--config",CONTROL]);
}
function deployWorkers(){
 console.log("\n[Workers] Deploying Agent Gateway first...");
 wrangler(["deploy","--config",GATEWAY]);
 console.log("\n[Workers] Deploying Control Worker with web assets...");
 wrangler(["deploy","--config",CONTROL]);
}
async function askSetup(){
 if(!process.stdin.isTTY)throw Error(
  "First deployment needs an interactive terminal. Configure Cloudflare Access first, then run in PowerShell.");
 const io=createInterface({input:process.stdin,output:process.stdout});
 try{
  console.log("\nYou must first create a Cloudflare Zero Trust Access application for the "+
   "Control Worker, with GitHub / Cloudflare identity providers and an allow policy.");
  const team=process.env.SSH_MANAGER_ACCESS_TEAM_DOMAIN||
   await io.question("Access team domain (example.cloudflareaccess.com): ");
  const aud=process.env.SSH_MANAGER_ACCESS_AUD||
   await io.question("Control Access application AUD (NOT a secret): ");
  const owner=process.env.SSH_MANAGER_OWNER_EMAIL||
   await io.question("Initial Owner's full email address: ");
  const config=accessSettings({team,aud,owner});
  console.log("\nSTAGING ONLY: create/reuse "+DB_NAME+"; deploy Control and Gateway.");
  console.log("Control Access MUST restrict the selected hostname or Worker.");
  console.log("Agent Gateway MUST NOT be protected by browser Access (WSS would fail).");
  const ok=await io.question('Type STAGING to confirm no production VPS/SSH changes: ');
  if(ok.trim()!=="STAGING")throw Error("Staging confirmation not supplied; no remote resource created");
  return config;
 }finally{io.close();}
}
function printNextSteps(){
 console.log("\n==================================================");
 console.log("Staging Workers deployment commands completed.");
 console.log("IMPORTANT: do not connect production VPS yet.");
 console.log("1. In Cloudflare Zero Trust, verify Control Worker is protected by Access.");
 console.log("2. Ensure the Access app uses the configured team domain and AUD.");
 console.log("3. Allow ONLY your GitHub/Cloudflare identities (with MFA).");
 console.log("4. Never put browser Access in front of Agent Gateway WebSockets.");
 console.log("5. Check both Workers' deployed URLs in the Wrangler output above.");
 console.log("6. Run docs/P3_STAGING_LIVE_RUNBOOK.md T01-T11 before production use.");
 console.log("7. Repeat 'npm run cf:quick' to deploy updates (same D1 and signer).");
 console.log("Manual SSH actions remain LOCKED (false) by default.");
 console.log("==================================================\n");
}
async function bootstrap(){
 const cfg=await askSetup();
 console.log("\n[Cloudflare] Checking staging D1...");
 let db=databaseList();
 if(!db){
  console.log("Creating "+DB_NAME+"...");
  wrangler(["d1","create",DB_NAME]);
  db=databaseList();
  if(!db)throw Error("D1 creation was not visible in account. Stop and inspect Cloudflare dashboard.");
 }else{
  console.log("Found existing staging D1 "+db.id);
  if(!process.stdin.isTTY)throw Error("Existing staging D1 requires an interactive confirmation");
  const io=createInterface({input:process.stdin,output:process.stdout});
  try{
   const answer=await io.question("Type the full name "+DB_NAME+" to REUSE its existing data: ");
   if(answer.trim()!==DB_NAME)throw Error("Existing database reuse not authorized");
  }finally{io.close();}
 }
 const signer=generateCommandSigner();
 const templates={
  control:readJSON(join(ROOT,"wrangler.control.staging.example.jsonc")),
  gateway:readJSON(join(ROOT,"wrangler.gateway.staging.example.jsonc"))
 };
 const configs=buildConfigs(templates.control,templates.gateway,{
  ...cfg,dbId:db.id,publicKey:signer.publicKey
 });
 const state={
  environment:"staging",
  status:"bootstrapping",
  database_id:db.id,
  control_name:configs.control.name,
  gateway_name:configs.gateway.name,
  command_public_key:signer.publicKey,
  // Public material only. Root/device private keys are NEVER saved here.
  created_at:new Date().toISOString()
 };
 writeJSON(CONTROL,configs.control);
 writeJSON(GATEWAY,configs.gateway);
 writeJSON(STATE,state);
 console.log("\nStaging configs created locally and excluded from Git.");
 migrate();
 deployWorkers();
 console.log("\nUploading ephemeral PKCS#8 signer to Control Worker secret store...");
 // The private key exists only in this Node process and is passed via stdin.
 // It is NOT printed, written to disk or uploaded to GitHub.
 wrangler(["secret","put","COMMAND_PRIVATE_KEY","--config",CONTROL],{
  input:signer.privateKeyPkcs8Base64+"\n"
 });
 state.status="ready";
 writeJSON(STATE,state);
 printNextSteps();
}
async function updateExisting(local){
 console.log("\n[Staging] Reusing existing D1, immutable signer and Worker names.");
 verifyDatabase(local.state.database_id);
 verifyControlSecret();
 if(local.state.status==="bootstrapping"){
  // It is possible a prior run uploaded the secret, then crashed before
  // recording ready. Only a confirmed existing Cloudflare secret can recover.
  local.state.status="ready";
  writeJSON(STATE,local.state);
  console.log("Recovered local staging phase after verifying existing Worker secret.");
 }
 migrate();
 deployWorkers();
 printNextSteps();
}
async function main(){
 const args=process.argv.slice(2);
 if(args.some(x=>!["--dry-run","--help"].includes(x)))throw Error("Unknown option. Supported: --dry-run, --help");
 if(args.includes("--help")){
  console.log("Run: npm ci && npm run cf:quick");
  console.log("First run prompts for Access team, AUD, Owner and STAGING confirmation.");
  console.log("Next runs safely reuse D1 and signer. --dry-run never contacts Cloudflare.");
  return;
 }
 if(Number(process.versions.node.split(".")[0])<22)throw Error("Node.js 22+ required");
 if(args.includes("--dry-run")){
  const cfg=buildConfigs(
   readJSON(join(ROOT,"wrangler.control.staging.example.jsonc")),
   readJSON(join(ROOT,"wrangler.gateway.staging.example.jsonc")),{
    dbId:"00000000-0000-4000-8000-000000000001",
    publicKey:generateCommandSigner().publicKey,
    team:"staging.cloudflareaccess.com",
    aud:"staging-aud-dryrun-0123456789",
    owner:"test@example.net"
   });
  console.log("DRY RUN PASS: paired staging Worker configs, DB binding, signer and disabled manual SSH features.");
  console.log("Target Workers:",cfg.control.name,"+",cfg.gateway.name);
  console.log("No network calls, no remote resources created, no local config files modified.");
  return;
 }
 const existing=validateLocal();
 if(!existsSync(WRANGLER))throw Error("Run npm ci to install Wrangler first");
 build();
 if(existing)await updateExisting(existing);
 else await bootstrap();
}
main().catch(err=>{
 console.error("\nQuick deployment stopped safely:",err instanceof Error?err.message:String(err));
 console.error("No production Worker or VPS action was requested.");
 if(existsSync(STATE))console.error(
  "For interrupted bootstrap, DO NOT delete local state or regenerate keys. "+
  "If Control secret exists, running again can safely resume.");
 process.exitCode=1;
});
