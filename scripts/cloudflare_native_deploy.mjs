#!/usr/bin/env node
// Cloudflare Workers Builds/GitHub integration: redeploy the SAME Worker.
//
// No parameters such as D1 UUID, domain, Access AUD, public signer or owner
// email need to be re-entered. Recover non-secret bindings from the already
// deployed Worker via Cloudflare's READ-ONLY settings API. NEVER bootstrap a
// new signer, Worker or D1 in a Git build.
import {existsSync,readFileSync,writeFileSync,mkdirSync,rmSync} from "node:fs";
import {dirname,resolve,join} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";
import {
 extractExistingStagingWorker,extractWhoamiAccount,requireCloudflareSettingsResponse
} from "./cloudflare_native_lib.mjs";

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const WRANGLER=join(ROOT,"node_modules","wrangler","bin","wrangler.js");
const TEMPLATE=join(ROOT,"wrangler.single.staging.example.jsonc");
const CONFIG=join(ROOT,".ssh-manager-deploy","native-build.jsonc");
const NAME="ssh-manager-staging";
const DB="ssh-manager-staging";

function run(entry,args,options={}){
 const child=spawnSync(process.execPath,[entry,...args],{
  cwd:ROOT,env:process.env,encoding:"utf8",
  stdio:options.capture?["ignore","pipe","pipe"]:"inherit",
  maxBuffer:4*1024*1024
 });
 if(child.error)throw Error("Unable to execute "+args[0]+": "+child.error.message);
 if(child.status!==0){
  throw Error("Command failed: "+args[0]+
   (options.capture?", check Cloudflare login/API token and permissions":""));
 }
 return options.capture?String(child.stdout||""):"";
}
function wrangler(args,options={}){
 if(!existsSync(WRANGLER))throw Error("Wrangler missing. Run npm install before deployment.");
 return run(WRANGLER,args,options);
}
function accountId(){
 if(process.env.CLOUDFLARE_ACCOUNT_ID){
  const id=process.env.CLOUDFLARE_ACCOUNT_ID.trim();
  if(!/^[a-f0-9]{32}$/i.test(id))throw Error("CLOUDFLARE_ACCOUNT_ID is not a valid account ID");
  return id;
 }
 const output=wrangler(["whoami","--json"],{capture:true});
 let json;
 try{json=JSON.parse(output);}catch{
  throw Error("Cannot discover Cloudflare Account ID. Add CLOUDFLARE_ACCOUNT_ID to Build Variables.");
 }
 return extractWhoamiAccount(json);
}
async function settings(id){
 const token=process.env.CLOUDFLARE_API_TOKEN;
 if(!token)throw Error(
  "Cloudflare Build requires CLOUDFLARE_API_TOKEN for read-only Worker settings lookup. "+
  "Use a scoped Cloudflare Builds API token with Workers Scripts Read/Edit + D1 Edit permissions.");
 const response=await fetch(
  "https://api.cloudflare.com/client/v4/accounts/"+id+"/workers/scripts/"+NAME+"/settings",
  {headers:{Authorization:"Bearer "+token,Accept:"application/json"},
   signal:AbortSignal.timeout(12000)}
 );
 if(response.status===404)throw Error(
  "Worker "+NAME+" does not exist. First run npm run cf:quick locally to initialize D1 and the command signer.");
 if(response.status===401||response.status===403)throw Error(
  "Cloudflare Build API token cannot read the existing Worker. Check scoped Workers Scripts permissions.");
 if(!response.ok)throw Error("Unable to read Worker settings (HTTP "+response.status+"). No deployment performed.");
 let json;
 try{json=await response.json();}catch{throw Error("Cloudflare returned invalid settings JSON");}
 return requireCloudflareSettingsResponse(json);
}
function databases(){
 let data;
 try{data=JSON.parse(wrangler(["d1","list","--json"],{capture:true}));}
 catch{throw Error("Cannot list existing D1. Ensure Build API token has D1 Read permission.");}
 return data;
}
function writeConfig(config){
 if(existsSync(CONFIG))throw Error("Temporary build configuration already exists; refusing to overwrite.");
 mkdirSync(dirname(CONFIG),{recursive:true,mode:0o700});
 writeFileSync(CONFIG,JSON.stringify(config,null,2)+"\n",{flag:"wx",mode:0o600});
}
function ensureOriginalSigner(){
 const raw=wrangler(["secret","list","--config",CONFIG],{capture:true});
 let items;
 try{items=JSON.parse(raw);}catch{throw Error("Cannot inspect existing Cloudflare Worker secrets");}
 if(!Array.isArray(items)||!items.some(x=>x?.name==="COMMAND_PRIVATE_KEY"))
  throw Error("Existing command private key is missing: refusing automatic key rotation");
}
function buildAssets(){
 console.log("[Build] Generating Control panel assets...");
 // The Native Builds 'Build command' may be left blank.
 const npm=process.platform==="win32"?"npm.cmd":"npm";
 const child=spawnSync(npm,["run","build:web"],{
  cwd:ROOT,env:process.env,stdio:"inherit"
 });
 if(child.error||child.status!==0)throw Error("Web build failed");
 const index=join(ROOT,"apps","console","dist","index.html");
 if(!existsSync(index))throw Error("Control panel assets were not generated");
}
async function main(){
 if(process.argv.length!==2)throw Error("Run: npm run cf:deploy (no arguments)");
 const id=accountId();
 console.log("[1/4] Reading verified settings from existing Cloudflare staging Worker...");
 const original=await settings(id);
 const template=JSON.parse(readFileSync(TEMPLATE,"utf8"));
 const config=extractExistingStagingWorker(template,original,databases());
 console.log("[2/4] Found original D1, domains and pinned public key; high-risk SSH writes remain off.");
 writeConfig(config);
 try{
  ensureOriginalSigner();
  buildAssets();
  console.log("[3/4] Applying only pending Staging D1 migrations...");
  wrangler(["d1","migrations","apply",DB,"--remote","--config",CONFIG]);
  console.log("[4/4] Deploying the original single Worker...");
  wrangler(["deploy","--config",CONFIG]);
 }finally{
  // Non-secret, locally generated file; remove even when build fails.
  rmSync(CONFIG,{force:true});
 }
 console.log("DEPLOY OK: one Worker, two exact custom domains, original D1 and signer kept.");
 console.log("Cloudflare Access and real VPS T01-T11 must still be checked before production use.");
}
main().catch(e=>{
 console.error("Safe Cloudflare deployment stopped:",e instanceof Error?e.message:String(e));
 console.error("No signing keys rotated, no D1 deleted, no VPS SSH action performed.");
 process.exitCode=1;
});
