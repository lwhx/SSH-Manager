#!/usr/bin/env node
// GitHub Actions renders NON-SECRET Cloudflare single Worker Staging config.
// The private Ed25519 command key stays only in Cloudflare Worker Secret.
import {readFileSync,writeFileSync} from "node:fs";
import {resolve,dirname} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";
import {buildSingleConfig} from "./cloudflare_quick_lib.mjs";

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const CONFIG=resolve(ROOT,process.env.SSH_MANAGER_CI_CONFIG_OUTPUT||"wrangler.single.staging.ci.jsonc");
const TEMPLATE=resolve(ROOT,"wrangler.single.staging.example.jsonc");
const WRANGLER=resolve(ROOT,"node_modules/wrangler/bin/wrangler.js");
function required(name){
 const value=String(process.env[name]||"").trim();
 if(!value)throw Error("Missing required GitHub Actions variable: "+name);
 return value;
}
function render(){
 const cfg=buildSingleConfig(JSON.parse(readFileSync(TEMPLATE,"utf8")),{
  dbId:required("SSH_MANAGER_STAGING_D1_UUID"),
  publicKey:required("SSH_MANAGER_STAGING_COMMAND_PUBLIC_KEY"),
  controlHost:required("SSH_MANAGER_STAGING_CONTROL_HOSTNAME"),
  agentHost:required("SSH_MANAGER_STAGING_AGENT_HOSTNAME"),
  team:required("SSH_MANAGER_STAGING_ACCESS_TEAM_DOMAIN"),
  aud:required("SSH_MANAGER_STAGING_ACCESS_AUD"),
  owner:required("SSH_MANAGER_STAGING_OWNER_EMAIL")
 });
 if(cfg.name!=="ssh-manager-staging"||
  cfg.vars.MANUAL_SSH_ACTIONS_ENABLED!=="false"){
  throw Error("Unsafe staging Worker settings");
 }
 writeFileSync(CONFIG,JSON.stringify(cfg,null,2)+"\n",{mode:0o600,flag:"wx"});
 console.log("One Worker, two exact Custom Domains, one D1/DO. SSH writes locked.");
}
function verifySecret(){
 const res=spawnSync(process.execPath,[WRANGLER,"secret","list","--config",CONFIG],{
  cwd:ROOT,env:process.env,encoding:"utf8",maxBuffer:1024*1024
 });
 if(res.error||res.status!==0)throw Error("Cannot verify existing Cloudflare signing Secret");
 let list;
 try{list=JSON.parse(res.stdout);}catch{throw Error("Invalid Wrangler secret list response");}
 if(!Array.isArray(list)||!list.some(x=>x?.name==="COMMAND_PRIVATE_KEY")){
  throw Error("Cloudflare COMMAND_PRIVATE_KEY missing; first perform the local one-time bootstrap.");
 }
 console.log("Existing Cloudflare signer Secret present; key was NOT rotated.");
}
try{
 const mode=process.argv[2];
 if(mode==="render")render();
 else if(mode==="verify-secret")verifySecret();
 else throw Error("Usage: cloudflare_ci_config.mjs render|verify-secret");
}catch(err){
 console.error("Single Worker CI guard:",err instanceof Error?err.message:String(err));
 process.exitCode=1;
}
