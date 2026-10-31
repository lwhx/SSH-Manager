// Recover the original NON-SECRET staging deployment configuration from the
// existing Cloudflare Worker. Never use account-level defaults or rotate keys.
import {buildSingleConfig,findStagingDatabase} from "./cloudflare_quick_lib.mjs";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SETTINGS=["CONTROL_HOSTNAME","AGENT_HOSTNAME","ACCESS_TEAM_DOMAIN",
 "ACCESS_AUD","BOOTSTRAP_OWNER_EMAIL","COMMAND_PUBLIC_KEY",
 "MANUAL_SSH_ACTIONS_ENABLED"];

function uniqueBinding(bindings,name){
 const matches=bindings.filter(x=>x&&x.name===name);
 if(matches.length!==1)throw Error("Worker binding missing/duplicate: "+name);
 return matches[0];
}
export function extractExistingStagingWorker(template,rawSettings,list){
 const bindings=rawSettings?.bindings;
 if(!Array.isArray(bindings)||bindings.length<9)
  throw Error("Remote Worker settings are missing or incomplete; refusing deployment");
 const vars={};
 for(const name of SETTINGS){
  const entry=uniqueBinding(bindings,name);
  if(entry.type!=="plain_text"||typeof entry.text!=="string")
   throw Error("Remote Worker variable has unexpected type: "+name);
  vars[name]=entry.text;
 }
 if(vars.MANUAL_SSH_ACTIONS_ENABLED!=="false")
  throw Error("Manual SSH writes are enabled on remote Worker; automatic deployment is locked");
 const secret=uniqueBinding(bindings,"COMMAND_PRIVATE_KEY");
 if(secret.type!=="secret_text")
  throw Error("Existing private signer Secret not found; refusing to generate or replace a key");
 const db=uniqueBinding(bindings,"DB");
 if(db.type!=="d1")throw Error("Remote D1 binding has incorrect type");
 const dbId=db.database_id||db.id;
 if(typeof dbId!=="string"||!UUID.test(dbId))
  throw Error("Remote D1 binding UUID is invalid");
 const found=findStagingDatabase(list,"ssh-manager-staging");
 if(!found||found.id!==dbId.toLowerCase())
  throw Error("The original D1 database is missing or belongs to another Cloudflare account");
 const durable=uniqueBinding(bindings,"NODE_SESSIONS");
 if(durable.type!=="durable_object_namespace"||
  durable.class_name!=="NodeSession"||durable.script_name)
  throw Error("Expected same-Worker NodeSession DO; refusing legacy cross-Worker migration");
 const cfg=buildSingleConfig(template,{
  dbId,
  publicKey:vars.COMMAND_PUBLIC_KEY,
  controlHost:vars.CONTROL_HOSTNAME,
  agentHost:vars.AGENT_HOSTNAME,
  team:vars.ACCESS_TEAM_DOMAIN,
  aud:vars.ACCESS_AUD,
  owner:vars.BOOTSTRAP_OWNER_EMAIL
 });
 // Restrict to the Worker actually deployed by the one-time bootstrap:
 if(cfg.name!=="ssh-manager-staging"||cfg.workers_dev!==false||
  cfg.preview_urls!==false||cfg.assets.run_worker_first!==true||
  cfg.routes.length!==2)throw Error("Unsafe single-Worker deployment config");
 return cfg;
}
export function extractWhoamiAccount(json){
 const all=[];
 const visit=x=>{
  if(Array.isArray(x)){for(const y of x)visit(y);return;}
  if(!x||typeof x!=="object")return;
  for(const entry of [x.account,x]){
   if(entry&&typeof entry==="object"&&typeof entry.id==="string"&&
    /^[a-f0-9]{32}$/i.test(entry.id))all.push(entry.id.toLowerCase());
  }
  if(x.accounts)visit(x.accounts);
  if(x.memberships)visit(x.memberships);
 };
 visit(json);
 const unique=[...new Set(all)];
 if(unique.length!==1)
  throw Error("Multiple/no Cloudflare accounts. Set CLOUDFLARE_ACCOUNT_ID in the build environment.");
 return unique[0];
}
export function requireCloudflareSettingsResponse(json){
 if(!json||json.success!==true||!json.result||
  !Array.isArray(json.result.bindings))
  throw Error("Cloudflare returned an incomplete Worker settings response");
 return json.result;
}
