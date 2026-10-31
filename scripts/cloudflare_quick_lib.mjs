import {generateKeyPairSync} from "node:crypto";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RAW_PUB=/^[A-Za-z0-9_-]{43}$/;
const EMAIL=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TEAM=/^[a-z0-9-]+\.cloudflareaccess\.com$/;
const AUD=/^[A-Za-z0-9_-]{16,128}$/;
const STAGING_WORKER="ssh-manager-staging";
const DB_NAME="ssh-manager-staging";

export function accessSettings(input){
 const team=String(input.team||"").trim().replace(/^https:\/\//i,"").replace(/\/$/,"").toLowerCase();
 const aud=String(input.aud||"").trim();
 const owner=String(input.owner||"").trim().toLowerCase();
 if(!TEAM.test(team)||team==="replace.cloudflareaccess.com"||
  team==="example.cloudflareaccess.com"){
  throw Error("ACCESS_TEAM_DOMAIN_INVALID: expected your team.cloudflareaccess.com");
 }
 if(!AUD.test(aud)||aud.startsWith("REPLACE"))throw Error("ACCESS_AUD_INVALID: use your actual Access application AUD");
 if(!EMAIL.test(owner)||owner==="owner@example.com")throw Error("OWNER_EMAIL_INVALID");
 return {team,aud,owner};
}
export function customDomain(input){
 const h=String(input||"").trim().toLowerCase();
 if(h.length<4||h.length>253||!h.includes(".")||h.includes("..")||
  h.includes("*")||h.includes("/")||h.includes(":")||
  h.endsWith(".workers.dev")||h==="workers.dev"||
  h.includes("replace")||!h.split(".").every(label=>
   label.length>0&&label.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))){
  throw Error("CUSTOM_DOMAIN_INVALID: must be an explicit hostname in your Cloudflare zone (not workers.dev)");
 }
 return h;
}
export function generateCommandSigner(){
 const {privateKey,publicKey}=generateKeyPairSync("ed25519");
 const key=publicKey.export({format:"jwk"});
 if(typeof key.x!=="string"||!RAW_PUB.test(key.x))throw Error("Ed25519 public key generation failed");
 return {
  publicKey:key.x,
  privateKeyPkcs8Base64:privateKey.export({type:"pkcs8",format:"der"}).toString("base64")
 };
}
export function findStagingDatabase(value,name=DB_NAME){
 const list=Array.isArray(value)?value:Array.isArray(value?.result)?value.result:
  Array.isArray(value?.databases)?value.databases:null;
 if(!list)throw Error("Unknown Wrangler d1 list JSON response");
 const matches=list.filter(item=>item?.name===name);
 if(matches.length>1)throw Error("Multiple matching staging databases");
 if(matches.length===0)return null;
 const id=String(matches[0].uuid||matches[0].id||matches[0].database_id||"");
 if(!UUID.test(id))throw Error("Invalid staging D1 UUID in Wrangler response");
 return {name,id:id.toLowerCase()};
}
function isSingleTemplate(cfg){
 const binds=cfg?.durable_objects?.bindings;
 const mig=cfg?.migrations;
 return cfg?.name===STAGING_WORKER&&cfg?.main==="apps/single-worker/src/index.ts"&&
  cfg?.d1_databases?.length===1&&
  cfg.d1_databases[0]?.binding==="DB"&&
  cfg.d1_databases[0]?.database_name===DB_NAME&&
  binds?.length===1&&binds[0]?.name==="NODE_SESSIONS"&&
  binds[0]?.class_name==="NodeSession"&&!binds[0]?.script_name&&
  mig?.length===1&&mig[0]?.tag==="v1"&&
  mig[0]?.new_sqlite_classes?.length===1&&mig[0]?.new_sqlite_classes[0]==="NodeSession"&&
  cfg?.assets?.binding==="ASSETS"&&cfg?.assets?.run_worker_first===true&&
  cfg?.assets?.directory==="./apps/console/dist"&&
  cfg?.workers_dev===false&&cfg?.preview_urls===false&&
  cfg?.routes?.length===2&&cfg.routes.every(r=>r?.custom_domain===true);
}
export function buildSingleConfig(template,params){
 const {dbId,publicKey}=params;
 if(!UUID.test(String(dbId||"")))throw Error("D1 UUID missing or invalid");
 if(!RAW_PUB.test(String(publicKey||"")))throw Error("Command Ed25519 raw public key invalid");
 const {team,aud,owner}=accessSettings(params);
 const controlHost=customDomain(params.controlHost);
 const agentHost=customDomain(params.agentHost);
 if(controlHost===agentHost)throw Error("Control and Agent domains must differ");
 if(!isSingleTemplate(template))throw Error("Refusing unsafe or non-single-Worker template");
 const cfg=structuredClone(template);
 cfg.d1_databases[0].database_id=dbId.toLowerCase();
 cfg.routes=[
  {pattern:controlHost,custom_domain:true},
  {pattern:agentHost,custom_domain:true}
 ];
 Object.assign(cfg.vars,{
  CONTROL_HOSTNAME:controlHost,
  AGENT_HOSTNAME:agentHost,
  ACCESS_TEAM_DOMAIN:team,
  ACCESS_AUD:aud,
  BOOTSTRAP_OWNER_EMAIL:owner,
  COMMAND_PUBLIC_KEY:publicKey,
  MANUAL_SSH_ACTIONS_ENABLED:"false"
 });
 return cfg;
}
export function validateStoredConfig(cfg,state){
 if(!isSingleTemplate(cfg)||state?.schema!=="ssh-manager-single-worker-v1"||
  state?.environment!=="staging"||state?.worker_name!==STAGING_WORKER||
  state?.status!=="ready"&&state?.status!=="bootstrapping"||
  !UUID.test(String(state?.database_id||""))||!RAW_PUB.test(String(state?.command_public_key||""))){
  throw Error("Invalid local single-Worker state; cannot redeploy");
 }
 const {controlHost,agentHost,team,aud,owner}={
  controlHost:customDomain(state.control_hostname),
  agentHost:customDomain(state.agent_hostname),
  ...accessSettings({
   team:cfg.vars?.ACCESS_TEAM_DOMAIN,
   aud:cfg.vars?.ACCESS_AUD,
   owner:cfg.vars?.BOOTSTRAP_OWNER_EMAIL
  })
 };
 if(controlHost===agentHost||cfg.d1_databases[0].database_id!==state.database_id||
  cfg.routes[0].pattern!==controlHost||cfg.routes[1].pattern!==agentHost||
  cfg.vars?.CONTROL_HOSTNAME!==controlHost||cfg.vars?.AGENT_HOSTNAME!==agentHost||
  cfg.vars?.COMMAND_PUBLIC_KEY!==state.command_public_key||
  cfg.vars?.ACCESS_TEAM_DOMAIN!==team||cfg.vars?.ACCESS_AUD!==aud||
  cfg.vars?.BOOTSTRAP_OWNER_EMAIL!==owner||
  cfg.vars?.MANUAL_SSH_ACTIONS_ENABLED!=="false"||
  Object.prototype.hasOwnProperty.call(cfg.vars||{},"COMMAND_PRIVATE_KEY")){
  throw Error("Domain, D1, signer or security settings changed; refusing deployment");
 }
 if(state.access_team_domain!==team||state.access_aud!==aud||state.owner_email!==owner){
  throw Error("Access identity settings differ from initial Staging state");
 }
}
