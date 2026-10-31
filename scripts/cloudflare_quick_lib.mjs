import {generateKeyPairSync} from "node:crypto";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RAW_PUB=/^[A-Za-z0-9_-]{43}$/;
const EMAIL=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TEAM=/^[a-z0-9-]+\.cloudflareaccess\.com$/;
const AUD=/^[A-Za-z0-9_-]{16,128}$/;

export function accessSettings(input){
 const team=String(input.team||"").trim().replace(/^https:\/\//i,"").replace(/\/$/,"").toLowerCase();
 const aud=String(input.aud||"").trim();
 const owner=String(input.owner||"").trim().toLowerCase();
 if(!TEAM.test(team)||team==="replace.cloudflareaccess.com"||team==="example.cloudflareaccess.com"){throw Error("ACCESS_TEAM_DOMAIN_INVALID: expected your real team.cloudflareaccess.com");}
 if(!AUD.test(aud)||aud.startsWith("REPLACE"))throw Error("ACCESS_AUD_INVALID: use the actual Access application AUD");
 if(!EMAIL.test(owner)||owner==="owner@example.com")throw Error("OWNER_EMAIL_INVALID");
 return {team,aud,owner};
}
export function generateCommandSigner(){
 const {privateKey,publicKey}=generateKeyPairSync("ed25519");
 const key=publicKey.export({format:"jwk"});
 if(typeof key.x!=="string"||!RAW_PUB.test(key.x))throw Error("Ed25519 raw public key generation failed");
 return {
  publicKey:key.x,
  // Cloudflare Control imports base64-encoded PKCS#8 DER, not PEM text.
  privateKeyPkcs8Base64:privateKey.export({type:"pkcs8",format:"der"}).toString("base64")
 };
}
export function findStagingDatabase(value,name="ssh-manager-staging"){
 const list=Array.isArray(value)?value:Array.isArray(value?.result)?value.result:
  Array.isArray(value?.databases)?value.databases:null;
 if(!list)throw Error("Unrecognized Wrangler d1 list --json response; no database changes made");
 const matches=list.filter(item=>item?.name===name);
 if(matches.length>1)throw Error("Multiple D1 databases matched the staging name");
 if(matches.length===0)return null;
 const id=String(matches[0].uuid||matches[0].id||matches[0].database_id||"");
 if(!UUID.test(id))throw Error("Cannot extract staging D1 UUID from Wrangler response");
 return {name,id:id.toLowerCase()};
}
export function buildConfigs(controlTemplate,gatewayTemplate,params){
 const {dbId,publicKey}=params;
 if(!UUID.test(dbId))throw Error("Invalid D1 UUID");
 if(!RAW_PUB.test(publicKey))throw Error("Invalid Ed25519 raw base64url public key");
 const {team,aud,owner}=accessSettings(params);
 const control=structuredClone(controlTemplate);
 const gateway=structuredClone(gatewayTemplate);
 if(control.name!=="ssh-manager-control-staging"||
  gateway.name!=="ssh-manager-agent-gateway-staging"||
  control.durable_objects?.bindings?.[0]?.script_name!==gateway.name){
  throw Error("Staging template names or cross-Worker Durable Object binding mismatch");
 }
 for(const c of [control,gateway]){
  if(c.d1_databases?.length!==1||c.d1_databases[0].binding!=="DB"||
    c.d1_databases[0].database_name!=="ssh-manager-staging"){
   throw Error("Unexpected D1 binding; will not update a non-staging database");
  }
  c.d1_databases[0].database_id=dbId.toLowerCase();
 }
 control.vars.ACCESS_TEAM_DOMAIN=team;
 control.vars.ACCESS_AUD=aud;
 control.vars.BOOTSTRAP_OWNER_EMAIL=owner;
 control.vars.MANUAL_SSH_ACTIONS_ENABLED="false";
 gateway.vars.COMMAND_PUBLIC_KEY=publicKey;
 return {control,gateway};
}
export function validateStoredConfigs(control,gateway,state){
 if(state?.environment!=="staging"||!UUID.test(String(state?.database_id||""))||
  state?.control_name!=="ssh-manager-control-staging"||
  state?.gateway_name!=="ssh-manager-agent-gateway-staging"){
  throw Error("Invalid staging local state; refusing to deploy");
 }
 if(control.name!==state.control_name||gateway.name!==state.gateway_name||
  control.d1_databases?.[0]?.database_id!==state.database_id||
  gateway.d1_databases?.[0]?.database_id!==state.database_id||
  gateway.vars?.COMMAND_PUBLIC_KEY!==state.command_public_key||
  control.durable_objects?.bindings?.[0]?.script_name!==gateway.name||
  control.vars?.MANUAL_SSH_ACTIONS_ENABLED!=="false"||
  !RAW_PUB.test(String(state.command_public_key||""))){
  throw Error("Staging binding, public key or safety lock changed; no deployment performed");
 }
 accessSettings({
  team:control.vars.ACCESS_TEAM_DOMAIN,
  aud:control.vars.ACCESS_AUD,
  owner:control.vars.BOOTSTRAP_OWNER_EMAIL
 });
 if(state.status!=="ready"&&state.status!=="bootstrapping"){
  throw Error("Unknown staging bootstrap phase");
 }
}
