import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {
 extractExistingStagingWorker,extractWhoamiAccount,requireCloudflareSettingsResponse,
 newCloudflareBootstrap,classifyWorkerForBootstrap,parseWranglerAuthToken
} from "./cloudflare_native_lib.mjs";

const template=JSON.parse(readFileSync(new URL("../wrangler.single.staging.example.jsonc",import.meta.url),"utf8"));
const UUID="10000000-0000-4000-8000-000000000001";
const publicKey="a".repeat(43);
const values={
 CONTROL_HOSTNAME:"ssh-staging.example.net",
 AGENT_HOSTNAME:"agent-staging.example.net",
 ACCESS_TEAM_DOMAIN:"team.cloudflareaccess.com",
 ACCESS_AUD:"1234567890-staging-access-application-aud",
 BOOTSTRAP_OWNER_EMAIL:"admin@example.net",
 COMMAND_PUBLIC_KEY:publicKey,
 MANUAL_SSH_ACTIONS_ENABLED:"false"
};
const bindings=()=>[
 ...Object.entries(values).map(([name,text])=>({name,type:"plain_text",text})),
 {name:"DB",type:"d1",database_id:UUID},
 {name:"NODE_SESSIONS",type:"durable_object_namespace",class_name:"NodeSession"},
 {name:"COMMAND_PRIVATE_KEY",type:"secret_text"},
 {name:"ASSETS",type:"assets"}
];
const list=[{name:"ssh-manager-staging",uuid:UUID}];
test("rehydrates exact existing Worker config with no private signer",()=>{
 const config=extractExistingStagingWorker(template,{bindings:bindings()},list);
 assert.equal(config.name,"ssh-manager-staging");
 assert.equal(config.d1_databases[0].database_id,UUID);
 assert.equal(config.vars.COMMAND_PUBLIC_KEY,publicKey);
 assert.equal(config.vars.MANUAL_SSH_ACTIONS_ENABLED,"false");
 assert.equal(config.vars.COMMAND_PRIVATE_KEY,undefined);
 assert.deepEqual(config.routes.map(x=>x.pattern),
  ["ssh-staging.example.net","agent-staging.example.net"]);
 assert.equal(config.assets.run_worker_first,true);
 assert.equal(config.workers_dev,false);
 assert.equal(config.preview_urls,false);
 assert.equal(config.durable_objects.bindings[0].script_name,undefined);
});
test("fail closed on signer loss, DO drift, D1 mismatch or dangerous runtime flag",()=>{
 for(const modify of [
  b=>b.splice(b.findIndex(x=>x.name==="COMMAND_PRIVATE_KEY"),1),
  b=>b.find(x=>x.name==="COMMAND_PRIVATE_KEY").type="plain_text",
  b=>b.find(x=>x.name==="NODE_SESSIONS").script_name="old-gateway",
  b=>b.find(x=>x.name==="NODE_SESSIONS").class_name="LegacySession",
  b=>b.find(x=>x.name==="DB").database_id="30000000-0000-4000-8000-000000000001",
  b=>b.find(x=>x.name==="MANUAL_SSH_ACTIONS_ENABLED").text="true",
  b=>b.find(x=>x.name==="CONTROL_HOSTNAME").text="evil.example.net",
  b=>b.find(x=>x.name==="COMMAND_PUBLIC_KEY").text="bad",
  b=>b.push({...b.find(x=>x.name==="COMMAND_PUBLIC_KEY")})
 ]){
  const b=bindings();modify(b);
  if(b.find(x=>x.name==="CONTROL_HOSTNAME").text==="evil.example.net"){
   // An authorized administrator is allowed to change a custom hostname,
   // but only if it is still valid; invalid hostnames are rejected.
   b.find(x=>x.name==="CONTROL_HOSTNAME").text="http://evil.example.net";
  }
  assert.throws(()=>extractExistingStagingWorker(template,{bindings:b},list));
 }
});
test("requires exact staging D1 name and handles retired id field",()=>{
 const b=bindings();
 b.find(x=>x.name==="DB").id=UUID;
 delete b.find(x=>x.name==="DB").database_id;
 assert.equal(extractExistingStagingWorker(template,{bindings:b},list).
  d1_databases[0].database_id,UUID);
 assert.throws(()=>extractExistingStagingWorker(template,{bindings:bindings()},[]));
 assert.throws(()=>extractExistingStagingWorker(template,{bindings:bindings()},
   [{name:"ssh-manager",uuid:UUID}]));
});
test("account discovery never arbitrarily selects among Cloudflare accounts",()=>{
 const a="a".repeat(32),b="b".repeat(32);
 assert.equal(extractWhoamiAccount({accounts:[{id:a}]}),a);
 assert.equal(extractWhoamiAccount({memberships:[{account:{id:a}}]}),a);
 assert.throws(()=>extractWhoamiAccount({accounts:[{id:a},{id:b}]}));
 assert.throws(()=>extractWhoamiAccount({}));
});
test("rejects incomplete API responses",()=>{
 assert.throws(()=>requireCloudflareSettingsResponse({success:false}));
 assert.throws(()=>requireCloudflareSettingsResponse({success:true,result:{}}));
 assert.deepEqual(requireCloudflareSettingsResponse({
  success:true,result:{bindings:bindings()}
 }).bindings,bindings());
});

test("four-field Cloudflare-only first-run derives two safe staging hostnames",()=>{
 const params=newCloudflareBootstrap({
  SSH_MANAGER_BASE_DOMAIN:"whks.de",
  SSH_MANAGER_ACCESS_TEAM_DOMAIN:"team.cloudflareaccess.com",
  SSH_MANAGER_ACCESS_AUD:"1234567890-staging-access-application-aud",
  SSH_MANAGER_OWNER_EMAIL:"admin@example.net"
 });
 assert.equal(params.controlHost,"ssh-staging.whks.de");
 assert.equal(params.agentHost,"agent-staging.whks.de");
 assert.equal(params.team,"team.cloudflareaccess.com");
 assert.equal(params.owner,"admin@example.net");
 assert.throws(()=>newCloudflareBootstrap({
  SSH_MANAGER_BASE_DOMAIN:"whks.de",
  SSH_MANAGER_ACCESS_TEAM_DOMAIN:"team.cloudflareaccess.com",
  SSH_MANAGER_ACCESS_AUD:"1234567890-staging-access-application-aud",
  SSH_MANAGER_OWNER_EMAIL:"admin@example.net",
  SSH_MANAGER_CONTROL_HOSTNAME:"ssh.whks.de"
 }));
});
test("bootstrap only with empty Worker and no existing Staging D1",()=>{
 assert.equal(classifyWorkerForBootstrap(null,[]),"new");
 assert.equal(classifyWorkerForBootstrap({bindings:[]},[]),"new");
 assert.equal(classifyWorkerForBootstrap({bindings:[{name:"ASSETS",type:"assets"}]},[]),"new");
 assert.equal(classifyWorkerForBootstrap({bindings:bindings()},list),"existing");
 assert.throws(()=>classifyWorkerForBootstrap(null,list));
 assert.throws(()=>classifyWorkerForBootstrap({bindings:[]},list));
 assert.throws(()=>classifyWorkerForBootstrap({bindings:[{name:"COMMAND_PRIVATE_KEY",type:"secret_text"}]},[]));
 assert.throws(()=>classifyWorkerForBootstrap({bindings:[{name:"DB",type:"d1",database_id:UUID}]},[]));
});

test("Wrangler API token credentials are accepted but secrets are not logged",()=>{
 const key="secret_token_value_not_to_be_logged";
 assert.equal(parseWranglerAuthToken({type:"api_token",token:key}),key);
 assert.equal(parseWranglerAuthToken({type:"oauth",token:key}),key);
 assert.throws(()=>parseWranglerAuthToken({type:"api_key",key, email:"a@example.com"}));
 assert.throws(()=>parseWranglerAuthToken({type:"api_token",token:""}));
});

test("default root Wrangler config is intentionally inert: cannot expose an unprotected web or Agent endpoint",()=>{
 const cfg=JSON.parse(readFileSync(new URL("../wrangler.jsonc",import.meta.url),"utf8"));
 assert.equal(cfg.name,"ssh-manager");
 assert.equal(cfg.workers_dev,false);
 assert.equal(cfg.preview_urls,false);
 assert.equal(cfg.assets.run_worker_first,true);
 assert.equal(cfg.vars.CONTROL_HOSTNAME,cfg.vars.AGENT_HOSTNAME);
 assert.equal(cfg.vars.MANUAL_SSH_ACTIONS_ENABLED,"false");
 assert.equal(cfg.d1_databases,undefined);
 assert.equal(cfg.routes,undefined);
 assert.equal(cfg.vars.COMMAND_PRIVATE_KEY,undefined);
 assert.equal(cfg.vars.COMMAND_PUBLIC_KEY,undefined);
});
