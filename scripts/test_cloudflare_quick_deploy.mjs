import test from "node:test";
import assert from "node:assert/strict";
import {createPrivateKey,createPublicKey,sign,verify} from "node:crypto";
import {readFileSync} from "node:fs";
import {
 accessSettings,customDomain,findStagingDatabase,generateCommandSigner,
 buildSingleConfig,validateStoredConfig
} from "./cloudflare_quick_lib.mjs";
const template=JSON.parse(readFileSync(new URL("../wrangler.single.staging.example.jsonc",import.meta.url),"utf8"));
const params={
 dbId:"00000000-0000-4000-8000-000000000001",publicKey:"a".repeat(43),
 team:"myteam.cloudflareaccess.com",
 aud:"test-access-aud-for-worker-0123456789",owner:"admin@example.net",
 controlHost:"console.example.net",agentHost:"agent.example.net"
};
function fixture(){
 const cfg=buildSingleConfig(template,params);
 const state={schema:"ssh-manager-single-worker-v1",environment:"staging",status:"ready",
  worker_name:cfg.name,database_id:params.dbId,command_public_key:params.publicKey,
  control_hostname:params.controlHost,agent_hostname:params.agentHost,
  access_team_domain:params.team,access_aud:params.aud,owner_email:params.owner};
 return {cfg,state};
}
test("requires real Access team, AUD, Owner email",()=>{
 assert.deepEqual(accessSettings({team:"https://myteam.cloudflareaccess.com/",aud:params.aud,owner:"ADMIN@example.net"}),
  {team:params.team,aud:params.aud,owner:params.owner});
 for(const p of [{...params,team:"REPLACE.cloudflareaccess.com"},
  {...params,aud:"REPLACE_STAGING_ACCESS_APPLICATION_AUD"},
  {...params,owner:"owner@example.com"}]){
  assert.throws(()=>accessSettings(p));
 }
});
test("rejects workers.dev, paths, wildcards, invalid custom hostnames and duplicate hosts",()=>{
 assert.equal(customDomain("CONSOLE.Example.net"),"console.example.net");
 for(const name of ["","https://console.example.net","*.example.net","foo.workers.dev",
  "ssh.example.net/api","agent..example.net","foo:443","REPLACE_CONTROL_HOSTNAME"])
  assert.throws(()=>customDomain(name),name);
 assert.throws(()=>buildSingleConfig(template,{...params,agentHost:params.controlHost}));
});
test("selects exact staging D1 database only",()=>{
 assert.deepEqual(findStagingDatabase([{name:"ssh-manager",uuid:"1".repeat(8)+"-0000-4000-8000-000000000001"},
  {name:"ssh-manager-staging",uuid:params.dbId}]),{name:"ssh-manager-staging",id:params.dbId});
 assert.equal(findStagingDatabase([{name:"ssh-manager",uuid:params.dbId}]),null);
 assert.throws(()=>findStagingDatabase({error:"bad"}));
});
test("generates PKCS#8 signer whose Ed25519 public JWK matches",()=>{
 const keys=generateCommandSigner();
 const priv=createPrivateKey({key:Buffer.from(keys.privateKeyPkcs8Base64,"base64"),format:"der",type:"pkcs8"});
 assert.equal(createPublicKey(priv).export({format:"jwk"}).x,keys.publicKey);
 const data=Buffer.from("single-worker-hostname-gate");
 assert(verify(null,data,createPublicKey(priv),sign(null,data,priv)));
});
test("builds one Worker with two Custom Domains, local NodeSession and assets-first protection",()=>{
 const original=structuredClone(template);
 const {cfg,state}=fixture();
 assert.deepEqual(template,original);
 assert.equal(cfg.name,"ssh-manager-staging");
 assert.equal(cfg.main,"apps/single-worker/src/index.ts");
 assert.equal(cfg.d1_databases.length,1);
 assert.equal(cfg.assets.run_worker_first,true);
 assert.equal(cfg.workers_dev,false);
 assert.equal(cfg.preview_urls,false);
 assert.equal(cfg.durable_objects.bindings[0].script_name,undefined);
 assert.equal(cfg.migrations[0].new_sqlite_classes[0],"NodeSession");
 assert.deepEqual(cfg.routes,[
  {pattern:params.controlHost,custom_domain:true},
  {pattern:params.agentHost,custom_domain:true}
 ]);
 assert.equal(cfg.vars.MANUAL_SSH_ACTIONS_ENABLED,"false");
 assert.equal(cfg.vars.COMMAND_PRIVATE_KEY,undefined);
 validateStoredConfig(cfg,state);
});
test("fails closed on domain, D1, key, Access and opt-in drift",()=>{
 for(const mutate of [
  c=>c.d1_databases[0].database_id="4".repeat(8)+"-0000-4000-8000-000000000001",
  c=>c.vars.COMMAND_PUBLIC_KEY="b".repeat(43),
  c=>c.vars.MANUAL_SSH_ACTIONS_ENABLED="true",
  c=>c.vars.CONTROL_HOSTNAME="another.example.net",
  c=>c.routes[1].pattern="another.example.net",
  c=>c.assets.run_worker_first=false,
  c=>c.durable_objects.bindings[0].script_name="old-agent-gateway",
  c=>c.workers_dev=true,
  c=>c.vars.ACCESS_AUD="another-access-aud-123456789",
  c=>c.vars.COMMAND_PRIVATE_KEY="unacceptable"
 ]){
  const {cfg,state}=fixture();mutate(cfg);
  assert.throws(()=>validateStoredConfig(cfg,state));
 }
});
