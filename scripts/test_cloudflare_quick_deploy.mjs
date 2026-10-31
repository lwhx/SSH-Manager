import test from "node:test";
import assert from "node:assert/strict";
import {createPrivateKey,createPublicKey,sign,verify} from "node:crypto";
import {readFileSync} from "node:fs";
import {
 accessSettings,findStagingDatabase,generateCommandSigner,buildConfigs,validateStoredConfigs
} from "./cloudflare_quick_lib.mjs";

const load=name=>JSON.parse(readFileSync(new URL("../"+name,import.meta.url),"utf8"));
const control=load("wrangler.control.staging.example.jsonc");
const gateway=load("wrangler.gateway.staging.example.jsonc");
const params={
 dbId:"00000000-0000-4000-8000-000000000001",
 publicKey:"a".repeat(43),
 team:"testing.cloudflareaccess.com",
 aud:"this-is-an-access-app-aud-1234567890",
 owner:"admin@example.net"
};
test("requires real Access team, application AUD and Owner email",()=>{
 assert.deepEqual(accessSettings({team:"https://testing.cloudflareaccess.com/",aud:params.aud,owner:"ADMIN@example.net"}),
  {team:"testing.cloudflareaccess.com",aud:params.aud,owner:"admin@example.net"});
 for(const k of [
  {...params,team:"REPLACE.cloudflareaccess.com"},
  {...params,team:"http://example.com"},
  {...params,aud:"REPLACE_STAGING_ACCESS_APPLICATION_AUD"},
  {...params,owner:"owner@example.com"}
 ])assert.throws(()=>accessSettings(k));
});
test("selects only exact staging D1 name and checks UUID",()=>{
 const db=findStagingDatabase([{name:"ssh-manager",uuid:"a".repeat(8)+"-0000-4000-8000-000000000001"},
  {name:"ssh-manager-staging",uuid:params.dbId}]);
 assert.deepEqual(db,{name:"ssh-manager-staging",id:params.dbId});
 assert.equal(findStagingDatabase([{name:"ssh-manager",uuid:params.dbId}]),null);
 assert.throws(()=>findStagingDatabase([{name:"ssh-manager-staging",uuid:"bad"}]));
 assert.throws(()=>findStagingDatabase({message:"invalid credentials"}));
});
test("creates a real Ed25519 PKCS8 signer matching raw Cloudflare public key",()=>{
 const keys=generateCommandSigner();
 const priv=createPrivateKey({key:Buffer.from(keys.privateKeyPkcs8Base64,"base64"),type:"pkcs8",format:"der"});
 assert.equal(createPublicKey(priv).export({format:"jwk"}).x,keys.publicKey);
 const raw=Buffer.from("ssh-manager-safe-quick-deploy");
 assert(verify(null,raw,createPublicKey(priv),sign(null,raw,priv)));
});
test("generates two coordinated Workers without enabling SSH writes",()=>{
 const original=structuredClone(control);
 const out=buildConfigs(control,gateway,params);
 assert.deepEqual(control,original,"must not modify example template");
 assert.equal(out.control.d1_databases[0].database_id,params.dbId);
 assert.equal(out.gateway.d1_databases[0].database_id,params.dbId);
 assert.equal(out.control.durable_objects.bindings[0].script_name,out.gateway.name);
 assert.equal(out.control.vars.MANUAL_SSH_ACTIONS_ENABLED,"false");
 assert.equal(out.gateway.vars.COMMAND_PUBLIC_KEY,params.publicKey);
 const state={environment:"staging",status:"ready",database_id:params.dbId,
  control_name:out.control.name,gateway_name:out.gateway.name,command_public_key:params.publicKey};
 validateStoredConfigs(out.control,out.gateway,state);
 out.control.vars.MANUAL_SSH_ACTIONS_ENABLED="true";
 assert.throws(()=>validateStoredConfigs(out.control,out.gateway,state));
});
test("refuses mismatched database and modified command public key",()=>{
 const out=buildConfigs(control,gateway,params);
 const state={environment:"staging",status:"ready",database_id:params.dbId,
  control_name:out.control.name,gateway_name:out.gateway.name,command_public_key:params.publicKey};
 out.gateway.vars.COMMAND_PUBLIC_KEY="b".repeat(43);
 assert.throws(()=>validateStoredConfigs(out.control,out.gateway,state));
});
