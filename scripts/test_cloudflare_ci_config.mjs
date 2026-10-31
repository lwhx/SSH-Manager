import test from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {mkdtempSync,existsSync,readFileSync,rmSync} from "node:fs";
import os from "node:os";
import path from "node:path";

const script=new URL("./cloudflare_ci_config.mjs",import.meta.url);
const valid={
 SSH_MANAGER_STAGING_D1_UUID:"00000000-0000-4000-8000-000000000001",
 SSH_MANAGER_STAGING_COMMAND_PUBLIC_KEY:"a".repeat(43),
 SSH_MANAGER_STAGING_CONTROL_HOSTNAME:"control.example.net",
 SSH_MANAGER_STAGING_AGENT_HOSTNAME:"agent.example.net",
 SSH_MANAGER_STAGING_ACCESS_TEAM_DOMAIN:"team.cloudflareaccess.com",
 SSH_MANAGER_STAGING_ACCESS_AUD:"test-staging-access-audience-123456",
 SSH_MANAGER_STAGING_OWNER_EMAIL:"admin@example.net"
};
test("GitHub renderer emits exactly one Worker with two domains and no private keys",()=>{
 const dir=mkdtempSync(path.join(os.tmpdir(),"ssh-manager-ci-"));
 const target=path.join(dir,"staging.jsonc");
 try{
  const child=spawnSync(process.execPath,[script.pathname,"render"],{
   encoding:"utf8",env:{...process.env,...valid,SSH_MANAGER_CI_CONFIG_OUTPUT:target}
  });
  assert.equal(child.status,0,child.stderr);
  assert(existsSync(target),"safe Wrangler config missing");
  const cfg=JSON.parse(readFileSync(target,"utf8"));
  assert.equal(cfg.name,"ssh-manager-staging");
  assert.deepEqual(cfg.routes.map(x=>x.pattern),["control.example.net","agent.example.net"]);
  assert.equal(cfg.assets.run_worker_first,true);
  assert.equal(cfg.workers_dev,false);
  assert.equal(cfg.preview_urls,false);
  assert.equal(cfg.durable_objects.bindings.length,1);
  assert.equal(cfg.durable_objects.bindings[0].script_name,undefined);
  assert.equal(cfg.vars.MANUAL_SSH_ACTIONS_ENABLED,"false");
  assert(!("COMMAND_PRIVATE_KEY" in cfg.vars));
  assert.equal(readFileSync(target,"utf8").includes("CLOUDFLARE_API_TOKEN"),false);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test("GitHub renderer fails without all required environment settings",()=>{
 const dir=mkdtempSync(path.join(os.tmpdir(),"ssh-manager-ci-invalid-"));
 const target=path.join(dir,"staging.jsonc");
 try{
  const vars={...valid};delete vars.SSH_MANAGER_STAGING_ACCESS_AUD;
  const env={...process.env,...vars,SSH_MANAGER_STAGING_ACCESS_AUD:"",
   SSH_MANAGER_CI_CONFIG_OUTPUT:target};
  const child=spawnSync(process.execPath,[script.pathname,"render"],{encoding:"utf8",env});
  assert.notEqual(child.status,0);
  assert(!existsSync(target));
  assert.match(child.stderr,/SSH_MANAGER_STAGING_ACCESS_AUD/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
