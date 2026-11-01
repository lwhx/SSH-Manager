import {describe,expect,it} from "vitest";
import {rotateGlobalPublicKey} from "./globalKeyRotation";

const key={
 id:"10000000-0000-4000-8000-000000000001",
 purpose:"daily" as const,
 name:"owner daily",
 algorithm:"ssh-ed25519",
 publicKey:"ssh-ed25519 AAAAfixture owner-daily",
 fingerprint:"SHA256:rotation-fixture",
 actorId:"20000000-0000-4000-8000-000000000001",
 auditId:"30000000-0000-4000-8000-000000000001",
 createdAt:1800000000
};
type Statement={sql:string;args:unknown[]};
function fixture(purpose:"daily"|"rescue",failure?:Error){
 const batches:Statement[][]=[];
 let outOfBatch=0;
 const n=purpose==="daily"?5:4;
 const replies=Array.from({length:n},(_,i)=>i===n-1?
  {results:[{version:7,active:1}],meta:{changes:0}}:
  {results:[],meta:{changes:1}});
 const db={
  prepare:(sql:string)=>({
   bind:(...args:unknown[])=>({
    sql,args,
    run:async()=>{outOfBatch++;throw Error("Independent write forbidden");},
    first:async()=>{outOfBatch++;throw Error("Non-transactional read forbidden");}
   })
  }),
  batch:async(stmts:Statement[])=>{
   batches.push(stmts);
   if(failure)throw failure;
   return replies;
  }
 } as unknown as D1Database;
 return {db,batches,getOutsideCalls:()=>outOfBatch};
}
describe("global SSH public key rotation is audited and versioned atomically",()=>{
 it("rotates the daily key, invalidates pending proofs and audits in one D1 batch",async()=>{
  const f=fixture("daily");
  await expect(rotateGlobalPublicKey(f.db,key)).resolves.toBe(7);
  expect(f.batches).toHaveLength(1);
  const [deactivate,insert,invalidate,audit,lookup]=f.batches[0];
  expect(deactivate.sql).toContain("UPDATE public_keys SET active=0");
  expect(deactivate.args).toEqual(["daily"]);
  expect(insert.sql).toContain("INSERT INTO public_keys");
  expect(insert.sql).toMatch(/COALESCE\(MAX\(version\),0\)\s*\+\s*1/i);
  expect(insert.sql).toContain("FROM public_keys WHERE purpose=?");
  expect(insert.args).toEqual([
   key.id,key.purpose,key.name,key.algorithm,key.publicKey,key.fingerprint,
   key.actorId,key.createdAt,key.purpose
  ]);
  expect(invalidate.sql).toContain("UPDATE ssh_verifications SET status='INVALIDATED'");
  expect(audit.sql).toContain("INSERT INTO audit_logs");
  expect(audit.args).toContain("keys.daily.update");
  expect(audit.args).toContain("key_id="+key.id);
  expect(lookup.sql).toContain("SELECT version,active FROM public_keys WHERE id=?");
  expect(lookup.args).toEqual([key.id]);
  expect(f.getOutsideCalls()).toBe(0);
 });
 it("rotates rescue key without invalidating daily login challenges",async()=>{
  const f=fixture("rescue");
  await expect(rotateGlobalPublicKey(f.db,{...key,purpose:"rescue"})).resolves.toBe(7);
  expect(f.batches).toHaveLength(1);
  expect(f.batches[0]).toHaveLength(4);
  expect(f.batches[0].some(s=>s.sql.includes("UPDATE ssh_verifications"))).toBe(false);
  expect(f.batches[0][2].args).toContain("keys.rescue.update");
  expect(f.getOutsideCalls()).toBe(0);
 });
 it("propagates audit failure instead of falsely confirming a key rotation",async()=>{
  const failure=Error("INJECTED_AUDIT_INSERT_FAILURE");
  const f=fixture("daily",failure);
  await expect(rotateGlobalPublicKey(f.db,key)).rejects.toBe(failure);
  expect(f.batches).toHaveLength(1);
  expect(f.getOutsideCalls()).toBe(0);
 });
 it("must never perform a separate SELECT max(version) before D1 batch",async()=>{
  const f=fixture("rescue");
  await rotateGlobalPublicKey(f.db,{...key,purpose:"rescue"});
  const select=f.batches[0].at(-1)!;
  expect(select.sql).toContain("WHERE id=?");
  expect(select.sql).not.toContain("MAX(version)");
  expect(f.getOutsideCalls()).toBe(0);
 });
});
