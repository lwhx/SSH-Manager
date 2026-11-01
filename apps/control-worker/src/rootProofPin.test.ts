import {describe,it,expect} from "vitest";
import {persistRootProofPin} from "./rootProofPin";

const pin={
 nodeId:"10000000-0000-4000-8000-000000000001",
 publicKey:"owner-inspected-ed25519-root-public-key",
 fingerprint:"SHA256:owner-confirmed-fingerprint",
 actorId:"20000000-0000-4000-8000-000000000001",
 auditId:"30000000-0000-4000-8000-000000000001",
 createdAt:1800000000
};
type Statement={sql:string;args:unknown[]};
function fixture(changes:[number,number],failure?:Error){
 const batches:Statement[][]=[];
 let independentWrites=0;
 const db={
  prepare:(sql:string)=>({
   bind:(...args:unknown[])=>({
    sql,args,
    run:async()=>{independentWrites++;throw Error("Unexpected non-transactional write");}
   })
  }),
  batch:async(statements:Statement[])=>{
   batches.push(statements);
   if(failure)throw failure;
   return changes.map(n=>({meta:{changes:n}}));
  }
 } as unknown as D1Database;
 return {db,batches,getIndependentWrites:()=>independentWrites};
}
describe("Owner-pinned Root trust anchor and audit must commit together",()=>{
 it("binds the per-node Root key and owner audit in ONE D1 transaction",async()=>{
  const f=fixture([1,1]);
  await expect(persistRootProofPin(f.db,pin)).resolves.toBeUndefined();
  expect(f.batches).toHaveLength(1);
  expect(f.batches[0]).toHaveLength(2);
  const [write,audit]=f.batches[0];
  expect(write.sql).toContain("INSERT OR IGNORE INTO node_ssh_proof_keys");
  expect(write.args).toEqual([pin.nodeId,pin.publicKey,pin.fingerprint,pin.actorId,pin.createdAt]);
  expect(audit.sql).toContain("INSERT INTO audit_logs");
  expect(audit.sql).toContain("'ssh.proof-key.pin'");
  expect(audit.sql).toContain("WHERE changes()=1");
  expect(audit.args).toEqual([pin.auditId,pin.actorId,pin.nodeId,pin.createdAt]);
  expect(f.getIndependentWrites()).toBe(0);
 });
 it("rejects a duplicate fixed key and does not write another audit",async()=>{
  const f=fixture([0,0]);
  await expect(persistRootProofPin(f.db,pin)).rejects.toMatchObject({
   code:"NODE_PROOF_KEY_ALREADY_PINNED",httpStatus:409
  });
  expect(f.batches).toHaveLength(1);
  expect(f.getIndependentWrites()).toBe(0);
 });
 it("aborts the Root binding if the owner audit INSERT fails",async()=>{
  const failure=new Error("CI_ROOT_AUDIT_INSERT_FAILED");
  const f=fixture([1,1],failure);
  await expect(persistRootProofPin(f.db,pin)).rejects.toBe(failure);
  expect(f.batches).toHaveLength(1);
  expect(f.getIndependentWrites()).toBe(0);
 });
 it("rejects inconsistent audit acknowledgement rather than reporting pin success",async()=>{
  const f=fixture([1,0]);
  await expect(persistRootProofPin(f.db,pin)).rejects.toMatchObject({
   code:"ROOT_PROOF_PIN_AUDIT_MISSING",httpStatus:500
  });
 });
});
