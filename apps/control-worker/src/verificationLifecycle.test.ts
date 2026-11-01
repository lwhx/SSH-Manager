import {describe,expect,it} from "vitest";
import {
 persistVerificationStart,cancelPendingVerification,projectVerificationReadStatus
} from "./verificationLifecycle";

const start={
 nodeId:"10000000-0000-4000-8000-000000000001",
 verificationId:"20000000-0000-4000-8000-000000000001",
 operationId:"30000000-0000-4000-8000-000000000001",
 auditId:"40000000-0000-4000-8000-000000000001",
 operatorId:"50000000-0000-4000-8000-000000000001",
 keyId:"60000000-0000-4000-8000-000000000001",
 keyFingerprint:"SHA256:staging-fixture",
 loginUser:"root",configRevision:"a".repeat(64),
 nonceHash:"b".repeat(64),createdAt:1800000000,
 expiresAt:1800000300,operationExpiresAt:1800000045,
 signedCommand:'{"v":1,"action":"ssh.verification.prepare"}',
 signature:"test-fixture-signature"
};
const cancel={
 nodeId:start.nodeId,verificationId:start.verificationId,
 actorId:start.operatorId,auditId:"70000000-0000-4000-8000-000000000001",
 at:1800000010
};
type Statement={sql:string;args:unknown[]};
function fixture(results:number[],error?:Error){
 const batches:Statement[][]=[];
 const db={
  prepare:(sql:string)=>({bind:(...args:unknown[])=>({
   sql,args,
   run:async()=>{throw Error("Unexpected non-transactional update")}
  })}),
  batch:async(statements:Statement[])=>{
   batches.push(statements);
   if(error)throw error;
   return results.map(changes=>({meta:{changes}}));
  }
 } as unknown as D1Database;
 return {db,batches};
}
describe("SSH verification challenge persistence and cancellation",()=>{
 it("expires stale pending, creates challenge+operation+audit atomically",async()=>{
  const f=fixture([1,1,1,1]);
  await persistVerificationStart(f.db,start);
  expect(f.batches).toHaveLength(1);
  const [expire,challenge,operation,audit]=f.batches[0];
  expect(expire.sql).toContain("expires_at<=?");
  expect(expire.args).toEqual([start.nodeId,start.createdAt]);
  expect(challenge.sql).toContain("INSERT INTO ssh_verifications");
  expect(challenge.sql).toContain("JOIN public_keys");
  expect(challenge.sql).toContain("JOIN");
  expect(challenge.sql).toContain("n.init_stage='WAITING_VERIFICATION'");
  expect(challenge.args).toContain(start.nonceHash);
  expect(operation.sql).toContain("INSERT INTO operations");
  expect(operation.sql).toContain("WHERE changes()=1");
  expect(operation.args).toContain(start.operationId);
  expect(operation.args).toContain(start.signedCommand);
  expect(audit.sql).toContain("ssh.verification.start");
  expect(audit.sql).toContain("WHERE changes()=1");
  expect(audit.args).toContain(start.verificationId);
 });
 it("rejects stale context when no challenge inserted, without dispatch",async()=>{
  const f=fixture([0,0,0,0]);
  await expect(persistVerificationStart(f.db,start)).rejects.toMatchObject({
   code:"VERIFICATION_START_CONTEXT_CHANGED",httpStatus:409
  });
 });
 it("rejects missing operation or audit acknowledgment",async()=>{
  for(const changes of [[0,1,0,0],[0,1,1,0]]){
   const f=fixture(changes);
   await expect(persistVerificationStart(f.db,start)).rejects.toMatchObject({
    code:"VERIFICATION_START_TRANSACTION_INCOMPLETE",httpStatus:500
   });
  }
 });
 it("maps concurrent pending verification uniqueness to HTTP 409",async()=>{
  const e=Error("D1_ERROR: UNIQUE constraint failed: ssh_verifications.node_id");
  const f=fixture([],e);
  await expect(persistVerificationStart(f.db,start)).rejects.toMatchObject({
   code:"VERIFICATION_ALREADY_PENDING",httpStatus:409
  });
 });
 it("does not mask unrelated D1 constraint failures",async()=>{
  const err=Error("D1_ERROR: foreign key mismatch");
  const f=fixture([],err);
  await expect(persistVerificationStart(f.db,start)).rejects.toBe(err);
 });
 it("cancels a live pending challenge and writes exactly one audit atomically",async()=>{
  const f=fixture([1,1]);
  await cancelPendingVerification(f.db,cancel);
  const [update,audit]=f.batches[0];
  expect(update.sql).toContain("status='PENDING'");
  expect(update.sql).toContain("expires_at>?");
  expect(update.sql).toContain("node_id=?");
  expect(update.args).toEqual([cancel.at,cancel.verificationId,cancel.nodeId,cancel.at]);
  expect(audit.sql).toContain("ssh.verification.cancel");
  expect(audit.sql).toContain("WHERE changes()=1");
  expect(audit.args).toContain(cancel.verificationId);
 });
 it("a concurrent VERIFIED, expired or already-CANCELLED challenge must not be falsely cancelled",async()=>{
  const f=fixture([0,0]);
  await expect(cancelPendingVerification(f.db,cancel)).rejects.toMatchObject({
   code:"VERIFICATION_NOT_PENDING",httpStatus:409
  });
  expect(f.batches[0][1].sql).toContain("WHERE changes()=1");
 });
 it("does not report cancellation if the audit fails",async()=>{
  const err=Error("D1 audit insert rejected");
  const f=fixture([],err);
  await expect(cancelPendingVerification(f.db,cancel)).rejects.toBe(err);
  expect(f.batches).toHaveLength(1);
 });
 it("GET projects expiration and stale key/revision without writing to D1",()=>{
  const row={status:"PENDING",expires_at:1800000300,config_revision:"a".repeat(64),
   public_key_id:start.keyId};
  expect(projectVerificationReadStatus(row,1800000200,row.config_revision,row.public_key_id)).toBe("PENDING");
  expect(projectVerificationReadStatus(row,1800000300,row.config_revision,row.public_key_id)).toBe("EXPIRED");
  expect(projectVerificationReadStatus(row,1800000200,"b".repeat(64),row.public_key_id)).toBe("INVALIDATED");
  expect(projectVerificationReadStatus(row,1800000200,row.config_revision,"different-key")).toBe("INVALIDATED");
  expect(projectVerificationReadStatus({...row,status:"VERIFIED"},1800000400,"different","different")).toBe("VERIFIED");
 });
});
