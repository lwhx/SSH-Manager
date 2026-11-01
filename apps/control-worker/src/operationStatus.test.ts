import {describe,expect,it} from "vitest";
import {
  projectOperationStatus,
  blockingNodeOperationCode,
  PENDING_NODE_OPERATION_SQL,
  withNodeOperationConflictGuard
} from "./operationStatus";

const at=1_800_000_000;

describe("operation result uncertainty must be fail closed",()=>{
 it("does not claim timed-out DISPATCHED or RUNNING operations are still in progress or succeeded",()=>{
  for(const status of ["DISPATCHED","RUNNING"]){
   expect(projectOperationStatus({status,expires_at:at-1},at)).toBe("RESULT_UNKNOWN");
   expect(projectOperationStatus({status,expires_at:at+30},at)).toBe(status);
  }
  expect(projectOperationStatus({status:"CREATED",expires_at:at-1},at)).toBe("EXPIRED");
  expect(projectOperationStatus({status:"SUCCEEDED",expires_at:at-1},at)).toBe("SUCCEEDED");
  expect(projectOperationStatus({status:"FAILED",expires_at:at-1},at)).toBe("FAILED");
 });
 it("blocks new node commands while dispatched or running results are unknown",()=>{
  for(const status of ["DISPATCHED","RUNNING"]){
   expect(blockingNodeOperationCode({status,expires_at:at-1},at)).toBe("NODE_OPERATION_RESULT_UNKNOWN");
   expect(blockingNodeOperationCode({status,expires_at:at+1},at)).toBe("NODE_OPERATION_IN_PROGRESS");
  }
  expect(blockingNodeOperationCode({status:"CREATED",expires_at:at+10},at)).toBe("NODE_OPERATION_IN_PROGRESS");
  expect(blockingNodeOperationCode({status:"CREATED",expires_at:at-1},at)).toBeNull();
  expect(blockingNodeOperationCode({status:"SUCCEEDED",expires_at:at-1},at)).toBeNull();
 });
 it("queries unresolved dispatched and running commands even after the command TTL",()=>{
  expect(PENDING_NODE_OPERATION_SQL).toContain("status IN ('DISPATCHED','RUNNING')");
  expect(PENDING_NODE_OPERATION_SQL).toContain("status='CREATED' AND expires_at>?");
  expect(PENDING_NODE_OPERATION_SQL).not.toMatch(/status IN \('CREATED','DISPATCHED','RUNNING'\) AND expires_at>\?/);
 });
});


describe("D1 single-operation uniqueness conflicts return a safe API status",()=>{
 const tick=1_800_000_000;
 const unique=new Error("D1_ERROR: UNIQUE constraint failed: operations.node_id: SQLITE_CONSTRAINT");
 it("maps a simultaneous active operation to 409 without retrying the insert",async()=>{
  let calls=0,reads=0;
  await expect(withNodeOperationConflictGuard(
   async()=>{calls++;throw unique;},
   async()=>{reads++;return {status:"CREATED",expires_at:tick+45};},tick
  )).rejects.toMatchObject({code:"NODE_OPERATION_IN_PROGRESS",httpStatus:409});
  expect(calls).toBe(1);expect(reads).toBe(1);
 });
 it("preserves result-unknown semantics for an expired dispatched or running command",async()=>{
  for(const status of ["DISPATCHED","RUNNING"]){
   await expect(withNodeOperationConflictGuard(
    async()=>{throw unique;},
    async()=>({status,expires_at:tick-1}),tick
   )).rejects.toMatchObject({code:"NODE_OPERATION_RESULT_UNKNOWN",httpStatus:409});
  }
 });
 it("handles the partial unique index name in a wrapped D1 exception",async()=>{
  const error=new Error("Database batch failed",{cause:new Error("UNIQUE constraint failed: idx_one_unresolved_operation_per_node")});
  await expect(withNodeOperationConflictGuard(
   async()=>{throw error;},
   async()=>({status:"DISPATCHED",expires_at:tick+10}),tick
  )).rejects.toMatchObject({code:"NODE_OPERATION_IN_PROGRESS",httpStatus:409});
 });
 it("never masks unrelated database faults or idempotency uniqueness conflicts",async()=>{
  for(const error of [
   new Error("D1_ERROR: no such table: operations"),
   new Error("UNIQUE constraint failed: operations.operator_id, operations.idempotency_key")
  ]){
   let inspected=0;
   await expect(withNodeOperationConflictGuard(
    async()=>{throw error;},
    async()=>{inspected++;return {status:"CREATED",expires_at:tick+45};},tick
   )).rejects.toBe(error);
   expect(inspected).toBe(0);
  }
 });
 it("returns a successful insert result without reading pending operations",async()=>{
  let inspected=0;
  const result=await withNodeOperationConflictGuard(
   async()=>({id:"new-operation"}),
   async()=>{inspected++;return null;},tick
  );
  expect(result).toEqual({id:"new-operation"});
  expect(inspected).toBe(0);
 });
});
