import {describe,expect,it} from "vitest";
import {
  projectOperationStatus,
  blockingNodeOperationCode,
  PENDING_NODE_OPERATION_SQL
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
