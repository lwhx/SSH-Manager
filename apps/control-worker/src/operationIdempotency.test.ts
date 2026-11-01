import {describe,expect,it} from "vitest";
import {findIdempotentOperation,recoverIdempotentInsertConflict} from "./operationIdempotency";
import {ApiError} from "../../../packages/protocol/src/index";

const nodeA="11111111-1111-4111-8111-111111111111";
const nodeB="22222222-2222-4222-8222-222222222222";
const at=1_800_000_000;
const intent={nodeId:nodeA,action:"node.preflight",payload:{login_user:"root",ssh_port:22}};
const id="33333333-3333-4333-8333-333333333333";
function operation(overrides:Record<string,unknown>={}){
 return {id,node_id:nodeA,action:"node.preflight",status:"DISPATCHED",expires_at:at-1,
  command_json:JSON.stringify({v:1,node_id:nodeA,action:"node.preflight",actor:"owner",
   payload:{ssh_port:22,login_user:"root"}}),
  ...overrides};
}
function fixture(found:ReturnType<typeof operation>|null){
 const queries:{sql:string;args:unknown[]}[]=[];
 return {queries,db:{prepare:(sql:string)=>({bind:(...args:unknown[])=>({
   first:async()=>{queries.push({sql,args});return found;}
  })})} as unknown as D1Database};
}
describe("idempotency tokens are scoped to one signed node command",()=>{
 it("replies with original operation and actual unknown status for an identical retry",async()=>{
  const f=fixture(operation());
  expect(await findIdempotentOperation(f.db,"actor","saved-key",intent,at)).toEqual({
   operation_id:id,status:"RESULT_UNKNOWN"
  });
  expect(f.queries).toHaveLength(1);
  expect(f.queries[0].sql).toContain("WHERE operator_id=? AND idempotency_key=?");
  expect(f.queries[0].sql).toContain("command_json");
  expect(f.queries[0].args).toEqual(["actor","saved-key"]);
 });
 it("does not treat the same key as valid for another VPS",async()=>{
  const f=fixture(operation());
  await expect(findIdempotentOperation(f.db,"actor","saved-key",
   {...intent,nodeId:nodeB},at)).rejects.toMatchObject({
    code:"IDEMPOTENCY_SCOPE_CONFLICT",httpStatus:409
   });
 });
 it("rejects a different action or altered SSH command payload using the same key",async()=>{
  for(const changed of [
   {...intent,action:"ssh.password.restore"},
   {...intent,payload:{ssh_port:2222,login_user:"root"}},
   {...intent,payload:{ssh_port:22,login_user:"ubuntu"}}
  ]){
   const f=fixture(operation());
   await expect(findIdempotentOperation(f.db,"actor","saved-key",changed,at))
    .rejects.toMatchObject({code:"IDEMPOTENCY_SCOPE_CONFLICT",httpStatus:409});
  }
 });
 it("rejects a stored signed-command/node mismatch or malformed JSON rather than reusing it",async()=>{
  for(const signed of [
   "{not-json",
   JSON.stringify({node_id:nodeB,action:"node.preflight",payload:intent.payload}),
   JSON.stringify({node_id:nodeA,action:"ssh.password.disable",payload:intent.payload}),
   JSON.stringify({node_id:nodeA,action:"node.preflight",payload:[]}),
   JSON.stringify({node_id:nodeA,action:"node.preflight",payload:null})
  ]){
   const f=fixture(operation({command_json:signed}));
   await expect(findIdempotentOperation(f.db,"actor","saved-key",intent,at))
    .rejects.toMatchObject({code:"IDEMPOTENCY_SCOPE_CONFLICT",httpStatus:409});
  }
 });
 it("permits the same request payload independent of object key order",async()=>{
  const f=fixture(operation({status:"SUCCEEDED"}));
  expect(await findIdempotentOperation(f.db,"actor","same-key",intent,at))
   .toEqual({operation_id:id,status:"SUCCEEDED"});
 });
 it("does not create a new operation or invent a response when no matching key exists",async()=>{
  const f=fixture(null);
  expect(await findIdempotentOperation(f.db,"actor","new-key",intent,at)).toBeNull();
  expect(f.queries).toHaveLength(1);
 });
});


describe("concurrent idempotency insert collision is reconciled without redispatch",()=>{
 const unique=new Error("D1_ERROR: UNIQUE constraint failed: operations.operator_id, operations.idempotency_key");
 it("returns the existing operation when concurrent identical requests race",async()=>{
  const f=fixture(operation({status:"RUNNING",expires_at:at+10}));
  let reads=0;
  const old=await recoverIdempotentInsertConflict(unique,async()=>{
   reads++;return findIdempotentOperation(f.db,"actor","same-key",intent,at);
  });
  expect(old).toEqual({operation_id:id,status:"RUNNING"});
  expect(reads).toBe(1);
 });
 it("handles a simultaneous identical request when the single-node index wins the race",async()=>{
  const f=fixture(operation());
  const prior=new ApiError("NODE_OPERATION_IN_PROGRESS",409);
  expect(await recoverIdempotentInsertConflict(prior,
   ()=>findIdempotentOperation(f.db,"actor","same-key",intent,at)))
   .toEqual({operation_id:id,status:"RESULT_UNKNOWN"});
 });
 it("never accepts the same key used for a different node or payload",async()=>{
  const f=fixture(operation());
  await expect(recoverIdempotentInsertConflict(unique,
   ()=>findIdempotentOperation(f.db,"actor","same-key",{...intent,nodeId:nodeB},at)))
   .rejects.toMatchObject({code:"IDEMPOTENCY_SCOPE_CONFLICT",httpStatus:409});
 });
 it("never masks unrelated SQL errors and does not attempt a lookup",async()=>{
  let calls=0;
  const other=new Error("D1_ERROR: no such table: operations");
  await expect(recoverIdempotentInsertConflict(other,async()=>{
   calls++;return {operation_id:id,status:"SUCCEEDED"};
  })).rejects.toBe(other);
  expect(calls).toBe(0);
 });
 it("does not invent a successful result if the colliding operation cannot be found",async()=>{
  const f=fixture(null);
  await expect(recoverIdempotentInsertConflict(unique,
   ()=>findIdempotentOperation(f.db,"actor","same-key",intent,at)))
   .rejects.toBe(unique);
 });
 it("retains the original DB failure when collision lookup fails unexpectedly",async()=>{
  await expect(recoverIdempotentInsertConflict(unique,async()=>{throw Error("D1_UNAVAILABLE");}))
   .rejects.toBe(unique);
 });
});
