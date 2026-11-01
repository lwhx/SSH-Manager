import {describe,expect,it} from "vitest";
import {canStartManualOperation} from "./ManualOperations";
const at=1_800_000_000;
const node={id:"11111111-1111-4111-8111-111111111111",status:"online",last_seen_at:at-10};
const reason="已在本台 VPS 验证新密钥并确认控制台可用";
describe("manual SSH controls require a fresh Agent heartbeat",()=>{
 it("allows an Owner only when this exact node is online and confirmation is complete",()=>{
  expect(canStartManualOperation(node,true,true,node.id,reason,at)).toBe(true);
 });
 it("disables dangerous controls when the heartbeat is older than 90 seconds",()=>{
  expect(canStartManualOperation({...node,last_seen_at:at-91},true,true,node.id,reason,at)).toBe(false);
 });
 it("rejects missing heartbeat, offline and unpaired nodes",()=>{
  expect(canStartManualOperation({...node,last_seen_at:null},true,true,node.id,reason,at)).toBe(false);
  expect(canStartManualOperation({...node,status:"offline"},true,true,node.id,reason,at)).toBe(false);
  expect(canStartManualOperation({...node,status:"unpaired"},true,true,node.id,reason,at)).toBe(false);
 });
 it("keeps controls locked for non-Owners, disabled feature flag or another node ID",()=>{
  expect(canStartManualOperation(node,false,true,node.id,reason,at)).toBe(false);
  expect(canStartManualOperation(node,true,false,node.id,reason,at)).toBe(false);
  expect(canStartManualOperation(node,true,true,"22222222-2222-4222-8222-222222222222",reason,at)).toBe(false);
 });
 it("rejects trimmed or out-of-range operation reasons",()=>{
  expect(canStartManualOperation(node,true,true,node.id,"  "+reason,at)).toBe(false);
  expect(canStartManualOperation(node,true,true,node.id,"short",at)).toBe(false);
  expect(canStartManualOperation(node,true,true,node.id,"x".repeat(281),at)).toBe(false);
 });
});
