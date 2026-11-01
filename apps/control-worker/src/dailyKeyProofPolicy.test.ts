import {describe,expect,it} from "vitest";
import {requirePinnedRootForDailyInstall} from "./dailyKeyProofPolicy";

function fakeDB(row:unknown){
 const calls:string[]=[];
 const db={
  prepare:(sql:string)=>{
   calls.push(sql);
   return {bind:(nodeId:string)=>({
    first:async()=>{
     expect(nodeId).toBe("node-test");
     return row;
    }
   })};
  }
 } as unknown as D1Database;
 return {db,calls};
}
describe("daily authorized_keys install needs Owner-pinned Root verification key",()=>{
 it("rejects a node without a pinned Root trust key",async()=>{
  const {db}=fakeDB(null);
  await expect(requirePinnedRootForDailyInstall(db,"node-test"))
   .rejects.toMatchObject({code:"NODE_ROOT_PROOF_KEY_NOT_PINNED",httpStatus:409});
 });
 it("accepts the specifically selected node after Owner pinning",async()=>{
  const {db,calls}=fakeDB({node_id:"node-test"});
  await expect(requirePinnedRootForDailyInstall(db,"node-test")).resolves.toBeUndefined();
  expect(calls).toHaveLength(1);
  expect(calls[0]).toContain("node_ssh_proof_keys");
 });
});
