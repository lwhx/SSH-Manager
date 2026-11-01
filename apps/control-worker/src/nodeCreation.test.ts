import {describe,expect,it} from "vitest";
import {createNodeWithPairingToken} from "./nodeCreation";

const node={
 id:"11111111-1111-4111-8111-111111111111",name:"Tokyo VPS",
 host:"vps.example.com",port:2222,loginUser:"ubuntu",createdAt:1800000000,
 tokenId:"22222222-2222-4222-8222-222222222222",tokenHash:"sha256-token-digest",
 tokenExpiresAt:1800000600,createdBy:"33333333-3333-4333-8333-333333333333",
 auditId:"44444444-4444-4444-8444-444444444444"
};
function fixture(fails=false){
 const batches:{sql:string;args:unknown[]}[][]=[];
 const db={
  prepare:(sql:string)=>({bind:(...args:unknown[])=>({sql,args})}),
  batch:async(statements:{sql:string;args:unknown[]}[])=>{
   batches.push(statements);
   if(fails)throw Error("SYNTHETIC_NODE_CREATE_TRANSACTION_FAILURE");
   return statements.map(()=>({meta:{changes:1}}));
  }
 };
 return {db:db as unknown as D1Database,batches};
}
describe("new VPS, initial pairing token and audit commit together",()=>{
 it("creates exactly one node, audit row and one-time pairing token in one D1 batch",async()=>{
  const f=fixture();
  await createNodeWithPairingToken(f.db,node);
  expect(f.batches).toHaveLength(1);
  expect(f.batches[0]).toHaveLength(3);
  expect(f.batches[0][0].sql).toContain("INSERT INTO nodes");
  expect(f.batches[0][0].args).toEqual([
   node.id,node.name,node.host,node.port,node.loginUser,node.createdAt
  ]);
  expect(f.batches[0][1].sql).toContain("INSERT INTO audit_logs");
  expect(f.batches[0][1].sql).toContain("'node.create'");
  expect(f.batches[0][1].args).toEqual([
   node.auditId,node.createdBy,node.id,node.createdAt
  ]);
  expect(f.batches[0][2].sql).toContain("INSERT INTO pairing_tokens");
  expect(f.batches[0][2].args).toEqual([
   node.tokenId,node.id,node.tokenHash,node.tokenExpiresAt,node.createdBy
  ]);
 });
 it("does not leave a visible node without its token or audit if D1 batch fails",async()=>{
  const f=fixture(true);
  await expect(createNodeWithPairingToken(f.db,node))
   .rejects.toThrow("SYNTHETIC_NODE_CREATE_TRANSACTION_FAILURE");
  expect(f.batches).toHaveLength(1);
 });
});
