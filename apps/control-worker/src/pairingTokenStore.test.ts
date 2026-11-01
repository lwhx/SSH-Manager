import {describe,expect,it} from "vitest";
import {rotatePairingToken} from "./pairingTokenStore";
const params={
 nodeId:"11111111-1111-4111-8111-111111111111",
 tokenId:"22222222-2222-4222-8222-222222222222",
 tokenHash:"opaque-sha256-digest",
 expiresAt:1800000600,
 createdBy:"33333333-3333-4333-8333-333333333333",
 auditId:"44444444-4444-4444-8444-444444444444",
 createdAt:1800000000
};

function fixture(fails=false){
 const calls:{sql:string;args:unknown[]}[][]=[];
 const database={
  prepare:(sql:string)=>({bind:(...args:unknown[])=>({sql,args})}),
  batch:async(batch:{sql:string;args:unknown[]}[])=>{
   calls.push(batch);
   if(fails)throw Error("SYNTHETIC_D1_TRANSACTION_FAILED");
   return batch.map(()=>({meta:{changes:1}}));
  }
 };
 return {db:database as unknown as D1Database,batches:calls};
}
describe("pairing-token rotation is a single audited D1 transaction",()=>{
 it("revokes old unused token, issues one new token and records audit atomically",async()=>{
  const f=fixture();
  await rotatePairingToken(f.db,params);
  expect(f.batches).toHaveLength(1);
  const statements=f.batches[0];
  expect(statements).toHaveLength(3);
  expect(statements[0].sql).toMatch(/DELETE FROM pairing_tokens WHERE node_id=\? AND used_at IS NULL/);
  expect(statements[0].args).toEqual([params.nodeId]);
  expect(statements[1].sql).toContain("INSERT INTO pairing_tokens");
  expect(statements[1].args).toEqual([
   params.tokenId,params.nodeId,params.tokenHash,params.expiresAt,params.createdBy
  ]);
  expect(statements[2].sql).toContain("INSERT INTO audit_logs");
  expect(statements[2].sql).toContain("node.pairing_token");
  expect(statements[2].args).toEqual([
   params.auditId,params.createdBy,params.nodeId,params.createdAt
  ]);
 });
 it("never reports successful rotation if the transaction fails",async()=>{
  const f=fixture(true);
  await expect(rotatePairingToken(f.db,params)).rejects.toThrow("SYNTHETIC_D1_TRANSACTION_FAILED");
  expect(f.batches).toHaveLength(1);
 });
});
