import {describe,expect,it} from "vitest";
import {dispatchPreparedOperation} from "./operationDispatch";

const nodeId="00000000-0000-4000-8000-000000000001";
const opId="00000000-0000-4000-8000-000000000002";
const signed={command:"signed-test-command",signature:"signed-test-signature"};
type StubFetch=(url:string,init:RequestInit)=>Promise<Response>;
function fixture(fetcher:StubFetch,claimChanges=1){
 const sqls:string[]=[];
 let calls=0;
 const env={
  DB:{prepare:(sql:string)=>({
   bind:(..._args:unknown[])=>({run:async()=>{sqls.push(sql);return {meta:{changes:sql.includes("SET status='DISPATCHED'")?claimChanges:1}};}})
  })},
  NODE_SESSIONS:{idFromName:(id:string)=>id,get:(_id:string)=>({fetch:async(url:string,init:RequestInit)=>{
   calls++;return fetcher(url,init);
  }})}
 };
 return {env:env as any,sqls,getCalls:()=>calls};
}
describe("opportunistic WebSocket command dispatch",()=>{
 it("keeps DISPATCHED on network timeout after an ambiguous send",async()=>{
  const f=fixture(async()=>{throw Error("HTTP_ACK_LOST");});
  await dispatchPreparedOperation(f.env,nodeId,opId,signed);
  expect(f.sqls).toHaveLength(1);
  expect(f.sqls[0]).toContain("SET status='DISPATCHED'");
  expect(f.getCalls()).toBe(1);
 });
 it("only enables HTTPS polling after a confirmed zero-delivery response",async()=>{
  const f=fixture(async()=>new Response(JSON.stringify({delivered:0}),{status:200}));
  await dispatchPreparedOperation(f.env,nodeId,opId,signed);
  expect(f.sqls).toHaveLength(2);
  expect(f.sqls[1]).toContain("SET status='CREATED'");
 });
 it("never requeues after successful delivery or untrusted HTTP failure",async()=>{
  for(const response of [
   new Response(JSON.stringify({delivered:1}),{status:200}),
   new Response(JSON.stringify({delivered:0}),{status:503}),
   new Response(JSON.stringify({error:"temporary"}),{status:200})
  ]){
   const f=fixture(async()=>response);
   await dispatchPreparedOperation(f.env,nodeId,opId,signed);
   expect(f.sqls).toHaveLength(1);
  }
 });
 it("does not send if another request already dispatched the same operation",async()=>{
  const f=fixture(async()=>new Response(JSON.stringify({delivered:1})),0);
  await dispatchPreparedOperation(f.env,nodeId,opId,signed);
  expect(f.getCalls()).toBe(0);
  expect(f.sqls).toHaveLength(1);
 });
});
