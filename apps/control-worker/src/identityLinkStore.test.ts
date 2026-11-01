import {describe,expect,it} from "vitest";
import {
 bootstrapFirstOwner,issueIdentityLinkToken,consumeIdentityLinkToken
} from "./identityLinkStore";

type Statement={sql:string;args:unknown[]};
const owner={
 userId:"10000000-0000-4000-8000-000000000001",
 email:"owner@example.invalid",subject:"access|owner",
 createdAt:1800000000,
 auditId:"20000000-0000-4000-8000-000000000001"
};
const token={
 tokenId:"30000000-0000-4000-8000-000000000001",
 userId:owner.userId,tokenHash:"hashed-owner-link-token",
 expiresAt:1800000300,createdAt:owner.createdAt,
 auditId:"40000000-0000-4000-8000-000000000001"
};
const claim={
 subject:"access|additional-provider",userId:owner.userId,email:owner.email,
 tokenId:token.tokenId,tokenHash:token.tokenHash,
 claimedAt:1800000010,auditId:"50000000-0000-4000-8000-000000000001"
};
function fixture(count:number,changes:number[],failure?:Error){
 const batches:Statement[][]=[];
 let independentWrites=0;
 const db={
  prepare:(sql:string)=>({
   bind:(...args:unknown[])=>({
    sql,args,
    run:async()=>{independentWrites++;throw Error("Unexpected independent SQL write");}
   })
  }),
  batch:async(statements:Statement[])=>{
   batches.push(statements);
   if(failure)throw failure;
   expect(statements).toHaveLength(count);
   return changes.map(n=>({meta:{changes:n}}));
  }
 } as unknown as D1Database;
 return {db,batches,independentWrites:()=>independentWrites};
}
describe("Cloudflare Access identity mutations must be audited transactionally",()=>{
 it("bootstraps first Owner, matching subject and audit in one batch",async()=>{
  const f=fixture(3,[1,1,1]);
  await bootstrapFirstOwner(f.db,owner);
  const [user,link,audit]=f.batches[0];
  expect(user.sql).toContain("INSERT INTO users");
  expect(user.sql).toContain("'owner'");
  expect(link.sql).toContain("INSERT INTO user_identities");
  expect(link.args).toContain(owner.subject);
  expect(audit.sql).toContain("identity.owner.bootstrap");
  expect(audit.args).toContain(owner.userId);
  expect(f.independentWrites()).toBe(0);
 });
 it("fails to bootstrap if any SQL write fails",async()=>{
  const failure=Error("OWNER_AUDIT_CONSTRAINT_FAILURE");
  const f=fixture(3,[1,1,1],failure);
  await expect(bootstrapFirstOwner(f.db,owner)).rejects.toBe(failure);
  expect(f.batches).toHaveLength(1);
 });
 it("issues owner-provided identity link tokens with audit in one batch",async()=>{
  const f=fixture(2,[1,1]);
  await issueIdentityLinkToken(f.db,token);
  expect(f.batches[0][0].sql).toContain("INSERT INTO identity_link_tokens");
  expect(f.batches[0][1].sql).toContain("identity.link_token");
  expect(f.independentWrites()).toBe(0);
 });
 it("claims, consumes and audits exactly once in a single batch",async()=>{
  const f=fixture(3,[1,1,1]);
  await consumeIdentityLinkToken(f.db,claim);
  const [link,consume,audit]=f.batches[0];
  expect(link.sql).toContain("INSERT OR IGNORE INTO user_identities");
  expect(link.sql).toContain("identity_link_tokens");
  expect(link.sql).toContain("u.status='active'");
  expect(consume.sql).toContain("UPDATE identity_link_tokens");
  expect(consume.sql).toContain("changes()=1");
  expect(audit.sql).toContain("INSERT INTO audit_logs");
  expect(audit.sql).toContain("WHERE changes()=1");
  expect(audit.args).toContain(owner.userId);
  expect(f.independentWrites()).toBe(0);
 });
 it("does not accept duplicate subject binding or burn another token",async()=>{
  const f=fixture(3,[0,0,0]);
  await expect(consumeIdentityLinkToken(f.db,claim)).rejects.toMatchObject({
   code:"IDENTITY_ALREADY_LINKED",httpStatus:409
  });
  expect(f.batches[0][1].sql).toContain("changes()=1");
  expect(f.batches[0][2].sql).toContain("changes()=1");
 });
 it("rejects missing token consumption or audit acknowledgments",async()=>{
  for(const changes of [[1,0,0],[1,1,0]]){
   const f=fixture(3,changes);
   await expect(consumeIdentityLinkToken(f.db,claim)).rejects.toMatchObject({
    code:"IDENTITY_LINK_TRANSACTION_INCOMPLETE",httpStatus:500
   });
  }
 });
 it("propagates D1 audit failure instead of returning successful identity linking",async()=>{
  const failure=Error("LINK_AUDIT_UNIQUE_CONSTRAINT_FAILURE");
  const f=fixture(3,[1,1,1],failure);
  await expect(consumeIdentityLinkToken(f.db,claim)).rejects.toBe(failure);
 });
});
