import{describe,it,expect}from"vitest";
import{base64url}from"./index";
import{verifyPinnedSSHProof,type ProofEvidence,type ExpectedSSHProof}from"./proof";

const node="10000000-0000-4000-8000-000000000001";
const verification="20000000-0000-4000-8000-000000000001";
const keyId="30000000-0000-4000-8000-000000000001";
const hash="a".repeat(64);
const revision="b".repeat(64);
const fp="SHA256:WqyC1TNJwaA73QFZwyV9a7G2SpMUEMDwVZ7OEWHsMmg";
function proof():ProofEvidence{return {
 v:1,proof_id:"40000000-0000-4000-8000-000000000001",node_id:node,
 verification_id:verification,key_id:keyId,login_user:"root",fingerprint:fp,
 config_revision:revision,nonce_hash:hash,authenticated_at:1020,observed_at:1025,
 client_ip:"203.0.113.9",client_port:52134,sshd_pid:128,
};}
function expected():ExpectedSSHProof{return {nodeId:node,verificationId:verification,keyId,
 loginUser:"root",fingerprint:fp,configRevision:revision,nonceHash:hash,
 createdAt:1000,expiresAt:1300,now:1027};}
async function sign(p:ProofEvidence){
 const keys=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
 const publicKey=base64url(new Uint8Array(await crypto.subtle.exportKey("raw",keys.publicKey)));
 const payload=JSON.stringify(p);
 const signature=base64url(new Uint8Array(await crypto.subtle.sign(
  "Ed25519",keys.privateKey,new TextEncoder().encode(payload))));
 return{payload,signature,publicKey};
}
describe("root-only pinned SSH attestation",()=>{
 it("accepts exact signature and node/key/user/expiry",async()=>{
  const s=await sign(proof());
  await expect(verifyPinnedSSHProof(s.payload,s.signature,s.publicKey,expected())).resolves.toMatchObject({node_id:node});
 });
 it("rejects tampering, wrong node, wrong key, stale proof, wrong revision and unpinned key",async()=>{
  const s=await sign(proof());
  await expect(verifyPinnedSSHProof(s.payload+" ",s.signature,s.publicKey,expected())).rejects.toThrow();
  for(const changes of [{nodeId:"50000000-0000-4000-8000-000000000001"},{keyId:"60000000-0000-4000-8000-000000000001"},
   {loginUser:"ubuntu"},{configRevision:"c".repeat(64)},{nonceHash:"d".repeat(64)},{now:1300}]){
   await expect(verifyPinnedSSHProof(s.payload,s.signature,s.publicKey,{...expected(),...changes})).rejects.toThrow();
  }
  const other=await sign(proof());
  await expect(verifyPinnedSSHProof(s.payload,s.signature,other.publicKey,expected())).rejects.toThrow();
 });
 it("rejects a root-signed session predating challenge or reporting after expiration",async()=>{
  for(const p of [{...proof(),authenticated_at:999},{...proof(),observed_at:1300}]){
   const s=await sign(p);
   await expect(verifyPinnedSSHProof(s.payload,s.signature,s.publicKey,expected())).rejects.toThrow();
  }
 });
});
