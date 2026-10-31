import {describe,expect,it} from "vitest";
import {parsePublicKey,validNodeId,safeUser,safeHost,signCommand,decodeBase64url} from "./index";

function keyBlob():Uint8Array{
 const b=new Uint8Array(51);
 const view=new DataView(b.buffer);
 view.setUint32(0,11);
 b.set(new TextEncoder().encode("ssh-ed25519"),4);
 view.setUint32(15,32);
 for(let i=0;i<32;i++)b[19+i]=i;
 return b;
}
function toBase64(b:Uint8Array):string{return btoa(String.fromCharCode(...b));}
describe("SSH public key parser",()=>{
 it("accepts a valid Ed25519 blob and uses the exact OpenSSH SHA256 fingerprint encoding",async()=>{
  const blob=keyBlob(),txt="ssh-ed25519 "+toBase64(blob)+" workstation";
  const result=await parsePublicKey(txt);
  expect(result.normalized).toBe(txt);
  const hash=new Uint8Array(await crypto.subtle.digest("SHA-256",blob));
  expect(result.fingerprint).toBe("SHA256:"+toBase64(hash).replace(/=+$/,""));
 });
 it("rejects invalid, short, or unsupported keys",async()=>{
  for(const txt of ["ssh-rsa AAAAB3","ssh-ed25519 AAAA","ssh-ed25519 no-base64",""]){
   await expect(parsePublicKey(txt)).rejects.toThrow();
  }
 });
});
describe("scope validators",()=>{
 it("requires a complete UUID and safe Linux account",()=>{
  expect(validNodeId("01234567-89ab-cdef-0123-456789abcdef")).toBe(true);
  expect(validNodeId("../passwd")).toBe(false);
  expect(safeUser("root")).toBe(true);
  expect(safeUser("../../root")).toBe(false);
  expect(safeHost("example.com")).toBe(true);
  expect(safeHost("example.com;evil")).toBe(false);
 });
});
describe("signed commands",()=>{
 it("produces a verifiable Ed25519 signature and binds exact JSON bytes",async()=>{
  const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
  const privateDer=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
  const command={v:1 as const,id:"12345678-1234-1234-1234-123456789abc",
   node_id:"12345678-1234-1234-1234-123456789abc",
   action:"node.preflight" as const,actor:"tester",issued_at:1000,expires_at:1040,expected_revision:"unverified",payload:{}};
  const signed=await signCommand(command,toBase64(privateDer));
  expect(await crypto.subtle.verify("Ed25519",pair.publicKey,Uint8Array.from(decodeBase64url(signed.signature)),new TextEncoder().encode(signed.command))).toBe(true);
  expect(await crypto.subtle.verify("Ed25519",pair.publicKey,Uint8Array.from(decodeBase64url(signed.signature)),new TextEncoder().encode(signed.command+"x"))).toBe(false);
 });
});
