import {decodeBase64url,validNodeId} from "./index";

export interface ProofEvidence{
  v:number;proof_id:string;node_id:string;verification_id:string;key_id:string;
  login_user:string;fingerprint:string;config_revision:string;nonce_hash:string;
  authenticated_at:number;observed_at:number;client_ip:string;
  client_port:number;sshd_pid:number;
}
export interface ExpectedSSHProof{
  nodeId:string;verificationId:string;keyId:string;loginUser:string;
  fingerprint:string;configRevision:string;nonceHash:string;
  createdAt:number;expiresAt:number;now:number;
}
function isRecord(v:unknown):v is Record<string,unknown>{
 return !!v&&typeof v==="object"&&!Array.isArray(v);
}
export function proofMatchesChallenge(proof:ProofEvidence,expected:ExpectedSSHProof):boolean{
 return proof.v===1&&validNodeId(proof.proof_id)&&
  proof.node_id===expected.nodeId&&proof.verification_id===expected.verificationId&&
  proof.key_id===expected.keyId&&proof.login_user===expected.loginUser&&
  proof.fingerprint===expected.fingerprint&&proof.config_revision===expected.configRevision&&
  proof.nonce_hash===expected.nonceHash&&
  /^[a-f0-9]{64}$/.test(proof.config_revision)&&/^[a-f0-9]{64}$/.test(proof.nonce_hash)&&
  /^SHA256:[A-Za-z0-9+/]{43}$/.test(proof.fingerprint)&&
  Number.isInteger(proof.authenticated_at)&&Number.isInteger(proof.observed_at)&&
  proof.authenticated_at>=expected.createdAt&&proof.authenticated_at<expected.expiresAt&&
  proof.observed_at>=proof.authenticated_at&&proof.observed_at<expected.expiresAt&&
  proof.observed_at<=expected.now+10&&proof.observed_at>=expected.now-60&&
  expected.now<expected.expiresAt&&
  Number.isInteger(proof.client_port)&&proof.client_port>0&&proof.client_port<=65535&&
  typeof proof.client_ip==="string"&&proof.client_ip.length>0&&proof.client_ip.length<=45&&
  Number.isInteger(proof.sshd_pid)&&proof.sshd_pid>1;
}
// The signature is over the EXACT original JSON UTF-8 bytes, not a
// reconstructed object, preventing noncanonical reserialization attacks.
export async function verifyPinnedSSHSignature(payload:string,signature:string,
 proofPublicKey:string):Promise<void>{
 if(payload.length===0||payload.length>4096||signature.length>128||
    !/^[A-Za-z0-9_-]{86}$/.test(signature)||
    !/^[A-Za-z0-9_-]{43}$/.test(proofPublicKey)){
  throw new Error("INVALID_ATTESTATION_ENVELOPE");
 }
 let verified=false;
 try{
  const pub=Uint8Array.from(decodeBase64url(proofPublicKey));
  const sig=Uint8Array.from(decodeBase64url(signature));
  if(pub.length!==32||sig.length!==64)throw new Error("invalid signed proof length");
  const key=await crypto.subtle.importKey("raw",pub,{name:"Ed25519"},false,["verify"]);
  verified=await crypto.subtle.verify({name:"Ed25519"},key,sig,new TextEncoder().encode(payload));
 }catch{throw new Error("INVALID_ROOT_PROOF_SIGNATURE");}
 if(!verified)throw new Error("INVALID_ROOT_PROOF_SIGNATURE");
}
// The signature is over the EXACT original JSON bytes.
export async function verifyPinnedSSHProof(payload:string,signature:string,
 proofPublicKey:string,expected:ExpectedSSHProof):Promise<ProofEvidence>{
 await verifyPinnedSSHSignature(payload,signature,proofPublicKey);
 let parsed:unknown;
 try{parsed=JSON.parse(payload);}catch{throw new Error("INVALID_ROOT_PROOF_PAYLOAD");}
 if(!isRecord(parsed)||!proofMatchesChallenge(parsed as unknown as ProofEvidence,expected)){
  throw new Error("ROOT_PROOF_CONTEXT_MISMATCH");
 }
 return parsed as unknown as ProofEvidence;
}

// A signed proof can reach the Gateway before the independent helper
// preparation report, e.g. due to temporary network failure. This state
// MUST NOT be interpreted as a permanently invalid SSH login.
export type ProofChallengeReadiness =
 "CHALLENGE_NOT_ACTIVE"|"CHALLENGE_PREPARATION_UNCONFIRMED"|null;
export function proofChallengeReadiness(
 challenge:{status:string;expires_at:number;prepared_at:number|null}|null,
 timestamp:number
):ProofChallengeReadiness{
 if(!challenge||challenge.status!=="PENDING"||challenge.expires_at<=timestamp){
  return "CHALLENGE_NOT_ACTIVE";
 }
 if(challenge.prepared_at==null||!Number.isInteger(challenge.prepared_at)||
  challenge.prepared_at<=0){
  return "CHALLENGE_PREPARATION_UNCONFIRMED";
 }
 return null;
}
