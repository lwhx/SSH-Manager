import {verifyPinnedSSHSignature} from "./proof";
import {sha256hex,validNodeId} from "./index";

export const MANUAL_ACTIONS=[
 "ssh.password.disable","ssh.password.restore","ssh.config.rollback",
 "ssh.rescue.enable","ssh.rescue.revoke"
] as const;
export type ManualAction=typeof MANUAL_ACTIONS[number];
export const isManualAction=(x:string):x is ManualAction=>
 (MANUAL_ACTIONS as readonly string[]).includes(x);

export interface RootManualExpected{
 nodeId:string; operationId:string; action:ManualAction; resultCode:string;
 expectedRevision:string; issuedAt:number; expiresAt:number;
}
export interface ManualOutcome{
 result:Record<string,unknown>;
 root_receipt:{payload:string;signature:string};
}
function plain(v:unknown):v is Record<string,unknown>{
 return !!v&&typeof v==="object"&&!Array.isArray(v);
}
const revision=(x:unknown):x is string=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const snapshot=(x:unknown):x is string=>typeof x==="string"&&/^[a-f0-9]{32}$/.test(x);
const shaFP=(x:unknown):x is string=>typeof x==="string"&&/^SHA256:[A-Za-z0-9+/]{43}$/.test(x);
export function manualResultMatches(action:ManualAction,code:string,
 result:Record<string,unknown>,payload:Record<string,unknown>,expectedRevision:string):boolean{
 if(action==="ssh.password.disable"){
  return code==="PASSWORD_DISABLED"&&snapshot(result.snapshot_ref)&&
   revision(result.after_revision)&&result.after_revision!==expectedRevision&&
   result.before_revision===expectedRevision&&revision(result.config_hash)&&
   result.passwordauthentication===false&&result.kbdinteractiveauthentication===false;
 }
 if(action==="ssh.password.restore"||action==="ssh.config.rollback"){
  const desired=action==="ssh.password.restore"?"PASSWORD_POLICY_RESTORED":"SSH_CONFIG_ROLLED_BACK";
  return code===desired&&snapshot(result.snapshot_ref)&&
   result.snapshot_ref===payload.snapshot_ref&&revision(result.after_revision)&&
   result.before_revision===expectedRevision&&revision(result.config_hash)&&
   typeof result.passwordauthentication==="boolean"&&typeof result.kbdinteractiveauthentication==="boolean";
 }
 return (action==="ssh.rescue.enable"?code==="RESCUE_KEY_INSTALLED":code==="RESCUE_KEY_REVOKED")&&
  result.key_fingerprint===payload.fingerprint&&shaFP(result.key_fingerprint)&&
  result.file_checked===true&&snapshot(result.snapshot_ref)&&
  revision(result.before_sha256)&&revision(result.after_sha256)&&
  result.before_sha256!==result.after_sha256&&
  (action!=="ssh.rescue.enable"||result.already_present!==true);
}
// The Agent may relay a Root result but cannot create a valid Ed25519 signature.
// Never accept a client-authenticated success without this independent receipt.
export async function verifyRootManualOutcome(
 detail:unknown,rootPublicKey:string,expected:RootManualExpected,
 commandPayload:Record<string,unknown>
):Promise<Record<string,unknown>>{
 if(!plain(detail)||!plain(detail.result)||!plain(detail.root_receipt))throw new Error("MISSING_SIGNED_ROOT_OUTCOME");
 const receipt=detail.root_receipt;
 if(typeof receipt.payload!=="string"||typeof receipt.signature!=="string")throw new Error("INVALID_ROOT_RECEIPT");
 await verifyPinnedSSHSignature(receipt.payload,receipt.signature,rootPublicKey);
 let r:unknown;
 try{r=JSON.parse(receipt.payload);}catch{throw new Error("INVALID_ROOT_RECEIPT_PAYLOAD")}
 if(!plain(r)||r.v!==1||!validNodeId(String(r.operation_id))||
  r.node_id!==expected.nodeId||r.operation_id!==expected.operationId||
  r.action!==expected.action||r.result_code!==expected.resultCode||
  r.expected_revision!==expected.expectedRevision||!revision(r.detail_sha256)||
  !Number.isInteger(r.executed_at)||Number(r.executed_at)<expected.issuedAt-10||
  Number(r.executed_at)>expected.expiresAt){
  throw new Error("ROOT_RECEIPT_CONTEXT_MISMATCH");
 }
 const computed=await sha256hex(JSON.stringify(detail.result));
 if(computed!==r.detail_sha256)throw new Error("ROOT_RECEIPT_RESULT_TAMPERED");
 if(!manualResultMatches(expected.action,expected.resultCode,detail.result,commandPayload,
   expected.expectedRevision)){
  throw new Error("ROOT_RECEIPT_RESULT_INVALID");
 }
 return detail.result;
}
