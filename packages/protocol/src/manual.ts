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
// A no-write proof is valid ONLY for failures before SSH changes begin.
// Keep in sync with agent/internal/sshhelper/manual_receipt.go.
const noWriteFailureCodes=new Set([
 "SSHD_INSPECTION_FAILED","UNSUPPORTED_SSH_POLICY","POLICY_REVISION_MISMATCH",
 "MANUAL_ACTOR_REQUIRED","MANUAL_PAYLOAD_INVALID","MANUAL_NODE_CONFIRMATION_REQUIRED",
 "PASSWORD_DISABLE_LOCAL_LOCKED","FRESH_VERIFIED_LOGIN_REQUIRED",
 "MANUAL_RESTORE_LOCAL_LOCKED","RESCUE_LOCAL_LOCKED","RESCUE_KEY_SCOPE_MISMATCH",
 "RESCUE_KEY_INVALID","RESCUE_LOGIN_USER_INVALID"
]);
// The Agent can relay but cannot mint the independently pinned Root proof.
async function verifiedRootReceipt(detail:unknown,rootPublicKey:string,expected:RootManualExpected
):Promise<{result:Record<string,unknown>;receipt:Record<string,unknown>}>{
 if(!plain(detail)||!plain(detail.result)||!plain(detail.root_receipt))throw new Error("MISSING_SIGNED_ROOT_OUTCOME");
 const signed=detail.root_receipt;
 if(typeof signed.payload!=="string"||typeof signed.signature!=="string")throw new Error("INVALID_ROOT_RECEIPT");
 await verifyPinnedSSHSignature(signed.payload,signed.signature,rootPublicKey);
 let receipt:unknown;
 try{receipt=JSON.parse(signed.payload);}catch{throw new Error("INVALID_ROOT_RECEIPT_PAYLOAD")}
 if(!plain(receipt)||receipt.v!==1||!validNodeId(String(receipt.operation_id))||
  receipt.node_id!==expected.nodeId||receipt.operation_id!==expected.operationId||
  receipt.action!==expected.action||receipt.result_code!==expected.resultCode||
  receipt.expected_revision!==expected.expectedRevision||!revision(receipt.detail_sha256)||
  !Number.isInteger(receipt.executed_at)||Number(receipt.executed_at)<expected.issuedAt-10||
  Number(receipt.executed_at)>expected.expiresAt){
  throw new Error("ROOT_RECEIPT_CONTEXT_MISMATCH");
 }
 const computed=await sha256hex(JSON.stringify(detail.result));
 if(computed!==receipt.detail_sha256)throw new Error("ROOT_RECEIPT_RESULT_TAMPERED");
 return {result:detail.result,receipt};
}
export async function verifyRootManualOutcome(
 detail:unknown,rootPublicKey:string,expected:RootManualExpected,
 commandPayload:Record<string,unknown>
):Promise<Record<string,unknown>>{
 const {result,receipt}=await verifiedRootReceipt(detail,rootPublicKey,expected);
 if(receipt.no_ssh_write===true||
  !manualResultMatches(expected.action,expected.resultCode,result,commandPayload,
   expected.expectedRevision)){
  throw new Error("ROOT_RECEIPT_RESULT_INVALID");
 }
 return result;
}
// A failed manual SSH operation may finish only when Root attests no write.
export async function verifyRootManualNoWriteFailure(
 detail:unknown,rootPublicKey:string,expected:RootManualExpected
):Promise<Record<string,unknown>>{
 const {result,receipt}=await verifiedRootReceipt(detail,rootPublicKey,expected);
 if(receipt.no_ssh_write!==true||!noWriteFailureCodes.has(expected.resultCode)||
  Object.keys(result).length!==1||result.code!==expected.resultCode){
  throw new Error("ROOT_NO_WRITE_FAILURE_NOT_PROVEN");
 }
 return result;
}
