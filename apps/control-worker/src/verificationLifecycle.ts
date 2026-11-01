import {ApiError} from "../../../packages/protocol/src/index";
import {verificationStatus} from "../../../packages/protocol/src/verification";

/** A prepared SSH challenge is not a verified SSH login. */
export interface VerificationStartRecord {
 nodeId:string;verificationId:string;operationId:string;auditId:string;
 operatorId:string;keyId:string;keyFingerprint:string;loginUser:string;
 configRevision:string;nonceHash:string;createdAt:number;expiresAt:number;
 operationExpiresAt:number;signedCommand:string;signature:string;
}
export interface VerificationCancelRecord {
 nodeId:string;verificationId:string;actorId:string;auditId:string;at:number;
}
export interface VerificationReadRow {
 status:string;expires_at:number;config_revision:string;public_key_id:string;
}

function isPendingVerificationUniqueness(error:unknown):boolean {
 const constraint=/UNIQUE constraint failed:\\s*(?:ssh_verifications\\.node_id\\b|idx_one_pending_verification_per_node\\b)/i;
 let candidate:unknown=error;
 for(let i=0;i<5;i++){
  if(typeof candidate==="string")return constraint.test(candidate);
  if(!(candidate instanceof Error))return false;
  if(constraint.test(candidate.message))return true;
  candidate=candidate.cause;
 }
 return false;
}

/**
 * One D1 transaction: expire only old PENDING challenges, create new PENDING
 * verification, reserve the signed preparation operation and write an audit.
 * Conditional inserts prevent a stale preflight from silently using a rotated
 * daily key, changed SSH revision, disconnected Agent or uninstalled key.
 * The nonce itself must NEVER be stored in D1; only its SHA-256 hash is stored.
 */
export async function persistVerificationStart(
 db:D1Database,r:VerificationStartRecord
):Promise<void>{
 let results:D1Result[];
 try {
  results=await db.batch([
   db.prepare(
    "UPDATE ssh_verifications SET status='EXPIRED' "+
    "WHERE node_id=? AND status='PENDING' AND expires_at<=?"
   ).bind(r.nodeId,r.createdAt),
   db.prepare(
    "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,config_revision,nonce_hash,"+
    "status,created_at,expires_at,public_key_id,issued_by) "+
    "SELECT ?,?,?,?,?,?,'PENDING',?,?,?,? WHERE EXISTS ("+
    "SELECT 1 FROM nodes n JOIN public_keys k ON k.id=? AND k.purpose='daily' AND k.active=1 "+
    "WHERE n.id=? AND n.status='online' AND n.last_seen_at>? "+
    "AND n.init_stage='WAITING_VERIFICATION' AND n.login_user=? AND n.config_revision=? "+
    "AND EXISTS (SELECT 1 FROM node_keys nk "+
    "WHERE nk.node_id=n.id AND nk.public_key_id=k.id AND nk.login_user=n.login_user "+
    "AND nk.purpose='daily' AND nk.state='installed'))"
   ).bind(
    r.verificationId,r.nodeId,r.keyFingerprint,r.loginUser,r.configRevision,
    r.nonceHash,r.createdAt,r.expiresAt,r.keyId,r.operatorId,
    r.keyId,r.nodeId,r.createdAt-90,r.loginUser,r.configRevision
   ),
   db.prepare(
    "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"+
    "expected_revision,command_json,signature,status,created_at,expires_at) "+
    "SELECT ?,?,'ssh.verification.prepare',?,?,?,?,?,'CREATED',?,? WHERE changes()=1"
   ).bind(
    r.operationId,r.nodeId,r.operatorId,"verify-"+r.verificationId,
    r.configRevision,r.signedCommand,r.signature,r.createdAt,r.operationExpiresAt
   ),
   db.prepare(
    "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
    "SELECT ?,?,?,'ssh.verification.start',?,'PENDING',NULL,? WHERE changes()=1"
   ).bind(r.auditId,r.operatorId,r.nodeId,r.verificationId,r.createdAt)
  ]);
 }catch(error){
  if(isPendingVerificationUniqueness(error)){
   throw new ApiError("VERIFICATION_ALREADY_PENDING",409);
  }
  throw error;
 }
 if(results[1]?.meta.changes!==1){
  throw new ApiError("VERIFICATION_START_CONTEXT_CHANGED",409);
 }
 if(results[2]?.meta.changes!==1||results[3]?.meta.changes!==1){
  throw new ApiError("VERIFICATION_START_TRANSACTION_INCOMPLETE",500);
 }
}

/**
 * CAS cancellation is scoped to a single node/challenge and not yet expired.
 * A proof that became VERIFIED between the handler read and this UPDATE is
 * never overwritten. In that case changes()=0 prevents a false audit entry.
 * An audit insertion error aborts the cancellation in the same D1 batch.
 * Already DISPATCHED preparation operations are NEVER cleared by cancellation.
 */
export async function cancelPendingVerification(
 db:D1Database,r:VerificationCancelRecord
):Promise<void>{
 const [cancelled,audited]=await db.batch([
  db.prepare(
   "UPDATE ssh_verifications SET status='CANCELLED',invalidated_at=? "+
   "WHERE id=? AND node_id=? AND status='PENDING' AND expires_at>?"
  ).bind(r.at,r.verificationId,r.nodeId,r.at),
  db.prepare(
   "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "SELECT ?,?,?,'ssh.verification.cancel',?,'CANCELLED',NULL,? WHERE changes()=1"
  ).bind(r.auditId,r.actorId,r.nodeId,r.verificationId,r.at)
 ]);
 if(cancelled.meta.changes!==1)throw new ApiError("VERIFICATION_NOT_PENDING",409);
 if(audited.meta.changes!==1)throw new ApiError("VERIFICATION_CANCEL_AUDIT_MISSING",500);
}

/** GET is strictly read-only; stale or expired PENDING is projected, not mutated. */
export function projectVerificationReadStatus(
 row:VerificationReadRow,at:number,currentRevision:string,activeDailyKeyId:string|undefined
):string{
 const status=verificationStatus(row.status,row.expires_at,at);
 if(status==="PENDING"&&
   (row.config_revision!==currentRevision||row.public_key_id!==activeDailyKeyId)){
  return "INVALIDATED";
 }
 return status;
}
