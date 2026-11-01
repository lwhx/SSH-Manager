import {ApiError} from "../../../packages/protocol/src/index";

export interface GlobalKeyRotation {
 id:string;
 purpose:"daily"|"rescue";
 name:string;
 algorithm:string;
 publicKey:string;
 fingerprint:string;
 actorId:string;
 auditId:string;
 createdAt:number;
}

/**
 * D1 batch serializes writes and executes them as one SQLite transaction.
 * Version allocation happens after deactivation inside the same transaction,
 * avoiding stale pre-batch MAX(version) reads and unaudited changes.
 * Updating this global setting never distributes a key to any VPS.
 */
export async function rotateGlobalPublicKey(db:D1Database,key:GlobalKeyRotation):Promise<number>{
 const statements=[
  db.prepare("UPDATE public_keys SET active=0 WHERE purpose=?").bind(key.purpose),
  db.prepare(
   "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,active,created_by,created_at) "+
   "SELECT ?,?,?,?,?,?,COALESCE(MAX(version),0) + 1,1,?,? FROM public_keys WHERE purpose=?"
  ).bind(key.id,key.purpose,key.name,key.algorithm,key.publicKey,key.fingerprint,
   key.actorId,key.createdAt,key.purpose)
 ];
 if(key.purpose==="daily"){
  statements.push(db.prepare(
   "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? WHERE status='PENDING'"
  ).bind(key.createdAt));
 }
 statements.push(db.prepare(
  "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
  "VALUES (?,?,NULL,?,NULL,'ok',?,?)"
 ).bind(key.auditId,key.actorId,"keys."+key.purpose+".update","key_id="+key.id,key.createdAt));
 statements.push(db.prepare("SELECT version,active FROM public_keys WHERE id=?").bind(key.id));
 const results=await db.batch(statements);
 const inserted=results[1];
 const audited=results[results.length-2];
 const row=results[results.length-1]?.results?.[0] as {version?:number;active?:number}|undefined;
 if(inserted?.meta?.changes!==1||audited?.meta?.changes!==1||
  row?.active!==1||!Number.isSafeInteger(row.version)||Number(row.version)<1){
  throw new ApiError("GLOBAL_KEY_ROTATION_NOT_CONFIRMED",500);
 }
 return Number(row.version);
}
