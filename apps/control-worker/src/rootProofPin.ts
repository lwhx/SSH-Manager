import {ApiError} from "../../../packages/protocol/src/index";

export interface RootProofPin {
 nodeId:string;
 publicKey:string;
 fingerprint:string;
 actorId:string;
 auditId:string;
 createdAt:number;
}
function isPinnedNodeConflict(error:unknown):boolean {
 const pattern=/UNIQUE constraint failed:\\s*node_ssh_proof_keys\\.node_id\\b/i;
 let candidate:unknown=error;
 for(let i=0;i<5;i++){
  if(typeof candidate==="string")return pattern.test(candidate);
  if(!(candidate instanceof Error))return false;
  if(pattern.test(candidate.message))return true;
  candidate=candidate.cause;
 }
 return false;
}
/**
 * Root proof-key pinning is a one-time owner trust decision. A plain INSERT
 * makes duplicate pins a SQL error (mapped to 409); the audit and in-batch
 * CHECK sentinel guarantee that a missing audit rolls the pin back.
 */
export async function persistRootProofPin(db:D1Database,pin:RootProofPin):Promise<void>{
 let results:D1Result[];
 try{
  results=await db.batch([
   db.prepare(
    "INSERT INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at) "+
    "VALUES (?,?,?,?,?)"
   ).bind(pin.nodeId,pin.publicKey,pin.fingerprint,pin.actorId,pin.createdAt),
   db.prepare(
    "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
    "SELECT ?,?,?, 'ssh.proof-key.pin',NULL,'ok',NULL,? WHERE changes()=1"
   ).bind(pin.auditId,pin.actorId,pin.nodeId,pin.createdAt),
   db.prepare(
    "INSERT INTO manual_ssh_assertions(value) SELECT 0 WHERE changes()!=1"
   )
  ]);
 }catch(error){
  if(isPinnedNodeConflict(error))throw new ApiError("NODE_PROOF_KEY_ALREADY_PINNED",409);
  throw error;
 }
 if(results[0]?.meta.changes!==1)throw new ApiError("ROOT_PROOF_PIN_NOT_CONFIRMED",500);
 if(results[1]?.meta.changes!==1)throw new ApiError("ROOT_PROOF_PIN_AUDIT_MISSING",500);
}
