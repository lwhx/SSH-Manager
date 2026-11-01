import {ApiError} from "../../../packages/protocol/src/index";

export interface RootProofPin {
 nodeId:string;
 publicKey:string;
 fingerprint:string;
 actorId:string;
 auditId:string;
 createdAt:number;
}
/**
 * Root proof-key pinning is a one-time owner trust decision. Its audit must
 * commit in the same D1 transaction: a failed audit cannot leave an unlogged,
 * irrevocably pinned Root identity.
 */
export async function persistRootProofPin(db:D1Database,pin:RootProofPin):Promise<void>{
 const [inserted,audited]=await db.batch([
  db.prepare(
   "INSERT OR IGNORE INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at) "+
   "VALUES (?,?,?,?,?)"
  ).bind(pin.nodeId,pin.publicKey,pin.fingerprint,pin.actorId,pin.createdAt),
  db.prepare(
   "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "SELECT ?,?,?, 'ssh.proof-key.pin',NULL,'ok',NULL,? WHERE changes()=1"
  ).bind(pin.auditId,pin.actorId,pin.nodeId,pin.createdAt)
 ]);
 if(inserted.meta.changes!==1)throw new ApiError("NODE_PROOF_KEY_ALREADY_PINNED",409);
 if(audited.meta.changes!==1)throw new ApiError("ROOT_PROOF_PIN_AUDIT_MISSING",500);
}
