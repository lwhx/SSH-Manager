export interface PairingTokenRotation {
 nodeId:string;tokenId:string;tokenHash:string;expiresAt:number;createdBy:string;
 auditId:string;createdAt:number;
}
/**
 * Revocation, issuance and audit must be a single SQLite transaction.
 * With separate requests an interleaving DELETE/INSERT could leave multiple
 * simultaneously usable tokens for the same VPS.
 */
export async function rotatePairingToken(db:D1Database,p:PairingTokenRotation):Promise<void>{
 await db.batch([
  db.prepare("DELETE FROM pairing_tokens WHERE node_id=? AND used_at IS NULL")
   .bind(p.nodeId),
  db.prepare("INSERT INTO pairing_tokens(id,node_id,token_hash,expires_at,created_by) VALUES (?,?,?,?,?)")
   .bind(p.tokenId,p.nodeId,p.tokenHash,p.expiresAt,p.createdBy),
  db.prepare("INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "VALUES (?,?,?,'node.pairing_token',NULL,'created',NULL,?)")
   .bind(p.auditId,p.createdBy,p.nodeId,p.createdAt)
 ]);
}
