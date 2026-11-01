export interface NewNodeWithPairingToken {
 id:string;name:string;host:string;port:number;loginUser:string;createdAt:number;
 tokenId:string;tokenHash:string;tokenExpiresAt:number;createdBy:string;auditId:string;
}
/**
 * Node creation is one user-visible action. Persist the node, its creation
 * audit event and the initial one-time Agent pairing token in a single D1
 * transaction so a failed response can never strand an unpairable node.
 */
export async function createNodeWithPairingToken(db:D1Database,p:NewNodeWithPairingToken):Promise<void>{
 await db.batch([
  db.prepare("INSERT INTO nodes(id,name,ssh_host,ssh_port,login_user,created_at) VALUES (?,?,?,?,?,?)")
   .bind(p.id,p.name,p.host,p.port,p.loginUser,p.createdAt),
  db.prepare("INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "VALUES (?,?,?,'node.create',NULL,'ok',NULL,?)")
   .bind(p.auditId,p.createdBy,p.id,p.createdAt),
  db.prepare("INSERT INTO pairing_tokens(id,node_id,token_hash,expires_at,created_by) VALUES (?,?,?,?,?)")
   .bind(p.tokenId,p.id,p.tokenHash,p.tokenExpiresAt,p.createdBy)
 ]);
}
