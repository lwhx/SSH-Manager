import {ApiError} from "../../../packages/protocol/src/index";

export interface FirstOwnerBootstrap {
 userId:string;email:string;subject:string;createdAt:number;auditId:string;
}
export interface IdentityLinkTokenIssue {
 tokenId:string;userId:string;tokenHash:string;expiresAt:number;
 createdAt:number;auditId:string;
}
export interface IdentityLinkClaim {
 subject:string;userId:string;email:string;tokenId:string;tokenHash:string;
 claimedAt:number;auditId:string;
}

/** The very first Access-verified Owner is security-sensitive and must be audited. */
export async function bootstrapFirstOwner(db:D1Database,owner:FirstOwnerBootstrap):Promise<void>{
 const [created,linked,audited]=await db.batch([
  db.prepare(
   "INSERT INTO users(id,email,role,status,created_at) VALUES (?,?,'owner','active',?)"
  ).bind(owner.userId,owner.email,owner.createdAt),
  db.prepare(
   "INSERT INTO user_identities(subject,user_id,provider,created_at) VALUES (?,?,'cloudflare-access',?)"
  ).bind(owner.subject,owner.userId,owner.createdAt),
  db.prepare(
   "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "VALUES (?,?,NULL,'identity.owner.bootstrap',NULL,'success',NULL,?)"
  ).bind(owner.auditId,owner.userId,owner.createdAt)
 ]);
 if(created.meta.changes!==1||linked.meta.changes!==1||audited.meta.changes!==1){
  throw new ApiError("OWNER_BOOTSTRAP_TRANSACTION_INCOMPLETE",500);
 }
}

/** The Owner's one-time linking token and creation audit cannot split. */
export async function issueIdentityLinkToken(db:D1Database,token:IdentityLinkTokenIssue):Promise<void>{
 const [issued,audited]=await db.batch([
  db.prepare(
   "INSERT INTO identity_link_tokens(id,user_id,token_hash,expires_at,created_at) "+
   "VALUES (?,?,?,?,?)"
  ).bind(token.tokenId,token.userId,token.tokenHash,token.expiresAt,token.createdAt),
  db.prepare(
   "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "VALUES (?,?,NULL,'identity.link_token',NULL,'created',NULL,?)"
  ).bind(token.auditId,token.userId,token.createdAt)
 ]);
 if(issued.meta.changes!==1||audited.meta.changes!==1){
  throw new ApiError("IDENTITY_TOKEN_ISSUE_INCOMPLETE",500);
 }
}

/**
 * SQLite changes() is evaluated within D1's serialized transactional batch.
 * A competing binding that INSERT OR IGNORE skips MUST NOT consume the token
 * or write an audit. An audit INSERT failure rolls the entire batch back.
 * The caller has already validated the access identity and Owner token.
 */
export async function consumeIdentityLinkToken(db:D1Database,claim:IdentityLinkClaim):Promise<void>{
 const [linked,consumed,audited]=await db.batch([
  db.prepare(
   "INSERT OR IGNORE INTO user_identities(subject,user_id,provider,created_at) "+
   "SELECT ?,?,'cloudflare-access',? WHERE EXISTS ("+
   "SELECT 1 FROM identity_link_tokens t JOIN users u ON u.id=t.user_id "+
   "WHERE t.id=? AND t.user_id=? AND t.token_hash=? AND t.used_at IS NULL "+
   "AND t.expires_at>? AND u.status='active' AND lower(u.email)=?)"
  ).bind(claim.subject,claim.userId,claim.claimedAt,claim.tokenId,
   claim.userId,claim.tokenHash,claim.claimedAt,claim.email),
  db.prepare(
   "UPDATE identity_link_tokens SET used_at=? "+
   "WHERE id=? AND user_id=? AND token_hash=? AND used_at IS NULL "+
   "AND expires_at>? AND changes()=1"
  ).bind(claim.claimedAt,claim.tokenId,claim.userId,claim.tokenHash,claim.claimedAt),
  db.prepare(
   "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "SELECT ?,?,NULL,'identity.link',NULL,'success',NULL,? WHERE changes()=1"
  ).bind(claim.auditId,claim.userId,claim.claimedAt)
 ]);
 if(linked.meta.changes!==1){
  throw new ApiError("IDENTITY_ALREADY_LINKED",409);
 }
 if(consumed.meta.changes!==1||audited.meta.changes!==1){
  throw new ApiError("IDENTITY_LINK_TRANSACTION_INCOMPLETE",500);
 }
}
